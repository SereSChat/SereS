use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use image::{ImageFormat, imageops::FilterType};
use sqlx::Row;
use std::io::Cursor;

const MAX_AVATAR_BYTES: usize = 2 * 1024 * 1024;
const MAX_AVATAR_PIXELS: u64 = 16_000_000;
const MAX_AVATAR_DIMENSION: u32 = 16_384;
const MAX_AVATAR_DECODE_ALLOC: u64 = 200 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/get_avatar", get(get_own_avatar))
        .route("/api/users/{username}/avatar", get(get_user_avatar))
        .route(
            "/api/chats/{chat_id}/avatar",
            get(get_group_avatar)
                .post(upload_group_avatar)
                .delete(delete_group_avatar),
        )
        .route("/api/upload_avatar", post(upload_avatar))
        .layer(DefaultBodyLimit::max(MAX_AVATAR_BYTES + 128 * 1024))
}

async fn get_own_avatar(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    avatar_response(&state, "user_avatars", "user_id", &id).await
}

async fn get_user_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    let viewer = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let viewer_id: String = viewer.try_get("id").unwrap_or_default();
    let other = sqlx::query("SELECT id FROM users WHERE username=? COLLATE NOCASE")
        .bind(username.trim())
        .fetch_optional(&state.db)
        .await;
    let other_id = match other {
        Ok(Some(row)) => row.try_get::<String, _>("id").unwrap_or_default(),
        Ok(None) => return error("No avatar uploaded", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if viewer_id != other_id {
        match is_blocked(&state.db, &viewer_id, &other_id).await {
            Ok(true) => return error("No avatar uploaded", StatusCode::NOT_FOUND),
            Ok(false) => {}
            Err(_) => return db_error(),
        }
    }
    let allowed = viewer_id == other_id || sqlx::query("SELECT 1 FROM friendships WHERE user_a=MIN(?,?) AND user_b=MAX(?,?) UNION SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=? LIMIT 1")
        .bind(&viewer_id).bind(&other_id).bind(&viewer_id).bind(&other_id).bind(&viewer_id).bind(&other_id).fetch_optional(&state.db).await.ok().flatten().is_some();
    if !allowed {
        return error("No avatar uploaded", StatusCode::NOT_FOUND);
    }
    avatar_response(&state, "user_avatars", "user_id", &other_id).await
}

async fn get_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row)) if row.try_get::<String, _>("type").ok().as_deref() == Some("group") => {
            avatar_response(&state, "group_avatars", "chat_id", &chat_id).await
        }
        Ok(Some(_)) => error("Only groups have group pictures", StatusCode::NOT_FOUND),
        Ok(None) => error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}

async fn upload_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    if state.rate_limited(format!("avatar-upload:{user_id}"), 10, 600) {
        return error(
            "Too many avatar uploads, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let image = match parse_upload(multipart).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("INSERT INTO user_avatars(user_id,image,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET image=excluded.image,updated_at=excluded.updated_at").bind(user_id).bind(image).bind(now()).execute(&state.db).await{
        Ok(_)=>json_ok(serde_json::json!({"message":"Image uploaded successfully"})).into_response(),Err(_)=>db_error()
    }
}

async fn upload_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    multipart: Multipart,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type,c.owner_id,m.role FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row))
            if row.try_get::<String, _>("type").ok().as_deref() == Some("group")
                && (row.try_get::<String, _>("role").ok().as_deref() == Some("owner")
                    || row.try_get::<String, _>("owner_id").ok().as_deref()
                        == Some(user_id.as_str())) => {}
        Ok(Some(_)) => return error("Only the group owner can do this", StatusCode::FORBIDDEN),
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    if state.rate_limited(format!("avatar-upload:{user_id}"), 10, 600) {
        return error(
            "Too many avatar uploads, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let image = match parse_upload(multipart).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let updated = uuid::Uuid::new_v4().simple().to_string();
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("INSERT INTO group_avatars(chat_id,image,updated_at) VALUES(?,?,?) ON CONFLICT(chat_id) DO UPDATE SET image=excluded.image,updated_at=excluded.updated_at").bind(&chat_id).bind(image).bind(now()).execute(&mut *tx).await.is_err()||sqlx::query("UPDATE chats SET avatar_updated_at=? WHERE id=?").bind(updated).bind(&chat_id).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return db_error()}
    json_ok(serde_json::json!({"message":"Group picture uploaded"})).into_response()
}

async fn delete_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type,c.owner_id,m.role FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row))
            if row.try_get::<String, _>("type").ok().as_deref() == Some("group")
                && (row.try_get::<String, _>("role").ok().as_deref() == Some("owner")
                    || row.try_get::<String, _>("owner_id").ok().as_deref()
                        == Some(user_id.as_str())) => {}
        Ok(Some(_)) => return error("Only the group owner can do this", StatusCode::FORBIDDEN),
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM group_avatars WHERE chat_id=?")
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("UPDATE chats SET avatar_updated_at=NULL WHERE id=?")
            .bind(&chat_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(serde_json::json!({"message":"Group picture removed"})).into_response()
}

async fn parse_upload(mut multipart: Multipart) -> ApiResult<Vec<u8>> {
    let mut raw = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| {
        ApiError::new(
            "Wrong filetype (png, jpg, gif or webp)",
            StatusCode::BAD_REQUEST,
        )
    })? {
        if field.name() == Some("avatar_img") {
            if field.file_name().is_none_or(str::is_empty) {
                return Err(ApiError::new("No selected file", StatusCode::BAD_REQUEST));
            }
            let bytes = field.bytes().await.map_err(|_| {
                ApiError::new("File size exceeds 2MB limit", StatusCode::BAD_REQUEST)
            })?;
            if bytes.len() > MAX_AVATAR_BYTES {
                return Err(ApiError::new(
                    "File size exceeds 2MB limit",
                    StatusCode::BAD_REQUEST,
                ));
            }
            raw = Some(bytes.to_vec());
            break;
        }
    }
    let raw = raw.ok_or_else(|| ApiError::new("No selected file", StatusCode::BAD_REQUEST))?;
    // Decoding a large picture takes a lot of memory: a few at a time.
    static DECODES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(3);
    let _permit = DECODES
        .acquire()
        .await
        .map_err(|_| ApiError::new("Image processing failed", StatusCode::INTERNAL_SERVER_ERROR))?;
    tokio::task::spawn_blocking(move || process_avatar_bytes(&raw))
        .await
        .map_err(|_| ApiError::new("Image processing failed", StatusCode::INTERNAL_SERVER_ERROR))?
}

fn process_avatar_bytes(raw: &[u8]) -> ApiResult<Vec<u8>> {
    let bad_type = || {
        ApiError::new(
            "Wrong filetype (png, jpg, gif or webp)",
            StatusCode::BAD_REQUEST,
        )
    };
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_AVATAR_DIMENSION);
    limits.max_image_height = Some(MAX_AVATAR_DIMENSION);
    limits.max_alloc = Some(MAX_AVATAR_DECODE_ALLOC);

    let mut reader = image::ImageReader::new(Cursor::new(raw))
        .with_guessed_format()
        .map_err(|_| bad_type())?;
    reader.limits(limits.clone());
    let (width, height) = reader.into_dimensions().map_err(|err| match err {
        image::ImageError::Limits(_) => {
            ApiError::new("Image is too large", StatusCode::BAD_REQUEST)
        }
        _ => bad_type(),
    })?;
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_AVATAR_PIXELS {
        return Err(ApiError::new("Image is too large", StatusCode::BAD_REQUEST));
    }

    let mut reader = image::ImageReader::new(Cursor::new(raw))
        .with_guessed_format()
        .map_err(|_| bad_type())?;
    reader.limits(limits);
    let image = reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_) => {
            ApiError::new("Image is too large", StatusCode::BAD_REQUEST)
        }
        _ => bad_type(),
    })?;
    let image = image.resize(512, 512, FilterType::Lanczos3).to_rgba8();
    let mut png = Cursor::new(Vec::new());
    image
        .write_to(&mut png, ImageFormat::Png)
        .map_err(|_| bad_type())?;
    Ok(png.into_inner())
}

async fn avatar_response(state: &AppState, table: &str, key: &str, id: &str) -> Response {
    // Table and column identifiers are selected from the fixed endpoint definitions above.
    let sql = format!("SELECT image FROM {table} WHERE {key}=?");
    match sqlx::query_scalar::<_, Vec<u8>>(&sql)
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(image)) => {
            let mut response = Body::from(image).into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=300"),
            );
            response
        }
        Ok(None) => error("No avatar uploaded", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn db_error() -> Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
async fn is_blocked(pool: &sqlx::SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
    )
    .bind(a)
    .bind(b)
    .bind(b)
    .bind(a)
    .fetch_optional(pool)
    .await?
    .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRequest;
    use axum::http::Request;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, AppState) {
            let dir = std::env::temp_dir().join(format!("seres-avatars-{}", uuid::Uuid::new_v4()));
            let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
            (Self(dir), AppState::new(pool))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn auth_headers(pool: &sqlx::SqlitePool, user_id: &str) -> HeaderMap {
        let token = format!("tok-{user_id}");
        let hash = crate::api::auth::hash_token(&token);
        sqlx::query(
            "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at,approved) VALUES(?,?,'2999-01-01T00:00:00Z','now',1)",
        )
        .bind(hash)
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("sessioncookie={token}")).unwrap(),
        );
        headers
    }

    fn patch_png_dimensions(mut png: Vec<u8>, width: u32, height: u32) -> Vec<u8> {
        png[16..20].copy_from_slice(&width.to_be_bytes());
        png[20..24].copy_from_slice(&height.to_be_bytes());
        let mut crc = 0xffff_ffffu32;
        for &b in &png[12..29] {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        png[29..33].copy_from_slice(&(!crc).to_be_bytes());
        png
    }

    #[tokio::test]
    async fn process_avatar_bytes_resizes_valid_png_and_rejects_oversized_dimensions() {
        let img = image::RgbaImage::new(4, 4);
        let mut valid_png = Cursor::new(Vec::new());
        img.write_to(&mut valid_png, ImageFormat::Png).unwrap();
        let valid_bytes = valid_png.into_inner();
        let out = process_avatar_bytes(&valid_bytes).unwrap();
        assert!(out.starts_with(b"\x89PNG\r\n\x1a\n"));

        // 7000x7000 (49M > 40M pixels) rejected before decoding
        let big_pixels = patch_png_dimensions(valid_bytes.clone(), 7000, 7000);
        let resp = process_avatar_bytes(&big_pixels)
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["message"], "Image is too large");

        // 20000x20000 (exceeds image::Limits max_image_width/height) rejected before decoding
        let bomb = patch_png_dimensions(valid_bytes, 20_000, 20_000);
        let resp = process_avatar_bytes(&bomb).unwrap_err().into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["message"], "Image is too large");

        let bad = process_avatar_bytes(b"not an image").unwrap_err();
        assert_eq!(bad.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocked_users_cannot_fetch_avatar_and_uploads_are_rate_limited() {
        let (_fix, state) = Fixture::new().await;
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(id)
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO friendships(user_a,user_b,created_at) VALUES('alice','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_avatars(user_id,image,updated_at) VALUES('bob',X'89504E47','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;

        let ok = get_user_avatar(
            State(state.clone()),
            alice_headers.clone(),
            Path("bob".into()),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);

        // Bob blocks Alice -> Alice cannot fetch Bob's avatar
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let denied = get_user_avatar(
            State(state.clone()),
            alice_headers.clone(),
            Path("bob".into()),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        // Bob also cannot fetch Alice's avatar if Alice had one, and cannot if blocked either way
        sqlx::query(
            "INSERT INTO user_avatars(user_id,image,updated_at) VALUES('alice',X'89504E47','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let denied_reverse =
            get_user_avatar(State(state.clone()), bob_headers, Path("alice".into())).await;
        assert_eq!(denied_reverse.status(), StatusCode::NOT_FOUND);

        // Rate limit on upload_avatar (10 per 600s)
        for i in 0..11 {
            let req = Request::builder()
                .method("POST")
                .header(header::CONTENT_TYPE, "multipart/form-data; boundary=b")
                .body(Body::from("--b--\r\n"))
                .unwrap();
            let mp = Multipart::from_request(req, &state).await.unwrap();
            let resp = upload_avatar(State(state.clone()), alice_headers.clone(), mp).await;
            if i < 10 {
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            } else {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
}
