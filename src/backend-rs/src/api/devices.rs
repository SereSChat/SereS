//! Devices of an account and the main device.
//!
//! Every login is a device (a session). One of them is the main device: a new
//! login waits until the main device allows it, or the main device links the
//! new device directly with a QR code, a link or a short code. When the main
//! device is lost, a reset with a backup code (or by e-mail) logs out every
//! device and the next login becomes the main device.
//!
//! Linking: the new device creates a key pair and shows its public key in the
//! QR code / link. The main device encrypts the account's private keys for it
//! (end-to-end; the server only passes the sealed box on) and the new device
//! gets a session once it picks the box up.

use super::auth::{create_session, hash_token, now_iso, require_user, session_hash};
use super::{ApiError, ApiResult, b64_field, json_ok, str_field};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;

/// A new login waits this long for the main device.
const PENDING_SECONDS: i64 = 15 * 60;
/// A QR code / link / code can be used this long.
const LINK_SECONDS: i64 = 10 * 60;
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/devices", get(list))
        .route("/api/devices/main", post(set_main))
        .route("/api/devices/logout", post(log_out_device))
        .route("/api/devices/approve", post(approve))
        .route("/api/devices/approval", get(approval_status))
        .route("/api/link/start", post(link_start))
        .route("/api/link/status", post(link_status))
        .route("/api/link/find", post(link_find))
        .route("/api/link/approve", post(link_approve))
        .route("/api/link/deny", post(link_deny))
}

fn iso_ago(seconds: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn db_error() -> ApiError {
    ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}

/// The main device's session, if the account has one that is still logged in.
pub(crate) async fn main_session(pool: &SqlitePool, user_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT u.main_session FROM users u JOIN user_sessions s ON s.token_hash=u.main_session
         WHERE u.id=? AND s.expires_at>? AND s.approved=1",
    )
    .bind(user_id)
    .bind(now_iso())
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Without a main device, the only logged-in device becomes it. With several
/// devices the user picks one (POST /api/devices/main).
pub(crate) async fn adopt_main_if_alone(pool: &SqlitePool, user_id: &str) {
    if main_session(pool, user_id).await.is_some() {
        return;
    }
    let sessions: Vec<String> = sqlx::query_scalar(
        "SELECT token_hash FROM user_sessions WHERE user_id=? AND expires_at>? AND approved=1",
    )
    .bind(user_id)
    .bind(now_iso())
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if let [only] = sessions.as_slice() {
        let _ = sqlx::query("UPDATE users SET main_session=? WHERE id=?")
            .bind(only)
            .bind(user_id)
            .execute(pool)
            .await;
    }
}

async fn forget_old_requests(pool: &SqlitePool) {
    let _ = sqlx::query("DELETE FROM user_sessions WHERE approved=0 AND created_at<?")
        .bind(iso_ago(PENDING_SECONDS))
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM device_links WHERE expires_at<?")
        .bind(now_iso())
        .execute(pool)
        .await;
}

struct Me {
    id: String,
    session: String,
    main: Option<String>,
}

impl Me {
    fn is_main(&self) -> bool {
        self.main.as_deref() == Some(self.session.as_str())
    }
}

async fn me(state: &AppState, headers: &HeaderMap) -> ApiResult<Me> {
    let user = require_user(state, headers).await?;
    let id: String = user.try_get("id").unwrap_or_default();
    let session = session_hash(headers)
        .ok_or_else(|| ApiError::new("Not logged in", StatusCode::UNAUTHORIZED))?;
    adopt_main_if_alone(&state.db, &id).await;
    let main = main_session(&state.db, &id).await;
    Ok(Me { id, session, main })
}

fn main_only() -> ApiError {
    ApiError::new("Only your main device can do this", StatusCode::FORBIDDEN)
}

/// All devices of the account, the waiting ones included.
async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    forget_old_requests(&state.db).await;
    let me = me(&state, &headers).await?;
    let rows = sqlx::query(
        "SELECT token_hash,user_agent,created_at,last_seen,approved FROM user_sessions
         WHERE user_id=? AND expires_at>? ORDER BY approved, last_seen DESC",
    )
    .bind(&me.id)
    .bind(now_iso())
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;
    let devices: Vec<Value> = rows
        .iter()
        .map(|row| {
            let id: String = row.try_get("token_hash").unwrap_or_default();
            json!({
                "id": id,
                "user_agent": row.try_get::<Option<String>, _>("user_agent").ok().flatten(),
                "created_at": row.try_get::<String, _>("created_at").unwrap_or_default(),
                "last_seen": row.try_get::<Option<String>, _>("last_seen").ok().flatten(),
                "approved": row.try_get::<i64, _>("approved").unwrap_or(1) == 1,
                "current": id == me.session,
                "main": me.main.as_deref() == Some(id.as_str()),
            })
        })
        .collect();
    Ok(json_ok(json!({
        "devices": devices,
        "has_main": me.main.is_some(),
        "is_main": me.is_main(),
    })))
}

/// Picks the main device. The first choice logs out every other device; later
/// only the main device can hand its role to another device.
async fn set_main(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    let target = str_field(&body, "id", 128)?;
    let first_choice = me.main.is_none();
    if !first_choice && !me.is_main() {
        return Err(main_only());
    }
    let exists = sqlx::query(
        "SELECT 1 FROM user_sessions WHERE token_hash=? AND user_id=? AND approved=1 AND expires_at>?",
    )
    .bind(target)
    .bind(&me.id)
    .bind(now_iso())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    if exists.is_none() {
        return Err(ApiError::new("Device not found", StatusCode::NOT_FOUND));
    }
    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| db_error())?;
    // Only the current main device, or the first choice while there is none,
    // changes it; two devices choosing at the same time can't both win.
    let changed = sqlx::query(
        "UPDATE users SET main_session=? WHERE id=? AND (main_session IS ? OR main_session IS NULL
         OR main_session NOT IN (SELECT token_hash FROM user_sessions WHERE user_id=? AND approved=1 AND expires_at>?))",
    )
    .bind(target)
    .bind(&me.id)
    .bind(me.main.as_deref())
    .bind(&me.id)
    .bind(now_iso())
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::new(
            "The main device has changed meanwhile",
            StatusCode::CONFLICT,
        ));
    }
    // Links approved by the previous main device can't be collected any more.
    sqlx::query("DELETE FROM device_links WHERE user_id=? AND state='approved'")
        .bind(&me.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    if first_choice {
        sqlx::query("DELETE FROM user_sessions WHERE user_id=? AND token_hash!=?")
            .bind(&me.id)
            .bind(target)
            .execute(&mut *tx)
            .await
            .map_err(|_| db_error())?;
    }
    tx.commit().await.map_err(|_| db_error())?;
    Ok(json_ok(
        json!({"logged_out": first_choice && target != me.session}),
    ))
}

/// The main device logs out another device. The main device itself first
/// hands its role to another device.
async fn log_out_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    if !me.is_main() {
        return Err(main_only());
    }
    let target = str_field(&body, "id", 128)?;
    if target == me.session {
        return Err(ApiError::new(
            "Choose another main device first",
            StatusCode::CONFLICT,
        ));
    }
    sqlx::query("DELETE FROM user_sessions WHERE token_hash=? AND user_id=?")
        .bind(target)
        .bind(&me.id)
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;
    Ok(json_ok(json!({})))
}

/// The main device allows or refuses a new login.
async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    if !me.is_main() {
        return Err(main_only());
    }
    let target = str_field(&body, "id", 128)?;
    let allow = body.get("allow").and_then(Value::as_bool) == Some(true);
    let query = if allow {
        "UPDATE user_sessions SET approved=1 WHERE token_hash=? AND user_id=? AND approved=0"
    } else {
        "DELETE FROM user_sessions WHERE token_hash=? AND user_id=? AND approved=0"
    };
    let done = sqlx::query(query)
        .bind(target)
        .bind(&me.id)
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;
    if done.rows_affected() == 0 {
        return Err(ApiError::new(
            "This login is no longer waiting",
            StatusCode::NOT_FOUND,
        ));
    }
    Ok(json_ok(json!({})))
}

/// Asked by a new login while it waits for the main device.
async fn approval_status(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    forget_old_requests(&state.db).await;
    let gone = || {
        ApiError::new(
            "This login was refused or has expired",
            StatusCode::UNAUTHORIZED,
        )
    };
    let session = session_hash(&headers).ok_or_else(gone)?;
    let row = sqlx::query(
        "SELECT user_id,approved FROM user_sessions WHERE token_hash=? AND expires_at>?",
    )
    .bind(&session)
    .bind(now_iso())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(gone)?;
    let user_id: String = row.try_get("user_id").unwrap_or_default();
    let main = match main_session(&state.db, &user_id).await {
        Some(main) => {
            sqlx::query("SELECT user_agent,last_seen FROM user_sessions WHERE token_hash=?")
                .bind(main)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .map(|row| {
                    json!({
                        "user_agent": row.try_get::<Option<String>, _>("user_agent").ok().flatten(),
                        "last_seen": row.try_get::<Option<String>, _>("last_seen").ok().flatten(),
                    })
                })
        }
        None => None,
    };
    Ok(json_ok(json!({
        "approved": row.try_get::<i64, _>("approved").unwrap_or(0) == 1,
        "main": main,
    })))
}

// ------------------------------------------------------------------ linking

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(300).collect())
}

fn new_code() -> String {
    (0..8)
        .map(|_| CODE_ALPHABET[usize::from(rand::random::<u8>()) % CODE_ALPHABET.len()] as char)
        .collect()
}

/// A new device asks to be linked: it gets a secret token (for the QR code and
/// the link) and a short code to type in on the main device.
async fn link_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let ip = super::client_ip(&headers, peer);
    if state.rate_limited(format!("link-start:{ip}"), 10, 600) {
        return Err(ApiError::new(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    let public = b64_field(&body, "pub", 200)?;
    forget_old_requests(&state.db).await;
    let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(LINK_SECONDS))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    // A code that is already taken is drawn again.
    for _ in 0..5 {
        let code = new_code();
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO device_links(token_hash,code,pub,user_agent,created_at,expires_at) VALUES(?,?,?,?,?,?)",
        )
        .bind(hash_token(&token))
        .bind(&code)
        .bind(public)
        .bind(user_agent(&headers))
        .bind(now_iso())
        .bind(&expires)
        .execute(&state.db)
        .await
        .map_err(|_| db_error())?;
        if inserted.rows_affected() == 1 {
            return Ok(json_ok(
                json!({"token": token, "code": code, "expires_in": LINK_SECONDS}),
            ));
        }
    }
    Err(db_error())
}

/// Asked by the new device: once the main device sent the sealed keys, the new
/// device gets them and its session (only once).
async fn link_status(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let ip = super::client_ip(&headers, peer);
    if state.rate_limited(format!("link-status:{ip}"), 60, 60) {
        return Err(ApiError::new(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    let token = str_field(&body, "token", 256)?;
    let gone = || ApiError::new("This code has expired", StatusCode::GONE);
    let row = sqlx::query("SELECT * FROM device_links WHERE token_hash=? AND expires_at>?")
        .bind(hash_token(token))
        .bind(now_iso())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(gone)?;
    let link_state: String = row.try_get("state").unwrap_or_default();
    match link_state.as_str() {
        "approved" => {
            // Taken exactly once, even if two requests arrive together.
            let taken =
                sqlx::query("DELETE FROM device_links WHERE token_hash=? AND state='approved'")
                    .bind(hash_token(token))
                    .execute(&state.db)
                    .await
                    .map_err(|_| db_error())?;
            if taken.rows_affected() == 0 {
                return Err(gone());
            }
            let user_id: String = row.try_get("user_id").unwrap_or_default();
            let sealed: Value = row
                .try_get::<Option<String>, _>("sealed")
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or(Value::Null);
            Ok(create_session(
                &state,
                &user_id,
                &headers,
                json!({"state": "approved", "sealed": sealed}),
                true,
            )
            .await)
        }
        "denied" => {
            let _ = sqlx::query("DELETE FROM device_links WHERE token_hash=?")
                .bind(hash_token(token))
                .execute(&state.db)
                .await;
            Ok(json_ok(json!({"state": "denied"})))
        }
        _ => Ok(json_ok(json!({"state": "waiting"}))),
    }
}

/// The main device looks up a link by the token from the QR code / link or by
/// the short code, to show what it is about to allow.
async fn link_find(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    if !me.is_main() {
        return Err(main_only());
    }
    if state.rate_limited(format!("link-find:{}", me.id), 20, 600) {
        return Err(ApiError::new(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    let row = if let Some(token) = body.get("token").and_then(Value::as_str) {
        sqlx::query(
            "SELECT * FROM device_links WHERE token_hash=? AND expires_at>? AND state='waiting'",
        )
        .bind(hash_token(token))
    } else {
        let code: String = str_field(&body, "code", 20)?
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        sqlx::query("SELECT * FROM device_links WHERE code=? AND expires_at>? AND state='waiting'")
            .bind(code)
    }
    .bind(now_iso())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| ApiError::new("This code is wrong or has expired", StatusCode::NOT_FOUND))?;
    Ok(json_ok(json!({
        "id": row.try_get::<String, _>("token_hash").unwrap_or_default(),
        "pub": row.try_get::<String, _>("pub").unwrap_or_default(),
        "user_agent": row.try_get::<Option<String>, _>("user_agent").ok().flatten(),
        "created_at": row.try_get::<String, _>("created_at").unwrap_or_default(),
    })))
}

async fn link_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    if !me.is_main() {
        return Err(main_only());
    }
    let id = str_field(&body, "id", 128)?;
    let bad = || ApiError::new("Invalid keys", StatusCode::BAD_REQUEST);
    let sealed = body.get("sealed").ok_or_else(bad)?;
    for (field, max) in [("epub", 200), ("iv", 40), ("ct", 8000)] {
        let ok = sealed
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty() && v.len() <= max);
        if !ok {
            return Err(bad());
        }
    }
    let done = sqlx::query(
        "UPDATE device_links SET state='approved', user_id=?, sealed=? WHERE token_hash=? AND state='waiting' AND expires_at>?",
    )
    .bind(&me.id)
    .bind(sealed.to_string())
    .bind(id)
    .bind(now_iso())
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;
    if done.rows_affected() == 0 {
        return Err(ApiError::new(
            "This code is wrong or has expired",
            StatusCode::NOT_FOUND,
        ));
    }
    Ok(json_ok(json!({})))
}

async fn link_deny(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = me(&state, &headers).await?;
    if !me.is_main() {
        return Err(main_only());
    }
    let id = str_field(&body, "id", 128)?;
    let _ = sqlx::query(
        "UPDATE device_links SET state='denied' WHERE token_hash=? AND state='waiting'",
    )
    .bind(id)
    .execute(&state.db)
    .await;
    Ok(json_ok(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, AppState) {
            let dir = std::env::temp_dir().join(format!("seres-devices-{}", uuid::Uuid::new_v4()));
            let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
            (Self(dir), AppState::new(pool))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn post_link_status_handles_states_and_rate_limits_by_ip() {
        let (_fix, state) = Fixture::new().await;
        sqlx::query("INSERT INTO users(id,username,enc_private) VALUES('u1','alice','enc')")
            .execute(&state.db)
            .await
            .unwrap();
        let peer: SocketAddr = "198.51.100.10:1234".parse().unwrap();

        // Missing token -> 400
        let err = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({})),
        )
        .await
        .unwrap_err();
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Waiting -> 200 waiting
        let tok_wait = "waiting-token-1";
        sqlx::query("INSERT INTO device_links(token_hash,code,pub,created_at,expires_at,state) VALUES(?,'CODE1111','pub','now','2999-01-01T00:00:00Z','waiting')")
            .bind(hash_token(tok_wait))
            .execute(&state.db)
            .await
            .unwrap();
        let resp = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_wait})),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["state"], "waiting");

        // Denied -> 200 denied, second call -> 410 Gone
        let tok_deny = "denied-token-1";
        sqlx::query("INSERT INTO device_links(token_hash,code,pub,created_at,expires_at,state) VALUES(?,'CODE2222','pub','now','2999-01-01T00:00:00Z','denied')")
            .bind(hash_token(tok_deny))
            .execute(&state.db)
            .await
            .unwrap();
        let resp = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_deny})),
        )
        .await
        .unwrap();
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["state"], "denied");
        let err = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_deny})),
        )
        .await
        .unwrap_err();
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            StatusCode::GONE
        );

        // Approved -> 200 approved with sealed + session cookie, consumed once
        let tok_ok = "approved-token-1";
        sqlx::query("INSERT INTO device_links(token_hash,code,pub,created_at,expires_at,user_id,sealed,state) VALUES(?,'CODE3333','pub','now','2999-01-01T00:00:00Z','u1',?,'approved')")
            .bind(hash_token(tok_ok))
            .bind(json!({"epub": "e", "iv": "i", "ct": "c"}).to_string())
            .execute(&state.db)
            .await
            .unwrap();
        let resp = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_ok})),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["state"], "approved");
        assert_eq!(body["sealed"]["epub"], "e");

        let err = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_ok})),
        )
        .await
        .unwrap_err();
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            StatusCode::GONE
        );

        // Rate limit: 60 per 60s per IP (6 calls already consumed above)
        for _ in 0..54 {
            let _ = link_status(
                State(state.clone()),
                ConnectInfo(peer),
                HeaderMap::new(),
                Json(json!({"token": tok_wait})),
            )
            .await;
        }
        let err = link_status(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({"token": tok_wait})),
        )
        .await
        .unwrap_err();
        assert_eq!(
            axum::response::IntoResponse::into_response(err).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
