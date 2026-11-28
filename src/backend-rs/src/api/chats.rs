use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::collections::HashMap;
use uuid::Uuid;

const MAX_GROUP_MEMBERS: usize = 50;
const MAX_CIPHERTEXT_LEN: usize = 64 * 1024;
const MAX_FILES_PER_MESSAGE: usize = 10;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024 + 1024;
const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_UPLOAD_DAILY_MB: i64 = 2048;

pub async fn scheduled_loop(pool: SqlitePool) {
    loop {
        if let Err(error) = deliver_due_messages(&pool).await {
            tracing::error!(%error, "scheduled message delivery failed");
        }
        if let Err(error) = purge_expired(&pool).await {
            tracing::error!(%error, "expired message purge failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

pub fn router() -> Router<AppState> {
    let json_routes = Router::new()
        .route("/api/chats", get(list_chats).post(create_chat))
        .route("/api/load_chats", get(list_chats))
        .route("/api/new_chat", post(new_chat_legacy))
        .route("/api/chats/{chat_id}", get(chat_details))
        .route(
            "/api/chats/{chat_id}/messages",
            get(get_chat_messages).post(post_message),
        )
        .route("/api/get_messages", get(get_messages_legacy))
        .route("/api/send_message", post(send_message_legacy))
        .route("/api/remove_chat", post(remove_chat_legacy))
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/delete",
            post(delete_message),
        )
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/edit",
            post(edit_message),
        )
        .route("/api/chats/{chat_id}/typing", post(set_typing))
        .route("/api/chats/{chat_id}/read", post(mark_read))
        .route("/api/chats/{chat_id}/members", post(add_member_route))
        .route(
            "/api/chats/{chat_id}/members/remove",
            post(remove_member_route),
        )
        .route("/api/chats/{chat_id}/rename", post(rename_group))
        .route(
            "/api/chats/{chat_id}/invite",
            get(invite_get).post(invite_create).delete(invite_revoke),
        )
        .route("/api/invites/{token}", get(invite_info))
        .route("/api/invites/{token}/join", post(invite_join))
        .route("/api/chats/{chat_id}/leave", post(delete_chat))
        .route("/api/chats/{chat_id}/delete", post(delete_chat))
        .route(
            "/api/chats/{chat_id}/messages/{message_id}",
            get(single_message),
        )
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/info",
            get(message_info),
        )
        .route("/api/chats/{chat_id}/pins", post(pin_message))
        .route("/api/chats/{chat_id}/prefs", post(chat_prefs))
        .route("/api/chats/{chat_id}/disappearing", post(set_disappearing))
        .route(
            "/api/chats/{chat_id}/scheduled",
            get(scheduled_list).post(schedule_message),
        )
        .route(
            "/api/chats/{chat_id}/scheduled/{message_id}",
            axum::routing::delete(cancel_scheduled),
        )
        .route("/api/chats/{chat_id}/files/{file_id}", get(download_file))
        .route(
            "/api/chats/{chat_id}/history/{user_id}",
            post(share_history),
        )
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES));

    let upload_routes = Router::new()
        .route("/api/chats/{chat_id}/files", post(upload_file))
        .layer(DefaultBodyLimit::max(MAX_FILE_BYTES + 64 * 1024));

    json_routes.merge(upload_routes)
}

async fn list_chats(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if purge_expired(&state.db).await.is_err() {
        return db_error();
    }
    let rows=sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived,m.delivered_seq,m.reset_seq,m.reset_cleared_seq FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE m.user_id=? AND m.hidden=0 ORDER BY c.last_activity DESC").bind(&me.id).fetch_all(&state.db).await;
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let mut chats = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        let _ = advance_receipt(
            &state.db,
            &id,
            &me.id,
            "delivered",
            max_seq(&state.db, &id).await.unwrap_or(0),
        )
        .await;
        match chat_summary(&state, &row, &me.id).await {
            Ok(v) => chats.push(v),
            Err(_) => return db_error(),
        }
    }
    json_ok(json!({"chats":chats})).into_response()
}

async fn create_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("create_chat:{}", me.id), 20, 60) {
        return error(
            "You are creating chats too fast",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if body.get("type").and_then(Value::as_str).unwrap_or("dm") == "dm" {
        let username = body
            .get("username")
            .or_else(|| body.get("friend_username"))
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty());
        let Some(username) = username else {
            return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
        };
        let other = match sqlx::query("SELECT id FROM users WHERE username=? COLLATE NOCASE")
            .bind(username.trim())
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(r)) => r.try_get::<String, _>("id").unwrap_or_default(),
            Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
            Err(_) => return db_error(),
        };
        return open_dm(&state, &me.id, &other).await;
    }
    if !has_e2ee_keys(me.pub_ecdh.as_deref(), me.pub_sign.as_deref()) {
        return error("Your account has no keys yet", StatusCode::BAD_REQUEST);
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.chars().count() <= 64);
    let Some(name) = name else {
        return error(
            "Group name must be 1-64 characters",
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(usernames) = body.get("usernames").and_then(Value::as_array) else {
        return error(
            "Pick at least one friend for the group",
            StatusCode::BAD_REQUEST,
        );
    };
    if usernames.is_empty() {
        return error(
            "Pick at least one friend for the group",
            StatusCode::BAD_REQUEST,
        );
    }
    if usernames.len() > MAX_GROUP_MEMBERS {
        return error(
            format!("A group needs 2-{MAX_GROUP_MEMBERS} members"),
            StatusCode::BAD_REQUEST,
        );
    }
    let mut members = Vec::new();
    for item in usernames {
        let Some(username) = item.as_str() else {
            return error("A member name is invalid", StatusCode::BAD_REQUEST);
        };
        let row =
            sqlx::query("SELECT id,pub_ecdh,pub_sign FROM users WHERE username=? COLLATE NOCASE")
                .bind(username.trim())
                .fetch_optional(&state.db)
                .await;
        let row = match row {
            Ok(Some(r)) => r,
            _ => {
                return error(
                    format!("{username} is not your friend"),
                    StatusCode::BAD_REQUEST,
                );
            }
        };
        let id: String = row.try_get("id").unwrap_or_default();
        if id == me.id {
            continue;
        }
        if !are_friends(&state.db, &me.id, &id).await.unwrap_or(false) {
            return error(
                format!("{username} is not your friend"),
                StatusCode::BAD_REQUEST,
            );
        }
        let member_ecdh = row.try_get::<Option<String>, _>("pub_ecdh").ok().flatten();
        let member_sign = row.try_get::<Option<String>, _>("pub_sign").ok().flatten();
        if !has_e2ee_keys(member_ecdh.as_deref(), member_sign.as_deref()) {
            return error(
                format!("{username} has not set up encryption keys yet"),
                StatusCode::BAD_REQUEST,
            );
        }
        if !members.contains(&id) {
            members.push(id)
        }
    }
    if members.is_empty() || members.len() + 1 > MAX_GROUP_MEMBERS {
        return error(
            format!("A group needs 2-{MAX_GROUP_MEMBERS} members"),
            StatusCode::BAD_REQUEST,
        );
    }
    let chat_id = Uuid::new_v4().to_string();
    let now = now();
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES(?,'group',?,?,?,?)").bind(&chat_id).bind(name).bind(&me.id).bind(&now).bind(&now).execute(&mut *tx).await.is_err(){return db_error()}
    for (uid, role) in
        std::iter::once((&me.id, "owner")).chain(members.iter().map(|id| (id, "member")))
    {
        if insert_member(&mut tx, &chat_id, uid, role).await.is_err() {
            return db_error();
        }
    }
    if system_message(
        &mut tx,
        &chat_id,
        "created",
        json!({"actor":me.display_name,"name":name}),
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"chat_id":chat_id,"message":"Group created successfully!"})).into_response()
}

async fn new_chat_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("create_chat:{}", me.id), 20, 60) {
        return error(
            "You are creating chats too fast",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty());
    let Some(name) = name else {
        return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
    };
    let other = match sqlx::query_scalar::<_, String>(
        "SELECT id FROM users WHERE username=? COLLATE NOCASE",
    )
    .bind(name.trim())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    open_dm(&state, &me.id, &other).await
}

async fn reopen_dm_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat_id: &str,
    me: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) SELECT ?,?, 'member', ?, COALESCE(MAX(seq),0),0,COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
        .bind(chat_id)
        .bind(me)
        .bind(now())
        .bind(chat_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=? AND user_id=?")
        .bind(chat_id)
        .bind(me)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn open_dm(state: &AppState, me: &str, other: &str) -> axum::response::Response {
    if me == other {
        return error("Cannot create chat with yourself", StatusCode::BAD_REQUEST);
    }
    if is_blocked(&state.db, me, other).await.unwrap_or(true) {
        return error("Cannot create chat with this user", StatusCode::BAD_REQUEST);
    }
    if !are_friends(&state.db, me, other).await.unwrap_or(false) {
        return error(
            "Cannot create chat with a user who is not your friend",
            StatusCode::BAD_REQUEST,
        );
    }
    let (a, b) = pair(me, other);
    let key = format!("{a}:{b}");
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if is_blocked(&mut *tx, me, other).await.unwrap_or(true) {
        return error("Cannot create chat with this user", StatusCode::BAD_REQUEST);
    }
    if !are_friends(&mut *tx, me, other).await.unwrap_or(false) {
        return error(
            "Cannot create chat with a user who is not your friend",
            StatusCode::BAD_REQUEST,
        );
    }
    if let Some(row) = sqlx::query("SELECT id FROM chats WHERE dm_key=?")
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
    {
        let id: String = row.try_get("id").unwrap_or_default();
        if reopen_dm_tx(&mut tx, &id, me).await.is_err() || tx.commit().await.is_err() {
            return db_error();
        }
        return json_ok(json!({"chat_id":id,"message":"Chat already exists","existing":true}))
            .into_response();
    }
    let id = Uuid::new_v4().to_string();
    let now = now();
    match sqlx::query(
        "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES(?,'dm',?,?,?)",
    )
    .bind(&id)
    .bind(&key)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            let _ = tx.rollback().await;
            let mut tx2 = match begin_write(&state.db).await {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            let existing =
                match sqlx::query_scalar::<_, String>("SELECT id FROM chats WHERE dm_key=?")
                    .bind(&key)
                    .fetch_optional(&mut *tx2)
                    .await
                {
                    Ok(Some(v)) => v,
                    _ => return db_error(),
                };
            if reopen_dm_tx(&mut tx2, &existing, me).await.is_err() || tx2.commit().await.is_err() {
                return db_error();
            }
            return json_ok(
                json!({"chat_id":existing,"message":"Chat already exists","existing":true}),
            )
            .into_response();
        }
        Err(_) => return db_error(),
    }
    if insert_member(&mut tx, &id, me, "member").await.is_err()
        || insert_member(&mut tx, &id, other, "member").await.is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"chat_id":id,"message":"Chat created successfully!"})).into_response()
}

async fn chat_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let row = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    match chat_summary(&state, &row, &me.id).await {
        Ok(mut chat) => {
            let members=sqlx::query("SELECT u.id,u.username,u.display_name,u.pub_ecdh,u.pub_sign,m.role,m.joined_seq,m.reset_seq,m.reset_cleared_seq FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.joined_at,u.username COLLATE NOCASE").bind(&chat_id).fetch_all(&state.db).await;
            let members = match members {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            let member_ids = members
                .iter()
                .filter_map(|m| m.try_get::<String, _>("id").ok())
                .collect::<Vec<_>>();
            let history = match previous_key_history(&state.db, &member_ids).await {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            chat["members"] = Value::Array(members.iter().map(|m| {
                let id=m.try_get::<String,_>("id").unwrap_or_default();
                json!({"id":id,"username":m.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(m),"pub_ecdh":m.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":m.try_get::<Option<String>,_>("pub_sign").ok().flatten(),"previous_keys":history.get(&id).cloned().unwrap_or_default(),"role":m.try_get::<String,_>("role").unwrap_or_default(),"history_reset":history_reset(m)})
            }).collect());
            chat["owner_id"] = row
                .try_get::<Option<String>, _>("owner_id")
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null);
            chat["pins"] = match chat_pins(
                &state.db,
                &chat_id,
                number(&row, "joined_seq").max(number(&row, "cleared_seq")),
            )
            .await
            {
                Ok(v) => json!(v),
                Err(_) => return db_error(),
            };
            json_ok(json!({"chat":chat})).into_response()
        }
        Err(_) => db_error(),
    }
}

async fn get_chat_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    messages_response(&state, &headers, &chat_id, &query).await
}
async fn get_messages_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let id = query.get("chat_id").cloned().unwrap_or_default();
    messages_response(&state, &headers, &id, &query).await
}
async fn send_message_legacy() -> axum::response::Response {
    error(
        "This client is outdated. Please reload the page to use encrypted messaging.",
        StatusCode::GONE,
    )
}
async fn remove_chat_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(chat_id) = body
        .get("chat_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64)
    else {
        return error("Missing or invalid 'chat_id'", StatusCode::BAD_REQUEST);
    };
    delete_chat_for(&state, &me, chat_id).await
}
async fn messages_response(
    state: &AppState,
    headers: &HeaderMap,
    chat_id: &str,
    query: &HashMap<String, String>,
) -> axum::response::Response {
    let me = match user(state, headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    if purge_expired(&state.db).await.is_err() {
        return db_error();
    }
    let base = "SELECT m.*,u.username AS sender,u.display_name AS sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id";
    let rows = if let Some(rev) = query.get("since_rev") {
        let rev = rev.parse::<i64>().unwrap_or(0);
        sqlx::query(&format!(
            "{base} WHERE m.chat_id=? AND m.seq>? AND m.rev>? ORDER BY m.rev ASC LIMIT ?"
        ))
        .bind(chat_id)
        .bind(floor)
        .bind(rev)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        let before = query
            .get("before_seq")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v != 0)
            .unwrap_or(i64::MAX);
        sqlx::query(&format!(
            "{base} WHERE m.chat_id=? AND m.seq>? AND m.seq<? ORDER BY m.seq DESC LIMIT ?"
        ))
        .bind(chat_id)
        .bind(floor)
        .bind(before)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map(|mut v| {
            v.reverse();
            v
        })
    };
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if let Some(max) = rows.iter().map(|r| number(r, "seq")).max()
        && advance_receipt(&state.db, chat_id, &me.id, "delivered", max)
            .await
            .is_err()
    {
        return db_error();
    }
    let messages = rows.iter().map(serialize_message).collect::<Vec<_>>();
    let messages = match add_shares(&state.db, messages, &me.id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let receipts = member_receipts(&state.db, chat_id, &me.id)
        .await
        .ok()
        .flatten();
    let typing = typing_values(state, chat_id, &me.id).await;
    json_ok(json!({"messages":messages,"has_more":rows.len() as i64==limit,"typing":typing,"receipts":receipts})).into_response()
}

async fn post_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64);
    let Some(id) = id else {
        return error("Missing or invalid 'id'", StatusCode::BAD_REQUEST);
    };
    if Uuid::parse_str(id).is_err() {
        return error("Invalid message id", StatusCode::BAD_REQUEST);
    }
    if state.rate_limited(format!("send:{}", me.id), 30, 10) {
        return error(
            "You are sending messages too fast",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let members = match member_ids(&state.db, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm")
        && let Some(other) = members.iter().find(|v| *v != &me.id)
        && is_blocked(&state.db, &me.id, other).await.unwrap_or(true)
    {
        return error(
            "You can't send messages to this chat",
            StatusCode::FORBIDDEN,
        );
    }
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    let clean_payload = match validate_and_clean_envelope(payload, &members) {
        Ok(v) => v,
        Err(problem) => {
            let status = if problem.contains("members") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return error(problem, status);
        }
    };
    let silent = body.get("silent").and_then(Value::as_bool) == Some(true);
    let files = body.get("files").cloned().unwrap_or(json!([]));
    let Some(files) = files.as_array() else {
        return error("Invalid files", StatusCode::BAD_REQUEST);
    };
    if files.len() > MAX_FILES_PER_MESSAGE
        || files
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.len() > 64))
    {
        return error("Invalid files", StatusCode::BAD_REQUEST);
    }
    let expires = number(&chat, "disappear_seconds");
    let expires_at = (expires > 0).then(|| {
        (chrono::Utc::now() + chrono::Duration::seconds(expires))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });
    let now = now();
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    for f in files {
        let Some(fid) = f.as_str() else {
            return error("Invalid files", StatusCode::BAD_REQUEST);
        };
        if sqlx::query("UPDATE files SET message_id=? WHERE id=? AND chat_id=? AND uploader_id=? AND message_id IS NULL").bind(id).bind(fid).bind(&chat_id).bind(&me.id).execute(&mut *tx).await.map(|r|r.rows_affected()).unwrap_or(0)==0{return error("Attachment not found, please upload it again",StatusCode::BAD_REQUEST)}
    }
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result=sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev,silent,expires_at) VALUES(?,?,?,'e2e',?,?,?,?,?)").bind(id).bind(&chat_id).bind(&me.id).bind(clean_payload.to_string()).bind(&now).bind(rev).bind(i64::from(silent)).bind(expires_at).execute(&mut *tx).await;
    let result = match result {
        Ok(v) => v,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return error("Duplicate message id", StatusCode::CONFLICT);
        }
        Err(_) => return db_error(),
    };
    let seq = result.last_insert_rowid();
    if !silent
        && (sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
            .bind(&now)
            .bind(&chat_id)
            .execute(&mut *tx)
            .await
            .is_err()
            || sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=?")
                .bind(&chat_id)
                .execute(&mut *tx)
                .await
                .is_err())
    {
        return db_error();
    }
    if sqlx::query(
        "UPDATE chat_members SET last_read_seq=?,delivered_seq=? WHERE chat_id=? AND user_id=?",
    )
    .bind(seq)
    .bind(seq)
    .bind(&chat_id)
    .bind(&me.id)
    .execute(&mut *tx)
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    if !silent {
        crate::api::push::message_sent(state.db.clone(), chat_id.clone(), me.id.clone());
    }
    state.set_typing(chat_id, me.id, false);
    json_ok(json!({"message":"Message sent successfully!","seq":seq,"rev":rev})).into_response()
}

async fn delete_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result=sqlx::query("UPDATE messages SET deleted=1,payload=NULL,rev=? WHERE id=? AND chat_id=? AND sender_id=? AND deleted=0").bind(rev).bind(&message_id).bind(&chat_id).bind(&me.id).execute(&mut *tx).await;
    let rows = match result {
        Ok(v) => v.rows_affected(),
        Err(_) => return db_error(),
    };
    if rows > 0
        && forget_message_data(&mut tx, &chat_id, &message_id)
            .await
            .is_err()
    {
        return db_error();
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    if rows == 0 {
        return error("Message not found", StatusCode::NOT_FOUND);
    }
    json_ok(json!({"message":"Message deleted"})).into_response()
}
async fn edit_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if state.rate_limited(format!("edit:{}", me.id), 30, 60) {
        return error(
            "You are editing messages too fast",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let members = match member_ids(&state.db, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm")
        && let Some(other) = members.iter().find(|v| *v != &me.id)
        && is_blocked(&state.db, &me.id, other).await.unwrap_or(true)
    {
        return error(
            "You can't edit messages in this chat",
            StatusCode::FORBIDDEN,
        );
    }
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    let clean_payload = match validate_and_clean_envelope(payload, &members) {
        Ok(v) => v,
        Err(problem) => {
            let status = if problem.contains("members") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return error(problem, status);
        }
    };
    let now = now();
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result = sqlx::query(
        "UPDATE messages SET payload=?,edited_at=?,rev=? WHERE id=? AND chat_id=? AND sender_id=? AND kind='e2e' AND deleted=0 AND (expires_at IS NULL OR expires_at>?)",
    )
    .bind(clean_payload.to_string())
    .bind(&now)
    .bind(rev)
    .bind(&message_id)
    .bind(&chat_id)
    .bind(&me.id)
    .bind(&now)
    .execute(&mut *tx)
    .await;
    let rows = match result {
        Ok(v) => v.rows_affected(),
        Err(_) => return db_error(),
    };
    if rows > 0
        && sqlx::query("DELETE FROM message_key_shares WHERE message_id=?")
            .bind(&message_id)
            .execute(&mut *tx)
            .await
            .is_err()
    {
        return db_error();
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    if rows == 0 {
        return error("Message not found", StatusCode::NOT_FOUND);
    }
    json_ok(json!({"message":"Message edited"})).into_response()
}

async fn set_typing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    state.set_typing(
        chat_id,
        me.id,
        body.get("typing").and_then(Value::as_bool) != Some(false),
    );
    json_ok(json!({})).into_response()
}
async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let Some(seq) = body.get("seq").and_then(Value::as_i64) else {
        return error("Invalid seq", StatusCode::BAD_REQUEST);
    };
    let seq = seq.min(max_seq(&state.db, &chat_id).await.unwrap_or(0));
    match advance_receipt(&state.db, &chat_id, &me.id, "read", seq).await {
        Ok(_) => json_ok(json!({})).into_response(),
        Err(_) => db_error(),
    }
}

async fn add_member_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty());
    let Some(name) = name else {
        return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
    };
    let other = match sqlx::query(
        "SELECT id,username,display_name,pub_ecdh,pub_sign FROM users WHERE username=? COLLATE NOCASE",
    )
    .bind(name.trim())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let other_id: String = other.try_get("id").unwrap_or_default();
    let other_ecdh = other
        .try_get::<Option<String>, _>("pub_ecdh")
        .ok()
        .flatten();
    let other_sign = other
        .try_get::<Option<String>, _>("pub_sign")
        .ok()
        .flatten();
    if !has_e2ee_keys(other_ecdh.as_deref(), other_sign.as_deref()) {
        return error(
            "User has not set up encryption keys yet",
            StatusCode::BAD_REQUEST,
        );
    }
    if !are_friends(&state.db, &me.id, &other_id)
        .await
        .unwrap_or(false)
    {
        return error("You can only add your friends", StatusCode::BAD_REQUEST);
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let chat = match membership(&mut *tx, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let is_owner = chat.try_get::<String, _>("role").ok().as_deref() == Some("owner");
    let banned = sqlx::query("SELECT 1 FROM group_bans WHERE chat_id=? AND user_id=?")
        .bind(&chat_id)
        .bind(&other_id)
        .fetch_optional(&mut *tx)
        .await;
    match banned {
        Ok(Some(_)) if !is_owner => {
            return error(
                "Only the group owner can re-add a removed member",
                StatusCode::FORBIDDEN,
            );
        }
        Ok(Some(_)) => {
            if sqlx::query("DELETE FROM group_bans WHERE chat_id=? AND user_id=?")
                .bind(&chat_id)
                .bind(&other_id)
                .execute(&mut *tx)
                .await
                .is_err()
            {
                return db_error();
            }
        }
        Ok(None) => {}
        Err(_) => return db_error(),
    }
    if membership(&mut *tx, &chat_id, &other_id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return error("Already in the group", StatusCode::BAD_REQUEST);
    }
    let owner_id: Option<String> = chat.try_get("owner_id").ok().flatten();
    if let Some(oid) = owner_id.as_deref()
        && is_blocked(&mut *tx, oid, &other_id).await.unwrap_or(true)
    {
        return error("Cannot add this user to the group", StatusCode::FORBIDDEN);
    }
    let current_members = match member_ids(&mut *tx, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if current_members.len() >= MAX_GROUP_MEMBERS {
        return error("The group is full", StatusCode::BAD_REQUEST);
    }
    for member_id in &current_members {
        if is_blocked(&mut *tx, member_id, &other_id)
            .await
            .unwrap_or(true)
        {
            return error("Cannot add this user to the group", StatusCode::FORBIDDEN);
        }
    }
    if insert_member(&mut tx, &chat_id, &other_id, "member")
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "added",
            json!({"actor":me.display_name,"target":display_name(&other)}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Member added"})).into_response()
}
async fn remove_member_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let other = match target_member(&state.db, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if other.0 == me.id {
        return error("Use 'leave group' instead", StatusCode::BAD_REQUEST);
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let chat = match membership(&mut *tx, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    if membership(&mut *tx, &chat_id, &other.0)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Not a member", StatusCode::BAD_REQUEST);
    }
    if sqlx::query("DELETE FROM chat_members WHERE chat_id=? AND user_id=?")
        .bind(&chat_id)
        .bind(&other.0)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("INSERT OR REPLACE INTO group_bans(chat_id,user_id,banned_at) VALUES(?,?,?)")
            .bind(&chat_id)
            .bind(&other.0)
            .bind(now())
            .execute(&mut *tx)
            .await
            .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "removed",
            json!({"actor":me.display_name,"target":other.1}),
        )
        .await
        .is_err()
        || crate::api::calls::remove_user_from_chat_calls(&mut tx, &chat_id, &other.0)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    crate::api::apns::calls_stopped_ringing(state.db.clone(), None);
    json_ok(json!({"message":"Member removed"})).into_response()
}
async fn rename_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.chars().count() <= 64);
    let Some(name) = name else {
        return error(
            "Group name must be 1-64 characters",
            StatusCode::BAD_REQUEST,
        );
    };
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("UPDATE chats SET name=? WHERE id=?")
        .bind(name)
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "renamed",
            json!({"actor":me.display_name,"name":name}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Group renamed"})).into_response()
}
async fn delete_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    delete_chat_for(&state, &me, &chat_id).await
}
async fn delete_chat_for(state: &AppState, me: &User, chat_id: &str) -> axum::response::Response {
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let chat = match membership(&mut *tx, chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let is_group = chat.try_get::<String, _>("type").ok().as_deref() == Some("group");
    if is_group {
        if sqlx::query("DELETE FROM chat_members WHERE chat_id=? AND user_id=?")
            .bind(chat_id)
            .bind(&me.id)
            .execute(&mut *tx)
            .await
            .is_err()
            || crate::api::calls::remove_user_from_chat_calls(&mut tx, chat_id, &me.id)
                .await
                .is_err()
        {
            return db_error();
        }
        let remaining = sqlx::query(
            "SELECT user_id FROM chat_members WHERE chat_id=? ORDER BY CASE WHEN role='owner' THEN 0 ELSE 1 END, joined_at, user_id COLLATE NOCASE",
        )
        .bind(chat_id)
        .fetch_all(&mut *tx)
        .await;
        let remaining = match remaining {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
        if remaining.is_empty() {
            if sqlx::query(
                "DELETE FROM message_key_shares WHERE message_id IN (SELECT id FROM messages WHERE chat_id=?)",
            )
            .bind(chat_id)
            .execute(&mut *tx)
            .await
            .is_err()
                || sqlx::query("DELETE FROM receipts WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM scheduled_messages WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM group_bans WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query(
                    "DELETE FROM call_signals WHERE call_id IN (SELECT id FROM calls WHERE chat_id=?)",
                )
                .bind(chat_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query(
                    "DELETE FROM call_participants WHERE call_id IN (SELECT id FROM calls WHERE chat_id=?)",
                )
                .bind(chat_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query("DELETE FROM calls WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM group_avatars WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query(
                    "DELETE FROM file_blobs WHERE id IN (SELECT id FROM files WHERE chat_id=?)",
                )
                .bind(chat_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query("DELETE FROM files WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM pinned_messages WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM messages WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM chats WHERE id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
            {
                return db_error();
            }
        } else {
            let was_owner = chat
                .try_get::<Option<String>, _>("owner_id")
                .ok()
                .flatten()
                .as_deref()
                == Some(&me.id)
                || chat.try_get::<String, _>("role").ok().as_deref() == Some("owner");
            if was_owner {
                let new_owner: String = remaining[0].try_get("user_id").unwrap_or_default();
                if sqlx::query("UPDATE chats SET owner_id=? WHERE id=?")
                    .bind(&new_owner)
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                    || sqlx::query(
                        "UPDATE chat_members SET role='owner' WHERE chat_id=? AND user_id=?",
                    )
                    .bind(chat_id)
                    .bind(new_owner)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                {
                    return db_error();
                }
            }
            if system_message(&mut tx, chat_id, "left", json!({"actor":me.display_name}))
                .await
                .is_err()
            {
                return db_error();
            }
        }
    } else {
        let max = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?",
        )
        .bind(chat_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if sqlx::query(
            "UPDATE chat_members SET hidden=1,cleared_seq=? WHERE chat_id=? AND user_id=?",
        )
        .bind(max)
        .bind(chat_id)
        .bind(&me.id)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return db_error();
        }
        if reclaim_mutually_cleared_dm(&mut tx, chat_id).await.is_err() {
            return db_error();
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    if is_group {
        crate::api::apns::calls_stopped_ringing(state.db.clone(), None);
    }
    json_ok(json!({"message":"Chat deleted successfully"})).into_response()
}
async fn target_member(pool: &SqlitePool, body: &Value) -> ApiResult<(String, String)> {
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::new("Missing or invalid 'username'", StatusCode::BAD_REQUEST))?;
    let row=sqlx::query("SELECT id,COALESCE(NULLIF(display_name,''),username) AS display_name FROM users WHERE username=? COLLATE NOCASE").bind(name.trim()).fetch_optional(pool).await.map_err(|_|ApiError::new("Database unavailable",StatusCode::INTERNAL_SERVER_ERROR))?.ok_or_else(||ApiError::new("User not found",StatusCode::NOT_FOUND))?;
    Ok((
        row.try_get("id").unwrap_or_default(),
        row.try_get("display_name").unwrap_or_default(),
    ))
}

async fn single_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let row = sqlx::query(
        "SELECT m.*,u.username sender,u.display_name sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.id=? AND m.chat_id=? AND m.seq>? AND (m.expires_at IS NULL OR m.expires_at>?)",
    )
    .bind(&message_id)
    .bind(&chat_id)
    .bind(floor)
    .bind(now())
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(Some(v)) => v,
        Ok(None) => return error("Message not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let msgs = match add_shares(&state.db, vec![serialize_message(&row)], &me.id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    json_ok(json!({"message":msgs[0]})).into_response()
}

async fn message_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let message = match sqlx::query(
        "SELECT seq,created_at,sender_id FROM messages WHERE id=? AND chat_id=? AND deleted=0 AND seq>? AND (expires_at IS NULL OR expires_at>?)",
    )
    .bind(&message_id)
    .bind(&chat_id)
    .bind(floor)
    .bind(now())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error("Message not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let seq = number(&message, "seq");
    let sender: Option<String> = message.try_get("sender_id").ok().flatten();
    let rows=match sqlx::query("SELECT u.id,u.username,u.display_name,m.delivered_seq,m.last_read_seq,m.joined_seq FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=?").bind(&chat_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return db_error()};
    let mut members = Vec::new();
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        if Some(id.as_str()) == sender.as_deref() || number(&row, "joined_seq") >= seq {
            continue;
        }
        let read = number(&row, "last_read_seq") >= seq;
        let delivered = read || number(&row, "delivered_seq") >= seq;
        let delivered_at = if delivered {
            receipt_time(&state.db, &chat_id, &id, "delivered", seq)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let read_at = if read {
            receipt_time(&state.db, &chat_id, &id, "read", seq)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        members.push(json!({"id":id,"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&row),"delivered":delivered,"delivered_at":delivered_at,"read":read,"read_at":read_at}))
    }
    json_ok(json!({"sent_at":message.try_get::<String,_>("created_at").unwrap_or_default(),"members":members})).into_response()
}
async fn receipt_time(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
    kind: &str,
    seq: i64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT MIN(at) FROM receipts WHERE chat_id=? AND user_id=? AND kind=? AND seq>=?",
    )
    .bind(chat)
    .bind(user)
    .bind(kind)
    .bind(seq)
    .fetch_one(pool)
    .await
}

async fn pin_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let message_id = body
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64);
    let Some(message_id) = message_id else {
        return error("Missing or invalid 'message_id'", StatusCode::BAD_REQUEST);
    };
    let pinned = body.get("pinned").and_then(Value::as_bool) != Some(false);
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let valid = sqlx::query(
        "SELECT 1 FROM messages WHERE id=? AND chat_id=? AND deleted=0 AND silent=0 AND kind!='system' AND seq>? AND (expires_at IS NULL OR expires_at>?)",
    )
    .bind(message_id)
    .bind(&chat_id)
    .bind(floor)
    .bind(now())
    .fetch_optional(&state.db)
    .await;
    match valid {
        Ok(Some(_)) => {}
        Ok(None) => return error("Message not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if pinned {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pinned_messages WHERE chat_id=?")
                .bind(&chat_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(0);
        if count >= 50 {
            return error("At most 50 pinned messages", StatusCode::BAD_REQUEST);
        }
        let added=sqlx::query("INSERT OR IGNORE INTO pinned_messages(chat_id,message_id,pinned_by,pinned_at) VALUES(?,?,?,?)").bind(&chat_id).bind(message_id).bind(&me.id).bind(now()).execute(&mut *tx).await.map(|r|r.rows_affected()).unwrap_or(0);
        if added > 0
            && system_message(
                &mut tx,
                &chat_id,
                "pinned",
                json!({"actor":me.display_name}),
            )
            .await
            .is_err()
        {
            return db_error();
        }
    } else if sqlx::query("DELETE FROM pinned_messages WHERE chat_id=? AND message_id=?")
        .bind(&chat_id)
        .bind(message_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return db_error();
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    match chat_pins(&state.db, &chat_id, floor).await {
        Ok(v) => json_ok(json!({"pins":v})).into_response(),
        Err(_) => db_error(),
    }
}
async fn chat_prefs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    for key in ["pinned", "archived"] {
        if let Some(v) = body.get(key) {
            let Some(value) = v.as_bool() else {
                return error(format!("Invalid '{key}'"), StatusCode::BAD_REQUEST);
            };
            let sql = format!("UPDATE chat_members SET {key}=? WHERE chat_id=? AND user_id=?");
            if sqlx::query(&sql)
                .bind(i64::from(value))
                .bind(&chat_id)
                .bind(&me.id)
                .execute(&mut *tx)
                .await
                .is_err()
            {
                return db_error();
            }
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({})).into_response()
}
async fn set_disappearing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("group")
        && chat.try_get::<String, _>("role").ok().as_deref() != Some("owner")
    {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let Some(seconds) = body.get("seconds").and_then(Value::as_i64) else {
        return error("Invalid timer", StatusCode::BAD_REQUEST);
    };
    if ![0, 3600, 86400, 604800, 7776000].contains(&seconds) {
        return error("Invalid timer", StatusCode::BAD_REQUEST);
    }
    if seconds == number(&chat, "disappear_seconds") {
        return json_ok(json!({"disappear_seconds":seconds})).into_response();
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("UPDATE chats SET disappear_seconds=? WHERE id=?")
        .bind(seconds)
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "disappearing",
            json!({"actor":me.display_name,"seconds":seconds}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"disappear_seconds":seconds})).into_response()
}

async fn scheduled_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    // The (still encrypted) message goes along, so the sender can read what is planned.
    match sqlx::query("SELECT id,send_at,created_at,payload FROM scheduled_messages WHERE chat_id=? AND sender_id=? ORDER BY send_at").bind(&chat_id).bind(&me.id).fetch_all(&state.db).await {
        Ok(rows) => json_ok(json!({"messages":rows.iter().map(|r| json!({"id":r.try_get::<String,_>("id").unwrap_or_default(),"send_at":r.try_get::<String,_>("send_at").unwrap_or_default(),"created_at":r.try_get::<String,_>("created_at").unwrap_or_default(),"payload":r.try_get::<String,_>("payload").ok().and_then(|p| serde_json::from_str::<Value>(&p).ok())})).collect::<Vec<_>>()})).into_response(),
        Err(_) => db_error()
    }
}

async fn schedule_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let Some(id) = body
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 64)
    else {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(at) = body.get("send_at").and_then(Value::as_str) else {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    };
    if Uuid::parse_str(id).is_err() {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    }
    let send_at = match chrono::DateTime::parse_from_rfc3339(at) {
        Ok(v) => v.with_timezone(&chrono::Utc),
        Err(_) => {
            return error(
                "Invalid scheduled time or message id",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let now_utc = chrono::Utc::now();
    if send_at < now_utc + chrono::Duration::minutes(1)
        || send_at > now_utc + chrono::Duration::days(365)
    {
        return error(
            "Schedule between one minute and one year from now",
            StatusCode::BAD_REQUEST,
        );
    }
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let member_rows = match sqlx::query(
        "SELECT m.user_id,u.pub_ecdh FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.user_id",
    )
    .bind(&chat_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let mut members = Vec::with_capacity(member_rows.len());
    let mut member_keys = std::collections::BTreeMap::new();
    for row in &member_rows {
        let uid: String = row.try_get("user_id").unwrap_or_default();
        let ecdh: Option<String> = row.try_get("pub_ecdh").ok().flatten();
        member_keys.insert(uid.clone(), ecdh);
        members.push(uid);
    }
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm") {
        for member in &members {
            if member != &me.id && is_blocked(&mut *tx, &me.id, member).await.unwrap_or(true) {
                return error(
                    "You can't send messages to this chat",
                    StatusCode::FORBIDDEN,
                );
            }
        }
    }
    let clean_payload = match validate_and_clean_envelope(payload, &members) {
        Ok(v) => v,
        Err(problem) => {
            let status = if problem.contains("members") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            return error(problem, status);
        }
    };
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scheduled_messages WHERE sender_id=?")
            .bind(&me.id)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    if count >= 100 {
        return error("Too many scheduled messages", StatusCode::BAD_REQUEST);
    }
    match sqlx::query(
        "SELECT 1 FROM messages WHERE id=? UNION SELECT 1 FROM scheduled_messages WHERE id=?",
    )
    .bind(id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(_)) => return error("Duplicate message id", StatusCode::CONFLICT),
        Err(_) => return db_error(),
        Ok(None) => {}
    }
    let member_ids = match serde_json::to_string(&members) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let member_keys_json = match serde_json::to_string(&member_keys) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match sqlx::query("INSERT INTO scheduled_messages(id,chat_id,sender_id,payload,member_ids,sender_sign_key,member_keys,send_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(id)
        .bind(&chat_id)
        .bind(&me.id)
        .bind(clean_payload.to_string())
        .bind(member_ids)
        .bind(me.pub_sign.unwrap_or_default())
        .bind(member_keys_json)
        .bind(send_at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .bind(now())
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {
            if tx.commit().await.is_err() {
                return db_error();
            }
            json_ok(json!({"message":"Message scheduled","id":id})).into_response()
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            error("Duplicate message id", StatusCode::CONFLICT)
        }
        Err(_) => db_error(),
    }
}

async fn cancel_scheduled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    match sqlx::query("DELETE FROM scheduled_messages WHERE id=? AND chat_id=? AND sender_id=?")
        .bind(message_id)
        .bind(chat_id)
        .bind(me.id)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            json_ok(json!({"message":"Scheduled message cancelled"})).into_response()
        }
        Ok(_) => error("Scheduled message not found", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}

async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    body: Bytes,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm") {
        let members = match member_ids(&state.db, &chat_id).await {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
        if let Some(other) = members.iter().find(|v| *v != &me.id)
            && is_blocked(&state.db, &me.id, other).await.unwrap_or(true)
        {
            return error("You can't send files to this chat", StatusCode::FORBIDDEN);
        }
    }
    if state.rate_limited(format!("upload:{}", me.id), 30, 60) {
        return error("You are uploading too fast", StatusCode::TOO_MANY_REQUESTS);
    }
    if body.is_empty() {
        return error("Empty file", StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_FILE_BYTES {
        return error("Files can be at most 16 MB", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let pending = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM files WHERE uploader_id=? AND message_id IS NULL",
    )
    .bind(&me.id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    if pending >= 30 {
        return error(
            "Too many unsent attachments, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let daily_limit = upload_daily_limit_bytes();
    let day_cutoff = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let uploaded_today = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(size),0) FROM files WHERE uploader_id=? AND created_at>?",
    )
    .bind(&me.id)
    .bind(&day_cutoff)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    if uploaded_today.saturating_add(body.len() as i64) > daily_limit {
        return error(
            "Daily upload quota exceeded, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let id = Uuid::new_v4().simple().to_string();
    if sqlx::query("INSERT INTO file_blobs(id,data) VALUES(?,?)")
        .bind(&id)
        .bind(body.as_ref())
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query(
            "INSERT INTO files(id,chat_id,uploader_id,message_id,size,created_at) VALUES(?,?,?,NULL,?,?)",
        )
        .bind(&id)
        .bind(&chat_id)
        .bind(&me.id)
        .bind(body.len() as i64)
        .bind(now())
        .execute(&mut *tx)
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"file_id":id})).into_response()
}
async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, file_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let now_ts = now();
    let row = sqlx::query(
        "SELECT f.uploader_id,f.message_id,m.seq,m.deleted,m.expires_at,b.data FROM files f LEFT JOIN messages m ON m.id=f.message_id LEFT JOIN file_blobs b ON b.id=f.id WHERE f.id=? AND f.chat_id=? AND (f.message_id IS NULL OR (m.deleted=0 AND (m.expires_at IS NULL OR m.expires_at>?)))",
    )
    .bind(file_id)
    .bind(&chat_id)
    .bind(&now_ts)
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(Some(v)) => v,
        Ok(None) => return error("File not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let message_id: Option<String> = row.try_get("message_id").ok().flatten();
    let expires_at: Option<String> = row.try_get("expires_at").ok().flatten();
    let visible = if message_id.is_none() {
        row.try_get::<String, _>("uploader_id").ok().as_deref() == Some(me.id.as_str())
    } else {
        row.try_get::<Option<i64>, _>("seq")
            .ok()
            .flatten()
            .is_some_and(|seq| seq > floor)
            && row.try_get::<Option<i64>, _>("deleted").ok().flatten() == Some(0)
            && expires_at.as_deref().is_none_or(|e| e > now_ts.as_str())
    };
    if !visible {
        return error("File not found", StatusCode::NOT_FOUND);
    }
    let Some(data) = row.try_get::<Option<Vec<u8>>, _>("data").ok().flatten() else {
        return error("File not found", StatusCode::NOT_FOUND);
    };
    let mut response = axum::body::Body::from(data).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    let cache_control = if expires_at.is_some() {
        "no-store"
    } else {
        "private, max-age=604800, immutable"
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(cache_control),
    );
    response
}

async fn share_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, target_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(pub_ecdh) = me
        .pub_ecdh
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
    else {
        return error("Your account has no keys yet", StatusCode::BAD_REQUEST);
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if target_id == me.id {
        return error(
            "You can't share the history with yourself",
            StatusCode::BAD_REQUEST,
        );
    }
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm")
        && is_blocked(&state.db, &me.id, &target_id)
            .await
            .unwrap_or(true)
    {
        return error(
            "You can't share history in this chat",
            StatusCode::FORBIDDEN,
        );
    }
    let empty = serde_json::Map::new();
    let keys = match body.get("keys") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => &empty,
        Some(Value::Number(value)) if value.as_i64() == Some(0) => &empty,
        Some(Value::String(value)) if value.is_empty() => &empty,
        Some(Value::Array(value)) if value.is_empty() => &empty,
        Some(Value::Object(value)) => value,
        Some(_) => return error("Invalid keys", StatusCode::BAD_REQUEST),
    };
    if keys.len() > 500 {
        return error("Invalid keys", StatusCode::BAD_REQUEST);
    }
    for (id, wrapped) in keys {
        if id.len() > 64
            || !wrapped.is_object()
            || !valid_b64_field(wrapped.get("iv"), 64)
            || !valid_b64_field(wrapped.get("k"), 128)
        {
            return error("Invalid keys", StatusCode::BAD_REQUEST);
        }
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let chat = match membership(&mut *tx, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm")
        && is_blocked(&mut *tx, &me.id, &target_id)
            .await
            .unwrap_or(true)
    {
        return error(
            "You can't share history in this chat",
            StatusCode::FORBIDDEN,
        );
    }
    let target = match membership(&mut *tx, &chat_id, &target_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let reset = number(&target, "reset_seq");
    if reset == 0 {
        return error("There is nothing to share", StatusCode::CONFLICT);
    }
    let target_floor = number(&target, "joined_seq").max(number(&target, "reset_cleared_seq"));
    let sharer_floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let lowest = target_floor.max(sharer_floor);
    let now_ts = now();
    let mut stored = 0i64;
    for (id, wrapped) in keys {
        let eligible = sqlx::query(
            "SELECT 1 FROM messages WHERE chat_id=? AND id=? AND kind='e2e' AND deleted=0 AND seq>? AND seq<=? AND (expires_at IS NULL OR expires_at>?)",
        )
        .bind(&chat_id)
        .bind(id)
        .bind(lowest)
        .bind(reset)
        .bind(&now_ts)
        .fetch_optional(&mut *tx)
        .await;
        match eligible {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(_) => return db_error(),
        }
        let iv = wrapped
            .get("iv")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let k = wrapped.get("k").and_then(Value::as_str).unwrap_or_default();
        match sqlx::query(
            "INSERT INTO message_key_shares(message_id,recipient_id,sharer_id,sharer_pub_ecdh,iv,k,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(message_id,recipient_id,sharer_id) DO UPDATE SET sharer_pub_ecdh=excluded.sharer_pub_ecdh,iv=excluded.iv,k=excluded.k,created_at=excluded.created_at",
        )
        .bind(id)
        .bind(&target_id)
        .bind(&me.id)
        .bind(&pub_ecdh)
        .bind(iv)
        .bind(k)
        .bind(&now_ts)
        .execute(&mut *tx)
        .await
        {
            Ok(v) => stored += v.rows_affected() as i64,
            Err(_) => return db_error(),
        }
    }
    if body.get("done").and_then(Value::as_bool) == Some(true) {
        let eligible_in_range: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE chat_id=? AND kind='e2e' AND deleted=0 AND seq>? AND seq<=? AND (expires_at IS NULL OR expires_at>?)",
        )
        .bind(&chat_id)
        .bind(lowest)
        .bind(reset)
        .bind(&now_ts)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        let shares_by_me: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM message_key_shares s JOIN messages m ON m.id=s.message_id WHERE m.chat_id=? AND m.kind='e2e' AND m.deleted=0 AND m.seq>? AND m.seq<=? AND (m.expires_at IS NULL OR m.expires_at>?) AND s.recipient_id=? AND s.sharer_id=?",
        )
        .bind(&chat_id)
        .bind(lowest)
        .bind(reset)
        .bind(&now_ts)
        .bind(&target_id)
        .bind(&me.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if eligible_in_range > 0 && stored == 0 && shares_by_me == 0 {
            return error("No message keys were shared", StatusCode::BAD_REQUEST);
        }
        if lowest > target_floor {
            if lowest >= reset {
                return error(
                    "You do not have earlier messages to share",
                    StatusCode::BAD_REQUEST,
                );
            }
            let narrowed = sqlx::query(
                "UPDATE chat_members SET cleared_seq=CASE WHEN cleared_seq<=reset_seq THEN MIN(cleared_seq,?) ELSE cleared_seq END,reset_seq=? WHERE chat_id=? AND user_id=? AND reset_seq>0",
            )
            .bind(lowest)
            .bind(lowest)
            .bind(&chat_id)
            .bind(&target_id)
            .execute(&mut *tx)
            .await;
            match narrowed {
                Ok(r) if r.rows_affected() > 0 => {}
                Ok(_) => return error("There is nothing to share", StatusCode::CONFLICT),
                Err(_) => return db_error(),
            }
        } else {
            let target_name = match sqlx::query(
                "SELECT COALESCE(NULLIF(display_name,''),username) AS name FROM users WHERE id=?",
            )
            .bind(&target_id)
            .fetch_optional(&mut *tx)
            .await
            {
                Ok(Some(row)) => row.try_get::<String, _>("name").unwrap_or_default(),
                _ => return db_error(),
            };
            let completed = sqlx::query(
                "UPDATE chat_members SET cleared_seq=CASE WHEN cleared_seq<=reset_seq THEN MIN(cleared_seq,?) ELSE cleared_seq END,reset_seq=0,reset_cleared_seq=0 WHERE chat_id=? AND user_id=? AND reset_seq>0",
            )
            .bind(number(&target, "reset_cleared_seq"))
            .bind(&chat_id)
            .bind(&target_id)
            .execute(&mut *tx)
            .await;
            match completed {
                Ok(r) if r.rows_affected() > 0 => {}
                Ok(_) => return error("There is nothing to share", StatusCode::CONFLICT),
                Err(_) => return db_error(),
            }
            if system_message(
                &mut tx,
                &chat_id,
                "history_shared",
                json!({"actor":me.display_name,"target":target_name,"target_id":target_id}),
            )
            .await
            .is_err()
            {
                return db_error();
            }
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({"stored":stored})).into_response()
}

async fn previous_key_history(
    pool: &SqlitePool,
    ids: &[String],
) -> Result<HashMap<String, Vec<Value>>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let query = format!(
        "SELECT user_id,pub_ecdh,pub_sign,replaced_at FROM user_key_history WHERE user_id IN ({placeholders}) ORDER BY replaced_at"
    );
    let mut q = sqlx::query(&query);
    for id in ids {
        q = q.bind(id)
    }
    let rows = q.fetch_all(pool).await?;
    let mut result: HashMap<String, Vec<Value>> = HashMap::new();
    for row in rows {
        let id: String = row.try_get("user_id")?;
        result.entry(id).or_default().push(json!({"pub_ecdh":row.try_get::<String,_>("pub_ecdh")?,"pub_sign":row.try_get::<String,_>("pub_sign")?,"until":row.try_get::<String,_>("replaced_at")?}))
    }
    Ok(result)
}

async fn chat_pins(pool: &SqlitePool, chat: &str, floor: i64) -> Result<Vec<Value>, sqlx::Error> {
    let rows=sqlx::query("SELECT p.message_id,p.pinned_at,m.seq,u.username,u.display_name FROM pinned_messages p JOIN messages m ON m.id=p.message_id LEFT JOIN users u ON u.id=p.pinned_by WHERE p.chat_id=? AND m.deleted=0 AND m.seq>? AND (m.expires_at IS NULL OR m.expires_at>?) ORDER BY p.pinned_at DESC").bind(chat).bind(floor).bind(now()).fetch_all(pool).await?;
    Ok(rows.iter().map(|r|json!({"message_id":r.try_get::<String,_>("message_id").unwrap_or_default(),"seq":number(r,"seq"),"pinned_at":r.try_get::<String,_>("pinned_at").unwrap_or_default(),"pinned_by":if r.try_get::<Option<String>,_>("username").ok().flatten().is_some(){Some(display_name(r))}else{None}})).collect())
}

async fn deliver_due_messages(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let due =
        sqlx::query("SELECT * FROM scheduled_messages WHERE send_at<=? ORDER BY send_at LIMIT 100")
            .bind(now())
            .fetch_all(pool)
            .await?;
    if due.is_empty() {
        return Ok(());
    }
    let mut tx = begin_write(pool).await?;
    let mut delivered = Vec::new();
    for item in due {
        let id: String = item.try_get("id")?;
        let chat_id: String = item.try_get("chat_id")?;
        let sender: String = item.try_get("sender_id")?;
        let payload: String = item.try_get("payload")?;
        let expected: String = item.try_get("member_ids")?;
        let sender_key: String = item.try_get("sender_sign_key")?;
        let member_keys_snap: Option<String> = item.try_get("member_keys").ok().flatten();
        let chat = sqlx::query("SELECT type,disappear_seconds FROM chats WHERE id=?")
            .bind(&chat_id)
            .fetch_optional(&mut *tx)
            .await?;
        let sender_row = sqlx::query("SELECT pub_sign FROM users WHERE id=?")
            .bind(&sender)
            .fetch_optional(&mut *tx)
            .await?;
        let current = sqlx::query(
            "SELECT m.user_id,u.pub_ecdh FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.user_id",
        )
        .bind(&chat_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut members = Vec::with_capacity(current.len());
        let mut current_keys = std::collections::BTreeMap::new();
        for row in current {
            let uid = row.try_get::<String, _>("user_id")?;
            let ecdh = row.try_get::<Option<String>, _>("pub_ecdh").ok().flatten();
            current_keys.insert(uid.clone(), ecdh);
            members.push(uid);
        }
        let members_now = serde_json::to_string(&members).unwrap_or_default();
        let keys_match = sender_row
            .and_then(|row| row.try_get::<Option<String>, _>("pub_sign").ok().flatten())
            .unwrap_or_default()
            == sender_key;
        let member_keys_match = match member_keys_snap.as_deref() {
            Some(snap) if !snap.is_empty() => {
                serde_json::from_str::<std::collections::BTreeMap<String, Option<String>>>(snap)
                    .is_ok_and(|expected_keys| expected_keys == current_keys)
            }
            _ => true,
        };
        let mut can_send =
            chat.is_some() && keys_match && members_now == expected && member_keys_match;
        if can_send
            && let Some(row) = &chat
            && row.try_get::<String, _>("type")?.as_str() == "dm"
        {
            for member in &members {
                if member != &sender && is_blocked(&mut *tx, &sender, member).await? {
                    can_send = false;
                    break;
                }
            }
        }
        if can_send {
            let rev = next_rev(&mut tx).await?;
            let disappear = chat
                .as_ref()
                .map(|r| r.try_get::<i64, _>("disappear_seconds").unwrap_or(0))
                .unwrap_or(0);
            let created = now();
            let expires = if disappear > 0 {
                Some(
                    (chrono::Utc::now() + chrono::Duration::seconds(disappear))
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string(),
                )
            } else {
                None
            };
            let result=sqlx::query("INSERT OR IGNORE INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev,expires_at) VALUES(?,?,?,'e2e',?,?,?,?)").bind(&id).bind(&chat_id).bind(&sender).bind(payload).bind(&created).bind(rev).bind(expires).execute(&mut *tx).await?;
            if result.rows_affected() > 0 {
                let seq = result.last_insert_rowid();
                sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
                    .bind(&created)
                    .bind(&chat_id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=?")
                    .bind(&chat_id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE chat_members SET last_read_seq=?,delivered_seq=? WHERE chat_id=? AND user_id=?").bind(seq).bind(seq).bind(&chat_id).bind(&sender).execute(&mut *tx).await?;
                delivered.push((chat_id.clone(), sender.clone()));
            }
        }
        sqlx::query("DELETE FROM scheduled_messages WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    for (chat_id, sender) in delivered {
        crate::api::push::message_sent(pool.clone(), chat_id, sender);
    }
    Ok(())
}

struct User {
    id: String,
    display_name: String,
    pub_ecdh: Option<String>,
    pub_sign: Option<String>,
}
async fn user(state: &AppState, headers: &HeaderMap) -> ApiResult<User> {
    let row = require_user(state, headers).await?;
    Ok(User {
        id: row.try_get("id").unwrap_or_default(),
        display_name: display_name(&row),
        pub_ecdh: row.try_get("pub_ecdh").ok().flatten(),
        pub_sign: row.try_get("pub_sign").ok().flatten(),
    })
}
fn has_e2ee_keys(pub_ecdh: Option<&str>, pub_sign: Option<&str>) -> bool {
    pub_ecdh.is_some_and(|v| !v.trim().is_empty()) && pub_sign.is_some_and(|v| !v.trim().is_empty())
}
fn upload_daily_limit_bytes() -> i64 {
    std::env::var("SERES_UPLOAD_DAILY_MB")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(DEFAULT_UPLOAD_DAILY_MB)
        .saturating_mul(1024 * 1024)
}
async fn begin_write(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    pool.begin_with("BEGIN IMMEDIATE").await
}
fn display_name(row: &SqliteRow) -> String {
    row.try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .or_else(|| row.try_get("username").ok())
        .unwrap_or_default()
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}
fn number(row: &SqliteRow, key: &str) -> i64 {
    row.try_get(key).unwrap_or(0)
}
fn history_reset(row: &SqliteRow) -> Value {
    let reset = number(row, "reset_seq");
    if reset == 0 {
        return Value::Null;
    }
    json!({"from_seq":number(row,"joined_seq").max(number(row,"reset_cleared_seq")),"until_seq":reset})
}
fn serialize_message(row: &SqliteRow) -> Value {
    let deleted = number(row, "deleted") != 0;
    let payload: Option<String> = row.try_get("payload").ok().flatten();
    let payload = if deleted {
        None
    } else {
        payload.and_then(|v| serde_json::from_str::<Value>(&v).ok())
    };
    json!({"seq":number(row,"seq"),"rev":number(row,"rev"),"id":row.try_get::<String,_>("id").unwrap_or_default(),"sender_id":row.try_get::<Option<String>,_>("sender_id").ok().flatten(),"sender":row.try_get::<Option<String>,_>("sender").ok().flatten(),"sender_display":row.try_get::<Option<String>,_>("sender_display").ok().flatten().filter(|v|!v.is_empty()).or_else(||row.try_get("sender").ok().flatten()),"kind":row.try_get::<String,_>("kind").unwrap_or_default(),"payload":payload,"created_at":row.try_get::<String,_>("created_at").unwrap_or_default(),"edited_at":row.try_get::<Option<String>,_>("edited_at").ok().flatten(),"deleted":deleted,"silent":number(row,"silent")!=0,"expires_at":row.try_get::<Option<String>,_>("expires_at").ok().flatten()})
}

async fn membership<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    chat: &str,
    user: &str,
) -> Result<Option<SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived,m.delivered_seq,m.reset_seq,m.reset_cleared_seq FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?")
        .bind(chat)
        .bind(user)
        .fetch_optional(exec)
        .await
}
async fn member_ids<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    chat: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=? ORDER BY user_id")
        .bind(chat)
        .fetch_all(exec)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get("user_id").ok())
        .collect())
}
async fn insert_member(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    user: &str,
    role: &str,
) -> Result<(), sqlx::Error> {
    let seq =
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
            .bind(chat)
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) VALUES(?,?,?,?,?,0,?)").bind(chat).bind(user).bind(role).bind(now()).bind(seq).bind(seq).execute(&mut **tx).await?;
    Ok(())
}
async fn max_seq(pool: &SqlitePool, chat: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
        .bind(chat)
        .fetch_one(pool)
        .await
}
async fn next_rev(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(rev),0)+1 FROM messages")
        .fetch_one(&mut **tx)
        .await
}
pub(crate) async fn system_message(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    event: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    let rev = next_rev(tx).await?;
    let created = now();
    let mut payload = details.as_object().cloned().unwrap_or_default();
    payload.insert("event".into(), json!(event));
    sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev) VALUES(?, ?, NULL,'system',?,?,?)").bind(Uuid::new_v4().to_string()).bind(chat).bind(Value::Object(payload).to_string()).bind(created.clone()).bind(rev).execute(&mut **tx).await?;
    sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
        .bind(created)
        .bind(chat)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn are_friends<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    a: &str,
    b: &str,
) -> Result<bool, sqlx::Error> {
    let (x, y) = pair(a, b);
    Ok(
        sqlx::query("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?")
            .bind(x)
            .bind(y)
            .fetch_optional(exec)
            .await?
            .is_some(),
    )
}
async fn is_blocked<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    a: &str,
    b: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").bind(a).bind(b).bind(b).bind(a).fetch_optional(exec).await?.is_some())
}

fn validate_and_clean_envelope(payload: &Value, members: &[String]) -> Result<Value, String> {
    let Some(obj) = payload.as_object() else {
        return Err("Unsupported message format".into());
    };
    if obj.get("v").and_then(Value::as_i64) != Some(1) {
        return Err("Unsupported message format".into());
    }
    if obj
        .keys()
        .any(|k| !matches!(k.as_str(), "v" | "iv" | "ct" | "sig" | "keys"))
    {
        return Err("Unknown fields in message".into());
    }
    for (field, max) in [("iv", 64usize), ("sig", 256), ("ct", MAX_CIPHERTEXT_LEN)] {
        if !valid_b64_field(obj.get(field), max) {
            return Err(format!("Invalid '{field}'"));
        }
    }
    let Some(keys) = obj.get("keys").and_then(Value::as_object) else {
        return Err("Message must be encrypted for exactly the current chat members".into());
    };
    let mut actual = keys.keys().cloned().collect::<Vec<_>>();
    actual.sort();
    let mut expected = members.to_vec();
    expected.sort();
    if actual != expected {
        return Err("Message must be encrypted for exactly the current chat members".into());
    }
    let mut clean_keys = serde_json::Map::with_capacity(keys.len());
    for (member_id, wrapped) in keys {
        let Some(wrapped) = wrapped.as_object() else {
            return Err("Invalid key".into());
        };
        if wrapped.keys().any(|k| !matches!(k.as_str(), "iv" | "k")) {
            return Err("Invalid key".into());
        }
        for field in ["iv", "k"] {
            if !valid_b64_field(wrapped.get(field), 128) {
                return Err("Invalid key".into());
            }
        }
        clean_keys.insert(
            member_id.clone(),
            json!({
                "iv": wrapped["iv"].as_str().unwrap_or_default(),
                "k": wrapped["k"].as_str().unwrap_or_default(),
            }),
        );
    }
    Ok(json!({
        "v": 1,
        "iv": obj["iv"].as_str().unwrap_or_default(),
        "ct": obj["ct"].as_str().unwrap_or_default(),
        "sig": obj["sig"].as_str().unwrap_or_default(),
        "keys": Value::Object(clean_keys),
    }))
}

fn validate_envelope(payload: &Value, members: &[String]) -> Option<String> {
    validate_and_clean_envelope(payload, members).err()
}
fn valid_b64_field(value: Option<&Value>, max: usize) -> bool {
    value.and_then(Value::as_str).is_some_and(|v| {
        let unpadded = v.trim_end_matches('=');
        let padding = v.len() - unpadded.len();
        !v.is_empty()
            && v.len() <= max
            && padding <= 2
            && unpadded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b))
    })
}

async fn advance_receipt(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
    kind: &str,
    seq: i64,
) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    let kinds: &[&str] = if kind == "read" {
        &["delivered", "read"]
    } else {
        &["delivered"]
    };
    for k in kinds {
        let column = if *k == "read" {
            "last_read_seq"
        } else {
            "delivered_seq"
        };
        let q = format!(
            "UPDATE chat_members SET {column}=? WHERE chat_id=? AND user_id=? AND {column}<?"
        );
        let r = sqlx::query(&q)
            .bind(seq)
            .bind(chat)
            .bind(user)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() > 0 {
            sqlx::query("INSERT INTO receipts(chat_id,user_id,kind,seq,at) VALUES(?,?,?,?,?)")
                .bind(chat)
                .bind(user)
                .bind(k)
                .bind(seq)
                .bind(now())
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await
}
async fn member_receipts(
    pool: &SqlitePool,
    chat: &str,
    me: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let row=sqlx::query("SELECT MIN(delivered_seq) delivered,MIN(last_read_seq) read,COUNT(*) n FROM chat_members WHERE chat_id=? AND user_id!=?").bind(chat).bind(me).fetch_one(pool).await?;
    if number(&row, "n") == 0 {
        return Ok(None);
    }
    let read = number(&row, "read");
    Ok(Some(
        json!({"delivered_seq":number(&row,"delivered").max(read),"read_seq":read}),
    ))
}
async fn add_shares(
    pool: &SqlitePool,
    mut messages: Vec<Value>,
    user: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    for message in &mut messages {
        let Some(id) = message.get("id").and_then(Value::as_str) else {
            continue;
        };
        let rows = sqlx::query(
            "SELECT sharer_id,iv,k,sharer_pub_ecdh FROM message_key_shares WHERE recipient_id=? AND message_id=? ORDER BY created_at DESC, sharer_id",
        )
        .bind(user)
        .bind(id)
        .fetch_all(pool)
        .await?;
        if !rows.is_empty() {
            let mut shares = Vec::with_capacity(rows.len());
            for row in rows {
                shares.push(json!({
                    "sharer_id": row.try_get::<String, _>("sharer_id")?,
                    "iv": row.try_get::<String, _>("iv")?,
                    "k": row.try_get::<String, _>("k")?,
                    "from_pub": row.try_get::<String, _>("sharer_pub_ecdh")?,
                }));
            }
            message["share"] = shares[0].clone();
            message["shares"] = Value::Array(shares);
        }
    }
    Ok(messages)
}
async fn typing_values(state: &AppState, chat: &str, me: &str) -> Vec<Value> {
    let ids = state.typing_users(chat, me);
    if ids.is_empty() {
        return vec![];
    }
    let mut result = Vec::new();
    for id in ids {
        if let Ok(Some(row)) = sqlx::query("SELECT id,username,display_name FROM users WHERE id=?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
        {
            result.push(json!({"id":row.try_get::<String,_>("id").unwrap_or_default(),"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&row)}))
        }
    }
    result
}
async fn purge_expired(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let timestamp = now();
    let expired=sqlx::query("SELECT id,chat_id FROM messages WHERE expires_at IS NOT NULL AND expires_at<=? AND deleted=0").bind(&timestamp).fetch_all(pool).await?;
    let stale_cutoff = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let stale = sqlx::query("SELECT id FROM files WHERE message_id IS NULL AND created_at<=?")
        .bind(stale_cutoff)
        .fetch_all(pool)
        .await?;
    if expired.is_empty() && stale.is_empty() {
        return Ok(());
    }
    let mut tx = begin_write(pool).await?;
    for row in expired {
        let id: String = row.try_get("id")?;
        let chat: String = row.try_get("chat_id")?;
        let rev = next_rev(&mut tx).await?;
        sqlx::query("UPDATE messages SET deleted=1,payload=NULL,rev=? WHERE id=?")
            .bind(rev)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        forget_message_data(&mut tx, &chat, &id).await?
    }
    for row in stale {
        let id: String = row.try_get("id")?;
        sqlx::query("DELETE FROM file_blobs WHERE id=?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM files WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}
async fn reclaim_mutually_cleared_dm(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat_id: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN hidden=1 THEN 1 ELSE 0 END),0) AS hidden_count, COALESCE(MIN(MAX(joined_seq, CASE WHEN reset_seq>0 THEN MIN(cleared_seq, reset_cleared_seq) ELSE cleared_seq END)),0) AS safe_floor FROM chat_members WHERE chat_id=?",
    )
    .bind(chat_id)
    .fetch_one(&mut **tx)
    .await?;
    let total = number(&row, "total");
    let hidden_count = number(&row, "hidden_count");
    let safe_floor = number(&row, "safe_floor");
    if total == 0 || hidden_count != total || safe_floor <= 0 {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM file_blobs WHERE id IN (SELECT id FROM files WHERE message_id IN (SELECT id FROM messages WHERE chat_id=? AND seq<=?))",
    )
    .bind(chat_id)
    .bind(safe_floor)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM files WHERE message_id IN (SELECT id FROM messages WHERE chat_id=? AND seq<=?)",
    )
    .bind(chat_id)
    .bind(safe_floor)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM pinned_messages WHERE chat_id=? AND message_id IN (SELECT id FROM messages WHERE chat_id=? AND seq<=?)",
    )
    .bind(chat_id)
    .bind(chat_id)
    .bind(safe_floor)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM message_key_shares WHERE message_id IN (SELECT id FROM messages WHERE chat_id=? AND seq<=?)",
    )
    .bind(chat_id)
    .bind(safe_floor)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM receipts WHERE chat_id=? AND seq<=?")
        .bind(chat_id)
        .bind(safe_floor)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM messages WHERE chat_id=? AND seq<=?")
        .bind(chat_id)
        .bind(safe_floor)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn forget_message_data(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    let files = sqlx::query("SELECT id FROM files WHERE message_id=?")
        .bind(message)
        .fetch_all(&mut **tx)
        .await?;
    for f in files {
        let id: String = f.try_get("id")?;
        sqlx::query("DELETE FROM file_blobs WHERE id=?")
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("DELETE FROM files WHERE message_id=?")
        .bind(message)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM pinned_messages WHERE chat_id=? AND message_id=?")
        .bind(chat)
        .bind(message)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM message_key_shares WHERE message_id=?")
        .bind(message)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn chat_summary(state: &AppState, row: &SqliteRow, me: &str) -> Result<Value, sqlx::Error> {
    let id: String = row.try_get("id")?;
    let floor = number(row, "joined_seq").max(number(row, "cleared_seq"));
    let last=sqlx::query("SELECT m.*,u.username sender,u.display_name sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? AND m.seq>? AND m.deleted=0 AND m.silent=0 ORDER BY m.seq DESC LIMIT 1").bind(&id).bind(floor).fetch_optional(&state.db).await?;
    let unread=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM messages WHERE chat_id=? AND seq>? AND deleted=0 AND silent=0 AND kind!='system' AND (sender_id IS NULL OR sender_id!=?)").bind(&id).bind(floor.max(number(row,"last_read_seq"))).bind(me).fetch_one(&state.db).await?;
    let members=sqlx::query("SELECT u.id,u.username,u.display_name FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.joined_at,u.username COLLATE NOCASE").bind(&id).fetch_all(&state.db).await?;
    let ty: String = row.try_get("type")?;
    let mut value = json!({"id":id,"chat":id,"type":ty,"name":row.try_get::<Option<String>,_>("name")?,"avatar_updated_at":row.try_get::<Option<String>,_>("avatar_updated_at").ok().flatten(),"role":row.try_get::<String,_>("role")?,"member_count":members.len(),"last_message":last.as_ref().map(serialize_message),"unread":unread,"last_activity":row.try_get::<String,_>("last_activity")?,"pinned":number(row,"pinned")!=0,"archived":number(row,"archived")!=0,"disappear_seconds":number(row,"disappear_seconds"),"typing":typing_values(state,&id,me).await});
    if ty == "dm" {
        let other = members
            .iter()
            .find(|m| m.try_get::<String, _>("id").ok().as_deref() != Some(me));
        let other_id = other.and_then(|r| r.try_get::<String, _>("id").ok());
        let other_name = other
            .map(display_name)
            .unwrap_or_else(|| "Unknown User".into());
        let blocked = if let Some(oid) = &other_id {
            is_blocked(&state.db, me, oid).await.unwrap_or(false)
        } else {
            false
        };
        let muted = if let Some(oid) = &other_id {
            sqlx::query("SELECT 1 FROM muted_users WHERE user_id=? AND muted_id=?")
                .bind(me)
                .bind(oid)
                .fetch_optional(&state.db)
                .await?
                .is_some()
        } else {
            false
        };
        let presence = if let Some(oid) = &other_id {
            presence(&state.db, me, oid).await?
        } else {
            None
        };
        value["other_user"] = other
            .and_then(|r| r.try_get::<String, _>("username").ok())
            .map(Value::String)
            .unwrap_or(json!("Unknown User"));
        value["other_user_id"] = other_id.map(Value::String).unwrap_or(Value::Null);
        value["name"] = json!(other_name);
        value["blocked"] = json!(blocked);
        value["muted"] = json!(muted);
        value["presence"] = presence.unwrap_or(Value::Null)
    }
    Ok(value)
}
async fn presence(pool: &SqlitePool, me: &str, other: &str) -> Result<Option<Value>, sqlx::Error> {
    if is_blocked(pool, me, other).await? {
        return Ok(None);
    }
    let visible = are_friends(pool, me, other).await?
        || sqlx::query(
            "SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id JOIN chats c ON c.id=a.chat_id WHERE a.user_id=? AND b.user_id=? AND (c.type='group' OR (a.hidden=0 AND b.hidden=0))",
        )
        .bind(me)
        .bind(other)
        .fetch_optional(pool)
        .await?
        .is_some();
    if !visible {
        return Ok(None);
    }
    let row=sqlx::query("SELECT a.show_last_seen av,b.show_last_seen bv,b.last_seen FROM users a JOIN users b ON b.id=? WHERE a.id=?").bind(other).bind(me).fetch_optional(pool).await?;
    let Some(row) = row else { return Ok(None) };
    if number(&row, "av") == 0 || number(&row, "bv") == 0 {
        return Ok(None);
    }
    let Some(last) = row.try_get::<Option<String>, _>("last_seen")? else {
        return Ok(None);
    };
    let time = chrono::DateTime::parse_from_str(
        &format!("{}+00:00", last.trim_end_matches('Z')),
        "%Y-%m-%dT%H:%M:%S%:z",
    )
    .ok();
    let online = time
        .is_some_and(|v| (chrono::Utc::now() - v.with_timezone(&chrono::Utc)).num_seconds() < 45);
    Ok(Some(json!({"online":online,"last_seen":last})))
}

// ------------------------------------------------------------ invite links
// The owner of a group can make a link; anyone logged in who has it can join.
// A new link replaces the old one, and the owner can turn it off.

fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|b| b.is_ascii_alphanumeric())
}

async fn owner_of_group(
    state: &AppState,
    headers: &HeaderMap,
    chat_id: &str,
) -> Result<User, axum::response::Response> {
    let me = user(state, headers)
        .await
        .map_err(axum::response::IntoResponse::into_response)?;
    let chat = match membership(&state.db, chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return Err(error("Chat not found", StatusCode::NOT_FOUND)),
        Err(_) => return Err(db_error()),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return Err(error("Only possible in groups", StatusCode::BAD_REQUEST));
    }
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return Err(error(
            "Only the owner of the group can do this",
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(me)
}

async fn invite_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    if let Err(response) = owner_of_group(&state, &headers, &chat_id).await {
        return response;
    }
    match sqlx::query_scalar::<_, Option<String>>("SELECT invite_token FROM chats WHERE id=?")
        .bind(&chat_id)
        .fetch_one(&state.db)
        .await
    {
        Ok(token) => json_ok(json!({"token":token})).into_response(),
        Err(_) => db_error(),
    }
}

async fn invite_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    if let Err(response) = owner_of_group(&state, &headers, &chat_id).await {
        return response;
    }
    let token = Uuid::new_v4().simple().to_string();
    match sqlx::query("UPDATE chats SET invite_token=? WHERE id=?")
        .bind(&token)
        .bind(&chat_id)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"token":token})).into_response(),
        Err(_) => db_error(),
    }
}

async fn invite_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    if let Err(response) = owner_of_group(&state, &headers, &chat_id).await {
        return response;
    }
    match sqlx::query("UPDATE chats SET invite_token=NULL WHERE id=?")
        .bind(&chat_id)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"token":null})).into_response(),
        Err(_) => db_error(),
    }
}

async fn invited_group(state: &AppState, token: &str) -> Result<Option<SqliteRow>, sqlx::Error> {
    if !valid_token(token) {
        return Ok(None);
    }
    sqlx::query("SELECT id,name FROM chats WHERE invite_token=? AND type='group'")
        .bind(token)
        .fetch_optional(&state.db)
        .await
}

async fn invite_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("invite:{}", me.id), 30, 60) {
        return error(
            "Too many tries, wait a minute",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let chat = match invited_group(&state, &token).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error(
                "This invite link is not valid (any more)",
                StatusCode::NOT_FOUND,
            );
        }
        Err(_) => return db_error(),
    };
    let chat_id: String = chat.try_get("id").unwrap_or_default();
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chat_members WHERE chat_id=?")
        .bind(&chat_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    let member = matches!(membership(&state.db, &chat_id, &me.id).await, Ok(Some(_)));
    json_ok(json!({
        "chat_id": if member { Some(chat_id.clone()) } else { None },
        "name": chat.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default(),
        "member_count": count,
        "member": member,
    }))
    .into_response()
}

async fn invite_join(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("invite:{}", me.id), 30, 60) {
        return error(
            "Too many tries, wait a minute",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if !has_e2ee_keys(me.pub_ecdh.as_deref(), me.pub_sign.as_deref()) {
        return error("Your account has no keys yet", StatusCode::BAD_REQUEST);
    }
    if !valid_token(&token) {
        return error(
            "This invite link is not valid (any more)",
            StatusCode::NOT_FOUND,
        );
    }
    let mut tx = match begin_write(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let chat =
        match sqlx::query("SELECT id,owner_id FROM chats WHERE invite_token=? AND type='group'")
            .bind(&token)
            .fetch_optional(&mut *tx)
            .await
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                return error(
                    "This invite link is not valid (any more)",
                    StatusCode::NOT_FOUND,
                );
            }
            Err(_) => return db_error(),
        };
    let chat_id: String = chat.try_get("id").unwrap_or_default();
    if let Ok(Some(_)) = membership(&mut *tx, &chat_id, &me.id).await {
        // Already in it: show it again if it was hidden.
        let _ = sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=? AND user_id=?")
            .bind(&chat_id)
            .bind(&me.id)
            .execute(&mut *tx)
            .await;
        let _ = tx.commit().await;
        return json_ok(json!({"chat_id":chat_id})).into_response();
    }
    match sqlx::query("SELECT 1 FROM group_bans WHERE chat_id=? AND user_id=?")
        .bind(&chat_id)
        .bind(&me.id)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(Some(_)) => return error("You cannot join this group", StatusCode::FORBIDDEN),
        Ok(None) => {}
        Err(_) => return db_error(),
    }
    let owner_id: Option<String> = chat.try_get("owner_id").ok().flatten();
    if let Some(oid) = owner_id.as_deref()
        && is_blocked(&mut *tx, oid, &me.id).await.unwrap_or(true)
    {
        return error("You cannot join this group", StatusCode::FORBIDDEN);
    }
    let members = match member_ids(&mut *tx, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if members.len() >= MAX_GROUP_MEMBERS {
        return error("The group is full", StatusCode::BAD_REQUEST);
    }
    for member_id in &members {
        if is_blocked(&mut *tx, member_id, &me.id)
            .await
            .unwrap_or(true)
        {
            return error("You cannot join this group", StatusCode::FORBIDDEN);
        }
    }
    if insert_member(&mut tx, &chat_id, &me.id, "member")
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "joined_link",
            json!({"actor":me.display_name}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"chat_id":chat_id})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, AppState) {
            let dir = std::env::temp_dir().join(format!("seres-chats-{}", uuid::Uuid::new_v4()));
            let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
            (Self(dir), AppState::new(pool))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn auth_headers(pool: &SqlitePool, user_id: &str) -> HeaderMap {
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

    fn valid_dm_payload(a: &str, b: &str) -> Value {
        json!({
            "v": 1,
            "iv": "AAAA",
            "sig": "AAAA",
            "ct": "AAAA",
            "keys": {
                a: {"iv": "AAAA", "k": "AAAA"},
                b: {"iv": "AAAA", "k": "AAAA"},
            }
        })
    }

    #[tokio::test]
    async fn dm_blocking_enforced_for_presence_edit_and_upload_and_edit_rate_limited() {
        let (_fix, state) = Fixture::new().await;
        let seen = now();
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO users(id,username,last_seen,show_last_seen) VALUES(?,?,?,1)")
                .bind(id)
                .bind(id)
                .bind(&seen)
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
        sqlx::query("INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for id in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO chat_members(chat_id,user_id,joined_at) VALUES('dm1',?,'now')",
            )
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev) VALUES('m1','dm1','alice','e2e','{}','now',1)")
            .execute(&state.db)
            .await
            .unwrap();

        assert!(presence(&state.db, "alice", "bob").await.unwrap().is_some());

        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;

        // Before block: edit succeeds
        let ok = edit_message(
            State(state.clone()),
            alice_headers.clone(),
            Path(("dm1".into(), "m1".into())),
            Json(json!({"payload": valid_dm_payload("alice", "bob")})),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);

        // Bob blocks Alice
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        assert!(presence(&state.db, "alice", "bob").await.unwrap().is_none());
        assert!(presence(&state.db, "bob", "alice").await.unwrap().is_none());

        let edit_blocked = edit_message(
            State(state.clone()),
            alice_headers.clone(),
            Path(("dm1".into(), "m1".into())),
            Json(json!({"payload": valid_dm_payload("alice", "bob")})),
        )
        .await;
        assert_eq!(edit_blocked.status(), StatusCode::FORBIDDEN);

        let upload_blocked_a = upload_file(
            State(state.clone()),
            alice_headers.clone(),
            Path("dm1".into()),
            Bytes::from_static(b"enc"),
        )
        .await;
        assert_eq!(upload_blocked_a.status(), StatusCode::FORBIDDEN);

        let upload_blocked_b = upload_file(
            State(state.clone()),
            bob_headers,
            Path("dm1".into()),
            Bytes::from_static(b"enc"),
        )
        .await;
        assert_eq!(upload_blocked_b.status(), StatusCode::FORBIDDEN);

        // Rate limit on edit_message (30 per 60s; 2 already consumed above)
        for _ in 0..28 {
            let resp = edit_message(
                State(state.clone()),
                alice_headers.clone(),
                Path(("dm1".into(), "m1".into())),
                Json(json!({"payload": valid_dm_payload("alice", "bob")})),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        let limited = edit_message(
            State(state.clone()),
            alice_headers,
            Path(("dm1".into(), "m1".into())),
            Json(json!({"payload": valid_dm_payload("alice", "bob")})),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn remove_member_and_group_leave_clean_up_active_calls() {
        let (_fix, state) = Fixture::new().await;
        for id in ["alice", "bob", "carol"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(id)
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Team','alice','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for (id, role) in [("alice", "owner"), ("bob", "member"), ("carol", "member")] {
            sqlx::query(
                "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('g1',?,?,'now')",
            )
            .bind(id)
            .bind(role)
            .execute(&state.db)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO calls(id,chat_id,started_by,started_at) VALUES('c1','g1','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        for (id, st) in [("alice", "joined"), ("bob", "ringing"), ("carol", "joined")] {
            sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('c1',?,?,'now','now')")
                .bind(id)
                .bind(st)
                .execute(&state.db)
                .await
                .unwrap();
        }

        let alice_headers = auth_headers(&state.db, "alice").await;
        let carol_headers = auth_headers(&state.db, "carol").await;

        // Owner removes bob -> bob is marked 'left', call stays active (alice+carol joined)
        let resp = remove_member_route(
            State(state.clone()),
            alice_headers,
            Path("g1".into()),
            Json(json!({"username": "bob"})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bob_state: String = sqlx::query_scalar(
            "SELECT state FROM call_participants WHERE call_id='c1' AND user_id='bob'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(bob_state, "left");

        // Carol leaves group -> only alice remains -> call ends
        let resp = delete_chat(State(state.clone()), carol_headers, Path("g1".into())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ended: Option<String> = sqlx::query_scalar("SELECT ended_at FROM calls WHERE id='c1'")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(ended.is_some());
    }

    async fn insert_user_with_keys(pool: &SqlitePool, id: &str) {
        sqlx::query(
            "INSERT INTO users(id,username,pub_ecdh,pub_sign,last_seen,show_last_seen) VALUES(?,?,?,?,?,1)",
        )
        .bind(id)
        .bind(id)
        .bind(format!("ecdh-{id}"))
        .bind(format!("sign-{id}"))
        .bind(now())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn befriend(pool: &SqlitePool, a: &str, b: &str) {
        let (x, y) = pair(a, b);
        sqlx::query("INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)")
            .bind(x)
            .bind(y)
            .bind(now())
            .execute(pool)
            .await
            .unwrap();
    }

    #[test]
    fn validate_envelope_rejects_unknown_keys_inside_member_entry() {
        let payload = json!({
            "v": 1,
            "iv": "AAAA",
            "sig": "AAAA",
            "ct": "AAAA",
            "keys": {
                "alice": {"iv": "AAAA", "k": "AAAA", "evil": "junk"}
            }
        });
        assert!(validate_envelope(&payload, &["alice".to_string()]).is_some());
    }

    #[tokio::test]
    async fn chats_router_enforces_tight_json_body_limit_outside_files() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        let _ = auth_headers(&state.db, "alice").await;
        let app = router().with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let big = "a".repeat(1_500_000);
        let body = format!(r#"{{"id":"{}","payload":{{"x":"{big}"}}}}"#, Uuid::new_v4());
        let res = reqwest::Client::new()
            .post(format!("http://{addr}/api/chats/c1/messages"))
            .header("cookie", "sessioncookie=tok-alice")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        server.abort();
    }

    #[tokio::test]
    async fn create_chat_checks_group_size_before_loop_requires_keys_and_rate_limits() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        insert_user_with_keys(&state.db, "bob").await;
        befriend(&state.db, "alice", "bob").await;

        sqlx::query("INSERT INTO users(id,username) VALUES('nokeys','nokeys')")
            .execute(&state.db)
            .await
            .unwrap();
        befriend(&state.db, "alice", "nokeys").await;

        let alice_headers = auth_headers(&state.db, "alice").await;

        // Duplicate usernames exceeding MAX_GROUP_MEMBERS must be rejected before loop.
        let too_many = vec!["bob"; MAX_GROUP_MEMBERS + 1];
        let resp = create_chat(
            State(state.clone()),
            alice_headers.clone(),
            Json(json!({"type": "group", "name": "Big", "usernames": too_many})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // User without E2EE keys cannot be added to a group.
        let resp = create_chat(
            State(state.clone()),
            alice_headers.clone(),
            Json(json!({"type": "group", "name": "NoKeys", "usernames": ["nokeys"]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // create_chat must be rate-limited.
        let mut saw_limited = false;
        for _ in 0..40 {
            let r = create_chat(
                State(state.clone()),
                alice_headers.clone(),
                Json(json!({"type": "group", "name": "Spam", "usernames": ["bob"]})),
            )
            .await;
            if r.status() == StatusCode::TOO_MANY_REQUESTS {
                saw_limited = true;
                break;
            }
        }
        assert!(saw_limited);
    }

    #[tokio::test]
    async fn empty_group_delete_cleans_shares_receipts_scheduled_and_calls() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Solo','alice','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('g1','alice','owner','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev) VALUES('m1','g1','alice','e2e','{}','now',1)")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO message_key_shares(message_id,recipient_id,sharer_id,sharer_pub_ecdh,iv,k,created_at) VALUES('m1','alice','alice','p','iv','k','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO receipts(chat_id,user_id,kind,seq,at) VALUES('g1','alice','read',1,'now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO scheduled_messages(id,chat_id,sender_id,payload,member_ids,sender_sign_key,send_at,created_at) VALUES('s1','g1','alice','{}','[\"alice\"]','sign-alice','2999-01-01T00:00:00Z','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO calls(id,chat_id,started_by,started_at) VALUES('c1','g1','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('c1','alice','joined','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO call_signals(call_id,from_id,to_id,kind,data,created_at) VALUES('c1','alice','bob','offer','{}','now')")
            .execute(&state.db)
            .await
            .unwrap();

        let alice_headers = auth_headers(&state.db, "alice").await;
        let resp = delete_chat(State(state.clone()), alice_headers, Path("g1".into())).await;
        assert_eq!(resp.status(), StatusCode::OK);

        for table in [
            "message_key_shares",
            "receipts",
            "scheduled_messages",
            "calls",
            "call_participants",
            "call_signals",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&state.db)
                .await
                .unwrap();
            assert_eq!(count, 0, "{table} should be empty");
        }
    }

    #[tokio::test]
    async fn share_history_hardening_and_edit_message_drops_shares() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        insert_user_with_keys(&state.db, "bob").await;
        insert_user_with_keys(&state.db, "carol").await;
        sqlx::query(
            "INSERT INTO users(id,username,pub_ecdh,pub_sign) VALUES('nokey','nokey','','sign-nk')",
        )
        .execute(&state.db)
        .await
        .unwrap();

        // 1. DM blocked share_history rejected, plus empty pub_ecdh sharer rejected.
        sqlx::query("INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO chat_members(chat_id,user_id,joined_at,reset_seq) VALUES('dm1',?,'now',1)")
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev) VALUES('mdm','dm1','alice','e2e','{}','now',1)")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let alice_headers = auth_headers(&state.db, "alice").await;
        let resp = share_history(
            State(state.clone()),
            alice_headers.clone(),
            Path(("dm1".into(), "bob".into())),
            Json(json!({"keys": {"mdm": {"iv": "AAAA", "k": "AAAA"}}, "done": true})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 2. Group history sharing hardening
        sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Team','alice','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq) VALUES('g1','alice','owner','now',0)")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq) VALUES('g1','nokey','member','now',0)")
            .execute(&state.db)
            .await
            .unwrap();
        // Bob joined at seq 10 (so he cannot see seq 10, only >10)
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq) VALUES('g1','bob','member','now',10)")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO messages(seq,id,chat_id,sender_id,kind,payload,created_at,rev) VALUES(10,'m1','g1','alice','e2e','{}','now',2)")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO messages(seq,id,chat_id,sender_id,kind,payload,created_at,rev) VALUES(20,'m2','g1','alice','e2e','{}','now',3)")
            .execute(&state.db)
            .await
            .unwrap();
        // Carol joined at 0 and reset at seq 20
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,reset_seq,reset_cleared_seq) VALUES('g1','carol','member','now',0,20,20,0)")
            .execute(&state.db)
            .await
            .unwrap();

        let nokey_headers = auth_headers(&state.db, "nokey").await;
        let bob_headers = auth_headers(&state.db, "bob").await;
        let carol_headers = auth_headers(&state.db, "carol").await;

        // Sharer with empty pub_ecdh rejected
        let r_nk = share_history(
            State(state.clone()),
            nokey_headers,
            Path(("g1".into(), "carol".into())),
            Json(json!({"keys": {"m1": {"iv": "AAAA", "k": "AAAA"}}, "done": true})),
        )
        .await;
        assert_eq!(r_nk.status(), StatusCode::BAD_REQUEST);

        // Unilateral done:true with stored==0 must NOT clear reset_seq
        let _ = share_history(
            State(state.clone()),
            alice_headers.clone(),
            Path(("g1".into(), "carol".into())),
            Json(json!({"keys": {}, "done": true})),
        )
        .await;
        let reset_after_empty: i64 = sqlx::query_scalar(
            "SELECT reset_seq FROM chat_members WHERE chat_id='g1' AND user_id='carol'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(reset_after_empty, 20);

        // Alice shares m2 first (without done) so both Alice and Bob can share m2.
        let r_alice_m2 = share_history(
            State(state.clone()),
            alice_headers.clone(),
            Path(("g1".into(), "carol".into())),
            Json(json!({"keys": {"m2": {"iv": "CCCC", "k": "CCCC"}}})),
        )
        .await;
        assert_eq!(r_alice_m2.status(), StatusCode::OK);

        // Bob (joined_seq=10) also shares m2 with done:true -> narrows reset_seq to 10 (NOT 0!) and keeps both shares!
        let r_bob = share_history(
            State(state.clone()),
            bob_headers,
            Path(("g1".into(), "carol".into())),
            Json(json!({"keys": {"m2": {"iv": "BBBB", "k": "BBBB"}}, "done": true})),
        )
        .await;
        assert_eq!(r_bob.status(), StatusCode::OK);
        let reset_narrowed: i64 = sqlx::query_scalar(
            "SELECT reset_seq FROM chat_members WHERE chat_id='g1' AND user_id='carol'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(reset_narrowed, 10);

        // Alice finishes remaining m1 with done:true -> clears reset_seq to 0; m2 retains both shares.
        let r_alice = share_history(
            State(state.clone()),
            alice_headers.clone(),
            Path(("g1".into(), "carol".into())),
            Json(json!({"keys": {"m1": {"iv": "AAAA", "k": "AAAA"}}, "done": true})),
        )
        .await;
        assert_eq!(r_alice.status(), StatusCode::OK);
        let share_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM message_key_shares WHERE message_id='m2' AND recipient_id='carol'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(share_count, 2);

        // Carol sees `shares` array on m2 via get_chat_messages
        let msgs_resp = get_chat_messages(
            State(state.clone()),
            carol_headers,
            Path("g1".into()),
            Query(HashMap::new()),
        )
        .await;
        let bytes = axum::body::to_bytes(msgs_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let m2 = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "m2")
            .unwrap();
        assert_eq!(m2["shares"].as_array().map(|a| a.len()), Some(2));

        // 3. edit_message deletes stale message_key_shares
        let r_edit = edit_message(
            State(state.clone()),
            alice_headers,
            Path(("g1".into(), "m2".into())),
            Json(json!({"payload": {
                "v": 1, "iv": "AAAA", "sig": "AAAA", "ct": "AAAA",
                "keys": {
                    "alice": {"iv": "AAAA", "k": "AAAA"},
                    "bob": {"iv": "AAAA", "k": "AAAA"},
                    "carol": {"iv": "AAAA", "k": "AAAA"},
                    "nokey": {"iv": "AAAA", "k": "AAAA"},
                }
            }})),
        )
        .await;
        assert_eq!(r_edit.status(), StatusCode::OK);
        let remaining_shares: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM message_key_shares WHERE message_id='m2'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining_shares, 0);
    }

    #[tokio::test]
    async fn disappearing_filters_no_store_dm_reclaim_and_upload_quota() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        insert_user_with_keys(&state.db, "bob").await;
        befriend(&state.db, "alice", "bob").await;

        sqlx::query("INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO chat_members(chat_id,user_id,joined_at,reset_seq) VALUES('dm1',?,'now',10)")
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        // Expired message + attachment
        sqlx::query("INSERT INTO messages(seq,id,chat_id,sender_id,kind,payload,created_at,rev,expires_at) VALUES(1,'mexp','dm1','alice','e2e','{}','now',1,'2000-01-01T00:00:00Z')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO file_blobs(id,data) VALUES('fexp',X'0102')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO files(id,chat_id,uploader_id,message_id,size,created_at) VALUES('fexp','dm1','alice','mexp',2,'now')")
            .execute(&state.db)
            .await
            .unwrap();
        // Active disappearing message + attachment
        sqlx::query("INSERT INTO messages(seq,id,chat_id,sender_id,kind,payload,created_at,rev,expires_at) VALUES(2,'mact','dm1','alice','e2e','{}','now',2,'2999-01-01T00:00:00Z')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO file_blobs(id,data) VALUES('fact',X'0304')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO files(id,chat_id,uploader_id,message_id,size,created_at) VALUES('fact','dm1','alice','mact',2,'now')")
            .execute(&state.db)
            .await
            .unwrap();

        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;

        assert_eq!(
            single_message(
                State(state.clone()),
                bob_headers.clone(),
                Path(("dm1".into(), "mexp".into())),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            message_info(
                State(state.clone()),
                alice_headers.clone(),
                Path(("dm1".into(), "mexp".into())),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            pin_message(
                State(state.clone()),
                alice_headers.clone(),
                Path("dm1".into()),
                Json(json!({"message_id": "mexp"})),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            edit_message(
                State(state.clone()),
                alice_headers.clone(),
                Path(("dm1".into(), "mexp".into())),
                Json(json!({"payload": valid_dm_payload("alice", "bob")})),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            download_file(
                State(state.clone()),
                bob_headers.clone(),
                Path(("dm1".into(), "fexp".into())),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        let share_exp = share_history(
            State(state.clone()),
            alice_headers.clone(),
            Path(("dm1".into(), "bob".into())),
            Json(json!({"keys": {"mexp": {"iv": "AAAA", "k": "AAAA"}}})),
        )
        .await;
        let share_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(share_exp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(share_body["stored"], 0);

        // Active disappearing attachment gets Cache-Control: no-store
        let active_dl = download_file(
            State(state.clone()),
            bob_headers.clone(),
            Path(("dm1".into(), "fact".into())),
        )
        .await;
        assert_eq!(active_dl.status(), StatusCode::OK);
        assert_eq!(
            active_dl
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        // Daily upload quota enforced (default 2048 MB)
        sqlx::query("INSERT INTO files(id,chat_id,uploader_id,message_id,size,created_at) VALUES('fquota','dm1','alice',NULL,?,?)")
            .bind(2048i64 * 1024 * 1024)
            .bind(now())
            .execute(&state.db)
            .await
            .unwrap();
        let quota_resp = upload_file(
            State(state.clone()),
            alice_headers.clone(),
            Path("dm1".into()),
            Bytes::from_static(b"x"),
        )
        .await;
        assert_eq!(quota_resp.status(), StatusCode::TOO_MANY_REQUESTS);
        sqlx::query("DELETE FROM files WHERE id='fquota'")
            .execute(&state.db)
            .await
            .unwrap();

        // Mutually cleared DM reclaims messages & file_blobs
        sqlx::query("UPDATE chat_members SET reset_seq=0 WHERE chat_id='dm1'")
            .execute(&state.db)
            .await
            .unwrap();
        assert_eq!(
            delete_chat(State(state.clone()), alice_headers, Path("dm1".into()))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            delete_chat(State(state.clone()), bob_headers, Path("dm1".into()))
                .await
                .status(),
            StatusCode::OK
        );
        let msg_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE chat_id='dm1'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        let blob_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_blobs")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(msg_count, 0);
        assert_eq!(blob_count, 0);
    }

    #[tokio::test]
    async fn group_bans_blocks_keys_and_hidden_dm_presence_and_reopen() {
        let (_fix, state) = Fixture::new().await;
        for id in ["alice", "bob", "carol", "dave"] {
            insert_user_with_keys(&state.db, id).await;
        }
        sqlx::query("INSERT INTO users(id,username) VALUES('nokeys','nokeys')")
            .execute(&state.db)
            .await
            .unwrap();
        befriend(&state.db, "alice", "bob").await;
        befriend(&state.db, "alice", "carol").await;
        befriend(&state.db, "carol", "bob").await;
        befriend(&state.db, "alice", "nokeys").await;

        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;
        let carol_headers = auth_headers(&state.db, "carol").await;
        let dave_headers = auth_headers(&state.db, "dave").await;

        sqlx::query("INSERT INTO chats(id,type,name,owner_id,invite_token,created_at,last_activity) VALUES('g1','group','Team','alice','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for (id, role) in [("alice", "owner"), ("bob", "member"), ("carol", "member")] {
            sqlx::query(
                "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('g1',?,?,'now')",
            )
            .bind(id)
            .bind(role)
            .execute(&state.db)
            .await
            .unwrap();
        }

        // Owner removes bob -> banned from invite_join & non-owner re-add
        assert_eq!(
            remove_member_route(
                State(state.clone()),
                alice_headers.clone(),
                Path("g1".into()),
                Json(json!({"username": "bob"})),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            invite_join(
                State(state.clone()),
                bob_headers.clone(),
                Path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            add_member_route(
                State(state.clone()),
                carol_headers,
                Path("g1".into()),
                Json(json!({"username": "bob"})),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        // Owner can re-add bob, clearing ban
        assert_eq!(
            add_member_route(
                State(state.clone()),
                alice_headers.clone(),
                Path("g1".into()),
                Json(json!({"username": "bob"})),
            )
            .await
            .status(),
            StatusCode::OK
        );

        // User without E2EE keys cannot be added via add_member_route
        assert_eq!(
            add_member_route(
                State(state.clone()),
                alice_headers.clone(),
                Path("g1".into()),
                Json(json!({"username": "nokeys"})),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );

        // Blocked user cannot join via invite_join (alice is owner, blocks dave)
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('alice','dave','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        assert_eq!(
            invite_join(
                State(state.clone()),
                dave_headers,
                Path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        // Hidden DM after unfriending cannot be reopened by open_dm and leaks no presence
        sqlx::query("DELETE FROM chat_members WHERE chat_id='g1' AND user_id='bob'")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm2','dm','alice:bob','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chat_members(chat_id,user_id,hidden,joined_at) VALUES('dm2','alice',1,'now'),('dm2','bob',0,'now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM friendships WHERE (user_a='alice' AND user_b='bob')")
            .execute(&state.db)
            .await
            .unwrap();
        assert!(presence(&state.db, "alice", "bob").await.unwrap().is_none());
        let reopen = create_chat(
            State(state.clone()),
            alice_headers,
            Json(json!({"type": "dm", "username": "bob"})),
        )
        .await;
        assert_eq!(reopen.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn scheduled_message_checks_member_pub_ecdh_snapshot_at_delivery() {
        let (_fix, state) = Fixture::new().await;
        insert_user_with_keys(&state.db, "alice").await;
        insert_user_with_keys(&state.db, "bob").await;
        sqlx::query("INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')")
            .execute(&state.db)
            .await
            .unwrap();
        for id in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO chat_members(chat_id,user_id,joined_at) VALUES('dm1',?,'now')",
            )
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
        }
        let alice_headers = auth_headers(&state.db, "alice").await;
        let msg_id = Uuid::new_v4().to_string();
        let send_at = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let resp = schedule_message(
            State(state.clone()),
            alice_headers,
            Path("dm1".into()),
            Json(json!({
                "id": msg_id,
                "send_at": send_at,
                "payload": valid_dm_payload("alice", "bob")
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Bob rotates ECDH key before delivery; make message due now
        sqlx::query("UPDATE users SET pub_ecdh='ecdh-bob-rotated' WHERE id='bob'")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("UPDATE scheduled_messages SET send_at='2000-01-01T00:00:00Z' WHERE id=?")
            .bind(&msg_id)
            .execute(&state.db)
            .await
            .unwrap();
        deliver_due_messages(&state.db).await.unwrap();

        let delivered_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id=?")
            .bind(&msg_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(delivered_count, 0);
    }
}
