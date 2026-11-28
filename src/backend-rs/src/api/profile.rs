use super::{error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::HashMap;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/users/keys", get(user_keys))
        .route("/api/profile/display_name", post(set_display_name))
        .route("/api/profile/privacy", post(set_privacy))
        .route("/api/profile/status", post(set_status))
}

async fn user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let me = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let me_id: String = me.try_get("id").unwrap_or_default();
    if state.rate_limited(format!("user-keys:{me_id}"), 60, 60) {
        return error(
            "Too many requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let mut ids = Vec::new();
    if let Some(raw) = query.get("ids") {
        for id in raw.split(',').filter(|id| !id.is_empty()) {
            if !ids.contains(&id) {
                ids.push(id);
                if ids.len() >= 100 {
                    break;
                }
            }
        }
    }
    if ids.is_empty() {
        return json_ok(json!({"users":[]})).into_response();
    }
    let marks = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT u.id,u.username,u.display_name,u.pub_ecdh,u.pub_sign FROM users u
         WHERE u.id IN ({marks}) AND (
             u.id = ?
             OR EXISTS (
                 SELECT 1 FROM friendships f
                 WHERE (f.user_a = ? AND f.user_b = u.id) OR (f.user_b = ? AND f.user_a = u.id)
             )
             OR EXISTS (
                 SELECT 1 FROM chat_members a
                 JOIN chat_members b ON a.chat_id = b.chat_id
                 WHERE a.user_id = ? AND b.user_id = u.id AND a.hidden = 0
             )
             OR EXISTS (
                 SELECT 1 FROM call_participants pa
                 JOIN call_participants pb ON pa.call_id = pb.call_id
                 JOIN calls c ON c.id = pa.call_id
                 WHERE c.ended_at IS NULL
                   AND pa.user_id = ? AND pb.user_id = u.id
                   AND pa.state IN ('ringing', 'joined')
                   AND pb.state IN ('ringing', 'joined')
             )
         )"
    );
    let mut users_query = sqlx::query(&sql);
    for id in &ids {
        users_query = users_query.bind(id);
    }
    users_query = users_query
        .bind(&me_id)
        .bind(&me_id)
        .bind(&me_id)
        .bind(&me_id)
        .bind(&me_id);
    let rows = match users_query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if rows.is_empty() {
        return json_ok(json!({"users":[]})).into_response();
    }
    let allowed_ids: Vec<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("id").ok())
        .collect();
    let history_marks = vec!["?"; allowed_ids.len()].join(",");
    let history_sql = format!(
        "SELECT user_id,pub_ecdh,pub_sign,replaced_at FROM user_key_history WHERE user_id IN ({history_marks}) ORDER BY replaced_at"
    );
    let mut history_query = sqlx::query(&history_sql);
    for id in &allowed_ids {
        history_query = history_query.bind(id);
    }
    let history_rows = match history_query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let mut history: HashMap<String, Vec<Value>> = HashMap::new();
    for row in history_rows {
        let id: String = row.try_get("user_id").unwrap_or_default();
        history.entry(id).or_default().push(json!({"pub_ecdh":row.try_get::<String,_>("pub_ecdh").unwrap_or_default(),"pub_sign":row.try_get::<String,_>("pub_sign").unwrap_or_default(),"until":row.try_get::<String,_>("replaced_at").unwrap_or_default()}))
    }
    let users=rows.iter().map(|row|{let id:String=row.try_get("id").unwrap_or_default();json!({"id":id,"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":row.try_get::<Option<String>,_>("display_name").ok().flatten().filter(|s|!s.is_empty()).or_else(||row.try_get("username").ok()),"pub_ecdh":row.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":row.try_get::<Option<String>,_>("pub_sign").ok().flatten(),"previous_keys":history.remove(&id).unwrap_or_default()})}).collect::<Vec<_>>();
    json_ok(json!({"users":users})).into_response()
}

async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let username: String = user.try_get("username").unwrap_or_default();
    let value = body.get("display_name");
    if value.is_some_and(|v| !v.is_null() && !v.is_string()) {
        return error("Invalid display name", StatusCode::BAD_REQUEST);
    }
    let normalized = value
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.chars().count() > 32 {
        return error(
            "Display name can be at most 32 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    let stored = if normalized.is_empty() {
        None
    } else {
        Some(normalized.as_str())
    };
    match sqlx::query("UPDATE users SET display_name=? WHERE id=?")
        .bind(stored)
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"display_name":stored.unwrap_or(&username)})).into_response(),
        Err(_) => db_error(),
    }
}
const MAX_STATUS_CHARS: usize = 140;

/// The short text under the profile; empty removes it.
async fn set_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let value = body.get("status");
    if value.is_some_and(|v| !v.is_null() && !v.is_string()) {
        return error("Invalid status", StatusCode::BAD_REQUEST);
    }
    // One line: line breaks and runs of spaces become single spaces.
    let normalized = value
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.chars().count() > MAX_STATUS_CHARS {
        return error(
            format!("The status can be at most {MAX_STATUS_CHARS} characters"),
            StatusCode::BAD_REQUEST,
        );
    }
    let stored = (!normalized.is_empty()).then_some(normalized.as_str());
    match sqlx::query("UPDATE users SET status_text=? WHERE id=?")
        .bind(stored)
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"status": stored})).into_response(),
        Err(_) => db_error(),
    }
}

async fn set_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(show) = body.get("show_last_seen").and_then(Value::as_bool) else {
        return error("Invalid 'show_last_seen'", StatusCode::BAD_REQUEST);
    };
    match sqlx::query("UPDATE users SET show_last_seen=? WHERE id=?")
        .bind(i64::from(show))
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"show_last_seen":show})).into_response(),
        Err(_) => db_error(),
    }
}
fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        http::{HeaderValue, header},
    };
    use sqlx::SqlitePool;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, AppState) {
            let dir = std::env::temp_dir().join(format!("seres-profile-{}", uuid::Uuid::new_v4()));
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

    #[tokio::test]
    async fn user_keys_restricts_to_authorized_peers_and_rate_limits() {
        let (_fix, state) = Fixture::new().await;
        for id in ["alice", "bob", "carol", "dave", "eve", "mallory"] {
            sqlx::query("INSERT INTO users(id,username,pub_ecdh,pub_sign) VALUES(?,?,?,?)")
                .bind(id)
                .bind(id)
                .bind(format!("ecdh-{id}"))
                .bind(format!("sign-{id}"))
                .execute(&state.db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO user_key_history(user_id,pub_ecdh,pub_sign,replaced_at) VALUES(?,?,?,'2025-01-01T00:00:00Z')")
                .bind(id)
                .bind(format!("old-ecdh-{id}"))
                .bind(format!("old-sign-{id}"))
                .execute(&state.db)
                .await
                .unwrap();
        }
        // Bob: friend
        sqlx::query(
            "INSERT INTO friendships(user_a,user_b,created_at) VALUES('alice','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        // Carol: shared active (non-hidden) group chat
        sqlx::query(
            "INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Team','alice','now','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at,hidden) VALUES('g1','alice','owner','now',0),('g1','carol','member','now',0)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        // Dave: shared ONLY a hidden chat (alice hid it)
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm-hidden','dm','alice:dave','now','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at,hidden) VALUES('dm-hidden','alice','member','now',1),('dm-hidden','dave','member','now',0)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        // Eve: shared active call
        sqlx::query("INSERT INTO calls(id,chat_id,started_by,started_at) VALUES('c1','g-call','alice','now')")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('c1','alice','joined','now','now'),('c1','eve','ringing','now','now')")
            .execute(&state.db)
            .await
            .unwrap();

        let headers = auth_headers(&state.db, "alice").await;
        let mut query = HashMap::new();
        query.insert("ids".into(), "alice,bob,carol,dave,eve,mallory".into());
        let resp = user_keys(State(state.clone()), headers.clone(), Query(query.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        let mut returned_ids: Vec<String> = body["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["id"].as_str().unwrap().to_string())
            .collect();
        returned_ids.sort();
        assert_eq!(returned_ids, vec!["alice", "bob", "carol", "eve"]);

        for _ in 0..59 {
            let r = user_keys(State(state.clone()), headers.clone(), Query(query.clone())).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let limited = user_keys(State(state), headers, Query(query)).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
