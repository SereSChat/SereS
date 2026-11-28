use super::{ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::collections::HashMap;
use uuid::Uuid;

const RING_SECONDS: i64 = 45;
const GONE_SECONDS: i64 = 20;
const MAX_GROUP_MEMBERS: usize = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/chats/{chat_id}/call", post(call_chat))
        .route("/api/calls/{call_id}/answer", post(answer_call))
        .route("/api/calls/{call_id}/decline", post(decline_call))
        .route("/api/calls/{call_id}/leave", post(leave_call))
        .route("/api/calls", get(my_calls))
        .route("/api/calls/{call_id}/signal", post(call_signal))
        .route("/api/calls/{call_id}/add", post(add_to_call))
        .route("/api/calls/ice", get(ice_servers))
}

struct Caller {
    id: String,
    display_name: String,
}
async fn caller(state: &AppState, headers: &HeaderMap) -> ApiResult<Caller> {
    let row = require_user(state, headers).await?;
    Ok(Caller {
        id: row.try_get("id").unwrap_or_default(),
        display_name: row
            .try_get::<Option<String>, _>("display_name")
            .ok()
            .flatten()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| row.try_get("username").unwrap_or_default()),
    })
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn ago(seconds: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
/// Tells iOS devices of calls that stopped ringing (see apns.rs), except the
/// device that made this request.
fn stopped_ringing(state: &AppState, headers: &HeaderMap, me: &Caller) {
    let actor = crate::api::auth::session_hash(headers).map(|session| (me.id.clone(), session));
    super::apns::calls_stopped_ringing(state.db.clone(), actor);
}
fn err_db() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}

async fn call_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return err_db(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm") {
        let members = match member_ids(&state.db, &chat_id).await {
            Ok(v) => v,
            Err(_) => return err_db(),
        };
        let Some(other) = members.iter().find(|v| *v != &me.id) else {
            return error("You can't call this person", StatusCode::FORBIDDEN);
        };
        if blocked(&state.db, &me.id, other).await.unwrap_or(true) {
            return error("You can't call this person", StatusCode::FORBIDDEN);
        }
    }
    if state.rate_limited(format!("call:{}", me.id), 20, 600) {
        return error(
            "Too many calls, please wait a moment",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if expire_calls(&mut tx).await.is_err() {
        return err_db();
    };
    let active=sqlx::query("SELECT id FROM calls WHERE chat_id=? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1").bind(&chat_id).fetch_optional(&mut *tx).await;
    let mut started = false;
    let call_id = match active {
        Ok(Some(row)) => {
            let id: String = row.try_get("id").unwrap_or_default();
            if leave_other_calls(&mut tx, &me.id, Some(&id)).await.is_err()
                || set_state(&mut tx, &id, &me.id, "joined").await.is_err()
                || sqlx::query("UPDATE calls SET answered_at=COALESCE(answered_at,?) WHERE id=?")
                    .bind(now())
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
            {
                return err_db();
            }
            id
        }
        Ok(None) => match start_call(&mut tx, &chat_id, &me.id).await {
            Ok(v) => {
                started = true;
                v
            }
            Err(_) => return err_db(),
        },
        Err(_) => return err_db(),
    };
    if tx.commit().await.is_err() {
        return err_db();
    };
    stopped_ringing(&state, &headers, &me);
    if started {
        crate::api::push::call_started(state.db.clone(), call_id.clone());
    }
    match serialize_call(&state.db, &call_id, &me.id).await {
        Ok(v) => json_ok(json!({"call":v})).into_response(),
        Err(_) => err_db(),
    }
}

async fn answer_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing", "joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if leave_other_calls(&mut tx, &me.id, Some(&call_id))
        .await
        .is_err()
        || set_state(&mut tx, &call_id, &me.id, "joined")
            .await
            .is_err()
        || sqlx::query("UPDATE calls SET answered_at=COALESCE(answered_at,?) WHERE id=?")
            .bind(now())
            .bind(&call_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    stopped_ringing(&state, &headers, &me);
    match serialize_call(&state.db, &call_id, &me.id).await {
        Ok(v) => json_ok(json!({"call":v})).into_response(),
        Err(_) => err_db(),
    }
}
async fn decline_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if set_state(&mut tx, &call_id, &me.id, "declined")
        .await
        .is_err()
        || finish_if_over(&mut tx, &call_id).await.is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    stopped_ringing(&state, &headers, &me);
    json_ok(json!({})).into_response()
}
async fn leave_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing", "joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if set_state(&mut tx, &call_id, &me.id, "left").await.is_err()
        || finish_if_over(&mut tx, &call_id).await.is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    stopped_ringing(&state, &headers, &me);
    json_ok(json!({})).into_response()
}

async fn my_calls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let after = query
        .get("after")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if expire_calls(&mut tx).await.is_err()||sqlx::query("UPDATE call_participants SET seen_at=? WHERE user_id=? AND state='joined' AND call_id IN (SELECT id FROM calls WHERE ended_at IS NULL)").bind(now()).bind(&me.id).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return err_db()};
    stopped_ringing(&state, &headers, &me);
    let rows=sqlx::query("SELECT c.id FROM calls c JOIN call_participants p ON p.call_id=c.id JOIN chat_members m ON m.chat_id=c.chat_id AND m.user_id=p.user_id WHERE p.user_id=? AND p.state IN ('ringing','joined') AND c.ended_at IS NULL ORDER BY c.started_at").bind(&me.id).fetch_all(&state.db).await;
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    let mut calls = Vec::new();
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        match serialize_call(&state.db, &id, &me.id).await {
            Ok(v) => calls.push(v),
            Err(_) => return err_db(),
        }
    }
    let signals = sqlx::query(
        "SELECT id,call_id,from_id,kind,data FROM call_signals WHERE to_id=? AND id>? ORDER BY id",
    )
    .bind(&me.id)
    .bind(after)
    .fetch_all(&state.db)
    .await;
    let signals = match signals {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    let signals=signals.iter().map(|r|{let data=r.try_get::<String,_>("data").ok().and_then(|v|serde_json::from_str::<Value>(&v).ok()).unwrap_or(Value::Null);json!({"id":r.try_get::<i64,_>("id").unwrap_or(0),"call_id":r.try_get::<String,_>("call_id").unwrap_or_default(),"from":r.try_get::<String,_>("from_id").unwrap_or_default(),"kind":r.try_get::<String,_>("kind").unwrap_or_default(),"data":data})}).collect::<Vec<_>>();
    json_ok(json!({"calls":calls,"signals":signals})).into_response()
}

async fn call_signal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let Some(to) = body
        .get("to")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64)
    else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let Some(kind @ ("offer" | "answer")) = body.get("kind").and_then(Value::as_str) else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let data = body.get("data");
    let Some(data) = data.and_then(Value::as_object) else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let sdp = data.get("sdp").and_then(Value::as_str);
    let sig = data.get("sig").and_then(Value::as_str);
    if data.keys().any(|k| k != "sdp" && k != "sig")
        || sdp.is_none_or(|v| v.is_empty() || v.len() > 16000)
        || sig.is_none_or(|v| !valid_b64(v, 256))
    {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    }
    if state.rate_limited(format!("call-signal:{}", me.id), 120, 60) {
        return error("Too many signals", StatusCode::TOO_MANY_REQUESTS);
    }
    let target = sqlx::query("SELECT state FROM call_participants WHERE call_id=? AND user_id=?")
        .bind(&call_id)
        .bind(to)
        .fetch_optional(&state.db)
        .await;
    match target {
        Ok(Some(row)) if row.try_get::<String, _>("state").ok().as_deref() == Some("joined") => {}
        _ => return error("This person is not in the call", StatusCode::CONFLICT),
    }
    match sqlx::query(
        "INSERT INTO call_signals(call_id,from_id,to_id,kind,data,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&call_id)
    .bind(&me.id)
    .bind(to)
    .bind(kind)
    .bind(Value::Object(data.clone()).to_string())
    .bind(now())
    .execute(&state.db)
    .await
    {
        Ok(_) => json_ok(json!({})).into_response(),
        Err(_) => err_db(),
    }
}

async fn add_to_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let call = match require_call(&state.db, &call_id, &me.id, &["joined"]).await {
        Ok(v) => v,
        Err(_) => return error("This call has ended", StatusCode::NOT_FOUND),
    };
    let Some(usernames) = body
        .get("usernames")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= MAX_GROUP_MEMBERS)
    else {
        return error("Pick at least one friend", StatusCode::BAD_REQUEST);
    };
    let joined = sqlx::query(
        "SELECT user_id FROM call_participants WHERE call_id=? AND state='joined' AND user_id!=?",
    )
    .bind(&call_id)
    .bind(&me.id)
    .fetch_all(&state.db)
    .await;
    let joined = match joined {
        Ok(v) => v
            .iter()
            .filter_map(|r| r.try_get::<String, _>("user_id").ok())
            .collect::<Vec<_>>(),
        Err(_) => return err_db(),
    };
    let mut added = Vec::new();
    for name in usernames {
        let text = name.as_str().unwrap_or("");
        let row=sqlx::query("SELECT id,COALESCE(NULLIF(display_name,''),username) AS name FROM users WHERE username=? COLLATE NOCASE").bind(text.trim()).fetch_optional(&state.db).await;
        let (id, _) = match row {
            Ok(Some(r)) => (
                r.try_get::<String, _>("id").unwrap_or_default(),
                r.try_get::<String, _>("name").unwrap_or_default(),
            ),
            _ => {
                return error(
                    format!("{text} is not your friend"),
                    StatusCode::BAD_REQUEST,
                );
            }
        };
        if !are_friends(&state.db, &me.id, &id).await.unwrap_or(false) {
            return error(
                format!("{text} is not your friend"),
                StatusCode::BAD_REQUEST,
            );
        }
        if id != me.id && !joined.contains(&id) && !added.iter().any(|v| v == &id) {
            added.push(id)
        }
    }
    if added.is_empty() {
        return error(
            "These people are already in the call",
            StatusCode::BAD_REQUEST,
        );
    }
    let mut member_ids = joined.clone();
    member_ids.extend(added);
    if member_ids.len() + 1 > MAX_GROUP_MEMBERS {
        return error(
            format!("A group can have at most {MAX_GROUP_MEMBERS} members"),
            StatusCode::BAD_REQUEST,
        );
    }
    let mut names = vec![me.display_name.clone()];
    for id in &member_ids {
        let name = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(NULLIF(display_name,''),username) FROM users WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await;
        match name {
            Ok(Some(v)) => names.push(v),
            _ => return err_db(),
        }
    }
    let mut group_name = names.join(", ");
    if group_name.chars().count() > 64 {
        group_name = group_name
            .chars()
            .take(61)
            .collect::<String>()
            .trim_end_matches(", ")
            .to_string()
            + "…"
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if end_call(&mut tx, &call).await.is_err() {
        return err_db();
    }
    let chat_id = Uuid::new_v4().to_string();
    let stamp = now();
    if sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES(?,'group',?,?,?,?)").bind(&chat_id).bind(&group_name).bind(&me.id).bind(&stamp).bind(&stamp).execute(&mut *tx).await.is_err(){return err_db()}
    for id in std::iter::once(&me.id).chain(member_ids.iter()) {
        let seq = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?",
        )
        .bind(&chat_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) VALUES(?,?,?, ?,?,0,?)").bind(&chat_id).bind(id).bind(if id==&me.id{"owner"}else{"member"}).bind(now()).bind(seq).bind(seq).execute(&mut *tx).await.is_err(){return err_db()}
    }
    if add_system(
        &mut tx,
        &chat_id,
        "created",
        json!({"actor":me.display_name,"name":group_name}),
    )
    .await
    .is_err()
    {
        return err_db();
    }
    let new_call = match start_call(&mut tx, &chat_id, &me.id).await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if tx.commit().await.is_err() {
        return err_db();
    }
    stopped_ringing(&state, &headers, &me);
    crate::api::push::call_started(state.db.clone(), new_call.clone());
    match serialize_call(&state.db, &new_call, &me.id).await {
        Ok(v) => json_ok(json!({"chat_id":chat_id,"call":v})).into_response(),
        Err(_) => err_db(),
    }
}

async fn ice_servers(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(e) = require_user(&_state, &headers).await {
        return axum::response::IntoResponse::into_response(e);
    }
    let urls = std::env::var("TURN_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let secret = std::env::var("TURN_SECRET").unwrap_or_default();
    let mut servers = Vec::new();
    if !urls.is_empty() && !secret.is_empty() {
        let username = format!(
            "{}:{}",
            chrono::Utc::now().timestamp() + 12 * 3600,
            require_user(&_state, &headers)
                .await
                .ok()
                .and_then(|r| r.try_get::<String, _>("id").ok())
                .unwrap_or_default()
        );
        let mut mac = match Hmac::<Sha1>::new_from_slice(secret.as_bytes()) {
            Ok(v) => v,
            Err(_) => return err_db(),
        };
        mac.update(username.as_bytes());
        servers.push(json!({"urls":urls,"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes())}))
    }
    let stun = std::env::var("STUN_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let stun = if stun.is_empty() {
        urls.first()
            .map(|v| {
                v.replace("turns:", "stun:")
                    .replace("turn:", "stun:")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .filter(|v| !v.is_empty())
            .map(|v| vec![v])
            .unwrap_or_else(|| vec!["stun:stun.cloudflare.com:3478".into()])
    } else {
        stun
    };
    servers.insert(0, json!({"urls":stun}));
    json_ok(json!({"ice_servers":servers})).into_response()
}

async fn membership(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
) -> Result<Option<SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(chat).bind(user).fetch_optional(pool).await
}
async fn member_ids(pool: &SqlitePool, chat: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=?")
        .bind(chat)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get("user_id").ok())
        .collect())
}
async fn blocked(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").bind(a).bind(b).bind(b).bind(a).fetch_optional(pool).await?.is_some())
}
async fn are_friends(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    Ok(
        sqlx::query("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?")
            .bind(x)
            .bind(y)
            .fetch_optional(pool)
            .await?
            .is_some(),
    )
}
async fn require_call(
    pool: &SqlitePool,
    id: &str,
    user: &str,
    states: &[&str],
) -> Result<SqliteRow, ()> {
    let call = sqlx::query("SELECT * FROM calls WHERE id=? AND ended_at IS NULL")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?;
    let Some(call) = call else { return Err(()) };
    let chat_id: String = call.try_get("chat_id").map_err(|_| ())?;
    let is_member = sqlx::query("SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?")
        .bind(&chat_id)
        .bind(user)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?
        .is_some();
    if !is_member {
        return Err(());
    }
    let mine = sqlx::query("SELECT state FROM call_participants WHERE call_id=? AND user_id=?")
        .bind(id)
        .bind(user)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?;
    if mine
        .and_then(|v| v.try_get::<String, _>("state").ok())
        .is_some_and(|v| states.contains(&v.as_str()))
    {
        Ok(call)
    } else {
        Err(())
    }
}
pub(crate) async fn remove_user_from_chat_calls(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat_id: &str,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT p.call_id FROM call_participants p
         JOIN calls c ON c.id=p.call_id
         WHERE c.chat_id=? AND c.ended_at IS NULL AND p.user_id=? AND p.state IN ('ringing','joined')",
    )
    .bind(chat_id)
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let call_id: String = row.try_get("call_id")?;
        set_state(tx, &call_id, user_id, "left").await?;
        finish_if_over(tx, &call_id).await?;
    }
    Ok(())
}
async fn set_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
    user: &str,
    state: &str,
) -> Result<(), sqlx::Error> {
    let stamp = now();
    sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES(?,?,?,?,?) ON CONFLICT(call_id,user_id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at,seen_at=excluded.seen_at").bind(call).bind(user).bind(state).bind(&stamp).bind(&stamp).execute(&mut **tx).await?;
    Ok(())
}
async fn leave_other_calls(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    keep: Option<&str>,
) -> Result<(), sqlx::Error> {
    let rows=sqlx::query("SELECT p.call_id FROM call_participants p JOIN calls c ON c.id=p.call_id WHERE p.user_id=? AND p.state='joined' AND c.ended_at IS NULL AND p.call_id!=?").bind(user).bind(keep.unwrap_or("")).fetch_all(&mut **tx).await?;
    for row in rows {
        let id: String = row.try_get("call_id")?;
        set_state(tx, &id, user, "left").await?;
        finish_if_over(tx, &id).await?
    }
    Ok(())
}
async fn start_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    caller: &str,
) -> Result<String, sqlx::Error> {
    leave_other_calls(tx, caller, None).await?;
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO calls(id,chat_id,started_by,started_at) VALUES(?,?,?,?)")
        .bind(&id)
        .bind(chat)
        .bind(caller)
        .bind(now())
        .execute(&mut **tx)
        .await?;
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=?")
        .bind(chat)
        .fetch_all(&mut **tx)
        .await?;
    for row in rows {
        let uid: String = row.try_get("user_id")?;
        set_state(
            tx,
            &id,
            &uid,
            if uid == caller { "joined" } else { "ringing" },
        )
        .await?
    }
    Ok(id)
}
async fn finish_if_over(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
) -> Result<(), sqlx::Error> {
    let states = sqlx::query("SELECT state FROM call_participants WHERE call_id=?")
        .bind(call)
        .fetch_all(&mut **tx)
        .await?;
    let joined = states
        .iter()
        .filter(|v| v.try_get::<String, _>("state").ok().as_deref() == Some("joined"))
        .count();
    let ringing = states
        .iter()
        .filter(|v| v.try_get::<String, _>("state").ok().as_deref() == Some("ringing"))
        .count();
    if joined == 0 || (joined == 1 && ringing == 0) {
        finish_call(tx, call).await?
    }
    Ok(())
}
async fn finish_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT * FROM calls WHERE id=? AND ended_at IS NULL")
        .bind(call)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else { return Ok(()) };
    let chat: String = row.try_get("chat_id")?;
    let started: Option<String> = row.try_get("answered_at")?;
    let ended = now();
    let seconds = started
        .and_then(|v| {
            chrono::DateTime::parse_from_str(
                &format!("{}+00:00", v.trim_end_matches('Z')),
                "%Y-%m-%dT%H:%M:%S%:z",
            )
            .ok()
        })
        .map(|v| {
            (chrono::Utc::now() - v.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0)
        });
    let caller: String = row.try_get("started_by")?;
    let name = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(NULLIF(display_name,''),username) FROM users WHERE id=?",
    )
    .bind(caller)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_default();
    add_system(tx, &chat, "call", json!({"actor":name,"seconds":seconds})).await?;
    sqlx::query("UPDATE calls SET ended_at=? WHERE id=?")
        .bind(ended.clone())
        .bind(call)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE call_participants SET state='missed',updated_at=? WHERE call_id=? AND state='ringing'").bind(&ended).bind(call).execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE call_participants SET state='left',updated_at=? WHERE call_id=? AND state='joined'",
    )
    .bind(ended)
    .bind(call)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM call_signals WHERE call_id=?")
        .bind(call)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn end_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &SqliteRow,
) -> Result<(), sqlx::Error> {
    let id: String = call.try_get("id")?;
    finish_call(tx, &id).await
}
async fn add_system(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    event: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    let rev: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(rev),0)+1 FROM messages")
        .fetch_one(&mut **tx)
        .await?;
    let mut payload = details.as_object().cloned().unwrap_or_default();
    payload.insert("event".into(), json!(event));
    let stamp = now();
    sqlx::query(
        "INSERT INTO messages(id,chat_id,kind,payload,created_at,rev) VALUES(?,?,'system',?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(chat)
    .bind(Value::Object(payload).to_string())
    .bind(&stamp)
    .bind(rev)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
        .bind(stamp)
        .bind(chat)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn expire_calls(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<(), sqlx::Error> {
    let rows=sqlx::query("SELECT p.call_id,p.user_id,p.state FROM call_participants p JOIN calls c ON c.id=p.call_id WHERE c.ended_at IS NULL AND ((p.state='ringing' AND p.updated_at<?) OR (p.state='joined' AND p.seen_at<?))").bind(ago(RING_SECONDS)).bind(ago(GONE_SECONDS)).fetch_all(&mut **tx).await?;
    let mut affected = Vec::new();
    for row in rows {
        let call: String = row.try_get("call_id")?;
        let user: String = row.try_get("user_id")?;
        let state: String = row.try_get("state")?;
        set_state(
            tx,
            &call,
            &user,
            if state == "ringing" { "missed" } else { "left" },
        )
        .await?;
        if !affected.contains(&call) {
            affected.push(call)
        }
    }
    for call in affected {
        finish_if_over(tx, &call).await?
    }
    sqlx::query("DELETE FROM call_signals WHERE created_at<?")
        .bind(ago(120))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn serialize_call(pool: &SqlitePool, id: &str, me: &str) -> Result<Value, sqlx::Error> {
    let call = sqlx::query("SELECT * FROM calls WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(call) = call else {
        return Err(sqlx::Error::RowNotFound);
    };
    let chat_id: String = call.try_get("chat_id")?;
    let chat = membership(pool, &chat_id, me).await?;
    let name = chat
        .as_ref()
        .and_then(|v| v.try_get::<Option<String>, _>("name").ok().flatten())
        .unwrap_or_default();
    let kind = chat
        .as_ref()
        .and_then(|v| v.try_get::<String, _>("type").ok())
        .unwrap_or_else(|| "dm".into());
    let participants=sqlx::query("SELECT p.user_id,p.state,u.username,u.display_name FROM call_participants p JOIN users u ON u.id=p.user_id WHERE p.call_id=? ORDER BY u.username COLLATE NOCASE").bind(id).fetch_all(pool).await?;
    // A direct chat has no name of its own: it is called after the other person.
    let name = if name.is_empty() && kind == "dm" {
        participants
            .iter()
            .find(|r| r.try_get::<String, _>("user_id").ok().as_deref() != Some(me))
            .map(|r| {
                r.try_get::<Option<String>, _>("display_name")
                    .ok()
                    .flatten()
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| r.try_get("username").unwrap_or_default())
            })
            .unwrap_or_default()
    } else {
        name
    };
    Ok(
        json!({"id":id,"chat_id":chat_id,"chat_name":name,"chat_type":kind,"started_by":call.try_get::<String,_>("started_by")?,"started_at":call.try_get::<String,_>("started_at")?,"answered_at":call.try_get::<Option<String>,_>("answered_at")?,"participants":participants.iter().map(|r|json!({"id":r.try_get::<String,_>("user_id").unwrap_or_default(),"username":r.try_get::<String,_>("username").unwrap_or_default(),"display_name":r.try_get::<Option<String>,_>("display_name").ok().flatten().filter(|v|!v.is_empty()).or_else(||r.try_get("username").ok()),"state":r.try_get::<String,_>("state").unwrap_or_default()})).collect::<Vec<_>>()}),
    )
}
fn valid_b64(v: &str, max: usize) -> bool {
    let unpadded = v.trim_end_matches('=');
    !v.is_empty()
        && v.len() <= max
        && v.len() - unpadded.len() <= 2
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, SqlitePool) {
            let dir = std::env::temp_dir().join(format!("seres-calls-{}", uuid::Uuid::new_v4()));
            let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
            (Self(dir), pool)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn require_call_checks_chat_membership_and_remove_user_from_chat_calls_cleans_up() {
        let (_fix, pool) = Fixture::new().await;
        for id in ["alice", "bob", "carol"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(id)
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO apns_tokens(token,user_id,session_hash,kind,environment,created_at) VALUES('voip-c','carol','sc','voip','sandbox','now')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Team','alice','now','now')")
            .execute(&pool)
            .await
            .unwrap();
        for id in ["alice", "bob", "carol"] {
            sqlx::query("INSERT INTO chat_members(chat_id,user_id,joined_at) VALUES('g1',?,'now')")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let mut tx = pool.begin().await.unwrap();
        let call_id = start_call(&mut tx, "g1", "alice").await.unwrap();
        set_state(&mut tx, &call_id, "bob", "joined").await.unwrap();
        tx.commit().await.unwrap();

        assert!(
            require_call(&pool, &call_id, "carol", &["ringing"])
                .await
                .is_ok()
        );

        // Removing carol from chat_members immediately blocks require_call even before participant update
        sqlx::query("DELETE FROM chat_members WHERE chat_id='g1' AND user_id='carol'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            require_call(&pool, &call_id, "carol", &["ringing"])
                .await
                .is_err()
        );

        // remove_user_from_chat_calls marks carol 'left' and notes apns_call_ends, keeping call active for alice+bob
        let mut tx = pool.begin().await.unwrap();
        remove_user_from_chat_calls(&mut tx, "g1", "carol")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let carol_state: String = sqlx::query_scalar(
            "SELECT state FROM call_participants WHERE call_id=? AND user_id='carol'",
        )
        .bind(&call_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(carol_state, "left");
        let ended: Option<String> = sqlx::query_scalar("SELECT ended_at FROM calls WHERE id=?")
            .bind(&call_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ended.is_none());
        let apns_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM apns_call_ends WHERE call_id=? AND user_id='carol'",
        )
        .bind(&call_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(apns_count, 1);

        // Removing bob leaves only alice joined -> finish_if_over ends the call
        sqlx::query("DELETE FROM chat_members WHERE chat_id='g1' AND user_id='bob'")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        remove_user_from_chat_calls(&mut tx, "g1", "bob")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let ended: Option<String> = sqlx::query_scalar("SELECT ended_at FROM calls WHERE id=?")
            .bind(&call_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ended.is_some());
    }

    async fn auth_headers(pool: &SqlitePool, user_id: &str) -> HeaderMap {
        let token = format!("tok-{user_id}-{}", Uuid::new_v4());
        let hash = crate::api::auth::hash_token(&token);
        let stamp = now();
        sqlx::query(
            "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at,approved,last_seen) VALUES(?,?,'2999-01-01T00:00:00Z','now',1,?)",
        )
        .bind(hash)
        .bind(user_id)
        .bind(stamp)
        .execute(pool)
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("sessioncookie={token}")).unwrap(),
        );
        headers
    }

    async fn insert_user(pool: &SqlitePool, id: &str, with_keys: bool) {
        let stamp = now();
        let (ecdh, sign) = if with_keys {
            (Some("pub-ecdh"), Some("pub-sign"))
        } else {
            (None, None)
        };
        sqlx::query(
            "INSERT INTO users(id,username,display_name,pub_ecdh,pub_sign,last_seen) VALUES(?,?,?,?,?,?)",
        )
        .bind(id)
        .bind(id)
        .bind(id)
        .bind(ecdh)
        .bind(sign)
        .bind(stamp)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn befriend(pool: &SqlitePool, a: &str, b: &str) {
        let (x, y) = if a <= b { (a, b) } else { (b, a) };
        sqlx::query(
            "INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,'now')",
        )
        .bind(x)
        .bind(y)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn add_to_call_enforces_group_owner_blocks_keys_and_rate_limit() {
        let (_fix, pool) = Fixture::new().await;
        for (id, keys) in [
            ("alice", true),
            ("bob", true),
            ("carol", true),
            ("dave", false),
            ("eve", true),
        ] {
            insert_user(&pool, id, keys).await;
        }
        for friend in ["bob", "carol", "dave", "eve"] {
            befriend(&pool, "alice", friend).await;
        }
        befriend(&pool, "bob", "carol").await;
        // Bob blocks Eve, even though Alice is friends with Eve.
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','eve','now')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES('g1','group','Team','alice','now','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('g1','alice','owner','now'),('g1','bob','member','now')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let call_id = start_call(&mut tx, "g1", "alice").await.unwrap();
        set_state(&mut tx, &call_id, "bob", "joined").await.unwrap();
        tx.commit().await.unwrap();

        let state = AppState::new(pool.clone());
        let alice_headers = auth_headers(&pool, "alice").await;
        let bob_headers = auth_headers(&pool, "bob").await;

        // Non-owner joined member Bob cannot add_to_call to kill the group call.
        let resp = add_to_call(
            State(state.clone()),
            bob_headers,
            Path(call_id.clone()),
            Json(json!({"usernames": ["carol"]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let ended: Option<String> = sqlx::query_scalar("SELECT ended_at FROM calls WHERE id=?")
            .bind(&call_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ended.is_none());

        // Pairwise block: Bob blocked Eve -> Alice cannot add Eve.
        let resp = add_to_call(
            State(state.clone()),
            alice_headers.clone(),
            Path(call_id.clone()),
            Json(json!({"usernames": ["eve"]})),
        )
        .await;
        assert!(!resp.status().is_success());

        // Added user must have E2EE keys (pub_ecdh/pub_sign).
        let resp = add_to_call(
            State(state.clone()),
            alice_headers.clone(),
            Path(call_id.clone()),
            Json(json!({"usernames": ["dave"]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Valid owner add succeeds and ends source call.
        let resp = add_to_call(
            State(state.clone()),
            alice_headers.clone(),
            Path(call_id.clone()),
            Json(json!({"usernames": ["carol"]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ended: Option<String> = sqlx::query_scalar("SELECT ended_at FROM calls WHERE id=?")
            .bind(&call_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ended.is_some());

        // Rate-limited via call:{me.id} (20 per 600s; 1 used above, 19 more -> 21st is 429).
        for _ in 0..19 {
            let r = add_to_call(
                State(state.clone()),
                alice_headers.clone(),
                Path(call_id.clone()),
                Json(json!({"usernames": ["carol"]})),
            )
            .await;
            assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let limited = add_to_call(
            State(state.clone()),
            alice_headers,
            Path(call_id),
            Json(json!({"usernames": ["carol"]})),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn add_to_call_is_atomic_under_concurrent_requests() {
        let (_fix, pool) = Fixture::new().await;
        for id in ["alice", "bob", "carol", "dave"] {
            insert_user(&pool, id, true).await;
        }
        befriend(&pool, "alice", "bob").await;
        befriend(&pool, "alice", "carol").await;
        befriend(&pool, "bob", "dave").await;
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('dm1','alice','member','now'),('dm1','bob','member','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let call_id = start_call(&mut tx, "dm1", "alice").await.unwrap();
        set_state(&mut tx, &call_id, "bob", "joined").await.unwrap();
        tx.commit().await.unwrap();

        let state = AppState::new(pool.clone());
        let alice_headers = auth_headers(&pool, "alice").await;
        let bob_headers = auth_headers(&pool, "bob").await;

        let (r1, r2) = tokio::join!(
            add_to_call(
                State(state.clone()),
                alice_headers,
                Path(call_id.clone()),
                Json(json!({"usernames": ["carol"]})),
            ),
            add_to_call(
                State(state.clone()),
                bob_headers,
                Path(call_id.clone()),
                Json(json!({"usernames": ["dave"]})),
            ),
        );
        let ok_count = [r1.status(), r2.status()]
            .into_iter()
            .filter(|s| *s == StatusCode::OK)
            .count();
        assert_eq!(ok_count, 1);
        let group_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chats WHERE type='group'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(group_count, 1);
    }

    #[tokio::test]
    async fn ice_servers_rate_limits_and_tightens_turn_ttl() {
        let (_fix, pool) = Fixture::new().await;
        insert_user(&pool, "alice", true).await;
        let state = AppState::new(pool.clone());
        let headers = auth_headers(&pool, "alice").await;

        // Set TURN env vars briefly to inspect credential TTL.
        unsafe {
            std::env::set_var("TURN_URLS", "turn:turn.example.com:3478");
            std::env::set_var("TURN_SECRET", "test-turn-secret");
        }
        let now_ts = chrono::Utc::now().timestamp();
        let resp = ice_servers(State(state.clone()), headers.clone()).await;
        unsafe {
            std::env::remove_var("TURN_URLS");
            std::env::remove_var("TURN_SECRET");
        }
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let turn_user = body["ice_servers"][1]["username"].as_str().unwrap();
        let expiry: i64 = turn_user.split(':').next().unwrap().parse().unwrap();
        assert!(
            expiry <= now_ts + 3605,
            "TURN TTL should be <= 3600s, got {}",
            expiry - now_ts
        );

        for _ in 0..59 {
            let r = ice_servers(State(state.clone()), headers.clone()).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let limited = ice_servers(State(state), headers).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn answer_call_prevents_answered_at_spoofing_and_expires_stale_calls() {
        let (_fix, pool) = Fixture::new().await;
        for id in ["alice", "bob"] {
            insert_user(&pool, id, true).await;
        }
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('dm1','alice','member','now'),('dm1','bob','member','now')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState::new(pool.clone());
        let alice_headers = auth_headers(&pool, "alice").await;
        let bob_headers = auth_headers(&pool, "bob").await;

        let mut tx = pool.begin().await.unwrap();
        let call_id = start_call(&mut tx, "dm1", "alice").await.unwrap();
        tx.commit().await.unwrap();

        // Caller Alice cannot spoof answered_at via answer_call or call_chat while Bob is still ringing.
        let r = answer_call(
            State(state.clone()),
            alice_headers.clone(),
            Path(call_id.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let answered: Option<String> =
            sqlx::query_scalar("SELECT answered_at FROM calls WHERE id=?")
                .bind(&call_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(answered.is_none(), "caller answer_call spoofed answered_at");

        let r = call_chat(
            State(state.clone()),
            alice_headers.clone(),
            Path("dm1".into()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let answered: Option<String> =
            sqlx::query_scalar("SELECT answered_at FROM calls WHERE id=?")
                .bind(&call_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(answered.is_none(), "caller call_chat spoofed answered_at");

        // Bob answering transitions ringing -> joined and sets answered_at.
        let r = answer_call(
            State(state.clone()),
            bob_headers.clone(),
            Path(call_id.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let answered: Option<String> =
            sqlx::query_scalar("SELECT answered_at FROM calls WHERE id=?")
                .bind(&call_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(answered.is_some());

        // Stale ringing call (> RING_SECONDS) must expire inside answer_call's transaction.
        sqlx::query("UPDATE calls SET ended_at=? WHERE id=?")
            .bind(now())
            .bind(&call_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let stale_call = start_call(&mut tx, "dm1", "alice").await.unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE call_participants SET updated_at=? WHERE call_id=? AND user_id='bob'")
            .bind(ago(RING_SECONDS + 10))
            .bind(&stale_call)
            .execute(&pool)
            .await
            .unwrap();

        let r = answer_call(State(state), bob_headers, Path(stale_call)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn my_calls_avoids_write_tx_when_idle_caps_signals_and_cleans_zombie_calls() {
        let dir = std::env::temp_dir().join(format!("seres-calls-rw-{}", Uuid::new_v4()));
        let db_path = dir.join("users.db");
        let pool = crate::db::connect(&db_path).await.unwrap();
        insert_user(&pool, "alice", true).await;
        insert_user(&pool, "bob", true).await;
        let alice_headers = auth_headers(&pool, "alice").await;

        // Open a short-timeout pool so any write attempt during an external write lock fails fast.
        let short_opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db_path)
            .busy_timeout(std::time::Duration::from_millis(80));
        let short_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(short_opts)
            .await
            .unwrap();
        let lock_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite:{}", db_path.display()))
            .await
            .unwrap();

        let mut lock_conn = lock_pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        let idle_resp = my_calls(
            State(AppState::new(short_pool.clone())),
            alice_headers.clone(),
            Query(HashMap::new()),
        )
        .await;
        sqlx::query("ROLLBACK")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        drop(lock_conn);
        lock_pool.close().await;
        short_pool.close().await;
        assert_eq!(idle_resp.status(), StatusCode::OK);

        // 1-member zombie call (joined=1, ringing=0, fresh seen_at) is finished on my_calls.
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('dm1','alice','member','now'),('dm1','bob','member','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO calls(id,chat_id,started_by,started_at) VALUES('zombie-call','dm1','alice',?)")
            .bind(now())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('zombie-call','alice','joined',?,?)",
        )
        .bind(now())
        .bind(now())
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState::new(pool.clone());
        let resp = my_calls(
            State(state.clone()),
            alice_headers.clone(),
            Query(HashMap::new()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ended: Option<String> =
            sqlx::query_scalar("SELECT ended_at FROM calls WHERE id='zombie-call'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(ended.is_some(), "1-member zombie call should be ended");

        // Signal query is capped with LIMIT.
        for i in 0..250 {
            sqlx::query(
                "INSERT INTO call_signals(call_id,from_id,to_id,kind,data,created_at) VALUES('c1','bob','alice','offer',?,?)",
            )
            .bind(format!("{{\"i\":{i}}}"))
            .bind(now())
            .execute(&pool)
            .await
            .unwrap();
        }
        let resp = my_calls(State(state), alice_headers, Query(HashMap::new())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let sig_len = body["signals"].as_array().unwrap().len();
        assert!(sig_len <= 200, "signals should be capped, got {sig_len}");

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn call_signal_forbids_self_target_and_finish_call_skips_missing_chat_message() {
        let (_fix, pool) = Fixture::new().await;
        for id in ["alice", "bob"] {
            insert_user(&pool, id, true).await;
        }
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES('dm1','alice','member','now'),('dm1','bob','member','now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let call_id = start_call(&mut tx, "dm1", "alice").await.unwrap();
        tx.commit().await.unwrap();

        let state = AppState::new(pool.clone());
        let alice_headers = auth_headers(&pool, "alice").await;
        let resp = call_signal(
            State(state),
            alice_headers,
            Path(call_id),
            Json(json!({"to": "alice", "kind": "offer", "data": {"sdp": "v=0", "sig": "AAAA"}})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // finish_call with a deleted chat must end the call without inserting a system message.
        sqlx::query("INSERT INTO calls(id,chat_id,started_by,started_at) VALUES('orphan-call','missing-chat','alice',?)")
            .bind(now())
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        finish_call(&mut tx, "orphan-call").await.unwrap();
        tx.commit().await.unwrap();
        let msg_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE chat_id='missing-chat'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(msg_count, 0);
    }
}
