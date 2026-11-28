use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use rand::{Rng, distributions::Alphanumeric};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/friends", get(list_friends))
        .route("/api/pending_friends", get(pending_friends_legacy))
        .route("/api/friends/request", post(request_friend))
        .route("/api/add_friend", post(request_friend))
        .route("/api/invite", get(my_invite))
        .route("/api/invite/renew", post(renew_invite))
        .route("/api/invite/{token}", get(show_invite))
        .route("/api/invite/{token}/accept", post(accept_invite))
        .route("/api/friends/accept", post(accept_friend))
        .route("/api/friends/decline", post(decline_friend))
        .route("/api/discard_request", post(decline_friend))
        .route("/api/friends/cancel", post(cancel_friend_request))
        .route("/api/friends/remove", post(remove_friend))
        .route("/api/block", post(block_user))
        .route("/api/block_user", post(block_user))
        .route("/api/unblock", post(unblock_user))
        .route("/api/users/mute", post(mute_user))
        .route("/api/users/{username}/profile", get(user_profile))
}

async fn pending_friends_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("SELECT u.username FROM friend_requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=?").bind(me).fetch_all(&state.db).await{Ok(rows)=>json_ok(json!({"pending_friends":rows.iter().filter_map(|r|r.try_get::<String,_>("username").ok()).collect::<Vec<_>>()})).into_response(),Err(_)=>db_error()}
}

async fn list_friends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let friends = sqlx::query("SELECT u.id,u.username,u.display_name,u.status_text FROM friendships f JOIN users u ON u.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END WHERE f.user_a=? OR f.user_b=? ORDER BY COALESCE(u.display_name,u.username) COLLATE NOCASE")
        .bind(&me).bind(&me).bind(&me).fetch_all(&state.db).await;
    let incoming = sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=? ORDER BY r.created_at")
        .bind(&me).fetch_all(&state.db).await;
    let outgoing = sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_requests r JOIN users u ON u.id=r.to_id WHERE r.from_id=? ORDER BY r.created_at")
        .bind(&me).fetch_all(&state.db).await;
    let blocked = sqlx::query("SELECT u.id,u.username,u.display_name FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=? ORDER BY u.username COLLATE NOCASE")
        .bind(&me).fetch_all(&state.db).await;
    match (friends, incoming, outgoing, blocked) {
        (Ok(f), Ok(i), Ok(o), Ok(b)) => json_ok(
            json!({"friends":users(f),"incoming":users(i),"outgoing":users(o),"blocked":users(b)}),
        )
        .into_response(),
        _ => error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn begin_immediate(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    pool.begin_with("BEGIN IMMEDIATE").await
}

async fn request_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("friend-request:{me}"), 30, 600) {
        return error(
            "Too many friend requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let other = match lookup_target_user(&state, &body).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error("Friend request could not be sent", StatusCode::BAD_REQUEST);
        }
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    send_friend_request(&state, &me, &other).await
}

async fn send_friend_request(state: &AppState, me: &str, other: &str) -> axum::response::Response {
    if me == other {
        return error("Cannot add yourself as a friend", StatusCode::BAD_REQUEST);
    }
    let mut tx = match begin_immediate(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match are_friends_conn(&mut *tx, me, other).await {
        Ok(true) => return error("Already Friends", StatusCode::BAD_REQUEST),
        Ok(false) => {}
        Err(_) => return db_error(),
    }
    match is_blocked_conn(&mut *tx, me, other).await {
        Ok(false) => {}
        _ => return error("Friend request could not be sent", StatusCode::BAD_REQUEST),
    }
    let incoming = sqlx::query("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(other)
        .bind(me)
        .fetch_optional(&mut *tx)
        .await;
    match incoming {
        Ok(Some(_)) => {
            let (a, b) = pair(me, other);
            if sqlx::query(
                "INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)",
            )
            .bind(a)
            .bind(b)
            .bind(now())
            .execute(&mut *tx)
            .await
            .is_err()
                || sqlx::query(
                    "DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                )
                .bind(me)
                .bind(other)
                .bind(other)
                .bind(me)
                .execute(&mut *tx)
                .await
                .is_err()
                || tx.commit().await.is_err()
            {
                return db_error();
            }
            return json_ok(json!({"message":"Friend added successfully!","status":"friends"}))
                .into_response();
        }
        Ok(None) => {}
        Err(_) => return db_error(),
    }
    let outgoing = sqlx::query("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(me)
        .bind(other)
        .fetch_optional(&mut *tx)
        .await;
    match outgoing {
        Ok(Some(_)) => return error("Already pending request", StatusCode::BAD_REQUEST),
        Ok(None) => {}
        Err(_) => return db_error(),
    }
    if sqlx::query("INSERT INTO friend_requests(from_id,to_id,created_at) VALUES(?,?,?)")
        .bind(me)
        .bind(other)
        .bind(now())
        .execute(&mut *tx)
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Request sent","status":"pending"})).into_response()
}

async fn my_invite(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    invite_response(&state, &headers, false).await
}
async fn renew_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    invite_response(&state, &headers, true).await
}
async fn invite_response(
    state: &AppState,
    headers: &HeaderMap,
    renew: bool,
) -> axum::response::Response {
    let me = match user_id(state, headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if !renew
        && let Ok(Some(token)) =
            sqlx::query_scalar::<_, String>("SELECT token FROM friend_invites WHERE user_id=?")
                .bind(&me)
                .fetch_optional(&state.db)
                .await
    {
        return json_ok(json!({"token":token})).into_response();
    }
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(char::from)
        .collect();
    match sqlx::query("INSERT INTO friend_invites(token,user_id,created_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token,created_at=excluded.created_at").bind(&token).bind(me).bind(now()).execute(&state.db).await{
        Ok(_)=>json_ok(json!({"token":token})).into_response(),Err(_)=>db_error()
    }
}

async fn show_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("invite-show:{me}"), 30, 60) {
        return error(
            "Too many requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let owner = match invite_owner(&state, &token).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let status = if owner.0 == me {
        "self"
    } else if are_friends(&state.db, &me, &owner.0).await.unwrap_or(false) {
        "friends"
    } else {
        "none"
    };
    json_ok(json!({"user":owner.1,"status":status})).into_response()
}
async fn accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("friend-request:{me}"), 30, 600) {
        return error(
            "Too many friend requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let owner = match invite_owner(&state, &token).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    send_friend_request(&state, &me, &owner.0).await
}
async fn invite_owner(state: &AppState, token: &str) -> ApiResult<(String, Value)> {
    let row=sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_invites i JOIN users u ON u.id=i.user_id WHERE i.token=?").bind(token.chars().take(64).collect::<String>()).fetch_optional(&state.db).await.map_err(|_|ApiError::new("Database unavailable",StatusCode::INTERNAL_SERVER_ERROR))?.ok_or_else(||ApiError::new("This invite link is invalid or expired",StatusCode::NOT_FOUND))?;
    let id: String = row.try_get("id").unwrap_or_default();
    Ok((id, public_user(&row)))
}

async fn accept_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let mut tx = match begin_immediate(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match is_blocked_conn(&mut *tx, &me, &other).await {
        Ok(false) => {}
        Ok(true) => {
            return error("Cannot accept friend request", StatusCode::FORBIDDEN);
        }
        Err(_) => return db_error(),
    }
    let deleted = sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&other)
        .bind(&me)
        .execute(&mut *tx)
        .await;
    match deleted {
        Ok(res) if res.rows_affected() == 1 => {}
        Ok(_) => return error("Request doesnt exist", StatusCode::BAD_REQUEST),
        Err(_) => return db_error(),
    }
    let (x, y) = pair(&me, &other);
    if sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&me)
        .bind(&other)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)")
            .bind(x)
            .bind(y)
            .bind(now())
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Friend added successfully!"})).into_response()
}
async fn decline_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&other)
        .bind(&me)
        .execute(&state.db)
        .await
    {
        Ok(v) if v.rows_affected() > 0 => {
            json_ok(json!({"message":"successfully deleted the request"})).into_response()
        }
        Ok(_) => error("Request doesnt exist", StatusCode::BAD_REQUEST),
        Err(_) => db_error(),
    }
}
async fn cancel_friend_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&me)
        .bind(other)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"message":"Request cancelled"})).into_response(),
        Err(_) => db_error(),
    }
}
async fn remove_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (a, b) = pair(&me, &other);
    match sqlx::query("DELETE FROM friendships WHERE user_a=? AND user_b=?")
        .bind(a)
        .bind(b)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"message":"Friend removed"})).into_response(),
        Err(_) => db_error(),
    }
}
async fn block_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if me == other {
        return error("Cannot block yourself", StatusCode::BAD_REQUEST);
    }
    let was_friend = are_friends(&state.db, &me, &other).await.unwrap_or(false) as i64;
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query(
        "INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at,was_friend) VALUES(?,?,?,?)",
    )
    .bind(&me)
    .bind(&other)
    .bind(now())
    .bind(was_friend)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return db_error();
    }
    let (a, b) = pair(&me, &other);
    if sqlx::query("DELETE FROM friendships WHERE user_a=? AND user_b=?")
        .bind(a)
        .bind(b)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query(
            "DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
        )
        .bind(&me)
        .bind(&other)
        .bind(&other)
        .bind(&me)
        .execute(&mut *tx)
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"User blocked"})).into_response()
}
async fn unblock_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let mut tx = match begin_immediate(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?")
        .bind(&me)
        .bind(&other)
        .execute(&mut *tx)
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"User unblocked","friends":false})).into_response()
}
async fn mute_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let muted = body.get("muted").and_then(Value::as_bool) == Some(true);
    let query = if muted {
        "INSERT OR IGNORE INTO muted_users(user_id,muted_id,created_at) VALUES(?,?,?)"
    } else {
        "DELETE FROM muted_users WHERE user_id=? AND muted_id=?"
    };
    let mut q = sqlx::query(query).bind(&me).bind(&other);
    if muted {
        q = q.bind(now())
    }
    match q.execute(&state.db).await {
        Ok(_) => json_ok(json!({"muted":muted})).into_response(),
        Err(_) => db_error(),
    }
}
async fn user_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(format!("profile:{me}"), 60, 60) {
        return error(
            "Too many requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let other = sqlx::query("SELECT * FROM users WHERE username=? COLLATE NOCASE")
        .bind(username.trim())
        .fetch_optional(&state.db)
        .await;
    let other = match other {
        Ok(Some(u)) => u,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let oid: String = other.try_get("id").unwrap_or_default();
    let is_me = oid == me;
    let req=sqlx::query("SELECT from_id FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)").bind(&me).bind(&oid).bind(&oid).bind(&me).fetch_optional(&state.db).await;
    let request = match req {
        Ok(Some(r)) => Some(
            if r.try_get::<String, _>("from_id").ok().as_deref() == Some(me.as_str()) {
                "outgoing"
            } else {
                "incoming"
            },
        ),
        Ok(None) => None,
        Err(_) => return db_error(),
    };
    let friend = are_friends(&state.db, &me, &oid).await.unwrap_or(false);
    let blocked = exists(
        &state.db,
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?",
        &me,
        &oid,
    )
    .await;
    let muted = exists(
        &state.db,
        "SELECT 1 FROM muted_users WHERE user_id=? AND muted_id=?",
        &me,
        &oid,
    )
    .await;
    let blocked_either = !is_me
        && match is_blocked(&state.db, &me, &oid).await {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
    let can_see = !blocked_either
        && (friend
            || exists(
                &state.db,
                "SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=? AND a.hidden=0 LIMIT 1",
                &me,
                &oid,
            )
            .await);
    let presence = if !is_me && can_see {
        let visibility=sqlx::query("SELECT v.show_last_seen viewer_show,o.show_last_seen other_show,o.last_seen FROM users v JOIN users o ON o.id=? WHERE v.id=?").bind(&oid).bind(&me).fetch_optional(&state.db).await;
        match visibility {
            Ok(Some(r)) => {
                let show = r.try_get::<i64, _>("viewer_show").unwrap_or(1) != 0
                    && r.try_get::<i64, _>("other_show").unwrap_or(1) != 0;
                let last = r.try_get::<Option<String>, _>("last_seen").ok().flatten();
                if show {
                    last.map(|last| json!({"online":online(&last),"last_seen":last}))
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(_) => return db_error(),
        }
    } else {
        None
    };
    // Like "last seen": only friends and people who share a chat see the status.
    let status = if is_me || can_see {
        other
            .try_get::<Option<String>, _>("status_text")
            .ok()
            .flatten()
    } else {
        None
    };
    json_ok(json!({"user":{"id":oid,"username":other.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&other),"status":status,"pub_ecdh":other.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":other.try_get::<Option<String>,_>("pub_sign").ok().flatten()},"is_me":is_me,"friend":friend,"blocked":blocked,"muted":muted,"request":request,"presence":presence})).into_response()
}

async fn user_id(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let row = require_user(state, headers).await?;
    Ok(row.try_get("id").unwrap_or_default())
}
async fn lookup_target_user(state: &AppState, body: &Value) -> ApiResult<Option<String>> {
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ApiError::new("Missing or invalid 'username'", StatusCode::BAD_REQUEST))?;
    sqlx::query_scalar("SELECT id FROM users WHERE username=? COLLATE NOCASE")
        .bind(name.trim())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR))
}
async fn target_user(state: &AppState, body: &Value) -> ApiResult<String> {
    lookup_target_user(state, body)
        .await?
        .ok_or_else(|| ApiError::new("User not found", StatusCode::NOT_FOUND))
}
fn users(rows: Vec<sqlx::sqlite::SqliteRow>) -> Vec<Value> {
    rows.iter().map(public_user).collect()
}
fn public_user(row: &sqlx::sqlite::SqliteRow) -> Value {
    let mut user = json!({"id":row.try_get::<String,_>("id").unwrap_or_default(),"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(row)});
    // Friends see each other's status (the query selects it only for them).
    if let Ok(Some(status)) = row.try_get::<Option<String>, _>("status_text") {
        user["status"] = json!(status);
    }
    user
}
fn display_name(row: &sqlx::sqlite::SqliteRow) -> String {
    row.try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .or_else(|| row.try_get("username").ok())
        .unwrap_or_default()
}
fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn online(last: &str) -> bool {
    chrono::DateTime::parse_from_str(
        &format!("{}+00:00", last.trim_end_matches('Z')),
        "%Y-%m-%dT%H:%M:%S%:z",
    )
    .ok()
    .is_some_and(|d| (chrono::Utc::now() - d.with_timezone(&chrono::Utc)).num_seconds() < 45)
}
async fn exists(pool: &SqlitePool, sql: &str, a: &str, b: &str) -> bool {
    sqlx::query(sql)
        .bind(a)
        .bind(b)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}
async fn are_friends_conn<'e, E>(exec: E, a: &str, b: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
async fn are_friends(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    are_friends_conn(pool, a, b).await
}
async fn is_blocked_conn<'e, E>(exec: E, a: &str, b: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    Ok(sqlx::query(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
    )
    .bind(a)
    .bind(b)
    .bind(b)
    .bind(a)
    .fetch_optional(exec)
    .await?
    .is_some())
}
async fn is_blocked(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    is_blocked_conn(pool, a, b).await
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

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        async fn new() -> (Self, AppState) {
            let dir = std::env::temp_dir().join(format!("seres-social-{}", uuid::Uuid::new_v4()));
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
    async fn user_profile_hides_status_and_presence_when_blocked_and_rate_limits() {
        let (_fix, state) = Fixture::new().await;
        let seen = now();
        for id in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO users(id,username,status_text,last_seen,show_last_seen) VALUES(?,?,'hello',?,1)",
            )
            .bind(id)
            .bind(id)
            .bind(&seen)
            .execute(&state.db)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO chats(id,type,created_at,last_activity) VALUES('g1','group','now','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO chat_members(chat_id,user_id,joined_at) VALUES('g1',?,'now')")
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;

        let resp = user_profile(
            State(state.clone()),
            alice_headers.clone(),
            Path("bob".into()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["user"]["status"], "hello");
        assert!(body["presence"].is_object());

        // Bob blocks Alice -> Alice sees neither status nor presence
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let resp = user_profile(
            State(state.clone()),
            alice_headers.clone(),
            Path("bob".into()),
        )
        .await;
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert!(body["user"]["status"].is_null());
        assert!(body["presence"].is_null());

        // Bob also sees neither Alice's status nor presence
        let resp = user_profile(State(state.clone()), bob_headers, Path("alice".into())).await;
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert!(body["user"]["status"].is_null());
        assert!(body["presence"].is_null());

        // Remaining requests up to 60 succeed, 61st is rate limited
        for _ in 0..58 {
            let resp = user_profile(
                State(state.clone()),
                alice_headers.clone(),
                Path("bob".into()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let limited = user_profile(State(state.clone()), alice_headers, Path("bob".into())).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn request_friend_rate_limits_before_lookup_and_hides_blocked_vs_missing() {
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
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('bob','alice','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let alice_headers = auth_headers(&state.db, "alice").await;

        let blocked_resp = request_friend(
            State(state.clone()),
            alice_headers.clone(),
            Json(json!({"username": "bob"})),
        )
        .await;
        let blocked_status = blocked_resp.status();
        let blocked_body: Value = serde_json::from_slice(
            &to_bytes(blocked_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        let missing_resp = request_friend(
            State(state.clone()),
            alice_headers.clone(),
            Json(json!({"username": "no_such_user_123"})),
        )
        .await;
        let missing_status = missing_resp.status();
        let missing_body: Value = serde_json::from_slice(
            &to_bytes(missing_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(blocked_status, StatusCode::BAD_REQUEST);
        assert_eq!(missing_status, blocked_status);
        assert_eq!(missing_body["message"], blocked_body["message"]);

        // Remaining 28 calls with nonexistent username succeed in counting toward 30/600s limit,
        // and the 31st is rate limited before target_user lookup.
        for _ in 0..28 {
            let r = request_friend(
                State(state.clone()),
                alice_headers.clone(),
                Json(json!({"username": "no_such_user_123"})),
            )
            .await;
            assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let limited = request_friend(
            State(state),
            alice_headers,
            Json(json!({"username": "no_such_user_123"})),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn invite_endpoints_are_rate_limited() {
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
            "INSERT INTO friend_invites(token,user_id,created_at) VALUES('tok-bob','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let alice_headers = auth_headers(&state.db, "alice").await;

        for _ in 0..30 {
            let r = show_invite(
                State(state.clone()),
                alice_headers.clone(),
                Path("tok-bob".into()),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let limited_show = show_invite(
            State(state.clone()),
            alice_headers.clone(),
            Path("tok-bob".into()),
        )
        .await;
        assert_eq!(limited_show.status(), StatusCode::TOO_MANY_REQUESTS);

        for _ in 0..30 {
            let r = accept_invite(
                State(state.clone()),
                alice_headers.clone(),
                Path("invalid-tok".into()),
            )
            .await;
            assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let limited_accept =
            accept_invite(State(state), alice_headers, Path("invalid-tok".into())).await;
        assert_eq!(limited_accept.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn accept_friend_rejects_blocked_and_unblock_does_not_refriend() {
        let (_fix, state) = Fixture::new().await;
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(id)
                .bind(id)
                .execute(&state.db)
                .await
                .unwrap();
        }
        let alice_headers = auth_headers(&state.db, "alice").await;
        let bob_headers = auth_headers(&state.db, "bob").await;

        // Pending friend request + block -> accept_friend must reject and not insert friendship.
        sqlx::query(
            "INSERT INTO friend_requests(from_id,to_id,created_at) VALUES('alice','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blocks(blocker_id,blocked_id,created_at) VALUES('alice','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let resp = accept_friend(
            State(state.clone()),
            bob_headers.clone(),
            Json(json!({"username": "alice"})),
        )
        .await;
        assert!(!resp.status().is_success());
        assert!(!are_friends(&state.db, "alice", "bob").await.unwrap());

        // Clear block/requests, make them friends, block, then unblock -> must NOT re-friend.
        sqlx::query("DELETE FROM blocks")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM friend_requests")
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO friendships(user_a,user_b,created_at) VALUES('alice','bob','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let blk = block_user(
            State(state.clone()),
            alice_headers.clone(),
            Json(json!({"username": "bob"})),
        )
        .await;
        assert_eq!(blk.status(), StatusCode::OK);
        let unblk = unblock_user(
            State(state.clone()),
            alice_headers,
            Json(json!({"username": "bob"})),
        )
        .await;
        assert_eq!(unblk.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(unblk.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["friends"], false);
        assert!(!are_friends(&state.db, "alice", "bob").await.unwrap());
    }

    #[tokio::test]
    async fn user_profile_requires_non_hidden_chat_for_can_see() {
        let (_fix, state) = Fixture::new().await;
        let seen = now();
        for id in ["alice", "bob"] {
            sqlx::query(
                "INSERT INTO users(id,username,status_text,last_seen,show_last_seen) VALUES(?,?,'secret-status',?,1)",
            )
            .bind(id)
            .bind(id)
            .bind(&seen)
            .execute(&state.db)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES('dm1','dm','alice:bob','now','now')",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at,hidden) VALUES('dm1','alice','member','now',1),('dm1','bob','member','now',0)",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let alice_headers = auth_headers(&state.db, "alice").await;
        let resp = user_profile(State(state), alice_headers, Path("bob".into())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert!(body["user"]["status"].is_null());
        assert!(body["presence"].is_null());
    }
}
