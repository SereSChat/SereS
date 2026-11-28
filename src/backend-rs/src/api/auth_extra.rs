use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth, state::AppState};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, Webauthn, WebauthnBuilder,
};

const MAX_2FA_ATTEMPTS: i64 = 5;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/recovery/codes",
            get(recovery_status).post(replace_recovery_codes),
        )
        .route("/api/recovery/prelogin", post(recovery_prelogin))
        .route("/api/recovery/unlock", post(recovery_unlock))
        .route("/api/recovery/reset", post(recovery_reset))
        .route("/api/2fa", get(twofa_status))
        .route("/api/2fa/totp/setup", post(totp_setup))
        .route("/api/2fa/totp/enable", post(totp_enable))
        .route("/api/2fa/totp/disable", post(totp_disable))
        .route("/api/2fa/passkeys/options", post(passkey_register_options))
        .route("/api/2fa/passkeys/register", post(passkey_register))
        .route("/api/2fa/passkeys/delete", post(passkey_delete))
        .route("/api/login/2fa/options", post(login_passkey_options))
        .route("/api/login/2fa", post(login_second_factor))
}

fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
fn now() -> String {
    auth::now_iso()
}
fn slot_valid(slot: &str) -> bool {
    slot.len() == 4
        && slot.bytes().all(|b| {
            (b.is_ascii_uppercase() && !matches!(b, b'I' | b'O')) || (b'2'..=b'9').contains(&b)
        })
}
fn verify_hash(stored: Option<&str>, candidate: &str) -> bool {
    auth::verify_password(stored, candidate)
}

async fn recovery_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let user = match auth::require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    match sqlx::query("SELECT COUNT(*) total,COALESCE(SUM(used_at IS NULL),0) unused,MAX(created_at) created_at FROM recovery_codes WHERE user_id=?").bind(id).fetch_one(&state.db).await{Ok(row)=>json_ok(json!({"total":row.try_get::<i64,_>("total").unwrap_or(0),"unused":row.try_get::<i64,_>("unused").unwrap_or(0),"created_at":row.try_get::<Option<String>,_>("created_at").ok().flatten()})).into_response(),Err(_)=>db_error()}
}

/// One backup code as sent by the browser: (slot, kdf_salt, auth_hash, enc_private).
pub(crate) type RecoveryCode = (String, String, String, String);

/// Checks the ten backup codes of a request body.
pub(crate) fn validate_recovery_codes(codes: Option<&Value>) -> ApiResult<Vec<RecoveryCode>> {
    let bad = |message: &str| ApiError::new(message, StatusCode::BAD_REQUEST);
    let codes = codes
        .and_then(Value::as_array)
        .filter(|codes| codes.len() == 10)
        .ok_or_else(|| bad("Exactly 10 codes are needed"))?;
    let mut seen = std::collections::HashSet::new();
    let mut validated = Vec::with_capacity(codes.len());
    for code in codes {
        let slot = code
            .get("slot")
            .and_then(Value::as_str)
            .filter(|slot| slot_valid(slot))
            .ok_or_else(|| bad("Invalid code slot"))?;
        let salt = code.get("kdf_salt").and_then(Value::as_str);
        let hash = code.get("auth_hash").and_then(Value::as_str);
        let enc = code.get("enc_private").and_then(Value::as_str);
        let (Some(salt), Some(hash), Some(enc)) = (salt, hash, enc) else {
            return Err(bad("Invalid code"));
        };
        if !(salt.len() <= 64 && valid_b64(salt))
            || !(hash.len() <= 128 && valid_b64(hash))
            || enc.is_empty()
            || enc.len() > 8192
        {
            return Err(bad("Invalid code"));
        }
        if !seen.insert(slot.to_string()) {
            return Err(bad("Code slots must be different"));
        }
        validated.push((
            slot.to_string(),
            salt.to_string(),
            hash.to_string(),
            enc.to_string(),
        ));
    }
    Ok(validated)
}

async fn replace_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match auth::require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let Some(old_hash) = body
        .get("old_auth_hash")
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 128 && valid_b64(v))
    else {
        return error(
            "Invalid encoding of 'old_auth_hash'",
            StatusCode::BAD_REQUEST,
        );
    };
    let validated = match validate_recovery_codes(body.get("codes")) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if state.rate_limited(format!("recovery-codes:{user_id}"), 5, 300) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let stored = user.try_get::<Option<String>, _>("passwd").ok().flatten();
    if !auth::verify_password(stored.as_deref(), old_hash) {
        return error("Password is wrong", StatusCode::BAD_REQUEST);
    }
    // Hash all ten codes in parallel before the transaction starts, so the
    // write lock is not held while Argon2 runs.
    let hashes: Vec<_> = {
        let inputs: Vec<&str> = validated.iter().map(|(_, _, h, _)| h.as_str()).collect();
        auth::hash_passwords(&inputs)
    };
    let mut hashed_codes = Vec::with_capacity(validated.len());
    for ((slot, salt, _, enc), hashed) in validated.into_iter().zip(hashes) {
        match hashed {
            Ok(v) => hashed_codes.push((slot, salt, v, enc)),
            Err(e) => return axum::response::IntoResponse::into_response(e),
        }
    }
    let created = now();
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM recovery_codes WHERE user_id=?")
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return db_error();
    }
    for (slot, salt, hashed, enc) in hashed_codes {
        if sqlx::query("INSERT INTO recovery_codes(user_id,slot,kdf_salt,auth_hash,enc_private,created_at) VALUES(?,?,?,?,?,?)").bind(&user_id).bind(slot).bind(salt).bind(hashed).bind(enc).bind(&created).execute(&mut *tx).await.is_err(){return db_error()}
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({"total":10,"unused":10,"created_at":created})).into_response()
}

async fn find_recovery(
    pool: &SqlitePool,
    body: &Value,
) -> Result<Option<(SqliteRow, SqliteRow)>, sqlx::Error> {
    let name = body
        .get("nameomail")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let slot = body
        .get("slot")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    if !slot_valid(&slot) {
        return Ok(None);
    }
    let col = if name.contains('@') {
        "email"
    } else {
        "username"
    };
    let query = format!("SELECT * FROM users WHERE {col}=? COLLATE NOCASE");
    let Some(user) = sqlx::query(&query).bind(name).fetch_optional(pool).await? else {
        return Ok(None);
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let code =
        sqlx::query("SELECT * FROM recovery_codes WHERE user_id=? AND slot=? AND used_at IS NULL")
            .bind(user_id)
            .bind(slot)
            .fetch_optional(pool)
            .await?;
    Ok(code.map(|code| (user, code)))
}
fn recovery_limited(state: &AppState, headers: &HeaderMap, peer: SocketAddr, body: &Value) -> bool {
    let account = body
        .get("nameomail")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let ip = super::client_ip(headers, peer);
    // Per account per address, plus a looser limit per account, so strangers
    // can't block the owner's way back in with backup codes.
    state.rate_limited(format!("recovery-ip:{ip}"), 20, 900)
        || state.rate_limited(format!("recovery-account:{account}:{ip}"), 10, 900)
        || state.rate_limited(format!("recovery-account:{account}"), 60, 3600)
}
async fn recovery_prelogin(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    if recovery_limited(&state, &headers, peer, &body) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    match find_recovery(&state.db, &body).await {
        Ok(Some((_, code))) => {
            json_ok(json!({"kdf_salt":code.try_get::<String,_>("kdf_salt").unwrap_or_default()}))
                .into_response()
        }
        Ok(None) => {
            let name = body.get("nameomail").and_then(Value::as_str).unwrap_or("");
            let slot = body.get("slot").and_then(Value::as_str).unwrap_or("");
            match auth::fake_salt(&state, &format!("recovery|{name}|{slot}")).await {
                Ok(v) => json_ok(json!({"kdf_salt":v})).into_response(),
                Err(e) => axum::response::IntoResponse::into_response(e),
            }
        }
        Err(_) => db_error(),
    }
}
async fn verified_recovery(state: &AppState, body: &Value) -> Option<(SqliteRow, SqliteRow)> {
    let auth_hash = body.get("auth_hash").and_then(Value::as_str).unwrap_or("");
    let found = find_recovery(&state.db, body).await.ok().flatten();
    match found {
        Some((user, code)) => {
            let hash: Option<String> = code.try_get("auth_hash").ok();
            if !verify_hash(hash.as_deref(), auth_hash) {
                None
            } else {
                Some((user, code))
            }
        }
        None => {
            let _ = auth::verify_password(None, auth_hash);
            None
        }
    }
}
async fn recovery_unlock(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    if recovery_limited(&state, &headers, peer, &body) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    match verified_recovery(&state,&body).await{Some((user,code))=>json_ok(json!({"enc_private":code.try_get::<String,_>("enc_private").unwrap_or_default(),"pub_ecdh":user.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":user.try_get::<Option<String>,_>("pub_sign").ok().flatten()})).into_response(),None=>error("Username or backup code is wrong",StatusCode::BAD_REQUEST)}
}
async fn recovery_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    if recovery_limited(&state, &headers, peer, &body) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let Some((user, code)) = verified_recovery(&state, &body).await else {
        return error("Username or backup code is wrong", StatusCode::BAD_REQUEST);
    };
    let Some(new_hash) = body
        .get("new_auth_hash")
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 128 && valid_b64(v))
    else {
        return error(
            "Invalid encoding of 'new_auth_hash'",
            StatusCode::BAD_REQUEST,
        );
    };
    let (salt, iterations) = match auth::validate_kdf(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(enc) = body
        .get("enc_private")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 8192)
    else {
        return error("Missing or invalid 'enc_private'", StatusCode::BAD_REQUEST);
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let slot: String = code.try_get("slot").unwrap_or_default();
    let hashed = match auth::hash_password(new_hash) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let used = sqlx::query(
        "UPDATE recovery_codes SET used_at=? WHERE user_id=? AND slot=? AND used_at IS NULL",
    )
    .bind(now())
    .bind(&user_id)
    .bind(slot)
    .execute(&mut *tx)
    .await;
    match used {
        Ok(r) if r.rows_affected() > 0 => {}
        Ok(_) => return error("Username or backup code is wrong", StatusCode::BAD_REQUEST),
        Err(_) => return db_error(),
    }
    if sqlx::query("UPDATE users SET passwd=?,kdf_salt=?,kdf_iterations=?,enc_private=? WHERE id=?")
        .bind(hashed)
        .bind(salt)
        .bind(iterations)
        .bind(enc)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("DELETE FROM user_sessions WHERE user_id=?")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || sqlx::query("DELETE FROM device_links WHERE user_id=?")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || sqlx::query("DELETE FROM password_resets WHERE user_id=?")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || sqlx::query("DELETE FROM twofa_challenges WHERE user_id=?")
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    auth::login_response(&state, &user_id, &headers).await
}

async fn twofa_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let user = match auth::require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    let rows = sqlx::query(
        "SELECT id,name,created_at,last_used_at FROM passkeys WHERE user_id=? ORDER BY created_at",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await;
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let totp = user
        .try_get::<Option<String>, _>("totp_secret")
        .ok()
        .flatten()
        .is_some();
    json_ok(json!({"enabled":totp||!rows.is_empty(),"totp":totp,"passkeys":rows.iter().map(|r|json!({"id":r.try_get::<String,_>("id").unwrap_or_default(),"name":r.try_get::<String,_>("name").unwrap_or_default(),"created_at":r.try_get::<String,_>("created_at").unwrap_or_default(),"last_used_at":r.try_get::<Option<String>,_>("last_used_at").ok().flatten()})).collect::<Vec<_>>()})).into_response()
}

async fn totp_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_password(&state, &headers, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = BASE32_NOPAD.encode(&bytes);
    if sqlx::query("UPDATE users SET totp_pending=? WHERE id=?")
        .bind(&secret)
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
        .is_err()
    {
        return db_error();
    }
    let username: String = user.try_get("username").unwrap_or_default();
    json_ok(json!({"secret":secret,"uri":format!("otpauth://totp/SereS:{}?secret={}&issuer=SereS&digits=6&period=30",username,secret)})).into_response()
}
async fn totp_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match auth::require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    if state.rate_limited(format!("totp-enable:{id}"), 10, 300) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let pending = user
        .try_get::<Option<String>, _>("totp_pending")
        .ok()
        .flatten();
    let code = body.get("code").and_then(Value::as_str);
    let Some(step) = pending.as_deref().and_then(|s| verify_totp(s, code, 0)) else {
        return error(
            "The code is wrong. Check the time on your phone and try again.",
            StatusCode::BAD_REQUEST,
        );
    };
    if sqlx::query(
        "UPDATE users SET totp_secret=totp_pending,totp_pending=NULL,totp_last_step=? WHERE id=?",
    )
    .bind(step)
    .bind(id)
    .execute(&state.db)
    .await
    .is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Authenticator app enabled"})).into_response()
}
async fn totp_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_password(&state, &headers, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if sqlx::query(
        "UPDATE users SET totp_secret=NULL,totp_pending=NULL,totp_last_step=0 WHERE id=?",
    )
    .bind(user.try_get::<String, _>("id").unwrap_or_default())
    .execute(&state.db)
    .await
    .is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Authenticator app removed"})).into_response()
}

async fn require_password(
    state: &AppState,
    headers: &HeaderMap,
    body: &Value,
) -> ApiResult<SqliteRow> {
    let user = auth::require_user(state, headers).await?;
    let id: String = user.try_get("id").unwrap_or_default();
    let Some(hash) = body.get("old_auth_hash").and_then(Value::as_str) else {
        return Err(ApiError::new(
            "Missing or invalid 'old_auth_hash'",
            StatusCode::BAD_REQUEST,
        ));
    };
    if state.rate_limited(format!("twofa-password:{id}"), 10, 300) {
        return Err(ApiError::new(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    let stored = user.try_get::<Option<String>, _>("passwd").ok().flatten();
    if !auth::verify_password(stored.as_deref(), hash) {
        return Err(ApiError::new("Password is wrong", StatusCode::BAD_REQUEST));
    }
    Ok(user)
}

fn verify_totp(secret: &str, code: Option<&str>, last_step: i64) -> Option<i64> {
    let code = code?.replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secret = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    let step = chrono::Utc::now().timestamp() / 30;
    for candidate in (step - 1)..=(step + 1) {
        if candidate <= last_step {
            continue;
        }
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret).ok()?;
        mac.update(&(candidate as u64).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 15) as usize;
        let value = ((u32::from(digest[offset] & 127) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]))
            % 1_000_000;
        let generated = format!("{value:06}");
        if generated.as_bytes().ct_eq(code.as_bytes()).unwrap_u8() == 1 {
            return Some(candidate);
        }
    }
    None
}
fn valid_b64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let unpadded = value.trim_end_matches('=');
    value.len() - unpadded.len() <= 2
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b))
}

async fn passkey_register_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_password(&state, &headers, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let rows =
        match sqlx::query("SELECT public_key FROM passkeys WHERE user_id=? ORDER BY created_at")
            .bind(&user_id)
            .fetch_all(&state.db)
            .await
        {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
    if rows.len() >= 10 {
        return error("You can add at most 10 passkeys", StatusCode::BAD_REQUEST);
    }
    let mut excludes = Vec::new();
    for row in rows {
        if let Ok(key) = serde_json::from_str::<Passkey>(
            &row.try_get::<String, _>("public_key").unwrap_or_default(),
        ) {
            excludes.push(key.cred_id().clone())
        }
    }
    let webauthn = match webauthn_for(&headers) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let uid = match Uuid::parse_str(&user_id) {
        Ok(v) => v,
        Err(_) => {
            return error(
                "Account identifier is invalid",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    let username: String = user.try_get("username").unwrap_or_default();
    let display = user
        .try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| username.clone());
    let (options, registration) =
        match webauthn.start_passkey_registration(uid, &username, &display, Some(excludes)) {
            Ok(v) => v,
            Err(_) => {
                return error(
                    "Could not start passkey registration",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };
    let registration_state = match serde_json::to_string(&registration) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let token = match new_challenge(&state.db, &user_id, "register", registration_state).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match serde_json::to_value(options) {
        Ok(options) => json_ok(json!({"token":token,"options":options})).into_response(),
        Err(_) => db_error(),
    }
}

async fn passkey_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match auth::require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let token = body.get("token").and_then(Value::as_str).unwrap_or("");
    let pending = match find_challenge(&state.db, token, "register").await {
        Ok(Some(v))
            if v.try_get::<String, _>("user_id").ok().as_deref() == Some(user_id.as_str()) =>
        {
            v
        }
        Ok(_) => {
            return error(
                "The request expired, please try again",
                StatusCode::BAD_REQUEST,
            );
        }
        Err(_) => return db_error(),
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let name = name.chars().take(40).collect::<String>();
    let name = if name.is_empty() {
        "Passkey".to_owned()
    } else {
        name
    };
    let Some(credential_value) = body.get("credential").cloned() else {
        return error("The passkey could not be verified", StatusCode::BAD_REQUEST);
    };
    let credential = match serde_json::from_value::<webauthn_rs::prelude::RegisterPublicKeyCredential>(
        credential_value.clone(),
    ) {
        Ok(v) => v,
        Err(_) => return error("The passkey could not be verified", StatusCode::BAD_REQUEST),
    };
    let state_json: String = pending.try_get("challenge").unwrap_or_default();
    let registration = match serde_json::from_str::<PasskeyRegistration>(&state_json) {
        Ok(v) => v,
        Err(_) => {
            return error(
                "The request expired, please try again",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let webauthn = match webauthn_for(&headers) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let passkey = match webauthn.finish_passkey_registration(&credential, &registration) {
        Ok(v) => v,
        Err(_) => return error("The passkey could not be verified", StatusCode::BAD_REQUEST),
    };
    let Some(id) = credential_value
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 1024)
    else {
        return error("The passkey could not be verified", StatusCode::BAD_REQUEST);
    };
    let public_key = match serde_json::to_string(&passkey) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let transports = credential_value
        .get("response")
        .and_then(|v| v.get("transports"))
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .take(8)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let transports = serde_json::to_string(&transports).unwrap_or_else(|_| "[]".into());
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM twofa_challenges WHERE token_hash=?")
        .bind(auth::hash_token(token))
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return db_error();
    }
    let result=sqlx::query("INSERT INTO passkeys(id,user_id,public_key,sign_count,transports,name,created_at) VALUES(?,?,?,0,?,?,?)").bind(id).bind(user_id).bind(public_key).bind(transports).bind(name).bind(now()).execute(&mut *tx).await;
    match result {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return error(
                "This passkey is already registered",
                StatusCode::BAD_REQUEST,
            );
        }
        Err(_) => return db_error(),
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({"message":"Passkey added"})).into_response()
}

async fn passkey_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_password(&state, &headers, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let id = body
        .get("id")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string())
        })
        .unwrap_or_default();
    match sqlx::query("DELETE FROM passkeys WHERE id=? AND user_id=?")
        .bind(id)
        .bind(user_id)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            json_ok(json!({"message":"Passkey removed"})).into_response()
        }
        Ok(_) => error("Passkey not found", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}

async fn login_passkey_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let token = body.get("token").and_then(Value::as_str).unwrap_or("");
    let pending = match find_challenge(&state.db, token, "login").await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error(
                "The login expired, please log in again",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(_) => return db_error(),
    };
    let user_id: String = pending.try_get("user_id").unwrap_or_default();
    let passkeys = match load_passkeys(&state.db, &user_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let webauthn = match webauthn_for(&headers) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (options, auth_state) = match webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(_) => return error("No passkeys are available", StatusCode::BAD_REQUEST),
    };
    let state_json = match serde_json::to_string(&auth_state) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("UPDATE twofa_challenges SET challenge=? WHERE token_hash=?")
        .bind(state_json)
        .bind(auth::hash_token(token))
        .execute(&state.db)
        .await
        .is_err()
    {
        return db_error();
    }
    match serde_json::to_value(options) {
        Ok(options) => json_ok(json!({"options":options})).into_response(),
        Err(_) => db_error(),
    }
}

async fn login_second_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    if state.rate_limited(
        format!("login-2fa:{}", super::client_ip(&headers, peer)),
        30,
        300,
    ) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let token = body.get("token").and_then(Value::as_str).unwrap_or("");
    let pending = match find_challenge(&state.db, token, "login").await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error(
                "The login expired, please log in again",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(_) => return db_error(),
    };
    let user_id: String = pending.try_get("user_id").unwrap_or_default();
    // Per account too, so guesses spread over many addresses stay rare.
    if state.rate_limited(format!("login-2fa-user:{user_id}"), 20, 3600) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let user = match sqlx::query("SELECT * FROM users WHERE id=?")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error(
                "The login expired, please log in again",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(_) => return db_error(),
    };
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let mut totp_step = None;
    let mut recovery_slot = None;
    let mut passkey_update = None;
    let valid = match method {
        "totp" => {
            let secret = user
                .try_get::<Option<String>, _>("totp_secret")
                .ok()
                .flatten();
            let last = user.try_get::<i64, _>("totp_last_step").unwrap_or(0);
            totp_step = secret
                .as_deref()
                .and_then(|v| verify_totp(v, body.get("code").and_then(Value::as_str), last));
            totp_step.is_some()
        }
        "backup" => {
            let slot = body
                .get("slot")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_uppercase();
            let candidate = body.get("auth_hash").and_then(Value::as_str).unwrap_or("");
            if !slot_valid(&slot) || candidate.is_empty() {
                false
            } else {
                match sqlx::query("SELECT auth_hash FROM recovery_codes WHERE user_id=? AND slot=? AND used_at IS NULL").bind(&user_id).bind(&slot).fetch_optional(&state.db).await{Ok(Some(row))=>{let stored=row.try_get::<String,_>("auth_hash").ok();if verify_hash(stored.as_deref(),candidate){recovery_slot=Some(slot);true}else{false}},_=>{let _=auth::verify_password(None,candidate);false}}
            }
        }
        "passkey" => {
            let challenge: String = pending.try_get("challenge").unwrap_or_default();
            let auth_state = serde_json::from_str::<PasskeyAuthentication>(&challenge);
            let credential_value = body.get("credential").cloned();
            match (auth_state, credential_value) {
                (Ok(auth_state), Some(value)) => match serde_json::from_value::<
                    webauthn_rs::prelude::PublicKeyCredential,
                >(value.clone())
                {
                    Ok(credential) => {
                        let passkeys = match load_passkeys(&state.db, &user_id).await {
                            Ok(v) => v,
                            Err(_) => return db_error(),
                        };
                        let selected = value.get("id").and_then(Value::as_str).unwrap_or("");
                        let Some(mut key) = passkeys
                            .into_iter()
                            .find(|v| URL_SAFE_NO_PAD.encode(v.cred_id().as_ref()) == selected)
                        else {
                            return invalid_second_factor(&state, &pending).await;
                        };
                        let webauthn = match webauthn_for(&headers) {
                            Ok(v) => v,
                            Err(e) => return axum::response::IntoResponse::into_response(e),
                        };
                        match webauthn.finish_passkey_authentication(&credential, &auth_state) {
                            Ok(result) => {
                                let serialized = serde_json::to_string(&key).unwrap_or_default();
                                let _ = key.update_credential(&result);
                                let serialized = serde_json::to_string(&key).unwrap_or(serialized);
                                passkey_update = Some((
                                    selected.to_owned(),
                                    serialized,
                                    i64::from(result.counter()),
                                ));
                                true
                            }
                            Err(_) => false,
                        }
                    }
                    Err(_) => false,
                },
                _ => false,
            }
        }
        _ => return error("Unknown method", StatusCode::BAD_REQUEST),
    };
    if !valid {
        return invalid_second_factor(&state, &pending).await;
    }
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if let Some(step) = totp_step {
        match sqlx::query("UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?")
            .bind(step)
            .bind(&user_id)
            .bind(step)
            .execute(&mut *tx)
            .await
        {
            Ok(v) if v.rows_affected() == 1 => {}
            _ => {
                drop(tx);
                return invalid_second_factor(&state, &pending).await;
            }
        }
    }
    if let Some(slot) = recovery_slot {
        match sqlx::query(
            "UPDATE recovery_codes SET used_at=? WHERE user_id=? AND slot=? AND used_at IS NULL",
        )
        .bind(now())
        .bind(&user_id)
        .bind(slot)
        .execute(&mut *tx)
        .await
        {
            Ok(v) if v.rows_affected() == 1 => {}
            _ => {
                drop(tx);
                return invalid_second_factor(&state, &pending).await;
            }
        }
    }
    if let Some((id, serialized, count)) = passkey_update
        && sqlx::query(
            "UPDATE passkeys SET public_key=?,sign_count=?,last_used_at=? WHERE id=? AND user_id=?",
        )
        .bind(serialized)
        .bind(count)
        .bind(now())
        .bind(id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return db_error();
    }
    let deleted = sqlx::query("DELETE FROM twofa_challenges WHERE token_hash=?")
        .bind(auth::hash_token(token))
        .execute(&mut *tx)
        .await;
    match deleted {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            let _ = tx.rollback().await;
            return error(
                "The login expired, please log in again",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(_) => return db_error(),
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    auth::login_response(&state, &user_id, &headers).await
}

async fn invalid_second_factor(state: &AppState, pending: &SqliteRow) -> axum::response::Response {
    let hash: String = pending.try_get("token_hash").unwrap_or_default();
    let updated = sqlx::query_scalar::<_, i64>(
        "UPDATE twofa_challenges SET attempts = attempts + 1 WHERE token_hash=? RETURNING attempts",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await;
    match updated {
        Ok(Some(attempts)) if attempts >= MAX_2FA_ATTEMPTS => {
            let _ = sqlx::query("DELETE FROM twofa_challenges WHERE token_hash=?")
                .bind(&hash)
                .execute(&state.db)
                .await;
            error(
                "Too many wrong attempts, please log in again",
                StatusCode::UNAUTHORIZED,
            )
        }
        Ok(Some(_)) => error("The code or passkey is wrong", StatusCode::BAD_REQUEST),
        Ok(None) => error(
            "The login expired, please log in again",
            StatusCode::UNAUTHORIZED,
        ),
        Err(_) => db_error(),
    }
}

async fn load_passkeys(pool: &SqlitePool, user: &str) -> Result<Vec<Passkey>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,public_key,sign_count FROM passkeys WHERE user_id=? ORDER BY created_at",
    )
    .bind(user)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().filter_map(load_passkey).collect())
}

fn load_passkey(row: &SqliteRow) -> Option<Passkey> {
    let stored = row.try_get::<String, _>("public_key").ok()?;
    if let Ok(passkey) = serde_json::from_str::<Passkey>(&stored) {
        return Some(passkey);
    }

    // The Flask backend stored WebAuthn's COSE public key as base64url. Rebuild
    // a legacy credential so accounts with existing passkeys continue to work.
    let id = row.try_get::<String, _>("id").ok()?;
    let credential_id = URL_SAFE_NO_PAD.decode(id).ok()?;
    let cose_bytes = URL_SAFE_NO_PAD.decode(stored).ok()?;
    let cose_key = serde_cbor_2::from_slice::<webauthn_rs::prelude::COSEKey>(&cose_bytes).ok()?;
    let counter = row.try_get::<i64, _>("sign_count").ok()?.try_into().ok()?;
    let legacy = webauthn_rs_core::proto::CredentialV3 {
        cred_id: credential_id,
        cred: cose_key,
        counter,
        verified: false,
        registration_policy: webauthn_rs_core::proto::UserVerificationPolicy::Preferred,
    };
    let credential: webauthn_rs_core::proto::Credential = legacy.into();
    let serialized = serde_json::to_value(credential).ok()?;
    serde_json::from_value::<Passkey>(json!({"cred":serialized})).ok()
}
async fn new_challenge(
    pool: &SqlitePool,
    user: &str,
    purpose: &str,
    challenge_state: String,
) -> Result<String, sqlx::Error> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    sqlx::query("INSERT INTO twofa_challenges(token_hash,user_id,purpose,challenge,attempts,expires_at) VALUES(?,?,?,?,0,?)").bind(auth::hash_token(&token)).bind(user).bind(purpose).bind(challenge_state).bind(expires).execute(pool).await?;
    sqlx::query("DELETE FROM twofa_challenges WHERE expires_at<?")
        .bind(now())
        .execute(pool)
        .await?;
    Ok(token)
}
async fn find_challenge(
    pool: &SqlitePool,
    token: &str,
    purpose: &str,
) -> Result<Option<SqliteRow>, sqlx::Error> {
    if token.is_empty() || token.len() > 100 {
        return Ok(None);
    }
    sqlx::query("SELECT * FROM twofa_challenges WHERE token_hash=? AND purpose=? AND expires_at>?")
        .bind(auth::hash_token(token))
        .bind(purpose)
        .bind(now())
        .fetch_optional(pool)
        .await
}

fn webauthn_for(headers: &HeaderMap) -> ApiResult<Webauthn> {
    webauthn_for_with(
        headers,
        std::env::var("PUBLIC_URL").ok().as_deref(),
        std::env::var("WEBAUTHN_RP_ID").ok().as_deref(),
        std::env::var("SERES_ALLOWED_HOSTS").ok().as_deref(),
    )
}

fn webauthn_origins_and_rp(
    headers: &HeaderMap,
    public_url: Option<&str>,
    rp_id_env: Option<&str>,
    allowed_hosts_env: Option<&str>,
) -> ApiResult<(String, Vec<url::Url>)> {
    let has_public = public_url.is_some_and(|v| !v.trim().is_empty());
    let public = if has_public {
        let raw = public_url.unwrap_or_default().trim();
        let mut parsed = url::Url::parse(raw)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| {
                ApiError::new(
                    "WebAuthn configuration is invalid",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        parsed.set_path("/");
        parsed.set_query(None);
        parsed.set_fragment(None);
        Some(parsed)
    } else {
        None
    };

    let has_allowed = allowed_hosts_env.is_some_and(|v| !v.trim().is_empty());
    let extra_hosts: Vec<String> = allowed_hosts_env
        .map(|v| {
            v.split(',')
                .filter_map(super::normalize_host_port)
                .collect()
        })
        .unwrap_or_default();
    if has_allowed && extra_hosts.is_empty() {
        return Err(ApiError::new(
            "WebAuthn configuration is invalid",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let mut origins = Vec::new();
    if has_public || has_allowed {
        if let Some(url) = public.as_ref() {
            origins.push(url.clone());
        }
        for host in extra_hosts {
            let scheme = if super::is_loopback_host(&host) {
                if public.as_ref().is_some_and(|u| u.scheme() == "http")
                    || (public.is_none() && !super::is_https_with(headers, public_url))
                {
                    "http"
                } else {
                    "https"
                }
            } else {
                "https"
            };
            if let Ok(mut origin) = url::Url::parse(&format!("{scheme}://{host}")) {
                origin.set_path("/");
                origin.set_query(None);
                origin.set_fragment(None);
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
        }
    } else {
        let host = super::first_header_host(headers, "x-forwarded-host")
            .or_else(|| super::first_header_host(headers, "host"));
        let host = match host {
            Some(h) if super::is_loopback_host(&h) => h,
            Some(_) => {
                return Err(ApiError::new(
                    "WebAuthn origin is not configured",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
            None => {
                if headers.contains_key("x-forwarded-host")
                    || headers.contains_key(axum::http::header::HOST)
                {
                    return Err(ApiError::new(
                        "WebAuthn origin is not configured",
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                }
                "localhost".to_owned()
            }
        };
        let scheme = if super::is_https_with(headers, public_url) {
            "https"
        } else {
            "http"
        };
        let mut origin = url::Url::parse(&format!("{scheme}://{host}")).map_err(|_| {
            ApiError::new(
                "WebAuthn configuration is invalid",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        origins.push(origin);
    }

    if origins.is_empty() {
        return Err(ApiError::new(
            "WebAuthn origin is not configured",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let rp_id = rp_id_env
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            public
                .as_ref()
                .and_then(|v| v.host_str().map(str::to_owned))
        })
        .or_else(|| {
            origins
                .first()
                .and_then(|v| v.host_str().map(str::to_owned))
        })
        .unwrap_or_else(|| "localhost".into());

    Ok((rp_id, origins))
}

fn webauthn_for_with(
    headers: &HeaderMap,
    public_url: Option<&str>,
    rp_id_env: Option<&str>,
    allowed_hosts_env: Option<&str>,
) -> ApiResult<Webauthn> {
    let (rp_id, origins) =
        webauthn_origins_and_rp(headers, public_url, rp_id_env, allowed_hosts_env)?;
    let Some(origin) = origins.first() else {
        return Err(ApiError::new(
            "WebAuthn origin is not configured",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    };
    let mut builder = WebauthnBuilder::new(&rp_id, origin).map_err(|_| {
        ApiError::new(
            "WebAuthn configuration is invalid",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;
    for allowed in origins.iter().skip(1) {
        builder = builder.append_allowed_origin(allowed)
    }
    builder.rp_name("SereS").build().map_err(|_| {
        ApiError::new(
            "WebAuthn configuration is invalid",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    async fn test_state() -> (AppState, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("seres-auth-extra-test-{}.db", Uuid::new_v4()));
        let pool = crate::db::connect(&path).await.unwrap();
        (AppState::new(pool), path)
    }

    fn current_totp_code(secret: &str) -> String {
        let secret = BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
        let step = chrono::Utc::now().timestamp() / 30;
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret).unwrap();
        mac.update(&(step as u64).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = (digest[19] & 15) as usize;
        let value = ((u32::from(digest[offset] & 127) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]))
            % 1_000_000;
        format!("{value:06}")
    }

    #[test]
    fn webauthn_origins_ignore_untrusted_headers_and_never_append_http() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.example".parse().unwrap());
        headers.insert("x-forwarded-host", "attacker.example".parse().unwrap());

        let (rp, origins) =
            webauthn_origins_and_rp(&headers, Some("https://chat.example"), None, None).unwrap();
        assert_eq!(rp, "chat.example");
        assert_eq!(
            origins.iter().map(|u| u.as_str()).collect::<Vec<_>>(),
            vec!["https://chat.example/"]
        );
        assert!(webauthn_for_with(&headers, Some("https://chat.example"), None, None).is_ok());

        let (_, origins) = webauthn_origins_and_rp(
            &headers,
            Some("https://chat.example"),
            None,
            Some("alt.example:8443"),
        )
        .unwrap();
        assert_eq!(
            origins.iter().map(|u| u.as_str()).collect::<Vec<_>>(),
            vec!["https://chat.example/", "https://alt.example:8443/"]
        );

        assert!(webauthn_origins_and_rp(&headers, None, None, None).is_err());

        let mut local_headers = HeaderMap::new();
        local_headers.insert("host", "localhost:2222".parse().unwrap());
        let (rp, origins) = webauthn_origins_and_rp(&local_headers, None, None, None).unwrap();
        assert_eq!(rp, "localhost");
        assert_eq!(
            origins.iter().map(|u| u.as_str()).collect::<Vec<_>>(),
            vec!["http://localhost:2222/"]
        );
    }

    #[tokio::test]
    async fn invalid_second_factor_increments_atomically_and_locks_out_at_limit() {
        let (state, path) = test_state().await;
        let user_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,email,username,passwd,auth_version) VALUES(?,?,?,?,1)")
            .bind(&user_id)
            .bind("dave@example.com")
            .bind("dave")
            .bind("hash")
            .execute(&state.db)
            .await
            .unwrap();
        let token = "twofa-token-1";
        let token_hash = auth::hash_token(token);
        sqlx::query("INSERT INTO twofa_challenges(token_hash,user_id,purpose,challenge,attempts,expires_at) VALUES(?,?,'login','c',0,?)")
            .bind(&token_hash)
            .bind(&user_id)
            .bind("2099-01-01T00:00:00Z")
            .execute(&state.db)
            .await
            .unwrap();
        let row = find_challenge(&state.db, token, "login")
            .await
            .unwrap()
            .unwrap();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let st = state.clone();
            let th = token_hash.clone();
            set.spawn(async move {
                let row = sqlx::query("SELECT * FROM twofa_challenges WHERE token_hash=?")
                    .bind(&th)
                    .fetch_optional(&st.db)
                    .await
                    .unwrap();
                match row {
                    Some(r) => invalid_second_factor(&st, &r).await.status(),
                    None => StatusCode::UNAUTHORIZED,
                }
            });
        }
        let mut statuses = Vec::new();
        while let Some(res) = set.join_next().await {
            statuses.push(res.unwrap());
        }
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::BAD_REQUEST)
                .count(),
            4
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::UNAUTHORIZED)
                .count(),
            2
        );
        assert!(row.try_get::<String, _>("token_hash").is_ok());
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM twofa_challenges WHERE token_hash=?")
                .bind(&token_hash)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(remaining, 0);

        state.db.close().await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn login_second_factor_consumes_challenge_once_and_recovery_reset_clears_tokens() {
        let (state, path) = test_state().await;
        let user_id = Uuid::new_v4().to_string();
        let secret = "JBSWY3DPEHPK3PXP";
        sqlx::query("INSERT INTO users(id,email,username,passwd,auth_version,totp_secret,totp_last_step) VALUES(?,?,?,?,1,?,0)")
            .bind(&user_id)
            .bind("erin@example.com")
            .bind("erin")
            .bind("hash")
            .bind(secret)
            .execute(&state.db)
            .await
            .unwrap();

        let token = "twofa-token-single";
        sqlx::query("INSERT INTO twofa_challenges(token_hash,user_id,purpose,challenge,attempts,expires_at) VALUES(?,?,'login','c',0,?)")
            .bind(auth::hash_token(token))
            .bind(&user_id)
            .bind("2099-01-01T00:00:00Z")
            .execute(&state.db)
            .await
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let code = current_totp_code(secret);
        let res1 = login_second_factor(
            State(state.clone()),
            HeaderMap::new(),
            ConnectInfo(peer),
            Json(json!({"token": token, "method": "totp", "code": code})),
        )
        .await;
        assert_eq!(res1.status(), StatusCode::OK);
        let res2 = login_second_factor(
            State(state.clone()),
            HeaderMap::new(),
            ConnectInfo(peer),
            Json(json!({"token": token, "method": "totp", "code": code})),
        )
        .await;
        assert_eq!(res2.status(), StatusCode::UNAUTHORIZED);

        // Recovery reset clears pending password_resets and twofa_challenges.
        let code_auth = STANDARD.encode([4u8; 32]);
        let code_hash = auth::hash_password(&code_auth).unwrap();
        sqlx::query("INSERT INTO recovery_codes(user_id,slot,kdf_salt,auth_hash,enc_private,created_at) VALUES(?,?,?,?,?,?)")
            .bind(&user_id)
            .bind("ABCD")
            .bind(STANDARD.encode([5u8; 16]))
            .bind(code_hash)
            .bind("{}")
            .bind(now())
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO password_resets(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        )
        .bind("pending-reset")
        .bind(&user_id)
        .bind(now())
        .bind("2099-01-01T00:00:00Z")
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO twofa_challenges(token_hash,user_id,purpose,challenge,attempts,expires_at) VALUES(?,?,'login','c',0,?)")
            .bind("pending-2fa")
            .bind(&user_id)
            .bind("2099-01-01T00:00:00Z")
            .execute(&state.db)
            .await
            .unwrap();

        let bad_reset = recovery_reset(
            State(state.clone()),
            HeaderMap::new(),
            ConnectInfo(peer),
            Json(json!({
                "nameomail": "erin",
                "slot": "ABCD",
                "auth_hash": STANDARD.encode([9u8; 32]),
                "new_auth_hash": STANDARD.encode([6u8; 32]),
                "kdf_salt": STANDARD.encode([7u8; 16]),
                "kdf_iterations": 600_000,
                "enc_private": "{}"
            })),
        )
        .await;
        assert_eq!(bad_reset.status(), StatusCode::BAD_REQUEST);

        let good_reset = recovery_reset(
            State(state.clone()),
            HeaderMap::new(),
            ConnectInfo(peer),
            Json(json!({
                "nameomail": "erin",
                "slot": "ABCD",
                "auth_hash": code_auth,
                "new_auth_hash": STANDARD.encode([6u8; 32]),
                "kdf_salt": STANDARD.encode([7u8; 16]),
                "kdf_iterations": 600_000,
                "enc_private": "{}"
            })),
        )
        .await;
        assert_eq!(good_reset.status(), StatusCode::OK);
        let resets: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM password_resets WHERE user_id=?")
                .bind(&user_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        let challenges: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM twofa_challenges WHERE user_id=?")
                .bind(&user_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(resets, 0);
        assert_eq!(challenges, 0);

        state.db.close().await;
        let _ = std::fs::remove_file(path);
    }
}
