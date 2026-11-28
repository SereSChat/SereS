use super::client_ip;
use super::{ApiError, ApiResult, auth, error, json_ok, json_response};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use lettre::{
    Message, SmtpTransport, Transport, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sqlx::{Row, Sqlite, Transaction};
use std::net::SocketAddr;

const RESET_MINUTES: i64 = 60;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/password_reset/request", post(request_reset))
        .route("/api/password_reset/check", post(check_reset))
        .route("/api/password_reset/confirm", post(confirm_reset))
}

async fn request_reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let nameomail = match body.get("nameomail").and_then(Value::as_str) {
        Some(v) if v.chars().count() <= 254 => v.trim().to_owned(),
        _ => return error("Missing or invalid 'nameomail'", StatusCode::BAD_REQUEST),
    };
    if !mail_configured() {
        return error(
            "Password reset by e-mail is not set up on this server",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }

    let lang = body
        .get("lang")
        .and_then(Value::as_str)
        .filter(|v| matches!(*v, "en" | "de" | "fr"))
        .unwrap_or("en");
    let Some(url) = public_base_url(&headers) else {
        return error(
            "Public URL is not configured",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    };

    let ip = client_ip(&headers, peer);
    if state.rate_limited(format!("reset-ip:{ip}"), 10, 3600)
        || state.rate_limited(
            format!("reset-account:{}", nameomail.to_lowercase()),
            3,
            3600,
        )
    {
        return error(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let lookup = if nameomail.contains('@') {
        sqlx::query("SELECT * FROM users WHERE email=? COLLATE NOCASE LIMIT 1")
    } else {
        sqlx::query("SELECT * FROM users WHERE username=? COLLATE NOCASE LIMIT 1")
    };
    let user = match lookup.bind(&nameomail).fetch_optional(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if let Some(user) = user {
        let email = user.try_get::<Option<String>, _>("email").ok().flatten();
        if let Some(email) = email.filter(|v| valid_email(v)) {
            let user_id: String = user.try_get("id").unwrap_or_default();
            let token = random_token();
            let created = auth::now_iso();
            let expires = (chrono::Utc::now() + chrono::Duration::minutes(RESET_MINUTES))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let mut tx = match state.db.begin().await {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            if sqlx::query("DELETE FROM password_resets WHERE user_id=?")
                .bind(&user_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query("INSERT INTO password_resets(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)")
                    .bind(auth::hash_token(&token))
                    .bind(&user_id)
                    .bind(created)
                    .bind(expires)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || tx.commit().await.is_err()
            {
                return db_error();
            }

            let name = user
                .try_get::<Option<String>, _>("display_name")
                .ok()
                .flatten()
                .filter(|v| !v.is_empty())
                .or_else(|| user.try_get("username").ok())
                .unwrap_or_default();
            let (subject, template) = mail_copy(lang);
            let link = format!("{url}/login.html?reset={token}");
            let content = template
                .replace("{name}", &name)
                .replace("{minutes}", &RESET_MINUTES.to_string())
                .replace("{link}", &link);
            tokio::task::spawn_blocking(move || {
                if let Err(err) = send_mail(&email, subject, &content) {
                    tracing::error!(error = %err, "password reset email could not be sent");
                }
            });
        }
    }
    json_ok(json!({"message":"If the account exists, an e-mail with a link is on its way."}))
}

async fn check_reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if state.rate_limited(
        format!("reset-check:{}", client_ip(&headers, peer)),
        30,
        600,
    ) {
        return error(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let token = match reset_token(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user = match find_reset_user(&state, token).await {
        Ok(Some(v)) => v,
        Ok(None) => return invalid_link(),
        Err(_) => return db_error(),
    };
    match has_two_factor(&state, &user).await {
        Ok(true) => return two_factor_blocks_reset(),
        Ok(false) => {}
        Err(_) => return db_error(),
    }
    let username: String = user.try_get("username").unwrap_or_default();
    let display_name = user
        .try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| username.clone());
    json_ok(json!({"username":username,"display_name":display_name}))
}

async fn confirm_reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if state.rate_limited(
        format!("reset-check:{}", client_ip(&headers, peer)),
        30,
        600,
    ) {
        return error(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let token = match reset_token(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user = match find_reset_user(&state, token).await {
        Ok(Some(v)) => v,
        Ok(None) => return invalid_link(),
        Err(_) => return db_error(),
    };
    match has_two_factor(&state, &user).await {
        Ok(true) => return two_factor_blocks_reset(),
        Ok(false) => {}
        Err(_) => return db_error(),
    }
    let auth_hash = match super::b64_field(&body, "auth_hash", 128) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (kdf_salt, kdf_iterations) = match auth::validate_kdf(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (pub_ecdh, pub_sign, enc_private) = match auth::validate_keys(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let password_hash = match auth::hash_password(auth_hash) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let mut tx = match state.db.begin_with("BEGIN IMMEDIATE").await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let outcome = match complete_reset(
        &mut tx,
        ResetCredentials {
            token,
            user: &user,
            user_id: &user_id,
            password_hash: &password_hash,
            kdf_salt: &kdf_salt,
            kdf_iterations,
            pub_ecdh: &pub_ecdh,
            pub_sign: &pub_sign,
            enc_private: &enc_private,
        },
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match outcome {
        ResetOutcome::Completed => {}
        ResetOutcome::InvalidLink => {
            let _ = tx.rollback().await;
            return invalid_link();
        }
        ResetOutcome::TwoFactorBlocked => {
            let _ = tx.rollback().await;
            return two_factor_blocks_reset();
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    auth::login_response(&state, &user_id, &headers).await
}

enum ResetOutcome {
    Completed,
    InvalidLink,
    TwoFactorBlocked,
}

struct ResetCredentials<'a> {
    token: &'a str,
    user: &'a sqlx::sqlite::SqliteRow,
    user_id: &'a str,
    password_hash: &'a str,
    kdf_salt: &'a str,
    kdf_iterations: i64,
    pub_ecdh: &'a str,
    pub_sign: &'a str,
    enc_private: &'a str,
}

async fn complete_reset(
    tx: &mut Transaction<'_, Sqlite>,
    credentials: ResetCredentials<'_>,
) -> Result<ResetOutcome, sqlx::Error> {
    let ResetCredentials {
        token,
        user,
        user_id,
        password_hash,
        kdf_salt,
        kdf_iterations,
        pub_ecdh,
        pub_sign,
        enc_private,
    } = credentials;
    let current_totp: Option<String> =
        sqlx::query_scalar("SELECT totp_secret FROM users WHERE id=?")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let passkeys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id=?")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await?;
    if current_totp.is_some() || passkeys != 0 {
        return Ok(ResetOutcome::TwoFactorBlocked);
    }
    let used = sqlx::query("UPDATE password_resets SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?")
        .bind(auth::now_iso())
        .bind(auth::hash_token(token))
        .bind(auth::now_iso())
        .execute(&mut **tx)
        .await?;
    if used.rows_affected() == 0 {
        return Ok(ResetOutcome::InvalidLink);
    }
    if let (Some(old_ecdh), Some(old_sign)) = (
        user.try_get::<Option<String>, _>("pub_ecdh").ok().flatten(),
        user.try_get::<Option<String>, _>("pub_sign").ok().flatten(),
    ) {
        sqlx::query(
            "INSERT INTO user_key_history(user_id,pub_ecdh,pub_sign,replaced_at) VALUES(?,?,?,?)",
        )
        .bind(user_id)
        .bind(old_ecdh)
        .bind(old_sign)
        .bind(auth::now_iso())
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query("UPDATE users SET passwd=?,auth_version=1,kdf_salt=?,kdf_iterations=?,pub_ecdh=?,pub_sign=?,enc_private=? WHERE id=?")
        .bind(password_hash)
        .bind(kdf_salt)
        .bind(kdf_iterations)
        .bind(pub_ecdh)
        .bind(pub_sign)
        .bind(enc_private)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM device_links WHERE user_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM twofa_challenges WHERE user_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM message_key_shares WHERE recipient_id=?")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;

    let memberships = sqlx::query("SELECT chat_id,joined_seq,cleared_seq,reset_seq,reset_cleared_seq FROM chat_members WHERE user_id=?")
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await?;
    for member in memberships {
        let chat_id: String = member.try_get("chat_id")?;
        let until: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
                .bind(&chat_id)
                .fetch_one(&mut **tx)
                .await?;
        let joined: i64 = member.try_get("joined_seq")?;
        let reset: i64 = member.try_get("reset_seq")?;
        let cleared: i64 = member.try_get("cleared_seq")?;
        let reset_cleared: i64 = member.try_get("reset_cleared_seq")?;
        let before = if reset != 0 { reset_cleared } else { cleared };
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE chat_id=? AND seq>? AND seq<=? AND kind='e2e' AND deleted=0")
            .bind(&chat_id)
            .bind(joined.max(before))
            .bind(until)
            .fetch_one(&mut **tx)
            .await?;
        let waiting = if count > 0 { until } else { 0 };
        sqlx::query("UPDATE chat_members SET cleared_seq=?,reset_seq=?,reset_cleared_seq=? WHERE chat_id=? AND user_id=?")
            .bind(until)
            .bind(waiting)
            .bind(if waiting != 0 { before } else { 0 })
            .bind(&chat_id)
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
        let actor = user
            .try_get::<Option<String>, _>("display_name")
            .ok()
            .flatten()
            .filter(|v| !v.is_empty())
            .or_else(|| user.try_get("username").ok())
            .unwrap_or_default();
        super::chats::system_message(tx, &chat_id, "keys_reset", json!({"actor":actor})).await?;
    }
    Ok(ResetOutcome::Completed)
}

async fn find_reset_user(
    state: &AppState,
    token: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT u.* FROM password_resets r JOIN users u ON u.id=r.user_id WHERE r.token_hash=? AND r.used_at IS NULL AND r.expires_at>? LIMIT 1")
        .bind(auth::hash_token(token))
        .bind(auth::now_iso())
        .fetch_optional(&state.db)
        .await
}

async fn has_two_factor(
    state: &AppState,
    user: &sqlx::sqlite::SqliteRow,
) -> Result<bool, sqlx::Error> {
    let id: String = user.try_get("id").unwrap_or_default();
    let totp = user
        .try_get::<Option<String>, _>("totp_secret")
        .ok()
        .flatten()
        .is_some();
    let passkey: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id=?")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    Ok(totp || passkey != 0)
}

fn reset_token(body: &Value) -> ApiResult<&str> {
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .filter(|v| (20..=100).contains(&v.len()))
        .ok_or_else(|| ApiError::new("This link is invalid or expired", StatusCode::NOT_FOUND))?;
    Ok(token)
}

fn invalid_link() -> Response {
    error("This link is invalid or expired", StatusCode::NOT_FOUND)
}

fn two_factor_blocks_reset() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        json!({
            "message":"Two-factor authentication is on: please use a backup code to reset your password",
            "success":false,
            "two_factor":true
        }),
    )
}

fn db_error() -> Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}

fn random_token() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn valid_email(value: &str) -> bool {
    auth::parse_email_address(value).is_some()
}

fn mail_configured() -> bool {
    std::env::var("MAIL_DEBUG").as_deref() == Ok("1")
        || std::env::var("SMTP_HOST").is_ok_and(|v| !v.trim().is_empty())
}

fn send_mail(to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
    if std::env::var("MAIL_DEBUG").as_deref() == Ok("1") {
        tracing::info!(to, subject, body = text, "MAIL_DEBUG: password reset email");
        return Ok(());
    }
    let host = std::env::var("SMTP_HOST")?;
    let port = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(587);
    let from = std::env::var("MAIL_FROM")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "SereS <no-reply@localhost>".to_owned())
        .parse::<Mailbox>()?;
    let to_addr =
        auth::parse_email_address(to).ok_or_else(|| anyhow::anyhow!("Invalid recipient email"))?;
    let message = Message::builder()
        .from(from)
        .to(Mailbox::new(None, to_addr))
        .subject(subject)
        .body(text.to_owned())?;
    let security = std::env::var("SMTP_SECURITY").unwrap_or_else(|_| "starttls".to_owned());
    let mut builder = match security.to_ascii_lowercase().as_str() {
        "ssl" => SmtpTransport::relay(&host)?.port(port),
        "none" => SmtpTransport::builder_dangerous(&host).port(port),
        _ => SmtpTransport::starttls_relay(&host)?.port(port),
    };
    if let Some(username) = std::env::var("SMTP_USER")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
    {
        builder = builder.credentials(Credentials::new(
            username,
            std::env::var("SMTP_PASSWORD").unwrap_or_default(),
        ));
    }
    builder.build().send(&message)?;
    Ok(())
}

fn mail_copy(language: &str) -> (&'static str, &'static str) {
    match language {
        "de" => (
            "SereS-Passwort zurücksetzen",
            "Hallo {name},\n\njemand (hoffentlich du) möchte das Passwort deines SereS-Kontos zurücksetzen.\nÖffne diesen Link innerhalb von {minutes} Minuten, um ein neues Passwort zu wählen:\n\n{link}\n\nWichtig: Da deine Chats Ende-zu-Ende-verschlüsselt sind, kannst du deine alten Nachrichten nach einem Zurücksetzen per E-Mail nicht mehr lesen. Wenn du noch einen Backup-Code hast, nutze lieber \"Passwort vergessen?\" mit dem Code – dann bleibt alles erhalten.\n\nFalls du das nicht warst, ignoriere diese E-Mail einfach. Dein Passwort bleibt unverändert.\n",
        ),
        "fr" => (
            "Réinitialiser ton mot de passe SereS",
            "Bonjour {name},\n\nquelqu'un (toi, espérons-le) a demandé à réinitialiser le mot de passe de ton compte SereS.\nOuvre ce lien dans les {minutes} minutes pour choisir un nouveau mot de passe :\n\n{link}\n\nImportant : comme tes discussions sont chiffrées de bout en bout, tu ne pourras plus lire tes anciens messages après une réinitialisation par e-mail. Si tu as encore un code de secours, utilise plutôt « Mot de passe oublié ? » avec le code – tu gardes alors tout.\n\nSi ce n'était pas toi, ignore simplement cet e-mail. Ton mot de passe reste inchangé.\n",
        ),
        _ => (
            "Reset your SereS password",
            "Hi {name},\n\nsomeone (hopefully you) asked to reset the password of your SereS account.\nOpen this link within {minutes} minutes to choose a new password:\n\n{link}\n\nImportant: because your chats are end-to-end encrypted, you won't be able to read your old messages after a reset by e-mail. If you still have a backup code, use \"Forgot password?\" with the code instead – then you keep everything.\n\nIf you didn't ask for this, you can ignore this e-mail. Your password stays the same.\n",
        ),
    }
}

fn public_base_url(headers: &HeaderMap) -> Option<String> {
    public_base_url_with(
        headers,
        std::env::var("PUBLIC_URL").ok().as_deref(),
        std::env::var("SERES_ALLOWED_HOSTS").ok().as_deref(),
    )
}

fn public_base_url_with(
    headers: &HeaderMap,
    public_url: Option<&str>,
    allowed_hosts_env: Option<&str>,
) -> Option<String> {
    if let Some(value) = public_url.map(str::trim).filter(|v| !v.is_empty()) {
        let parsed = url::Url::parse(value).ok()?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return None;
        }
        return Some(value.trim_end_matches('/').to_owned());
    }
    let scheme = if super::is_https_with(headers, public_url) {
        "https"
    } else {
        "http"
    };
    let candidate = super::first_header_host(headers, "x-forwarded-host")
        .or_else(|| super::first_header_host(headers, "host"));
    if let Some(extra) = allowed_hosts_env.map(str::trim).filter(|v| !v.is_empty()) {
        let allowed: std::collections::HashSet<String> = extra
            .split(',')
            .filter_map(super::normalize_host_port)
            .collect();
        let host = candidate.filter(|h| allowed.contains(h))?;
        return Some(format!("{scheme}://{host}"));
    }
    match candidate {
        Some(host) if super::is_loopback_host(&host) => Some(format!("{scheme}://{host}")),
        Some(_) => None,
        None => {
            if headers.contains_key("x-forwarded-host") || headers.contains_key("host") {
                None
            } else {
                Some(format!("{scheme}://localhost"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_base_url_requires_config_or_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.example".parse().unwrap());
        assert_eq!(public_base_url_with(&headers, None, None), None);
        assert_eq!(
            public_base_url_with(&headers, Some("https://chat.example/"), None),
            Some("https://chat.example".into())
        );
        assert_eq!(
            public_base_url_with(&headers, None, Some("chat.example")),
            None
        );

        let mut allowed_headers = HeaderMap::new();
        allowed_headers.insert("host", "chat.example".parse().unwrap());
        allowed_headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            public_base_url_with(&allowed_headers, None, Some("chat.example")),
            Some("https://chat.example".into())
        );

        let mut local_headers = HeaderMap::new();
        local_headers.insert("host", "127.0.0.1:2222".parse().unwrap());
        assert_eq!(
            public_base_url_with(&local_headers, None, None),
            Some("http://127.0.0.1:2222".into())
        );
    }

    #[test]
    fn valid_email_rejects_angle_brackets_commas_quotes_and_controls() {
        assert!(valid_email("alice+tag@example.com"));
        assert!(!valid_email("Alice <alice@example.com>"));
        assert!(!valid_email("Alice<alice@example.com>"));
        assert!(!valid_email("a@b.com,c@d.com"));
        assert!(!valid_email("\"alice\"@example.com"));
        assert!(!valid_email("alice\r\n@example.com"));
    }

    #[tokio::test]
    async fn confirm_reset_clears_device_links_and_complete_reset_rechecks_two_factor() {
        let dir = std::env::temp_dir().join(format!("seres-reset-test-{}", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
        let state = AppState::new(pool);

        let user_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,email,username,passwd,auth_version,pub_ecdh,pub_sign,enc_private) VALUES(?,?,?,?,1,'ecdh','sign','enc')")
            .bind(&user_id)
            .bind("reset@example.com")
            .bind("resetuser")
            .bind("oldhash")
            .execute(&state.db)
            .await
            .unwrap();
        let token = "reset-token-12345678901234567890";
        sqlx::query(
            "INSERT INTO password_resets(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        )
        .bind(auth::hash_token(token))
        .bind(&user_id)
        .bind(auth::now_iso())
        .bind("2099-01-01T00:00:00Z")
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO device_links(token_hash,code,pub,created_at,expires_at,user_id,state) VALUES('dl-reset','CODE5678','pub',?,'2099-01-01T00:00:00Z',?,'approved')")
            .bind(auth::now_iso())
            .bind(&user_id)
            .execute(&state.db)
            .await
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        use base64::Engine;
        let resp = confirm_reset(
            State(state.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(json!({
                "token": token,
                "auth_hash": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
                "kdf_salt": base64::engine::general_purpose::STANDARD.encode([2u8; 16]),
                "kdf_iterations": 600_000,
                "keys": {
                    "pub_ecdh": base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                    "pub_sign": base64::engine::general_purpose::STANDARD.encode([4u8; 32]),
                    "enc_private": "{}"
                }
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let links_left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_links WHERE user_id=?")
                .bind(&user_id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(links_left, 0);

        // Also verify complete_reset refuses if 2FA was enabled in DB before tx commits.
        let tok2 = "reset-token-2fa-race-1234567890";
        sqlx::query(
            "INSERT INTO password_resets(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        )
        .bind(auth::hash_token(tok2))
        .bind(&user_id)
        .bind(auth::now_iso())
        .bind("2099-01-01T00:00:00Z")
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("UPDATE users SET totp_secret='JBSWY3DPEHPK3PXP' WHERE id=?")
            .bind(&user_id)
            .execute(&state.db)
            .await
            .unwrap();
        let user_row = sqlx::query("SELECT * FROM users WHERE id=?")
            .bind(&user_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        let mut tx = state.db.begin().await.unwrap();
        let res = complete_reset(
            &mut tx,
            ResetCredentials {
                token: tok2,
                user: &user_row,
                user_id: &user_id,
                password_hash: "hashed-pw",
                kdf_salt: "BBBB",
                kdf_iterations: 600_000,
                pub_ecdh: "CCCC",
                pub_sign: "DDDD",
                enc_private: "{}",
            },
        )
        .await;
        assert!(
            matches!(res, Ok(ResetOutcome::TwoFactorBlocked)),
            "complete_reset must refuse to reset password when 2FA is enabled in tx"
        );

        state.db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn send_mail_filters_blank_mail_from_and_smtp_user() {
        use std::io::{BufRead, BufReader, Write};
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_srv = stop.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            if stop_srv.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = writer.write_all(b"220 localhost ESMTP\r\n");
            let mut line = String::new();
            let mut in_data = false;
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                if in_data {
                    if line == ".\r\n" || line == ".\n" {
                        in_data = false;
                        let _ = writer.write_all(b"250 Ok\r\n");
                    }
                } else if line.starts_with("EHLO") || line.starts_with("HELO") {
                    let _ = writer.write_all(b"250-localhost\r\n250 SIZE 1024000\r\n");
                } else if line.starts_with("MAIL FROM") || line.starts_with("RCPT TO") {
                    let _ = writer.write_all(b"250 Ok\r\n");
                } else if line.starts_with("DATA") {
                    in_data = true;
                    let _ = writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n");
                } else if line.starts_with("QUIT") {
                    let _ = writer.write_all(b"221 Bye\r\n");
                    break;
                } else {
                    let _ = writer.write_all(b"500 Unknown command\r\n");
                }
                line.clear();
            }
        });

        unsafe {
            std::env::remove_var("MAIL_DEBUG");
            std::env::set_var("SMTP_HOST", "127.0.0.1");
            std::env::set_var("SMTP_PORT", port.to_string());
            std::env::set_var("SMTP_SECURITY", "none");
            std::env::set_var("MAIL_FROM", "   ");
            std::env::set_var("SMTP_USER", "   ");
        }
        let result = send_mail("user@example.com", "Subject", "Body");
        unsafe {
            std::env::remove_var("SMTP_HOST");
            std::env::remove_var("SMTP_PORT");
            std::env::remove_var("SMTP_SECURITY");
            std::env::remove_var("MAIL_FROM");
            std::env::remove_var("SMTP_USER");
        }
        if result.is_err() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        }
        let _ = server.join();
        assert!(
            result.is_ok(),
            "send_mail should filter blank MAIL_FROM and SMTP_USER and succeed: {:?}",
            result.err()
        );
    }
}
