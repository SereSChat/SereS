//! APNs: notifications for the native iOS app, which can't use web push.
//!
//! The app registers its device tokens with Apple's push service: one for
//! normal notifications ("alert") and one for incoming calls ("voip"). Like a
//! web push subscription, a token belongs to the device's session, so logging
//! out (or a password reset that ends all sessions) stops its notifications.
//! The server only sends who wrote or calls; message texts stay end-to-end
//! encrypted and never leave the app. A call rings through a VoIP push; when
//! it stops ringing before the device answered, a silent push tells the app.
//!
//! Settings: APNS_KEY_P8 (path to the .p8 key from Apple, or its contents),
//! APNS_KEY_ID, APNS_TEAM_ID and APNS_TOPIC (the app's bundle id). Without
//! them the iOS app gets no push notifications and subscribing answers 503.

use super::auth::{require_user, session_hash};
use super::{ApiError, ApiResult, json_ok, str_field};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::{
    sync::{Mutex, OnceLock},
    time::Duration,
};

const DEFAULT_TOPIC: &str = "net.fyralsmp.seres";
/// An alert and a VoIP token for each of the newest devices of an account.
const MAX_TOKENS_PER_USER: i64 = 20;
/// Apple accepts a provider token for an hour and refuses new ones more
/// often than every 20 minutes.
const PROVIDER_TOKEN_SECONDS: i64 = 50 * 60;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/push/apns/subscribe", post(subscribe))
        .route("/api/push/apns/unsubscribe", post(unsubscribe))
}

struct Config {
    key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
}

/// Read once at the first use. None: APNs is off on this server.
fn config() -> Option<&'static Config> {
    static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
    CONFIG.get_or_init(load_config).as_ref()
}

fn load_config() -> Option<Config> {
    let setting = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let key = setting("APNS_KEY_P8")?;
    let key_id = setting("APNS_KEY_ID")?;
    let team_id = setting("APNS_TEAM_ID")?;
    // Either the key itself or the path of the .p8 file.
    let pem = if key.contains("-----BEGIN") {
        key
    } else {
        match std::fs::read_to_string(&key) {
            Ok(pem) => pem,
            Err(error) => {
                tracing::warn!(%error, "APNS_KEY_P8 can't be read, APNs is off");
                return None;
            }
        }
    };
    let Some(key) = parse_key(&pem) else {
        tracing::warn!("APNS_KEY_P8 is not a valid .p8 key, APNs is off");
        return None;
    };
    Some(Config {
        key,
        key_id,
        team_id,
        topic: setting("APNS_TOPIC").unwrap_or_else(|| DEFAULT_TOPIC.into()),
    })
}

/// The .p8 file is a PEM encoded PKCS#8 P-256 key. In a .env file it may be
/// on one line, with "\n" instead of line breaks.
fn parse_key(pem: &str) -> Option<SigningKey> {
    let pem = pem.replace("\\n", "\n");
    let body = pem.split("-----").nth(2)?;
    let der = STANDARD
        .decode(body.split_whitespace().collect::<String>())
        .ok()?;
    SigningKey::from_pkcs8_der(&der).ok()
}

struct Subscription {
    token: String,
    kind: &'static str,
    environment: &'static str,
    topic: Option<String>,
}

/// Device tokens are hex (32 bytes today; Apple may make them longer).
fn device_token(value: &str) -> Option<String> {
    (value.len() >= 64 && value.len() <= 200 && value.len().is_multiple_of(2))
        .then_some(())
        .filter(|_| value.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|_| value.to_ascii_lowercase())
}

/// A bundle id like net.fyralsmp.seres. VoIP pushes go to "<topic>.voip".
fn bundle_id(value: &str) -> Option<String> {
    let value = value.strip_suffix(".voip").unwrap_or(value);
    (!value.is_empty()
        && value.len() <= 155
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    .then(|| value.to_owned())
}

fn parse_subscription(body: &Value) -> Option<Subscription> {
    let token = device_token(body.get("token")?.as_str()?)?;
    let kind = match body.get("kind")?.as_str()? {
        "alert" => "alert",
        "voip" => "voip",
        _ => return None,
    };
    let environment = match body.get("environment")?.as_str()? {
        "sandbox" => "sandbox",
        "production" => "production",
        _ => return None,
    };
    let topic = match body.get("topic") {
        None | Some(Value::Null) => None,
        Some(value) => Some(bundle_id(value.as_str()?)?),
    };
    Some(Subscription {
        token,
        kind,
        environment,
        topic,
    })
}

async fn subscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = require_user(&state, &headers).await?;
    let user_id: String = me.try_get("id").unwrap_or_default();
    let session = session_hash(&headers)
        .ok_or_else(|| ApiError::new("Not logged in", StatusCode::UNAUTHORIZED))?;
    if config().is_none() {
        return Err(ApiError::new(
            "APNs is not configured on this server",
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    let subscription = parse_subscription(&body)
        .ok_or_else(|| ApiError::new("Invalid APNs token", StatusCode::BAD_REQUEST))?;
    if state.rate_limited(format!("apns-subscribe:{user_id}"), 60, 3600) {
        return Err(ApiError::new(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    store(&state.db, &user_id, &session, &subscription)
        .await
        .map_err(|_| ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(json_ok(json!({})))
}

/// A token belongs to one account and device: registering it again moves it.
/// A device keeps only its newest token of each kind.
async fn store(
    pool: &SqlitePool,
    user_id: &str,
    session: &str,
    subscription: &Subscription,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM apns_tokens WHERE session_hash=? AND kind=? AND token!=?")
        .bind(session)
        .bind(subscription.kind)
        .bind(&subscription.token)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO apns_tokens(token,user_id,session_hash,kind,environment,topic,created_at) VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, session_hash=excluded.session_hash,
         kind=excluded.kind, environment=excluded.environment, topic=excluded.topic, created_at=excluded.created_at",
    )
    .bind(&subscription.token)
    .bind(user_id)
    .bind(session)
    .bind(subscription.kind)
    .bind(subscription.environment)
    .bind(&subscription.topic)
    .bind(super::auth::now_iso())
    .execute(&mut *tx)
    .await?;
    // Only the newest devices of an account keep their tokens.
    sqlx::query(
        "DELETE FROM apns_tokens WHERE user_id=? AND token NOT IN
         (SELECT token FROM apns_tokens WHERE user_id=? ORDER BY created_at DESC LIMIT ?)",
    )
    .bind(user_id)
    .bind(user_id)
    .bind(MAX_TOKENS_PER_USER)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

async fn unsubscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = require_user(&state, &headers).await?;
    let user_id: String = me.try_get("id").unwrap_or_default();
    let token = str_field(&body, "token", 200)?.to_ascii_lowercase();
    let _ = sqlx::query("DELETE FROM apns_tokens WHERE token=? AND user_id=?")
        .bind(token)
        .bind(&user_id)
        .execute(&state.db)
        .await;
    Ok(json_ok(json!({})))
}

// ------------------------------------------------------------------ sending

/// The provider token: a JWT signed with the .p8 key (ES256).
fn provider_token(config: &Config, issued_at: i64) -> String {
    let header = json!({"alg": "ES256", "kid": config.key_id});
    let claims = json!({"iss": config.team_id, "iat": issued_at});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = config.key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

static PROVIDER_TOKEN: Mutex<Option<(String, i64)>> = Mutex::new(None);

/// The cached provider token, renewed after 50 minutes.
fn current_provider_token(config: &Config) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut cached = PROVIDER_TOKEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match cached.as_ref() {
        Some((token, issued_at)) if now - issued_at < PROVIDER_TOKEN_SECONDS => token.clone(),
        _ => {
            let token = provider_token(config, now);
            *cached = Some((token.clone(), now));
            token
        }
    }
}

fn forget_provider_token() {
    *PROVIDER_TOKEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default()
    })
}

fn host(environment: &str) -> &'static str {
    if environment == "sandbox" {
        "api.sandbox.push.apple.com"
    } else {
        "api.push.apple.com"
    }
}

struct Push {
    push_type: &'static str,
    priority: u8,
    /// Unix time after which Apple drops the push; 0: deliver now or never.
    expiration: i64,
    collapse_id: Option<String>,
    payload: Value,
}

struct Target {
    token: String,
    session: String,
    environment: String,
    topic: String,
}

/// The logged-in devices of `user_id` with a token of `kind`. With
/// `skip_open`, devices that have SereS open right now are left out (they
/// show notifications themselves); `except_session` leaves out one device.
async fn targets(
    pool: &SqlitePool,
    user_id: &str,
    kind: &str,
    skip_open: bool,
    except_session: Option<&str>,
) -> Vec<Target> {
    let open_since = if skip_open {
        (chrono::Utc::now() - chrono::Duration::seconds(super::push::OPEN_SECONDS))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    } else {
        // Later than any last_seen: no device counts as open.
        "9999".into()
    };
    let rows = sqlx::query(
        "SELECT a.token,a.session_hash,a.environment,a.topic FROM apns_tokens a
         JOIN user_sessions s ON s.token_hash=a.session_hash AND s.expires_at>? AND s.approved=1
         WHERE a.user_id=? AND a.kind=? AND a.session_hash!=? AND (s.last_seen IS NULL OR s.last_seen<?)",
    )
    .bind(super::auth::now_iso())
    .bind(user_id)
    .bind(kind)
    .bind(except_session.unwrap_or(""))
    .bind(open_since)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let default_topic = config()
        .map(|config| config.topic.as_str())
        .unwrap_or(DEFAULT_TOPIC);
    rows.iter()
        .map(|row| Target {
            token: row.try_get("token").unwrap_or_default(),
            session: row.try_get("session_hash").unwrap_or_default(),
            environment: row.try_get("environment").unwrap_or_default(),
            topic: row
                .try_get::<Option<String>, _>("topic")
                .ok()
                .flatten()
                .unwrap_or_else(|| default_topic.to_owned()),
        })
        .collect()
}

/// Sends one push to each target. Tokens Apple no longer knows are removed.
async fn deliver(pool: &SqlitePool, targets: &[Target], push: &Push) {
    let Some(config) = config() else {
        return;
    };
    let body = push.payload.to_string();
    for target in targets {
        // VoIP pushes go to the app's VoIP topic.
        let topic = if push.push_type == "voip" {
            format!("{}.voip", target.topic)
        } else {
            target.topic.clone()
        };
        let mut request = client()
            .post(format!(
                "https://{}/3/device/{}",
                host(&target.environment),
                target.token
            ))
            .header(
                "authorization",
                format!("bearer {}", current_provider_token(config)),
            )
            .header("apns-topic", topic)
            .header("apns-push-type", push.push_type)
            .header("apns-priority", push.priority.to_string())
            .header("apns-expiration", push.expiration.to_string())
            .header("content-type", "application/json")
            .body(body.clone());
        if let Some(collapse_id) = &push.collapse_id {
            request = request.header("apns-collapse-id", collapse_id);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(error = %error.without_url(), "sending APNs push failed");
                continue;
            }
        };
        let status = response.status();
        if status.is_success() {
            let _ = sqlx::query("UPDATE apns_tokens SET last_used_at=? WHERE token=?")
                .bind(super::auth::now_iso())
                .bind(&target.token)
                .execute(pool)
                .await;
            continue;
        }
        let reason = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|reply| reply.get("reason")?.as_str().map(str::to_owned))
            .unwrap_or_default();
        match (status.as_u16(), reason.as_str()) {
            // Gone: the app was removed or the token replaced.
            (410, _) | (_, "BadDeviceToken" | "Unregistered") => {
                let _ = sqlx::query("DELETE FROM apns_tokens WHERE token=?")
                    .bind(&target.token)
                    .execute(pool)
                    .await;
            }
            (403, "ExpiredProviderToken" | "InvalidProviderToken") => {
                forget_provider_token();
                tracing::warn!(%reason, "APNs refused the provider token");
            }
            _ => tracing::warn!(%status, %reason, "APNs refused a notification"),
        }
    }
}

/// Title and body like the web push notification (sw.js): who wrote, never
/// what (the text is end-to-end encrypted).
fn message_alert(from: &str, group: Option<&str>) -> (String, String) {
    let from = if from.is_empty() { "SereS" } else { from };
    match group {
        Some(group) => (group.to_owned(), format!("{from}: New message")),
        None => (from.to_owned(), "New message".to_owned()),
    }
}

fn message_payload(chat_id: &str, title: &str, body: &str, badge: Option<i64>) -> Value {
    let mut aps = json!({
        "alert": {"title": title, "body": body},
        "sound": "default",
        "thread-id": chat_id,
        "mutable-content": 1,
    });
    if let Some(badge) = badge {
        aps["badge"] = json!(badge);
    }
    json!({"aps": aps, "type": "message", "chat_id": chat_id})
}

/// Unread messages of all chats that aren't archived (like the chat list).
async fn unread_count(pool: &SqlitePool, user_id: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_members c JOIN messages m ON m.chat_id=c.chat_id
         AND m.seq>MAX(c.joined_seq,c.cleared_seq,c.last_read_seq)
         WHERE c.user_id=? AND c.archived=0 AND m.deleted=0 AND m.silent=0 AND m.kind!='system'
         AND (m.sender_id IS NULL OR m.sender_id!=?)",
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .ok()
}

/// After a new message: the same people and rules as web push.
pub async fn message_sent(
    pool: &SqlitePool,
    recipients: &[String],
    chat_id: &str,
    from: &str,
    group: Option<&str>,
) {
    if config().is_none() {
        return;
    }
    let (title, body) = message_alert(from, group);
    for user_id in recipients {
        let targets = targets(pool, user_id, "alert", true, None).await;
        if targets.is_empty() {
            continue;
        }
        let badge = unread_count(pool, user_id).await;
        let push = Push {
            push_type: "alert",
            priority: 10,
            expiration: chrono::Utc::now().timestamp() + 24 * 3600,
            // One notification per chat, replaced by the next one.
            collapse_id: Some(chat_id.to_owned()),
            payload: message_payload(chat_id, &title, &body, badge),
        };
        deliver(pool, &targets, &push).await;
    }
}

// -------------------------------------------------------------------- calls

/// An incoming call, as the VoIP push tells it to the app.
pub struct Call<'a> {
    pub call_id: &'a str,
    pub chat_id: &'a str,
    pub caller_id: &'a str,
    pub caller_name: &'a str,
    pub video: bool,
    pub group: bool,
}

fn call_payload(call: &Call) -> Value {
    json!({
        "type": "call",
        "call_id": call.call_id,
        "chat_id": call.chat_id,
        "caller_id": call.caller_id,
        "caller_name": call.caller_name,
        "video": call.video,
        "group": call.group,
    })
}

fn call_end_payload(call_id: &str) -> Value {
    json!({"aps": {"content-available": 1}, "type": "call_end", "call_id": call_id})
}

/// After a call started: a VoIP push to every logged-in iOS device of the
/// people it rings for. iOS shows it with CallKit, also when SereS is open
/// (the app knows the call by its id), so open devices aren't left out.
pub async fn call_started(pool: &SqlitePool, ringing: &[String], call: &Call<'_>) {
    if config().is_none() {
        return;
    }
    let push = Push {
        push_type: "voip",
        priority: 10,
        // A call that can't ring right now is over for this device.
        expiration: 0,
        collapse_id: None,
        payload: call_payload(call),
    };
    for user_id in ringing {
        let targets = targets(pool, user_id, "voip", false, None).await;
        if !targets.is_empty() {
            deliver(pool, &targets, &push).await;
        }
    }
}

/// Stops the ringing on iOS devices: a call stopped ringing for someone
/// (answered or declined on another device, cancelled by the caller, ended
/// or rung out). The database notes this in apns_call_ends (see db.rs);
/// after each change to a call the server sends what was noted as a silent
/// push to the alert tokens of the devices that got the VoIP push. Never a
/// second VoIP push: iOS would ring again. `actor` is the user and device
/// that made the change; that device already knows.
pub fn calls_stopped_ringing(pool: SqlitePool, actor: Option<(String, String)>) {
    tokio::spawn(async move {
        // Most calls ring no iOS device: then there is nothing to write.
        let pending = sqlx::query_scalar::<_, i64>("SELECT 1 FROM apns_call_ends LIMIT 1")
            .fetch_optional(&pool)
            .await;
        if !matches!(pending, Ok(Some(_))) {
            return;
        }
        let rows = sqlx::query(
            "DELETE FROM apns_call_ends WHERE rowid IN (SELECT rowid FROM apns_call_ends LIMIT 200)
             RETURNING call_id,user_id,created_at",
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        if rows.is_empty() || config().is_none() {
            return;
        }
        // Older notes belong to calls that rang out long ago.
        let fresh_since = (chrono::Utc::now() - chrono::Duration::seconds(120))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let mut sent = Vec::new();
        for row in rows {
            let call_id: String = row.try_get("call_id").unwrap_or_default();
            let user_id: String = row.try_get("user_id").unwrap_or_default();
            let created_at: String = row.try_get("created_at").unwrap_or_default();
            if created_at < fresh_since || sent.contains(&(call_id.clone(), user_id.clone())) {
                continue;
            }
            let except = actor
                .as_ref()
                .filter(|(actor_id, _)| *actor_id == user_id)
                .map(|(_, session)| session.as_str());
            let voip_sessions: Vec<String> = sqlx::query_scalar(
                "SELECT session_hash FROM apns_tokens WHERE user_id=? AND kind='voip'",
            )
            .bind(&user_id)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let targets: Vec<Target> = targets(&pool, &user_id, "alert", false, except)
                .await
                .into_iter()
                .filter(|target| voip_sessions.contains(&target.session))
                .collect();
            if !targets.is_empty() {
                let push = Push {
                    push_type: "background",
                    // Apple requires priority 5 for background pushes.
                    priority: 5,
                    expiration: chrono::Utc::now().timestamp() + 60,
                    collapse_id: None,
                    payload: call_end_payload(&call_id),
                };
                deliver(&pool, &targets, &push).await;
            }
            sent.push((call_id, user_id));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    async fn database() -> (SqlitePool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("seres-apns-{}", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
        (pool, dir)
    }

    fn subscription(token: &str, kind: &'static str) -> Subscription {
        Subscription {
            token: token.into(),
            kind,
            environment: "sandbox",
            topic: None,
        }
    }

    #[test]
    fn only_valid_tokens_are_accepted() {
        let token = "a1".repeat(32);
        let parsed = parse_subscription(
            &json!({"token": token.to_uppercase(), "kind": "voip", "environment": "production", "topic": "net.fyralsmp.seres.voip"}),
        )
        .unwrap();
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.kind, "voip");
        assert_eq!(parsed.environment, "production");
        assert_eq!(parsed.topic.as_deref(), Some("net.fyralsmp.seres"));
        assert!(
            parse_subscription(&json!({"token": token, "kind": "alert", "environment": "sandbox"}))
                .is_some_and(|s| s.topic.is_none())
        );
        for body in [
            json!({"token": "a1".repeat(31), "kind": "alert", "environment": "sandbox"}),
            json!({"token": format!("{}0", "a1".repeat(32)), "kind": "alert", "environment": "sandbox"}),
            json!({"token": "zz".repeat(32), "kind": "alert", "environment": "sandbox"}),
            json!({"token": "a1".repeat(101), "kind": "alert", "environment": "sandbox"}),
            json!({"token": token, "kind": "web", "environment": "sandbox"}),
            json!({"token": token, "kind": "alert", "environment": "test"}),
            json!({"token": token, "kind": "alert"}),
            json!({"token": token, "kind": "alert", "environment": "sandbox", "topic": "evil/topic"}),
            json!({"token": token, "kind": "alert", "environment": "sandbox", "topic": 5}),
        ] {
            assert!(parse_subscription(&body).is_none(), "{body}");
        }
    }

    #[test]
    fn reads_the_p8_key_as_file_or_one_line() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let parsed = parse_key(&pem).unwrap();
        assert_eq!(parsed.to_bytes(), key.to_bytes());
        let one_line = pem.trim().replace('\n', "\\n");
        assert_eq!(parse_key(&one_line).unwrap().to_bytes(), key.to_bytes());
        assert!(
            parse_key("-----BEGIN PRIVATE KEY-----\nbm9wZQ==\n-----END PRIVATE KEY-----").is_none()
        );
        assert!(parse_key("not a key").is_none());
    }

    fn test_config() -> Config {
        Config {
            key: SigningKey::from_slice(&[7u8; 32]).unwrap(),
            key_id: "ABC123DEFG".into(),
            team_id: "TEAM456789".into(),
            topic: DEFAULT_TOPIC.into(),
        }
    }

    #[test]
    fn provider_token_is_an_es256_jwt() {
        use p256::ecdsa::{VerifyingKey, signature::Verifier};
        let config = test_config();
        let token = provider_token(&config, 1_700_000_000);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |part: &str| -> Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
        };
        assert_eq!(
            decode(parts[0]),
            json!({"alg": "ES256", "kid": "ABC123DEFG"})
        );
        assert_eq!(
            decode(parts[1]),
            json!({"iss": "TEAM456789", "iat": 1_700_000_000})
        );
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64);
        let signature = Signature::from_slice(&signature).unwrap();
        VerifyingKey::from(&config.key)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn message_pushes_say_who_wrote_but_not_what() {
        assert_eq!(
            message_alert("Alice", None),
            ("Alice".into(), "New message".into())
        );
        assert_eq!(
            message_alert("Alice", Some("Team")),
            ("Team".into(), "Alice: New message".into())
        );
        assert_eq!(message_alert("", None).0, "SereS");
        assert_eq!(
            message_payload("chat-1", "Team", "Alice: New message", Some(3)),
            json!({
                "aps": {
                    "alert": {"title": "Team", "body": "Alice: New message"},
                    "sound": "default",
                    "badge": 3,
                    "thread-id": "chat-1",
                    "mutable-content": 1,
                },
                "type": "message",
                "chat_id": "chat-1",
            })
        );
        assert!(
            message_payload("chat-1", "A", "B", None)["aps"]
                .get("badge")
                .is_none()
        );
    }

    #[test]
    fn call_pushes_ring_and_stop_ringing() {
        let call = Call {
            call_id: "call-1",
            chat_id: "chat-1",
            caller_id: "alice",
            caller_name: "Alice",
            video: false,
            group: true,
        };
        assert_eq!(
            call_payload(&call),
            json!({
                "type": "call",
                "call_id": "call-1",
                "chat_id": "chat-1",
                "caller_id": "alice",
                "caller_name": "Alice",
                "video": false,
                "group": true,
            })
        );
        assert_eq!(
            call_end_payload("call-1"),
            json!({"aps": {"content-available": 1}, "type": "call_end", "call_id": "call-1"})
        );
    }

    #[tokio::test]
    async fn a_call_that_stops_ringing_is_noted_for_ios_devices() {
        let (pool, dir) = database().await;
        for user in ["alice", "bob", "carol"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(user)
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at) VALUES('session-b','bob','2999-01-01T00:00:00Z','now')")
            .execute(&pool).await.unwrap();
        store(
            &pool,
            "bob",
            "session-b",
            &subscription(&"ab".repeat(32), "voip"),
        )
        .await
        .unwrap();
        for user in ["bob", "carol"] {
            sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('call-1',?,'ringing','now','now')")
                .bind(user).execute(&pool).await.unwrap();
        }
        // Like set_state in calls.rs.
        for (user, state) in [("bob", "joined"), ("carol", "declined"), ("bob", "left")] {
            sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES('call-1',?,?,'now','now') ON CONFLICT(call_id,user_id) DO UPDATE SET state=excluded.state")
                .bind(user).bind(state).execute(&pool).await.unwrap();
        }
        // Only bob has an iOS device, and only his answer stopped a ringing.
        let noted: Vec<(String, String)> =
            sqlx::query_as("SELECT call_id,user_id FROM apns_call_ends")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(noted, vec![("call-1".into(), "bob".into())]);
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn tokens_move_between_devices_and_go_with_the_session() {
        let (pool, dir) = database().await;
        for (session, user) in [("session-a", "alice"), ("session-b", "bob")] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(user)
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,'2999-01-01T00:00:00Z','now')")
                .bind(session).bind(user).execute(&pool).await.unwrap();
        }
        let owner = |token: String| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT user_id FROM apns_tokens WHERE token=?")
                    .bind(token)
                    .fetch_optional(&pool)
                    .await
                    .unwrap()
            }
        };
        let first = "ab".repeat(32);
        let second = "cd".repeat(32);
        store(&pool, "alice", "session-a", &subscription(&first, "alert"))
            .await
            .unwrap();
        store(&pool, "alice", "session-a", &subscription(&second, "voip"))
            .await
            .unwrap();
        // The same token registered by another account belongs to it now.
        store(&pool, "bob", "session-b", &subscription(&first, "alert"))
            .await
            .unwrap();
        assert_eq!(owner(first.clone()).await.as_deref(), Some("bob"));
        // A new alert token replaces the device's old one.
        let third = "ef".repeat(32);
        store(&pool, "bob", "session-b", &subscription(&third, "alert"))
            .await
            .unwrap();
        assert_eq!(owner(first.clone()).await, None);
        assert_eq!(owner(third.clone()).await.as_deref(), Some("bob"));
        // Logging out the device removes its tokens.
        sqlx::query("DELETE FROM user_sessions WHERE token_hash='session-a'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(owner(second).await, None);
        assert_eq!(owner(third).await.as_deref(), Some("bob"));
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn subscribing_without_apns_settings_says_so() {
        let (pool, dir) = database().await;
        sqlx::query("INSERT INTO users(id,username) VALUES('alice','alice')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,'alice','2999-01-01T00:00:00Z','now')")
            .bind(super::super::auth::hash_token("cookie")).execute(&pool).await.unwrap();
        let state = AppState::new(pool.clone());
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "sessioncookie=cookie".parse().unwrap());
        let body = json!({"token": "ab".repeat(32), "kind": "alert", "environment": "sandbox"});
        let response = subscribe(State(state.clone()), headers.clone(), Json(body)).await;
        let response = axum::response::IntoResponse::into_response(response.unwrap_err());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            reply,
            json!({"success": false, "message": "APNs is not configured on this server"})
        );
        // Not logged in comes first.
        let response = subscribe(State(state.clone()), HeaderMap::new(), Json(json!({}))).await;
        let response = axum::response::IntoResponse::into_response(response.unwrap_err());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = unsubscribe(
            State(state),
            headers,
            Json(json!({"token": "ab".repeat(32)})),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}

// --------------------------------------------------------------- new logins

/// A password login waits for the main device, which is this app.
pub async fn login_waiting(pool: &SqlitePool, user_id: &str, main_session: &str, device: &str) {
    if config().is_none() {
        return;
    }
    let targets: Vec<Target> = targets(pool, user_id, "alert", true, None)
        .await
        .into_iter()
        .filter(|target| target.session == main_session)
        .collect();
    if targets.is_empty() {
        return;
    }
    let push = Push {
        push_type: "alert",
        priority: 10,
        // The request expires after 15 minutes.
        expiration: chrono::Utc::now().timestamp() + 15 * 60,
        collapse_id: Some("login".into()),
        payload: json!({
            "aps": {
                "alert": {
                    "title": "New login",
                    "body": format!("{device} wants to log in. Open SereS to allow or refuse it."),
                },
                "sound": "default",
            },
            "type": "login",
        }),
    };
    deliver(pool, &targets, &push).await;
}
