//! Web push: notifications for new messages and calls while SereS is closed.
//!
//! Each device subscribes with its browser's push service. The subscription
//! belongs to the device's session, so logging out (or a password reset that
//! ends all sessions) stops its notifications. The server only sends who wrote
//! or calls; message texts stay end-to-end encrypted and never leave the app.
//! The payload itself is encrypted for the device (RFC 8291) and signed with
//! the server's VAPID key (RFC 8292), which lives in the database.

use super::auth::{require_user, session_hash};
use super::{ApiResult, json_ok, str_field};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::{sync::OnceLock, time::Duration};
use url::Url;
use web_push::{
    ContentEncoding, PartialVapidSignatureBuilder, SubscriptionInfo, Urgency,
    VapidSignatureBuilder, WebPushMessageBuilder,
};

const MAX_SUBSCRIPTIONS_PER_USER: i64 = 10;
/// A device that asked the server within this time has SereS open.
pub(crate) const OPEN_SECONDS: i64 = 30;
/// Hosts of the push services of Chrome/Edge (Google), Firefox, Safari and Windows.
/// The server sends requests to these only, never to a URL a client made up.
const PUSH_HOSTS: [&str; 5] = [
    "fcm.googleapis.com",
    "android.googleapis.com",
    "push.services.mozilla.com",
    "push.apple.com",
    "notify.windows.com",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/push/key", get(public_key))
        .route("/api/push/subscribe", post(subscribe))
        .route("/api/push/unsubscribe", post(unsubscribe))
}

/// Creates the VAPID key pair once. A random 32-byte value is a valid P-256
/// private key in practice; the rare invalid one is just drawn again.
pub async fn ensure_vapid_key(pool: &SqlitePool) -> anyhow::Result<()> {
    let existing =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key='vapid_private'")
            .fetch_optional(pool)
            .await?;
    if existing.is_some() {
        return Ok(());
    }
    let private = loop {
        let candidate = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        if VapidSignatureBuilder::from_base64_no_sub(&candidate).is_ok() {
            break candidate;
        }
    };
    sqlx::query("INSERT OR IGNORE INTO meta(key,value) VALUES('vapid_private',?)")
        .bind(private)
        .execute(pool)
        .await?;
    Ok(())
}

async fn vapid(pool: &SqlitePool) -> Option<PartialVapidSignatureBuilder> {
    let private =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key='vapid_private'")
            .fetch_optional(pool)
            .await
            .ok()??;
    VapidSignatureBuilder::from_base64_no_sub(&private).ok()
}

async fn public_key(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    require_user(&state, &headers).await?;
    let builder = vapid(&state.db).await.ok_or_else(|| {
        super::ApiError::new("Push is not available", StatusCode::SERVICE_UNAVAILABLE)
    })?;
    Ok(json_ok(
        json!({"public_key": URL_SAFE_NO_PAD.encode(builder.get_public_key())}),
    ))
}

/// Push services use https on their own hosts. SERES_PUSH_ALLOWED_HOSTS adds
/// hosts for tests (plain http only on the loopback address).
fn endpoint_allowed(endpoint: &str) -> bool {
    let Ok(url) = Url::parse(endpoint) else {
        return false;
    };
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    let extra = std::env::var("SERES_PUSH_ALLOWED_HOSTS").unwrap_or_default();
    if extra
        .split(',')
        .map(str::trim)
        .any(|allowed| !allowed.is_empty() && allowed.eq_ignore_ascii_case(&host))
    {
        let loopback = host == "127.0.0.1" || host == "localhost" || host == "[::1]";
        return url.scheme() == "https" || (url.scheme() == "http" && loopback);
    }
    url.scheme() == "https"
        && PUSH_HOSTS
            .iter()
            .any(|known| host == *known || host.ends_with(&format!(".{known}")))
}

fn key_field<'a>(body: &'a Value, name: &str, max_len: usize) -> Option<&'a str> {
    body.get("keys")?.get(name)?.as_str().filter(|v| {
        !v.is_empty()
            && v.len() <= max_len
            && URL_SAFE_NO_PAD.decode(v.trim_end_matches('=')).is_ok()
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
        .ok_or_else(|| super::ApiError::new("Not logged in", StatusCode::UNAUTHORIZED))?;
    let bad = || super::ApiError::new("Invalid push subscription", StatusCode::BAD_REQUEST);
    let endpoint = str_field(&body, "endpoint", 1000)?;
    if !endpoint_allowed(endpoint) {
        return Err(bad());
    }
    let p256dh = key_field(&body, "p256dh", 200).ok_or_else(bad)?;
    let auth = key_field(&body, "auth", 60).ok_or_else(bad)?;
    if state.rate_limited(format!("push-subscribe:{user_id}"), 20, 3600) {
        return Err(super::ApiError::new(
            "Too many attempts, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    let db = || super::ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR);
    sqlx::query(
        "INSERT INTO push_subscriptions(endpoint,user_id,session_hash,p256dh,auth,created_at) VALUES(?,?,?,?,?,?)
         ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id, session_hash=excluded.session_hash,
         p256dh=excluded.p256dh, auth=excluded.auth",
    )
    .bind(endpoint)
    .bind(&user_id)
    .bind(&session)
    .bind(p256dh)
    .bind(auth)
    .bind(super::auth::now_iso())
    .execute(&state.db)
    .await
    .map_err(|_| db())?;
    // Only the newest devices of an account keep their subscription.
    sqlx::query(
        "DELETE FROM push_subscriptions WHERE user_id=? AND endpoint NOT IN
         (SELECT endpoint FROM push_subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT ?)",
    )
    .bind(&user_id)
    .bind(&user_id)
    .bind(MAX_SUBSCRIPTIONS_PER_USER)
    .execute(&state.db)
    .await
    .map_err(|_| db())?;
    Ok(json_ok(json!({})))
}

async fn unsubscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let me = require_user(&state, &headers).await?;
    let user_id: String = me.try_get("id").unwrap_or_default();
    let endpoint = str_field(&body, "endpoint", 1000)?;
    let _ = sqlx::query("DELETE FROM push_subscriptions WHERE endpoint=? AND user_id=?")
        .bind(endpoint)
        .bind(&user_id)
        .execute(&state.db)
        .await;
    Ok(json_ok(json!({})))
}

// ------------------------------------------------------------------ sending

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default()
    })
}

/// The sender of the signature ("sub" claim): the public address of SereS.
fn vapid_subject() -> String {
    std::env::var("PUBLIC_URL")
        .ok()
        .filter(|url| url.starts_with("https://"))
        .unwrap_or_else(|| "mailto:no-reply@localhost".into())
}

struct Delivery {
    topic: Option<String>,
    urgency: Urgency,
    ttl: u32,
}

async fn eligible_subscriptions(
    pool: &SqlitePool,
    user_ids: &[String],
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    let placeholders = vec!["?"; user_ids.len()].join(",");
    let sql = format!(
        "SELECT p.endpoint,p.p256dh,p.auth FROM push_subscriptions p
         JOIN user_sessions s ON s.token_hash=p.session_hash AND s.expires_at>? AND s.approved=1
         WHERE (s.last_seen IS NULL OR s.last_seen<?) AND p.user_id IN ({placeholders})"
    );
    // Devices with SereS open right now show notifications themselves.
    let open_since = (chrono::Utc::now() - chrono::Duration::seconds(OPEN_SECONDS))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut query = sqlx::query(&sql)
        .bind(super::auth::now_iso())
        .bind(open_since);
    for id in user_ids {
        query = query.bind(id);
    }
    query.fetch_all(pool).await
}

/// Sends `payload` to every device of `user_ids` that is still logged in.
async fn send(pool: &SqlitePool, user_ids: &[String], payload: &Value, delivery: &Delivery) {
    if user_ids.is_empty() {
        return;
    }
    let Some(key) = vapid(pool).await else {
        return;
    };
    let Ok(rows) = eligible_subscriptions(pool, user_ids).await else {
        return;
    };
    deliver(pool, &key, rows, payload, delivery).await;
}

/// Sends `payload` to the subscriptions in `rows` (endpoint, p256dh, auth).
async fn deliver(
    pool: &SqlitePool,
    key: &PartialVapidSignatureBuilder,
    rows: Vec<sqlx::sqlite::SqliteRow>,
    payload: &Value,
    delivery: &Delivery,
) {
    let content = payload.to_string();
    for row in rows {
        let endpoint: String = row.try_get("endpoint").unwrap_or_default();
        let info = SubscriptionInfo::new(
            endpoint.clone(),
            row.try_get("p256dh").unwrap_or_default(),
            row.try_get("auth").unwrap_or_default(),
        );
        let mut signature = key.clone().add_sub_info(&info);
        signature.add_claim("sub", vapid_subject());
        let Ok(signature) = signature.build() else {
            continue;
        };
        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::Aes128Gcm, content.as_bytes());
        builder.set_vapid_signature(signature);
        builder.set_ttl(delivery.ttl);
        builder.set_urgency(delivery.urgency);
        if let Some(topic) = &delivery.topic {
            builder.set_topic(topic.clone());
        }
        let Ok(message) = builder.build() else {
            continue;
        };
        let mut request = client()
            .post(&endpoint)
            .header("TTL", message.ttl.to_string());
        if let Some(urgency) = message.urgency {
            request = request.header("Urgency", urgency.to_string());
        }
        if let Some(topic) = message.topic {
            request = request.header("Topic", topic);
        }
        if let Some(payload) = message.payload {
            request = request
                .header("Content-Encoding", payload.content_encoding.to_str())
                .header("Content-Type", "application/octet-stream");
            for (name, value) in payload.crypto_headers {
                request = request.header(name, value);
            }
            request = request.body(payload.content);
        }
        match request.send().await {
            // Gone: the browser removed the subscription.
            Ok(response) if matches!(response.status().as_u16(), 404 | 410) => {
                let _ = sqlx::query("DELETE FROM push_subscriptions WHERE endpoint=?")
                    .bind(&endpoint)
                    .execute(pool)
                    .await;
            }
            Ok(response) if !response.status().is_success() => {
                tracing::warn!(status = %response.status(), "push service refused a notification");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error.without_url(), "sending push failed"),
        }
    }
}

async fn display_name(pool: &SqlitePool, user_id: &str) -> String {
    sqlx::query("SELECT username,display_name FROM users WHERE id=?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|row| {
            row.try_get::<Option<String>, _>("display_name")
                .ok()
                .flatten()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| row.try_get("username").unwrap_or_default())
        })
        .unwrap_or_default()
}

/// Name of a group (None for a direct chat).
async fn group_name(pool: &SqlitePool, chat_id: &str) -> Option<String> {
    sqlx::query("SELECT type,name FROM chats WHERE id=?")
        .bind(chat_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .filter(|row| row.try_get::<String, _>("type").ok().as_deref() == Some("group"))
        .and_then(|row| row.try_get("name").ok())
}

async fn is_group(pool: &SqlitePool, chat_id: &str) -> bool {
    sqlx::query_scalar::<_, String>("SELECT type FROM chats WHERE id=?")
        .bind(chat_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some_and(|kind| kind == "group")
}

/// After a new message: everyone else in the chat who hasn't muted the sender.
pub fn message_sent(pool: SqlitePool, chat_id: String, sender_id: String) {
    tokio::spawn(async move {
        let recipients: Vec<String> = sqlx::query_scalar(
            "SELECT m.user_id FROM chat_members m WHERE m.chat_id=? AND m.user_id!=?
             AND NOT EXISTS (SELECT 1 FROM muted_users u WHERE u.user_id=m.user_id AND u.muted_id=?)",
        )
        .bind(&chat_id)
        .bind(&sender_id)
        .bind(&sender_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let from = display_name(&pool, &sender_id).await;
        let group = group_name(&pool, &chat_id).await;
        let payload = json!({
            "type": "message",
            "chat": chat_id,
            "from": from,
            "group": group,
        });
        // One notification per chat replaces the older one at the push service.
        let topic = URL_SAFE_NO_PAD.encode(&chat_id.as_bytes()[..chat_id.len().min(24)]);
        let delivery = Delivery {
            topic: Some(topic),
            urgency: Urgency::Normal,
            ttl: 24 * 3600,
        };
        // The iOS app gets the same notification through APNs.
        tokio::join!(
            send(&pool, &recipients, &payload, &delivery),
            super::apns::message_sent(&pool, &recipients, &chat_id, &from, group.as_deref()),
        );
    });
}

/// After a call started: everyone whose phone should ring.
pub fn call_started(pool: SqlitePool, call_id: String) {
    tokio::spawn(async move {
        let Ok(Some(call)) = sqlx::query("SELECT chat_id,started_by FROM calls WHERE id=?")
            .bind(&call_id)
            .fetch_optional(&pool)
            .await
        else {
            return;
        };
        let chat_id: String = call.try_get("chat_id").unwrap_or_default();
        let caller: String = call.try_get("started_by").unwrap_or_default();
        let ringing: Vec<String> = sqlx::query_scalar(
            "SELECT user_id FROM call_participants WHERE call_id=? AND state='ringing'",
        )
        .bind(&call_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let from = display_name(&pool, &caller).await;
        let group = group_name(&pool, &chat_id).await;
        let payload = json!({
            "type": "call",
            "chat": chat_id,
            "call": call_id,
            "from": from,
            "group": group,
        });
        // A call is only worth ringing while it rings (45 seconds).
        let delivery = Delivery {
            topic: None,
            urgency: Urgency::High,
            ttl: 45,
        };
        // The iOS app rings through a VoIP push (CallKit).
        let call = super::apns::Call {
            call_id: &call_id,
            chat_id: &chat_id,
            caller_id: &caller,
            caller_name: &from,
            video: false,
            group: is_group(&pool, &chat_id).await,
        };
        tokio::join!(
            send(&pool, &ringing, &payload, &delivery),
            super::apns::call_started(&pool, &ringing, &call),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_push_services_are_allowed() {
        assert!(endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(endpoint_allowed(
            "https://updates.push.services.mozilla.com/wpush/v2/x"
        ));
        assert!(endpoint_allowed("https://web.push.apple.com/QK"));
        assert!(endpoint_allowed(
            "https://wns2-par02p.notify.windows.com/w/?token=x"
        ));
        assert!(!endpoint_allowed("http://fcm.googleapis.com/fcm/send/abc"));
        assert!(!endpoint_allowed("https://evil.example/fcm.googleapis.com"));
        assert!(!endpoint_allowed(
            "https://fcm.googleapis.com.evil.example/x"
        ));
        assert!(!endpoint_allowed("https://127.0.0.1/x"));
        assert!(!endpoint_allowed("not a url"));
    }

    #[tokio::test]
    async fn send_skips_unapproved_sessions() {
        let dir = std::env::temp_dir().join(format!("seres-push-{}", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
        sqlx::query("INSERT INTO users(id,username) VALUES('u1','alice')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at,approved) VALUES
             ('s-ok','u1','2999-01-01T00:00:00Z','now',1),
             ('s-wait','u1','2999-01-01T00:00:00Z','now',0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO push_subscriptions(endpoint,user_id,session_hash,p256dh,auth,created_at) VALUES
             ('https://fcm.googleapis.com/ok','u1','s-ok','k','a','now'),
             ('https://fcm.googleapis.com/wait','u1','s-wait','k','a','now')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let rows = eligible_subscriptions(&pool, &["u1".into()]).await.unwrap();
        let endpoints: Vec<String> = rows
            .iter()
            .map(|r| r.try_get::<String, _>("endpoint").unwrap())
            .collect();
        assert_eq!(endpoints, vec!["https://fcm.googleapis.com/ok"]);
        let _ = client();
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn subscribe_refreshes_created_at_on_conflict_so_active_device_is_not_pruned() {
        let dir = std::env::temp_dir().join(format!("seres-push-upsert-{}", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
        sqlx::query("INSERT INTO users(id,username) VALUES('u1','alice')")
            .execute(&pool)
            .await
            .unwrap();
        let token = "tok-u1";
        let sess_hash = super::super::auth::hash_token(token);
        sqlx::query(
            "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at,approved) VALUES(?,'u1','2999-01-01T00:00:00Z','now',1)",
        )
        .bind(&sess_hash)
        .execute(&pool)
        .await
        .unwrap();

        let ep0 = "https://fcm.googleapis.com/fcm/send/ep0";
        sqlx::query(
            "INSERT INTO push_subscriptions(endpoint,user_id,session_hash,p256dh,auth,created_at) VALUES(?,'u1',?,'k','a','2020-01-01T00:00:00Z')",
        )
        .bind(ep0)
        .bind(&sess_hash)
        .execute(&pool)
        .await
        .unwrap();
        for i in 1..=10 {
            sqlx::query(
                "INSERT INTO push_subscriptions(endpoint,user_id,session_hash,p256dh,auth,created_at) VALUES(?,'u1',?,'k','a','2025-01-01T00:00:00Z')",
            )
            .bind(format!("https://fcm.googleapis.com/fcm/send/ep{i}"))
            .bind(&sess_hash)
            .execute(&pool)
            .await
            .unwrap();
        }

        let state = AppState::new(pool.clone());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("sessioncookie={token}")).unwrap(),
        );
        let resp = subscribe(
            State(state),
            headers,
            Json(json!({
                "endpoint": ep0,
                "keys": {"p256dh": "AAAA", "auth": "BBBB"}
            })),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let created_at: Option<String> =
            sqlx::query_scalar("SELECT created_at FROM push_subscriptions WHERE endpoint=?")
                .bind(ep0)
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(
            created_at
                .as_deref()
                .is_some_and(|ts| ts > "2025-01-01T00:00:00Z"),
            "re-subscribed endpoint should refresh created_at and survive pruning, got {:?}",
            created_at
        );
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ------------------------------------------------------------ new logins

/// "Windows · Chrome" for a user agent, like the device list (devices.ts).
pub(crate) fn device_label(user_agent: Option<&str>) -> String {
    let ua = user_agent.unwrap_or("");
    let has = |parts: &[&str]| parts.iter().any(|part| ua.contains(part));
    if !ua.contains("Mozilla/") && has(&["CFNetwork", "Darwin"]) {
        return if ua.contains("iPad") {
            "iPad · SereS App"
        } else {
            "iPhone · SereS App"
        }
        .into();
    }
    let os = if has(&["iPhone"]) {
        "iPhone"
    } else if has(&["iPad"]) {
        "iPad"
    } else if has(&["Android", "okhttp"]) {
        "Android"
    } else if has(&["Windows"]) {
        "Windows"
    } else if has(&["CrOS"]) {
        "ChromeOS"
    } else if has(&["Mac OS X", "Macintosh"]) {
        "macOS"
    } else if has(&["Linux"]) {
        "Linux"
    } else {
        "?"
    };
    let browser = if has(&["Edg/"]) {
        "Edge"
    } else if has(&["OPR/"]) {
        "Opera"
    } else if has(&["SamsungBrowser/"]) {
        "Samsung Internet"
    } else if has(&["Firefox/", "FxiOS/"]) {
        "Firefox"
    } else if has(&["Chrome/", "CriOS/"]) {
        "Chrome"
    } else if has(&["Safari/"]) {
        "Safari"
    } else if has(&["okhttp"]) {
        "SereS App"
    } else {
        "?"
    };
    format!("{os} · {browser}")
}

/// A password login waits for the main device: tell that device (web push or
/// the iOS app), so the request isn't missed while SereS is closed there.
pub fn login_waiting(
    pool: SqlitePool,
    user_id: String,
    main_session: String,
    user_agent: Option<String>,
) {
    tokio::spawn(async move {
        let device = device_label(user_agent.as_deref());
        if let Some(key) = vapid(&pool).await {
            let open_since = (chrono::Utc::now() - chrono::Duration::seconds(OPEN_SECONDS))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let rows = sqlx::query(
                "SELECT p.endpoint,p.p256dh,p.auth FROM push_subscriptions p
                 JOIN user_sessions s ON s.token_hash=p.session_hash AND s.expires_at>?
                 WHERE p.session_hash=? AND (s.last_seen IS NULL OR s.last_seen<?)",
            )
            .bind(super::auth::now_iso())
            .bind(&main_session)
            .bind(open_since)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
            let delivery = Delivery {
                topic: Some("login".into()),
                urgency: Urgency::High,
                ttl: 15 * 60,
            };
            deliver(
                &pool,
                &key,
                rows,
                &json!({"type": "login", "device": device}),
                &delivery,
            )
            .await;
        }
        super::apns::login_waiting(&pool, &user_id, &main_session, &device).await;
    });
}
