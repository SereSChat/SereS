//! APNs: notifications for the native iOS app, which can't use web push.
//!
//! The app registers its device tokens with Apple's push service: one for
//! normal notifications ("alert") and one for incoming calls ("voip"). Like a
//! web push subscription, a token belongs to the device's session, so logging
//! out (or a password reset that ends all sessions) stops its notifications.
//! The server only sends who wrote or calls; message texts stay end-to-end
//! encrypted and never leave the app.
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
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::sync::OnceLock;

const DEFAULT_TOPIC: &str = "net.fyralsmp.seres";
/// An alert and a VoIP token for each of the newest devices of an account.
const MAX_TOKENS_PER_USER: i64 = 20;

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
    (value.len() >= 64 && value.len() <= 200 && value.len() % 2 == 0)
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
