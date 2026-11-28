mod apns;
mod auth;
mod auth_extra;
mod avatars;
mod calls;
pub(crate) mod chats;
pub(crate) mod devices;
mod links;
mod password_reset;
mod profile;
pub(crate) mod push;
mod social;

use axum::{
    Json, Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use url::Url;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/online", get(online).post(online))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_app_site_association),
        )
        .merge(auth::router())
        .merge(auth_extra::router())
        .merge(avatars::router())
        .merge(chats::router())
        .merge(calls::router())
        .merge(devices::router())
        .merge(links::router())
        .merge(profile::router())
        .merge(push::router())
        .merge(apns::router())
        .merge(social::router())
}

/// Lets iOS open links to this server in the SereS app when it is installed
/// (universal links): device linking, group and friend invites. Needs the
/// Apple team id (APPLE_TEAM_ID, or APNS_TEAM_ID from the push settings) and
/// the app's bundle id (APNS_TOPIC, default net.fyralsmp.seres).
async fn apple_app_site_association() -> Response {
    let setting = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let Some(team) = setting("APPLE_TEAM_ID").or_else(|| setting("APNS_TEAM_ID")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bundle = setting("APNS_TOPIC").unwrap_or_else(|| "net.fyralsmp.seres".into());
    let components: Vec<Value> = ["link", "join", "invite"]
        .iter()
        .map(|name| json!({"/": "/", "?": {*name: "?*"}, "comment": format!("?{name}=…")}))
        .collect();
    let body = json!({
        "applinks": {"details": [{"appIDs": [format!("{team}.{bundle}")], "components": components}]}
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn online() -> Response {
    Json(json!({"message":"im up", "success":true})).into_response()
}

pub async fn security_middleware(mut request: Request<Body>, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let is_https = match prepare_security_request(&mut request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let mut response = next.run(request).await;
    apply_security_headers(&mut response, is_api, is_https);
    response
}

fn prepare_security_request(request: &mut Request<Body>) -> Result<bool, Response> {
    let is_loopback = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
    if !is_loopback {
        for name in [
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-for",
            "cf-connecting-ip",
            "x-real-ip",
        ] {
            request.headers_mut().remove(name);
        }
    }
    let is_https = request
        .uri()
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        || (is_loopback && forwarded_proto_is_https(request.headers()));
    let method = request.method().clone();
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        && let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        && !origin_allowed(request.headers(), origin)
    {
        return Err(error("Cross-site request rejected", StatusCode::FORBIDDEN));
    }
    Ok(is_https)
}

fn apply_security_headers(response: &mut Response, is_api: bool, is_https: bool) {
    let headers = response.headers_mut();
    headers.entry("Content-Security-Policy").or_insert(HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https://tile.openstreetmap.org; media-src 'self' blob:; object-src 'self'; frame-src 'self'; connect-src 'self' https: wss: http://localhost:* http://127.0.0.1:* http://[::1]:*; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"));
    headers
        .entry("X-Content-Type-Options")
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry("Referrer-Policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("X-Frame-Options")
        .or_insert(HeaderValue::from_static("SAMEORIGIN"));
    headers
        .entry("Permissions-Policy")
        .or_insert(HeaderValue::from_static(
            "camera=(self), microphone=(self), display-capture=(self), geolocation=(self)",
        ));
    if is_https {
        headers
            .entry("Strict-Transport-Security")
            .or_insert(HeaderValue::from_static("max-age=31536000"));
    }
    if is_api {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    } else {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-cache"));
    }
}

fn forwarded_proto_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
}

pub(crate) fn is_https_with(headers: &HeaderMap, public_url: Option<&str>) -> bool {
    forwarded_proto_is_https(headers)
        || public_url.is_some_and(|value| value.trim().to_ascii_lowercase().starts_with("https://"))
}

pub(crate) fn is_https(headers: &HeaderMap) -> bool {
    is_https_with(headers, std::env::var("PUBLIC_URL").ok().as_deref())
}

pub(crate) fn normalize_host_port(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains([',', '@', '/', '\\', '?', '#'])
    {
        return None;
    }
    let parsed = Url::parse(&format!("http://{trimmed}")).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

pub(crate) fn is_loopback_host(host_port: &str) -> bool {
    let Ok(parsed) = Url::parse(&format!("http://{host_port}")) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub(crate) fn first_header_host(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(normalize_host_port)
}

fn allowed_hosts_with(
    headers: &HeaderMap,
    public_url: Option<&str>,
    extra_hosts: Option<&str>,
) -> HashSet<String> {
    let has_public = public_url.is_some_and(|v| !v.trim().is_empty());
    let has_extra = extra_hosts.is_some_and(|v| !v.trim().is_empty());
    if has_public || has_extra {
        let mut allowed = HashSet::new();
        if let Some(url) = public_url
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .and_then(|v| Url::parse(v).ok())
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            && let Some(host) = url.host_str()
        {
            let authority = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            };
            allowed.insert(authority.to_ascii_lowercase());
        }
        if let Some(extra) = extra_hosts {
            allowed.extend(extra.split(',').filter_map(normalize_host_port));
        }
        return allowed;
    }
    let mut allowed = HashSet::new();
    for name in ["host", "x-forwarded-host"] {
        if let Some(host) = first_header_host(headers, name) {
            allowed.insert(host);
        }
    }
    allowed
}

fn origin_allowed_with(
    headers: &HeaderMap,
    origin: &str,
    public_url: Option<&str>,
    extra_hosts: Option<&str>,
) -> bool {
    Url::parse(origin)
        .ok()
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(url.path(), "" | "/")
                && url.query().is_none()
                && url.fragment().is_none()
                && url.host_str().is_some()
        })
        .is_some_and(|url| {
            allowed_hosts_with(headers, public_url, extra_hosts)
                .iter()
                .any(|host| {
                    Url::parse(&format!("{}://{host}", url.scheme()))
                        .ok()
                        .is_some_and(|allowed| {
                            allowed.host_str() == url.host_str()
                                && allowed.port_or_known_default() == url.port_or_known_default()
                        })
                })
        })
}

fn origin_allowed(headers: &HeaderMap, origin: &str) -> bool {
    origin_allowed_with(
        headers,
        origin,
        std::env::var("PUBLIC_URL").ok().as_deref(),
        std::env::var("SERES_ALLOWED_HOSTS").ok().as_deref(),
    )
}

/// Forwarded addresses are accepted only from the local reverse proxy.
pub(crate) fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        for name in ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"] {
            if let Some(ip) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
    }
    peer.ip()
}

pub fn json_ok(value: Value) -> Response {
    let mut body = value.as_object().cloned().unwrap_or_default();
    body.insert("success".into(), Value::Bool(true));
    json_response(StatusCode::OK, Value::Object(body))
}

pub fn error(message: impl Into<String>, status: StatusCode) -> Response {
    json_response(status, json!({"message": message.into(), "success": false}))
}

#[derive(Debug)]
pub struct ApiError {
    message: String,
    status: StatusCode,
}

impl ApiError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error(self.message, self.status)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn json_response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

pub fn str_field<'a>(body: &'a Value, name: &str, max_len: usize) -> ApiResult<&'a str> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.chars().count() <= max_len)
        .ok_or_else(|| {
            ApiError::new(
                format!("Missing or invalid '{name}'"),
                StatusCode::BAD_REQUEST,
            )
        })
}

pub fn b64_field<'a>(body: &'a Value, name: &str, max_len: usize) -> ApiResult<&'a str> {
    let value = str_field(body, name, max_len)?;
    let unpadded = value.trim_end_matches('=');
    let padding = value.len() - unpadded.len();
    let valid = padding <= 2
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b));
    if !valid {
        return Err(ApiError::new(
            format!("Invalid encoding of '{name}'"),
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_checks_preserve_ports_and_support_ipv6_and_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:2222".parse().unwrap());
        assert!(origin_allowed(&headers, "http://localhost:2222"));
        assert!(!origin_allowed(&headers, "http://localhost:3333"));
        assert!(!origin_allowed(&headers, "http://other.example:2222"));
        assert!(!origin_allowed(&headers, "null"));
        headers.insert("host", "[::1]:2222".parse().unwrap());
        assert!(origin_allowed(&headers, "http://[::1]:2222"));
        headers.insert("x-forwarded-host", "chat.example:443".parse().unwrap());
        assert!(origin_allowed(&headers, "https://chat.example"));
        assert!(!origin_allowed(&headers, "https://chat.example:444"));
    }

    #[tokio::test]
    async fn proxy_clients_have_independent_limits_and_remote_headers_are_ignored() {
        let peer = "127.0.0.1:9000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.2".parse().unwrap(),
        );
        let ip = client_ip(&headers, peer);
        assert_eq!(ip.to_string(), "203.0.113.2");
        // Client-supplied CF-Connecting-IP must NOT override the default header behind Nginx/Caddy.
        headers.insert("cf-connecting-ip", "203.0.113.3".parse().unwrap());
        assert_eq!(client_ip(&headers, peer).to_string(), "203.0.113.2");

        // Multi-header X-Forwarded-For uses the last appended header (next_back).
        headers.append(
            "x-forwarded-for",
            "198.51.100.9, 203.0.113.4".parse().unwrap(),
        );
        let other_ip = client_ip(&headers, peer);
        assert_eq!(other_ip.to_string(), "203.0.113.4");

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let state = AppState::new(pool);
        assert!(!state.rate_limited(format!("login-ip:{ip}"), 1, 60));
        assert!(state.rate_limited(format!("login-ip:{ip}"), 1, 60));
        assert!(!state.rate_limited(format!("login-ip:{other_ip}"), 1, 60));
        let remote = "198.51.100.10:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, remote), remote.ip());
    }

    #[test]
    fn origin_allowed_hardens_configured_and_malformed_hosts() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.com@good.example".parse().unwrap());
        assert!(!origin_allowed_with(
            &headers,
            "https://good.example",
            None,
            None
        ));
        headers.insert("host", "evil.com".parse().unwrap());
        headers.insert("x-forwarded-host", "evil.com".parse().unwrap());
        assert!(origin_allowed_with(
            &headers,
            "https://chat.example",
            Some("https://chat.example"),
            None,
        ));
        assert!(!origin_allowed_with(
            &headers,
            "https://evil.com",
            Some("https://chat.example"),
            None,
        ));
        assert!(origin_allowed_with(
            &headers,
            "https://alt.example:8443",
            Some("https://chat.example"),
            Some("alt.example:8443"),
        ));
        assert!(!origin_allowed_with(
            &headers,
            "https://chat.example/path",
            Some("https://chat.example"),
            None,
        ));
    }

    #[tokio::test]
    async fn security_middleware_strips_untrusted_headers_and_sets_csp_hsts() {
        // 1. Non-loopback peer: forwarded headers stripped, no HSTS, spoofed origin rejected.
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/echo")
            .header("host", "chat.example")
            .header("origin", "https://evil.example")
            .header("x-forwarded-host", "evil.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "1.2.3.4")
            .header("cf-connecting-ip", "1.2.3.4")
            .header("x-real-ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.10:1234".parse::<SocketAddr>().unwrap(),
        ));
        let err_resp = prepare_security_request(&mut req).unwrap_err();
        assert_eq!(err_resp.status(), StatusCode::FORBIDDEN);
        assert!(
            err_resp
                .headers()
                .get("Strict-Transport-Security")
                .is_none()
        );

        let mut req = Request::builder()
            .method("POST")
            .uri("/api/echo")
            .header("host", "chat.example")
            .header("origin", "https://chat.example")
            .header("x-forwarded-host", "evil.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "1.2.3.4")
            .header("cf-connecting-ip", "1.2.3.4")
            .header("x-real-ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.10:1234".parse::<SocketAddr>().unwrap(),
        ));
        let is_https = prepare_security_request(&mut req).unwrap();
        assert!(!is_https);
        for name in [
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-for",
            "cf-connecting-ip",
            "x-real-ip",
        ] {
            assert!(req.headers().get(name).is_none());
        }
        let mut resp = json_ok(json!({}));
        apply_security_headers(&mut resp, true, is_https);
        assert!(resp.headers().get("Strict-Transport-Security").is_none());

        // 2. End-to-end Axum middleware over loopback TCP: forwarded headers preserved, CSP + HSTS set.
        async fn echo_headers(headers: HeaderMap) -> Response {
            let forwarded = headers.contains_key("x-forwarded-host")
                && headers.contains_key("x-forwarded-proto");
            json_ok(json!({ "forwarded": forwarded }))
        }
        let app = Router::new()
            .route("/api/echo", axum::routing::post(echo_headers))
            .layer(axum::middleware::from_fn(security_middleware));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::new();
        let res = client
            .post(format!("http://{addr}/api/echo"))
            .header("origin", "https://chat.example")
            .header("x-forwarded-host", "chat.example")
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("Strict-Transport-Security")
                .and_then(|v| v.to_str().ok()),
            Some("max-age=31536000")
        );
        let csp = res
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(csp.contains(
            "connect-src 'self' https: wss: http://localhost:* http://127.0.0.1:* http://[::1]:*"
        ));
        let bytes = res.bytes().await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["forwarded"], true);
        server.abort();
    }
}
