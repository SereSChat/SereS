//! Link previews.
//!
//! The sender's browser asks for the preview of a link it is about to send;
//! the title, description and a small picture then travel inside the
//! encrypted message, so the people receiving it never contact the site.
//! The server only fetches public addresses (no local network), follows a
//! few redirects, and reads at most a small part of the page.

use super::{error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use regex::Regex;
use serde_json::json;
use sqlx::Row;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::Semaphore;
use url::Url;

const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const PREVIEW_DEADLINE: Duration = Duration::from_secs(10);

static PREVIEW_SEMAPHORE: Semaphore = Semaphore::const_new(8);

static LINK_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // A proxy would connect wherever the name points, past the check above.
        .no_proxy()
        .timeout(Duration::from_secs(6))
        .connect_timeout(Duration::from_secs(4))
        .dns_resolver(Arc::new(PublicDnsResolver))
        .user_agent("Mozilla/5.0 (compatible; SereS link preview)")
        .build()
        .expect("build link preview HTTP client")
});

struct PublicDnsResolver;

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let lookup =
                tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_str(), 0)))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup timed out")
                    })?
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let addrs: Vec<SocketAddr> = lookup.collect();
            let allow_private = std::env::var("SERES_LINK_ALLOW_PRIVATE").as_deref() == Ok("1");
            if addrs.is_empty() || (!allow_private && !addrs.iter().all(|a| is_public(a.ip()))) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Disallowed target IP",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn allowed_preview_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && matches!(url.port_or_known_default(), Some(80 | 443))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/link-preview", get(link_preview))
}

async fn link_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(user) => user,
        Err(e) => return e.into_response(),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    if state.rate_limited(format!("link-preview:{user_id}"), 30, 60) {
        return error(
            "Too many previews, try again in a minute",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let Some(url) = query
        .get("url")
        .filter(|u| u.len() <= 2048)
        .and_then(|u| Url::parse(u).ok())
        .filter(allowed_preview_url)
    else {
        return error("Invalid link", StatusCode::BAD_REQUEST);
    };
    let result = tokio::time::timeout(PREVIEW_DEADLINE, async {
        let _permit = PREVIEW_SEMAPHORE.acquire().await.map_err(|_| ())?;
        let (final_url, content_type, body) = fetch(url, MAX_HTML_BYTES).await?;
        if !content_type.starts_with("text/html") && !content_type.starts_with("application/xhtml")
        {
            return Err(());
        }
        let html = String::from_utf8_lossy(&body);
        let page = parse(&html);
        let title = page
            .meta("og:title")
            .or_else(|| page.meta("twitter:title"))
            .or(page.title.clone())
            .map(|t| clip(&t, 200));
        let Some(title) = title.filter(|t| !t.is_empty()) else {
            return Err(());
        };
        let description = page
            .meta("og:description")
            .or_else(|| page.meta("twitter:description"))
            .or_else(|| page.meta("description"))
            .map(|t| clip(&t, 300));
        let site = page.meta("og:site_name").map(|t| clip(&t, 80));
        let mut image = None;
        if let Some(src) = page
            .meta("og:image")
            .or_else(|| page.meta("og:image:url"))
            .or_else(|| page.meta("twitter:image"))
            .and_then(|src| final_url.join(&src).ok())
            .filter(allowed_preview_url)
            && let Ok((_, kind, bytes)) = fetch(src, MAX_IMAGE_BYTES).await
            && matches!(
                kind.as_str(),
                "image/png" | "image/jpeg" | "image/gif" | "image/webp"
            )
        {
            image = Some(format!(
                "data:{kind};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            ));
        }
        Ok(json!({
            "url": final_url.as_str(),
            "title": title,
            "description": description,
            "site": site,
            "image": image,
        }))
    })
    .await;
    match result {
        Ok(Ok(payload)) => json_ok(payload),
        _ => error("No preview for this link", StatusCode::NOT_FOUND),
    }
}

/// Fetches a public URL, following up to a few redirects, each one checked again.
async fn fetch(mut url: Url, limit: usize) -> Result<(Url, String, Vec<u8>), ()> {
    for _ in 0..=MAX_REDIRECTS {
        if !allowed_preview_url(&url) || url.host_str().is_none() {
            return Err(());
        }
        let mut response = LINK_CLIENT
            .get(url.clone())
            .header("Accept", "text/html,application/xhtml+xml,image/*;q=0.8")
            .send()
            .await
            .map_err(|_| ())?;
        if response.status().is_redirection() {
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|l| url.join(l).ok())
                .filter(allowed_preview_url)
                .ok_or(())?;
            url = next;
            continue;
        }
        if !response.status().is_success() {
            return Err(());
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let is_image = content_type.starts_with("image/");
        let body = read_body_limited(&mut response, is_image, limit).await?;
        return Ok((url, content_type, body));
    }
    Err(())
}

async fn read_body_limited(
    response: &mut reqwest::Response,
    is_image: bool,
    limit: usize,
) -> Result<Vec<u8>, ()> {
    let cap = if is_image { limit + 1 } else { limit };
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        let room = cap.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() >= cap {
            break;
        }
    }
    if is_image && body.len() > limit {
        return Err(());
    }
    Ok(body)
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
                || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
                || (a == 192 && b == 88 && c == 99) // deprecated 6to4 relay anycast
                || (a == 198 && (b == 18 || b == 19)) // benchmarking
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            // Allow only global unicast (2000::/3).
            if (seg[0] & 0xe000) != 0x2000 {
                return false;
            }
            // Exclude documentation (2001:db8::/32), Teredo (2001::/32), and 6to4 (2002::/16).
            if seg[0] == 0x2001 && (seg[1] == 0x0db8 || seg[1] == 0x0000) {
                return false;
            }
            if seg[0] == 0x2002 {
                return false;
            }
            true
        }
    }
}

struct Page {
    title: Option<String>,
    meta: HashMap<String, String>,
}

impl Page {
    fn meta(&self, key: &str) -> Option<String> {
        self.meta.get(key).filter(|v| !v.trim().is_empty()).cloned()
    }
}

static META_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<meta\b([^>]*)>").unwrap());
static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)([a-z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#).unwrap()
});
static TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());

fn parse(html: &str) -> Page {
    // Only the head matters.
    let head = match html.to_ascii_lowercase().find("</head>") {
        Some(end) if html.is_char_boundary(end) => &html[..end],
        _ => html,
    };
    let mut meta = HashMap::new();
    for tag in META_TAG.captures_iter(head) {
        let mut key = None;
        let mut content = None;
        for attr in ATTRIBUTE.captures_iter(&tag[1]) {
            let name = attr[1].to_ascii_lowercase();
            let value = attr
                .get(2)
                .or(attr.get(3))
                .or(attr.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");
            match name.as_str() {
                "property" | "name" => key = Some(value.to_ascii_lowercase()),
                "content" => content = Some(decode_entities(value)),
                _ => {}
            }
        }
        if let (Some(key), Some(content)) = (key, content) {
            meta.entry(key).or_insert(content);
        }
    }
    let title = TITLE.captures(head).map(|c| decode_entities(&c[1]));
    Page { title, meta }
}

fn decode_entities(text: &str) -> String {
    static ENTITY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);").unwrap());
    let decoded = ENTITY.replace_all(text, |c: &regex::Captures| {
        let name = &c[1];
        let ch = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(dec) = name.strip_prefix('#') {
            dec.parse().ok().and_then(char::from_u32)
        } else {
            match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                "auml" => Some('ä'),
                "ouml" => Some('ö'),
                "uuml" => Some('ü'),
                "Auml" => Some('Ä'),
                "Ouml" => Some('Ö'),
                "Uuml" => Some('Ü'),
                "szlig" => Some('ß'),
                "eacute" => Some('é'),
                "egrave" => Some('è'),
                "ecirc" => Some('ê'),
                "agrave" => Some('à'),
                "acirc" => Some('â'),
                "ccedil" => Some('ç'),
                "Eacute" => Some('É'),
                "ocirc" => Some('ô'),
                "icirc" => Some('î'),
                "ugrave" => Some('ù'),
                "hellip" => Some('…'),
                "mdash" => Some('—'),
                "ndash" => Some('–'),
                "laquo" => Some('«'),
                "raquo" => Some('»'),
                "lsquo" => Some('‘'),
                "rsquo" => Some('’'),
                "ldquo" => Some('“'),
                "rdquo" => Some('”'),
                "bdquo" => Some('„'),
                "copy" => Some('©'),
                "reg" => Some('®'),
                "trade" => Some('™'),
                "euro" => Some('€'),
                "middot" => Some('·'),
                _ => None,
            }
        };
        ch.map(String::from).unwrap_or_else(|| c[0].to_string())
    });
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_open_graph_and_title() {
        let page = parse(
            r#"<html><head><title>Fallback &amp; more</title>
            <meta property="og:title" content="Hello &quot;World&quot; &auml;">
            <meta content='A page' name="description">
            <meta property="og:image" content="/pic.png"></head><body><meta property="og:title" content="no"></body>"#,
        );
        assert_eq!(page.meta("og:title").as_deref(), Some("Hello \"World\" ä"));
        assert_eq!(page.meta("description").as_deref(), Some("A page"));
        assert_eq!(page.meta("og:image").as_deref(), Some("/pic.png"));
        assert_eq!(page.title.as_deref(), Some("Fallback & more"));
    }

    #[test]
    fn blocks_local_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::",
            "::1",
            "::7f00:1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001:828::200e",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn blocks_reserved_192_0_0_and_192_88_99_addresses() {
        for ip in ["192.0.0.1", "192.0.0.254", "192.88.99.1", "192.88.99.254"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn link_preview_rejects_non_80_443_ports() {
        let dir = std::env::temp_dir().join(format!("seres-links-{}", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&dir.join("users.db")).await.unwrap();
        sqlx::query("INSERT INTO users(id,username) VALUES('u1','alice')")
            .execute(&pool)
            .await
            .unwrap();
        let token = "tok-links-1";
        let hash = crate::api::auth::hash_token(token);
        sqlx::query(
            "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at,approved) VALUES(?,'u1','2999-01-01T00:00:00Z','now',1)",
        )
        .bind(hash)
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState::new(pool);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("sessioncookie={token}")).unwrap(),
        );
        let mut query = HashMap::new();
        query.insert("url".into(), "http://example.com:8080/".into());
        let resp = link_preview(State(state), headers, Query(query)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn image_body_allows_exact_limit_and_rejects_oversized() {
        let app = Router::new()
            .route("/exact", get(|| async { vec![b'a'; 16] }))
            .route("/over", get(|| async { vec![b'a'; 17] }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let mut exact_resp = client
            .get(format!("http://{addr}/exact"))
            .send()
            .await
            .unwrap();
        let exact = read_body_limited(&mut exact_resp, true, 16).await.unwrap();
        assert_eq!(exact.len(), 16);

        let mut over_resp = client
            .get(format!("http://{addr}/over"))
            .send()
            .await
            .unwrap();
        assert!(read_body_limited(&mut over_resp, true, 16).await.is_err());

        server.abort();
    }
}
