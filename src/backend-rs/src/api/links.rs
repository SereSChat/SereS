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
    sync::LazyLock,
    time::Duration,
};
use url::Url;

const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 3;

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
        .filter(|u| matches!(u.scheme(), "http" | "https"))
    else {
        return error("Invalid link", StatusCode::BAD_REQUEST);
    };
    let Ok((final_url, content_type, body)) = fetch(url, MAX_HTML_BYTES).await else {
        return error("No preview for this link", StatusCode::NOT_FOUND);
    };
    if !content_type.starts_with("text/html") && !content_type.starts_with("application/xhtml") {
        return error("No preview for this link", StatusCode::NOT_FOUND);
    }
    let html = String::from_utf8_lossy(&body);
    let page = parse(&html);
    let title = page
        .meta("og:title")
        .or_else(|| page.meta("twitter:title"))
        .or(page.title.clone())
        .map(|t| clip(&t, 200));
    let Some(title) = title.filter(|t| !t.is_empty()) else {
        return error("No preview for this link", StatusCode::NOT_FOUND);
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
        .filter(|u| matches!(u.scheme(), "http" | "https"))
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
    json_ok(json!({
        "url": final_url.as_str(),
        "title": title,
        "description": description,
        "site": site,
        "image": image,
    }))
}

/// Fetches a public URL, following up to a few redirects, each one checked again.
async fn fetch(mut url: Url, limit: usize) -> Result<(Url, String, Vec<u8>), ()> {
    for _ in 0..=MAX_REDIRECTS {
        let host = url
            .host_str()
            .ok_or(())?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = url.port_or_known_default().ok_or(())?;
        let addr = public_address(&host, port).await.ok_or(())?;
        // The checked address is used for the connection, so a second DNS
        // answer can not point somewhere else.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // A proxy would connect wherever the name points, past the check above.
            .no_proxy()
            .timeout(Duration::from_secs(6))
            .connect_timeout(Duration::from_secs(4))
            .resolve(&host, addr)
            .user_agent("Mozilla/5.0 (compatible; SereS link preview)")
            .build()
            .map_err(|_| ())?;
        let mut response = client
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
                .filter(|u| matches!(u.scheme(), "http" | "https"))
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
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            let room = limit.saturating_sub(body.len());
            body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if body.len() >= limit {
                // Pages: the head is enough. Pictures: too big, no picture.
                if content_type.starts_with("image/") {
                    return Err(());
                }
                break;
            }
        }
        return Ok((url, content_type, body));
    }
    Err(())
}

/// Resolves the host and returns an address only if all of them are public.
async fn public_address(host: &str, port: u16) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.ok()?.collect();
    let allow_private = std::env::var("SERES_LINK_ALLOW_PRIVATE").as_deref() == Ok("1");
    if addrs.is_empty() || (!allow_private && !addrs.iter().all(|a| is_public(a.ip()))) {
        return None;
    }
    addrs.first().copied()
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
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
}
