//! Header hygiene in both directions. Requests lose hop-by-hop and spoofable
//! forwarding headers; responses lose hop-by-hop headers, server banners and
//! anything that would reveal overlay addresses or internal names.

use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use std::net::{IpAddr, SocketAddr};

pub const SESSION_COOKIE: &str = "__Host-blaktail-ingress";
pub const FLOW_COOKIE: &str = "__Host-blaktail-ingress-flow";
pub const USER_HEADER: &str = "x-blaktail-user";

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const CLIENT_SUPPLIED_FORWARDING: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
];

const RESPONSE_BANNERS: &[&str] = &[
    "server",
    "x-powered-by",
    "via",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-backend-server",
    "x-served-by",
    "x-upstream",
    "x-forwarded-for",
    "x-real-ip",
];

fn connection_named(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in connection_named(headers) {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// True for a WebSocket upgrade request.
pub fn is_websocket(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"));
    let connection = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    upgrade && connection
}

/// Removes this ingress's own cookies so the upstream never sees them.
fn strip_ingress_cookies(headers: &mut HeaderMap) {
    let kept: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && !pair.starts_with("__Host-blaktail-ingress"))
        .map(str::to_owned)
        .collect();
    headers.remove(header::COOKIE);
    if !kept.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&kept.join("; ")) {
            headers.insert(header::COOKIE, value);
        }
    }
}

pub fn upstream_request_headers(
    incoming: &HeaderMap,
    fqdn: &str,
    client: IpAddr,
    websocket: bool,
    user: Option<&str>,
) -> HeaderMap {
    let mut headers = incoming.clone();
    strip_hop_by_hop(&mut headers);
    for name in CLIENT_SUPPLIED_FORWARDING {
        headers.remove(*name);
    }
    let blaktail: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-blaktail-"))
        .cloned()
        .collect();
    for name in blaktail {
        headers.remove(name);
    }
    strip_ingress_cookies(&mut headers);
    headers.remove(header::HOST);
    if let Ok(host) = HeaderValue::from_str(fqdn) {
        headers.insert(header::HOST, host.clone());
        headers.insert("x-forwarded-host", host);
    }
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client.to_string()).expect("IP address is a valid header"),
    );
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if websocket {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    }
    if let Some(user) = user.and_then(|u| HeaderValue::from_str(u).ok()) {
        headers.insert(USER_HEADER, user);
    }
    headers
}

/// Whether a header value would reveal an overlay address or internal name.
pub fn leaks(value: &str, target: SocketAddr) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains(".blaktail") || lower.contains(&target.ip().to_string()) {
        return true;
    }
    lower
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|token| token.len() >= 3)
        .any(|token| {
            // `[fd00::1]:80` and `100.64.0.2:8080` both reduce to the address.
            let candidates = [
                token,
                token.rsplit_once(':').map_or(token, |(host, _)| host),
            ];
            candidates
                .iter()
                .filter_map(|t| {
                    t.trim_matches(|c| c == ':' || c == '.')
                        .parse::<IpAddr>()
                        .ok()
                })
                .any(internal_ip)
        })
}

fn internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            (a == 100 && (64..128).contains(&b)) || v4.is_loopback() || v4.is_link_local()
        }
        // Unique-local (fc00::/7) carries the overlay's IPv6 addresses.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_loopback(),
    }
}

/// Rewrites a redirect that points back at the target (or any internal
/// host) onto the public name. Redirects are returned to the client, never
/// followed by the ingress.
fn rewrite_location(value: &str, fqdn: &str, target: SocketAddr) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    let host = url.host_str()?.trim_matches(|c| c == '[' || c == ']');
    let internal = host.eq_ignore_ascii_case(fqdn)
        || host.parse::<IpAddr>().is_ok_and(internal_ip)
        || host.to_ascii_lowercase().ends_with(".blaktail")
        || host == target.ip().to_string();
    if !internal {
        return None;
    }
    let mut rewritten = format!("https://{fqdn}{}", url.path());
    if let Some(query) = url.query() {
        rewritten.push('?');
        rewritten.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        rewritten.push('#');
        rewritten.push_str(fragment);
    }
    Some(rewritten)
}

pub fn client_response_headers(
    upstream: &HeaderMap,
    fqdn: &str,
    target: SocketAddr,
    upgrade: bool,
) -> HeaderMap {
    let mut headers = upstream.clone();
    let upgrade_value = headers.get(header::UPGRADE).cloned();
    strip_hop_by_hop(&mut headers);
    for name in RESPONSE_BANNERS {
        headers.remove(*name);
    }
    for name in [header::LOCATION, header::CONTENT_LOCATION] {
        let rewritten = headers
            .get(&name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| rewrite_location(v, fqdn, target))
            .and_then(|v| HeaderValue::from_str(&v).ok());
        if let Some(value) = rewritten {
            headers.insert(name, value);
        }
    }
    let leaking: Vec<HeaderName> = headers
        .iter()
        .filter(|(_, value)| {
            value
                .to_str()
                .map(|v| leaks(v, target))
                // Opaque bytes cannot be checked; drop them.
                .unwrap_or(true)
        })
        .map(|(name, _)| name.clone())
        .collect();
    for name in leaking {
        headers.remove(name);
    }
    if upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(
            header::UPGRADE,
            upgrade_value.unwrap_or(HeaderValue::from_static("websocket")),
        );
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddr {
        "100.64.0.7:8080".parse().unwrap()
    }

    #[test]
    fn requests_lose_spoofable_and_hop_by_hop_headers() {
        let mut incoming = HeaderMap::new();
        incoming.insert("host", "evil.example".parse().unwrap());
        incoming.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        incoming.insert("x-real-ip", "10.0.0.1".parse().unwrap());
        incoming.insert("forwarded", "for=10.0.0.1".parse().unwrap());
        incoming.insert("x-blaktail-user", "admin@example.org.au".parse().unwrap());
        incoming.insert("connection", "keep-alive, x-secret".parse().unwrap());
        incoming.insert("x-secret", "1".parse().unwrap());
        incoming.insert("proxy-authorization", "Basic abc".parse().unwrap());
        incoming.insert(
            "cookie",
            "a=1; __Host-blaktail-ingress=signed; b=2".parse().unwrap(),
        );
        incoming.insert("accept", "text/html".parse().unwrap());
        let out = upstream_request_headers(
            &incoming,
            "app.example.org.au",
            "203.0.113.9".parse().unwrap(),
            false,
            None,
        );
        assert_eq!(out["host"], "app.example.org.au");
        assert_eq!(out["x-forwarded-for"], "203.0.113.9");
        assert_eq!(out["x-forwarded-proto"], "https");
        assert_eq!(out["cookie"], "a=1; b=2");
        assert_eq!(out["accept"], "text/html");
        for gone in [
            "x-real-ip",
            "forwarded",
            "x-blaktail-user",
            "connection",
            "x-secret",
            "proxy-authorization",
        ] {
            assert!(!out.contains_key(gone), "{gone} survived");
        }
    }

    #[test]
    fn responses_never_reveal_overlay_addresses_or_internal_names() {
        let mut upstream = HeaderMap::new();
        upstream.insert("server", "nginx/1.2 (office-box)".parse().unwrap());
        upstream.insert("x-powered-by", "PHP".parse().unwrap());
        upstream.insert(
            "location",
            "http://100.64.0.7:8080/login?next=/".parse().unwrap(),
        );
        upstream.insert("x-debug-peer", "100.65.1.2".parse().unwrap());
        upstream.insert("x-node", "app.12345678.blaktail".parse().unwrap());
        upstream.insert("x-v6", "[fd12:3456::9]:80".parse().unwrap());
        upstream.insert(
            "set-cookie",
            "sid=1; Domain=app.12345678.blaktail".parse().unwrap(),
        );
        upstream.insert("content-type", "text/html".parse().unwrap());
        upstream.insert("x-request-id", "abc-123".parse().unwrap());
        upstream.insert("date", "Sat, 03 Oct 2026 00:00:00 GMT".parse().unwrap());
        upstream.insert("transfer-encoding", "chunked".parse().unwrap());
        let out = client_response_headers(&upstream, "app.example.org.au", target(), false);
        assert_eq!(out["location"], "https://app.example.org.au/login?next=/");
        assert_eq!(out["content-type"], "text/html");
        assert_eq!(out["x-request-id"], "abc-123");
        assert!(out.contains_key("date"));
        for gone in [
            "server",
            "x-powered-by",
            "x-debug-peer",
            "x-node",
            "x-v6",
            "set-cookie",
            "transfer-encoding",
        ] {
            assert!(!out.contains_key(gone), "{gone} survived");
        }
        for (_, value) in &out {
            assert!(!leaks(value.to_str().unwrap(), target()));
        }
    }

    #[test]
    fn external_redirects_pass_through_unchanged() {
        let mut upstream = HeaderMap::new();
        upstream.insert(
            "location",
            "https://login.example.org.au/authorize?x=1"
                .parse()
                .unwrap(),
        );
        let out = client_response_headers(&upstream, "app.example.org.au", target(), false);
        assert_eq!(
            out["location"],
            "https://login.example.org.au/authorize?x=1"
        );
        let mut relative = HeaderMap::new();
        relative.insert("location", "/next".parse().unwrap());
        let out = client_response_headers(&relative, "app.example.org.au", target(), false);
        assert_eq!(out["location"], "/next");
    }

    #[test]
    fn leak_detection_ignores_public_addresses() {
        assert!(!leaks("203.0.113.5", target()));
        assert!(!leaks("max-age=100", target()));
        assert!(leaks("100.64.0.1", target()));
        assert!(leaks("upstream=127.0.0.1:9000", target()));
        assert!(leaks("169.254.169.254", target()));
    }

    #[test]
    fn websocket_detection_needs_both_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        assert!(!is_websocket(&headers));
        headers.insert("connection", "keep-alive, Upgrade".parse().unwrap());
        assert!(is_websocket(&headers));
    }
}
