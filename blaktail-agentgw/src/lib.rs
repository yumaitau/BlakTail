//! BlakTail agent network gateway: an OpenAI-compatible proxy that runs on an
//! enrolled node and is reached only over the overlay.
//!
//! Every request is authorised by the coordinator (agent key, device binding,
//! size, model allowlist, offshore policy, daily quota). The gateway then
//! applies the key's redaction patterns, forwards to the granted upstream and
//! reports token usage back. Provider credentials and agent keys are never
//! logged: they only travel inside [`Secret`], whose `Debug` is redacted.

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Matches the coordinator's hard cap; per-key limits are lower.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_UPSTREAM_RESPONSE: usize = 16 * 1024 * 1024;
const MAX_LOGGED_CHARS: usize = 256 * 1024;
const NON_STREAM_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_PORT: u16 = 8686;

/// A value that must never reach logs, errors or debug output.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The subset of `blaktaild`'s `state.json` the gateway needs.
#[derive(Deserialize)]
pub struct NodeIdentity {
    pub node_id: Uuid,
    pub node_token: Secret,
    pub coord: String,
    #[serde(default)]
    pub assigned_ip: String,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("coord", &self.coord)
            .field("assigned_ip", &self.assigned_ip)
            .finish_non_exhaustive()
    }
}

/// The gateway must never listen publicly. Loopback, the BlakTail overlay
/// (100.64.0.0/10, fd7a:115c:a1e0::/48) and this node's own overlay address
/// are allowed; RFC 1918 / ULA only with an explicit lab flag; never the
/// unspecified address.
pub fn check_listen(
    ip: IpAddr,
    assigned: Option<IpAddr>,
    allow_private: bool,
) -> Result<(), String> {
    if ip.is_unspecified() {
        return Err(
            "refusing to listen on every interface; bind the node's overlay address".into(),
        );
    }
    let overlay = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64,
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    };
    if ip.is_loopback() || overlay || Some(ip) == assigned {
        return Ok(());
    }
    let private = match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if private && allow_private {
        return Ok(());
    }
    Err(format!(
        "{ip} is not an overlay or loopback address; the agent gateway is never public"
    ))
}

pub struct GatewayConfig {
    pub coordinator_url: String,
    pub node_id: Uuid,
    pub node_token: Secret,
    pub coord_ca_pem: Option<Vec<u8>>,
}

pub struct Gateway {
    coord: String,
    node_id: Uuid,
    node_token: Secret,
    coord_client: reqwest::Client,
    upstream: reqwest::Client,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Result<Self, String> {
        let mut coord = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(pem) = &config.coord_ca_pem {
            let ca = reqwest::Certificate::from_pem(pem)
                .map_err(|_| "coordinator CA is not valid PEM".to_string())?;
            coord = coord.add_root_certificate(ca);
        }
        // Redirects could steer a credential-bearing request somewhere the
        // coordinator never validated.
        let upstream = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("upstream client: {e}"))?;
        Ok(Self {
            coord: config.coordinator_url.trim_end_matches('/').to_owned(),
            node_id: config.node_id,
            node_token: config.node_token,
            coord_client: coord
                .build()
                .map_err(|e| format!("coordinator client: {e}"))?,
            upstream,
        })
    }

    async fn coord_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        let response = self
            .coord_client
            .post(format!(
                "{}/v1/nodes/{}/agent-gateway/{path}",
                self.coord, self.node_id
            ))
            .bearer_auth(self.node_token.expose())
            .json(body)
            .send()
            .await
            .map_err(|_| "coordinator unreachable".to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("coordinator refused the gateway ({status})"));
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return serde_json::from_value(Value::Null).map_err(|_| "unexpected reply".into());
        }
        response
            .json()
            .await
            .map_err(|_| "coordinator sent an unreadable reply".to_string())
    }
}

pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .fallback(|| async {
            openai_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "this gateway serves /v1/chat/completions and /v1/models",
            )
        })
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(gateway)
}

fn openai_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error": {"message": message, "type": code, "code": code}})),
    )
        .into_response()
}

fn api_key(headers: &HeaderMap) -> Option<Secret> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(Secret::new)
}

fn client_ip(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6))
            .to_string(),
        ip => ip.to_string(),
    }
}

#[derive(Deserialize)]
struct Denial {
    status: u16,
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct Upstream {
    base_url: String,
    credential: Option<Secret>,
    data_location: String,
    residency: String,
}

#[derive(Deserialize)]
struct Grant {
    request_id: Uuid,
    model: String,
    provider: Upstream,
    logging_mode: String,
    redact_patterns: Vec<String>,
}

#[derive(Deserialize)]
struct Decision {
    #[serde(default)]
    denial: Option<Denial>,
    #[serde(default)]
    grant: Option<Grant>,
}

#[derive(Deserialize)]
struct ModelEntry {
    id: String,
    provider: String,
    data_location: String,
    residency: String,
}

#[derive(Deserialize)]
struct ModelList {
    #[serde(default)]
    denial: Option<Denial>,
    #[serde(default)]
    models: Vec<ModelEntry>,
}

fn denied(denial: &Denial) -> Response {
    openai_error(
        StatusCode::from_u16(denial.status).unwrap_or(StatusCode::FORBIDDEN),
        &denial.code,
        &denial.message,
    )
}

fn unavailable() -> Response {
    openai_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "gateway_unavailable",
        "the gateway cannot reach the BlakTail coordinator; requests fail closed",
    )
}

async fn list_models(
    State(gw): State<Arc<Gateway>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(key) = api_key(&headers) else {
        return openai_error(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "send an agent key as a Bearer token",
        );
    };
    let list: ModelList = match gw
        .coord_post(
            "models",
            &json!({"api_key": key.expose(), "client_ip": client_ip(addr)}),
        )
        .await
    {
        Ok(list) => list,
        Err(_) => return unavailable(),
    };
    if let Some(denial) = &list.denial {
        return denied(denial);
    }
    let data: Vec<Value> = list
        .models
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "object": "model",
                "created": 0,
                "owned_by": m.provider,
                "blaktail": {"data_location": m.data_location, "residency": m.residency},
            })
        })
        .collect();
    Json(json!({"object": "list", "data": data})).into_response()
}

/// Replaces matches in message text with `[REDACTED]`; returns the count.
pub fn redact(body: &mut Value, patterns: &[Regex]) -> usize {
    if patterns.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut scrub = |text: &mut String| {
        for pattern in patterns {
            let matches = pattern.find_iter(text).count();
            if matches > 0 {
                count += matches;
                *text = pattern.replace_all(text, "[REDACTED]").into_owned();
            }
        }
    };
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            match message.get_mut("content") {
                Some(Value::String(text)) => scrub(text),
                Some(Value::Array(parts)) => {
                    for part in parts {
                        if let Some(Value::String(text)) = part.get_mut("text") {
                            scrub(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    count
}

#[derive(Default, Serialize)]
struct UsageReport {
    request_id: Uuid,
    status: &'static str,
    http_status: Option<u16>,
    prompt_tokens: i64,
    completion_tokens: i64,
    usage_estimated: bool,
    latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_content: Option<String>,
}

fn record(gw: Arc<Gateway>, report: UsageReport) {
    tokio::spawn(async move {
        for attempt in 0..2 {
            match gw.coord_post::<Value>("usage", &report).await {
                Ok(_) => return,
                Err(error) if attempt == 0 => {
                    tracing::warn!(request_id = %report.request_id, %error, "usage report failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(error) => {
                    tracing::warn!(request_id = %report.request_id, %error, "usage report lost")
                }
            }
        }
    });
}

fn estimate(chars: usize) -> i64 {
    i64::try_from(chars.div_ceil(4)).unwrap_or(i64::MAX)
}

fn usage_of(value: &Value) -> Option<(i64, i64)> {
    let usage = value.get("usage")?;
    Some((
        usage.get("prompt_tokens")?.as_i64()?,
        usage
            .get("completion_tokens")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    ))
}

async fn chat_completions(
    State(gw): State<Arc<Gateway>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let Some(key) = api_key(&headers) else {
        return openai_error(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "send an agent key as a Bearer token",
        );
    };
    let Ok(mut request) = serde_json::from_slice::<Value>(&body) else {
        return openai_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must be a JSON chat completion request",
        );
    };
    let Some(model) = request
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return openai_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "model is required",
        );
    };
    let stream = request
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let decision: Decision = match gw
        .coord_post(
            "authorize",
            &json!({
                "api_key": key.expose(),
                "model": model,
                "client_ip": client_ip(addr),
                "request_bytes": body.len(),
            }),
        )
        .await
    {
        Ok(decision) => decision,
        Err(_) => return unavailable(),
    };
    let grant = match (decision.grant, decision.denial) {
        (Some(grant), _) => grant,
        (None, Some(denial)) => {
            tracing::info!(code = %denial.code, "agent request denied");
            return denied(&denial);
        }
        (None, None) => return unavailable(),
    };
    let patterns: Vec<Regex> = grant
        .redact_patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    if patterns.len() != grant.redact_patterns.len() {
        // Fail closed: never forward text a configured pattern should hide.
        record(
            gw.clone(),
            UsageReport {
                request_id: grant.request_id,
                status: "error",
                ..Default::default()
            },
        );
        return openai_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "redaction_failed",
            "a redaction pattern could not be compiled",
        );
    }
    let redactions = redact(&mut request, &patterns);
    request["model"] = Value::String(grant.model.clone());
    if stream {
        request["stream_options"] = json!({"include_usage": true});
    }
    let full = grant.logging_mode == "full";
    let logged_request = full.then(|| {
        request
            .to_string()
            .chars()
            .take(MAX_LOGGED_CHARS)
            .collect::<String>()
    });
    let request_chars = body.len();
    let mut upstream = gw
        .upstream
        .post(format!("{}/chat/completions", grant.provider.base_url))
        .json(&request);
    if let Some(credential) = &grant.provider.credential {
        upstream = upstream.bearer_auth(credential.expose());
    }
    tracing::info!(
        request_id = %grant.request_id,
        model = %grant.model,
        residency = %grant.provider.residency,
        stream,
        redactions,
        "forwarding agent request"
    );
    let location = HeaderValue::from_str(&grant.provider.data_location).ok();
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(_) => {
            record(
                gw.clone(),
                UsageReport {
                    request_id: grant.request_id,
                    status: "error",
                    http_status: Some(502),
                    latency_ms: Some(elapsed(started)),
                    ..Default::default()
                },
            );
            return openai_error(
                StatusCode::BAD_GATEWAY,
                "upstream_unreachable",
                "the model provider could not be reached",
            );
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok());
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(location) = location {
        builder = builder.header("x-blaktail-data-location", location);
    }
    builder = builder.header("x-blaktail-request-id", grant.request_id.to_string());

    if stream && status.is_success() {
        let tap = Arc::new(Mutex::new(SseTap::default()));
        let finisher = Finisher {
            gw: gw.clone(),
            tap: tap.clone(),
            request_id: grant.request_id,
            http_status: status.as_u16(),
            started,
            request_chars,
            logged_request,
            full,
        };
        let body = response.bytes_stream().map(move |chunk| {
            let _keep_alive = &finisher;
            let mut tap = tap.lock().unwrap_or_else(|e| e.into_inner());
            match &chunk {
                Ok(bytes) => tap.feed(bytes, full),
                Err(_) => tap.failed = true,
            }
            chunk
        });
        return builder
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from_stream(body))
            .unwrap_or_else(|_| unavailable());
    }

    let bytes = match tokio::time::timeout(NON_STREAM_TIMEOUT, read_capped(response)).await {
        Ok(Ok(bytes)) => bytes,
        _ => {
            record(
                gw.clone(),
                UsageReport {
                    request_id: grant.request_id,
                    status: "error",
                    http_status: Some(502),
                    latency_ms: Some(elapsed(started)),
                    ..Default::default()
                },
            );
            return openai_error(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "the model provider response was too large or timed out",
            );
        }
    };
    let parsed: Option<Value> = serde_json::from_slice(&bytes).ok();
    let answer = parsed
        .as_ref()
        .and_then(|v| v.pointer("/choices/0/message/content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let (prompt_tokens, completion_tokens, estimated) = match parsed.as_ref().and_then(usage_of) {
        Some((p, c)) => (p, c, false),
        None if status.is_success() => (
            estimate(request_chars),
            estimate(answer.chars().count()),
            true,
        ),
        None => (0, 0, false),
    };
    record(
        gw.clone(),
        UsageReport {
            request_id: grant.request_id,
            status: if status.is_success() { "ok" } else { "error" },
            http_status: Some(status.as_u16()),
            prompt_tokens,
            completion_tokens,
            usage_estimated: estimated,
            latency_ms: Some(elapsed(started)),
            response_content: full.then(|| answer.chars().take(MAX_LOGGED_CHARS).collect()),
            request_content: logged_request,
        },
    );
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| unavailable())
}

fn elapsed(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

async fn read_capped(response: reqwest::Response) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if out.len() + chunk.len() > MAX_UPSTREAM_RESPONSE {
            return Err(());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Watches an SSE stream as it passes through, unchanged, for the usage
/// chunk and (only under full logging) the assistant text.
#[derive(Default)]
pub struct SseTap {
    pending: Vec<u8>,
    pub usage: Option<(i64, i64)>,
    pub text: String,
    pub done: bool,
    pub failed: bool,
}

impl SseTap {
    pub fn feed(&mut self, bytes: &[u8], keep_text: bool) {
        self.pending.extend_from_slice(bytes);
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let Ok(line) = std::str::from_utf8(&line) else {
                continue;
            };
            let Some(data) = line.trim().strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data == "[DONE]" {
                self.done = true;
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(usage) = usage_of(&value) {
                self.usage = Some(usage);
            }
            if let Some(delta) = value
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
            {
                if keep_text {
                    if self.text.len() < MAX_LOGGED_CHARS {
                        self.text.push_str(delta);
                    }
                } else {
                    // Count characters only, for an estimate if no usage arrives.
                    self.text.extend(std::iter::repeat_n(
                        ' ',
                        delta.chars().count().min(MAX_LOGGED_CHARS),
                    ));
                }
            }
        }
        // A runaway line without newlines is not SSE; stop buffering it.
        if self.pending.len() > MAX_LOGGED_CHARS {
            self.pending.clear();
        }
    }
}

/// Reports usage when the streamed body is dropped: finished, failed, or
/// abandoned by the client.
struct Finisher {
    gw: Arc<Gateway>,
    tap: Arc<Mutex<SseTap>>,
    request_id: Uuid,
    http_status: u16,
    started: Instant,
    request_chars: usize,
    logged_request: Option<String>,
    full: bool,
}

impl Drop for Finisher {
    fn drop(&mut self) {
        let tap = std::mem::take(&mut *self.tap.lock().unwrap_or_else(|e| e.into_inner()));
        let (prompt_tokens, completion_tokens, estimated) = match tap.usage {
            Some((p, c)) => (p, c, false),
            None => (
                estimate(self.request_chars),
                estimate(tap.text.chars().count()),
                true,
            ),
        };
        let report = UsageReport {
            request_id: self.request_id,
            status: if tap.done && !tap.failed {
                "ok"
            } else {
                "error"
            },
            http_status: Some(self.http_status),
            prompt_tokens,
            completion_tokens,
            usage_estimated: estimated,
            latency_ms: Some(elapsed(self.started)),
            request_content: self.logged_request.take(),
            response_content: self.full.then_some(tap.text),
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            record(self.gw.clone(), report);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_debug_print() {
        let secret = Secret::new("sk-should-not-appear");
        assert_eq!(format!("{secret:?}"), "[redacted]");
        let identity: NodeIdentity = serde_json::from_value(json!({
            "node_id": Uuid::nil(), "node_token": "node-token-value", "coord": "https://coord", "assigned_ip": "100.64.0.2/32",
            "peers": [],
        }))
        .unwrap();
        assert!(!format!("{identity:?}").contains("node-token-value"));
    }

    #[test]
    fn listen_address_is_never_public() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(check_listen(ip("0.0.0.0"), None, true).is_err());
        assert!(check_listen(ip("::"), None, true).is_err());
        assert!(check_listen(ip("203.0.113.9"), None, true).is_err());
        assert!(check_listen(ip("192.168.1.5"), None, false).is_err());
        assert!(check_listen(ip("192.168.1.5"), None, true).is_ok());
        assert!(check_listen(ip("100.64.0.7"), None, false).is_ok());
        assert!(check_listen(ip("127.0.0.1"), None, false).is_ok());
        assert!(check_listen(ip("fd7a:115c:a1e0::5"), None, false).is_ok());
    }

    #[test]
    fn redaction_covers_string_and_part_content() {
        let mut body = json!({"messages": [
            {"role": "user", "content": "call 0412-345-678 now"},
            {"role": "user", "content": [{"type": "text", "text": "id 0412-345-678"}]},
        ]});
        let patterns = [Regex::new(r"\d{4}-\d{3}-\d{3}").unwrap()];
        assert_eq!(redact(&mut body, &patterns), 2);
        assert_eq!(body["messages"][0]["content"], "call [REDACTED] now");
        assert_eq!(body["messages"][1]["content"][0]["text"], "id [REDACTED]");
    }

    #[test]
    fn sse_tap_finds_usage_across_chunk_boundaries() {
        let mut tap = SseTap::default();
        let stream = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
        for chunk in stream.as_bytes().chunks(5) {
            tap.feed(chunk, true);
        }
        assert_eq!(tap.usage, Some((7, 2)));
        assert_eq!(tap.text, "Hello");
        assert!(tap.done);
    }
}
