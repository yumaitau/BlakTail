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
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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

/// Whether the gateway may connect to `ip` for a provider. `private_ok` is
/// true when the provider URL itself names a private or loopback target (an
/// IP literal or a `localhost`, `.internal` or `.blaktail` name the
/// coordinator accepted as private); a public name that resolves to a
/// private, loopback or overlay address is refused, as are link-local and
/// cloud metadata addresses always.
pub fn upstream_allowed(ip: IpAddr, private_ok: bool) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        ip => ip,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4 == Ipv4Addr::new(100, 100, 100, 200)
            {
                return false;
            }
            let private = v4.is_loopback() || v4.is_private() || (a == 100 && b & 0xc0 == 64);
            private_ok || !private
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if (first & 0xffc0) == 0xfe80
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
            {
                return false;
            }
            let private = v6.is_loopback() || (first & 0xfe00) == 0xfc00;
            private_ok || !private
        }
    }
}

fn private_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".internal") || host.ends_with(".blaktail")
}

/// Resolves provider names at connect time and drops every address
/// [`upstream_allowed`] refuses, so DNS cannot steer a credential-bearing
/// request to metadata or internal services.
struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let private_ok = private_name(&host);
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|address| upstream_allowed(address.ip(), private_ok))
                .collect();
            if addresses.is_empty() {
                return Err(format!("{host} resolves only to refused addresses").into());
            }
            let addresses: reqwest::dns::Addrs = Box::new(addresses.into_iter());
            Ok(addresses)
        })
    }
}

/// IP-literal provider URLs never reach the resolver; check them directly.
fn literal_allowed(base_url: &str) -> bool {
    let Some(host) = reqwest::Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
    else {
        return false;
    };
    match host.trim_start_matches('[').trim_end_matches(']').parse() {
        Ok(ip) => upstream_allowed(ip, true),
        Err(_) => true,
    }
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
            .no_proxy()
            .dns_resolver(Arc::new(GuardedResolver))
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
    ) -> Result<T, CoordError> {
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
            .map_err(|_| CoordError::Unreachable)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CoordError::NotAuthorised);
        }
        if !status.is_success() {
            return Err(CoordError::Unreachable);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return serde_json::from_value(Value::Null).map_err(|_| CoordError::Unreachable);
        }
        response.json().await.map_err(|_| CoordError::Unreachable)
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
    /// Output tokens the coordinator reserved against the daily quota.
    #[serde(default)]
    max_tokens: Option<i64>,
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

/// Why the coordinator could not answer for a request. Both fail closed.
#[derive(Debug)]
enum CoordError {
    /// The coordinator was unreachable or sent an unusable reply.
    Unreachable,
    /// The coordinator refused this gateway node: it is not designated as an
    /// AI gateway, or its credential was revoked or suspended.
    NotAuthorised,
}

impl std::fmt::Display for CoordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unreachable => "coordinator unreachable",
            Self::NotAuthorised => "coordinator refused this gateway",
        })
    }
}

fn unavailable() -> Response {
    unavailable_for(&CoordError::Unreachable)
}

fn unavailable_for(error: &CoordError) -> Response {
    let message = match error {
        CoordError::Unreachable => {
            "the gateway cannot reach the BlakTail coordinator; requests fail closed"
        }
        CoordError::NotAuthorised => {
            "this gateway is not authorised by the BlakTail coordinator (not designated as an AI gateway, or its credential was revoked); requests fail closed"
        }
    };
    openai_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "gateway_unavailable",
        message,
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
        Err(error) => return unavailable_for(&error),
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

/// Replaces matches with `[REDACTED]` in every string anywhere in the
/// request (messages, names, tool calls and their arguments, tool and
/// function descriptions, prompts, unknown fields) except the top-level
/// `model`, which the coordinator already checked; returns the count.
pub fn redact(body: &mut Value, patterns: &[Regex]) -> usize {
    fn walk(value: &mut Value, patterns: &[Regex], count: &mut usize) {
        match value {
            Value::String(text) => {
                for pattern in patterns {
                    let matches = pattern.find_iter(text).count();
                    if matches > 0 {
                        *count += matches;
                        *text = pattern.replace_all(text, "[REDACTED]").into_owned();
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, patterns, count);
                }
            }
            Value::Object(fields) => {
                for value in fields.values_mut() {
                    walk(value, patterns, count);
                }
            }
            _ => {}
        }
    }
    let mut count = 0;
    if patterns.is_empty() {
        return count;
    }
    match body {
        Value::Object(fields) => {
            for (name, value) in fields.iter_mut() {
                if name != "model" {
                    walk(value, patterns, &mut count);
                }
            }
        }
        other => walk(other, patterns, &mut count),
    }
    count
}

/// The output limit the client asked for (`max_completion_tokens` wins, as
/// in the OpenAI API).
fn requested_max_tokens(request: &Value) -> Option<i64> {
    ["max_completion_tokens", "max_tokens"]
        .iter()
        .find_map(|field| request.get(*field).and_then(Value::as_i64))
}

/// Never lets the provider produce more than the coordinator reserved.
fn clamp_max_tokens(request: &mut Value, limit: i64) {
    let mut present = false;
    for field in ["max_completion_tokens", "max_tokens"] {
        if let Some(value) = request.get(field).filter(|v| !v.is_null()) {
            present = true;
            let clamped = value
                .as_i64()
                .filter(|v| *v > 0)
                .map_or(limit, |v| v.min(limit));
            request[field] = json!(clamped);
        }
    }
    if !present {
        request["max_tokens"] = json!(limit);
    }
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
                "max_tokens": requested_max_tokens(&request),
            }),
        )
        .await
    {
        Ok(decision) => decision,
        Err(error) => return unavailable_for(&error),
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
    if !literal_allowed(&grant.provider.base_url) {
        record(
            gw.clone(),
            UsageReport {
                request_id: grant.request_id,
                status: "error",
                ..Default::default()
            },
        );
        return openai_error(
            StatusCode::BAD_GATEWAY,
            "upstream_refused",
            "the provider address is link-local or a metadata endpoint",
        );
    }
    let redactions = redact(&mut request, &patterns);
    request["model"] = Value::String(grant.model.clone());
    if let Some(limit) = grant.max_tokens {
        clamp_max_tokens(&mut request, limit);
    }
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

    #[tokio::test]
    async fn refused_gateway_says_it_is_not_authorised() {
        let response = unavailable_for(&CoordError::NotAuthorised);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("not designated"), "{body}");
        assert!(!body.contains("cannot reach"), "{body}");
    }

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
    fn redaction_walks_every_string_but_the_model() {
        let mut body = json!({
            "model": "0412-345-678",
            "messages": [
                {"role": "user", "name": "0412-345-678", "content": "hi"},
                {"role": "assistant", "tool_calls": [{"type": "function", "function": {
                    "name": "lookup", "arguments": "{\"phone\":\"0412-345-678\"}"}}]},
            ],
            "tools": [{"type": "function", "function": {"description": "dial 0412-345-678"}}],
            "prompt": ["0412-345-678"],
            "metadata": {"nested": {"deep": "0412-345-678"}},
            "max_tokens": 10,
        });
        let patterns = [Regex::new(r"\d{4}-\d{3}-\d{3}").unwrap()];
        assert_eq!(redact(&mut body, &patterns), 5);
        assert_eq!(body["model"], "0412-345-678");
        assert!(!body
            .to_string()
            .replace("\"model\":\"0412-345-678\"", "")
            .contains("0412"));
        assert_eq!(body["max_tokens"], 10);
    }

    #[test]
    fn max_tokens_is_clamped_to_the_reservation() {
        let mut body = json!({"max_tokens": 5000});
        assert_eq!(requested_max_tokens(&body), Some(5000));
        clamp_max_tokens(&mut body, 300);
        assert_eq!(body["max_tokens"], 300);
        let mut body = json!({"max_completion_tokens": 20, "max_tokens": 9000});
        assert_eq!(requested_max_tokens(&body), Some(20));
        clamp_max_tokens(&mut body, 300);
        assert_eq!(body["max_completion_tokens"], 20);
        assert_eq!(body["max_tokens"], 300);
        let mut body = json!({});
        clamp_max_tokens(&mut body, 300);
        assert_eq!(body["max_tokens"], 300);
    }

    #[test]
    fn upstream_addresses_are_guarded() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for refused in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fe80::1",
            "fd00:ec2::254",
            "0.0.0.0",
            "100.100.100.200",
            "224.0.0.1",
        ] {
            assert!(!upstream_allowed(ip(refused), true), "{refused}");
        }
        for private in [
            "127.0.0.1",
            "::ffff:127.0.0.1",
            "10.0.0.5",
            "100.64.0.9",
            "fd12::1",
            "::1",
        ] {
            assert!(upstream_allowed(ip(private), true), "{private}");
            assert!(
                !upstream_allowed(ip(private), false),
                "{private} via public name"
            );
        }
        assert!(upstream_allowed(ip("203.0.113.7"), false));
        assert!(private_name("ollama.internal") && private_name("LOCALHOST."));
        assert!(!private_name("api.example.com"));
        assert!(literal_allowed("http://10.0.0.5:11434/v1"));
        assert!(literal_allowed("https://api.example.com/v1"));
        assert!(!literal_allowed("http://[::ffff:169.254.169.254]/v1"));
        assert!(!literal_allowed("http://169.254.169.254/v1"));
    }

    #[tokio::test]
    async fn resolver_keeps_loopback_for_private_names() {
        use reqwest::dns::Resolve;
        // `localhost` is a private name, so loopback is fine there; a public
        // name resolving to loopback is filtered by `upstream_allowed`.
        let resolved: Vec<SocketAddr> = GuardedResolver
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert!(resolved.iter().all(|a| a.ip().is_loopback()) && !resolved.is_empty());
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
