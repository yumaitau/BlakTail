//! End to end: a real in-memory coordinator, the gateway, and a local
//! OpenAI-compatible mock upstream, all on loopback.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blaktail_agentgw::{router, Gateway, GatewayConfig, Secret};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const SECRET: &[u8] = b"test-only-hmac-secret-at-least-32-bytes";
const CREDENTIAL: &str = "sk-mock-upstream-credential-7f3a";
const MOCK_SSE: &str = concat!(
    "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Kaya\"}}]}\n\n",
    "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" mob\"}}]}\n\n",
    "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13}}\n\n",
    "data: [DONE]\n\n",
);

// ------------------------------------------------------------ log capture

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> &'static Captured {
    static LOGS: OnceLock<Captured> = OnceLock::new();
    LOGS.get_or_init(|| {
        let captured = Captured::default();
        let writer = captured.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .init();
        captured
    })
}

// ------------------------------------------------------------ mock upstream

/// (Authorization header, JSON body) for each upstream request.
type Seen = Vec<(Option<String>, Value)>;

#[derive(Clone, Default)]
struct Mock {
    seen: Arc<Mutex<Seen>>,
}

async fn mock_completion(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    mock.seen.lock().unwrap().push((auth.clone(), body.clone()));
    if auth.as_deref() != Some(&format!("Bearer {CREDENTIAL}")) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "bad upstream credential"})),
        )
            .into_response();
    }
    if body["stream"] == true {
        // Several writes so the gateway sees real chunk boundaries.
        let chunks: Vec<Result<String, std::io::Error>> = MOCK_SSE
            .split_inclusive("\n\n")
            .map(|chunk| Ok(chunk.to_owned()))
            .collect();
        return Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))
            .unwrap();
    }
    Json(json!({
        "id": "c2",
        "object": "chat.completion",
        "model": body["model"],
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Yaama"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12},
    }))
    .into_response()
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

// ------------------------------------------------------------ coordinator

fn assertion(org: Uuid, role: &str, action: Option<&str>) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "sub": format!("{role}-user"), "org_id": org, "role": role, "name": role,
            "email": format!("{role}@example.org.au"), "iss": "blaktail-console", "aud": "blaktail-coord",
            "iat": now, "exp": now + 60, "jti": Uuid::new_v4(), "action": action,
        }))
        .unwrap(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

struct Lab {
    http: reqwest::Client,
    coord: String,
    gateway: String,
    org: Uuid,
    mock: Mock,
    secret: String,
    node_token: String,
}

impl Lab {
    async fn owner(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self
            .http
            .request(method, format!("{}/v1/orgs/{}{path}", self.coord, self.org))
            .bearer_auth(assertion(self.org, "owner", None));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn chat(&self, key: &str, body: Value) -> reqwest::Response {
        self.http
            .post(format!("{}/v1/chat/completions", self.gateway))
            .bearer_auth(key)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Usage is reported asynchronously; wait until it lands.
    async fn today(&self) -> Value {
        for _ in 0..100 {
            let (_, overview) = self.owner(reqwest::Method::GET, "/agents", None).await;
            let today = overview["keys"][0]["today"].clone();
            let (_, usage) = self
                .owner(reqwest::Method::GET, "/agents/usage", None)
                .await;
            let recorded: i64 = usage["days"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["requests"].as_i64().unwrap())
                .sum();
            if recorded == today["requests"].as_i64().unwrap() {
                return json!({"today": today, "usage": usage});
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("usage was never recorded");
    }

    async fn start(policy: Value) -> Lab {
        logs();
        let store = blaktail_coord::Store::memory().await.unwrap();
        let coord_addr = serve(blaktail_coord::app(store, "ap-southeast-2".into(), SECRET)).await;
        let coord = format!("http://{coord_addr}");
        let mock = Mock::default();
        let mock_addr = serve(
            Router::new()
                .route("/v1/chat/completions", post(mock_completion))
                .with_state(mock.clone()),
        )
        .await;
        let http = reqwest::Client::new();
        let org = Uuid::new_v4();
        let response = http
            .post(format!("{coord}/v1/orgs"))
            .bearer_auth(assertion(org, "service", Some("bootstrap.prepare")))
            .json(&json!({"id": org, "name": "Gateway lab", "acl": {"version": 1, "defaults": "same_tag", "rules": []}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202);
        let response = http
            .post(format!("{coord}/v1/orgs/{org}/bootstrap-commit"))
            .bearer_auth(assertion(org, "service", Some("bootstrap.commit")))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        let mut lab = Lab {
            http,
            coord: coord.clone(),
            gateway: String::new(),
            org,
            mock,
            secret: String::new(),
            node_token: String::new(),
        };
        let (status, join) = lab
            .owner(
                reqwest::Method::POST,
                "/join-keys",
                Some(json!({"expires_in_seconds": 60, "tags": ["office"]})),
            )
            .await;
        assert_eq!(status, 201, "{join}");
        let node: Value = lab
            .http
            .post(format!("{coord}/v1/nodes/register"))
            .json(&json!({
                "join_key": join["key"], "name": "agent-gw",
                "wg_public_key": format!("key-{}", Uuid::new_v4()),
                "capabilities": ["agent-gateway"],
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        lab.node_token = node["node_token"].as_str().unwrap().to_owned();
        let (status, designated) = lab
            .owner(
                reqwest::Method::PUT,
                &format!("/agents/gateways/{}", node["id"].as_str().unwrap()),
                Some(json!({"designated": true})),
            )
            .await;
        assert_eq!(status, 204, "{designated}");
        let (status, provider) = lab
            .owner(
                reqwest::Method::POST,
                "/agents/providers",
                Some(json!({
                    "name": "local-ollama",
                    "base_url": format!("http://{mock_addr}/v1"),
                    "data_location": "Australia (self-hosted)",
                    "residency": "onshore",
                    "credential": CREDENTIAL,
                    "models": ["llama3.2:1b"],
                })),
            )
            .await;
        assert_eq!(status, 201, "{provider}");
        let mut policy = policy;
        policy["allowed_provider_ids"] = json!([provider["id"]]);
        let acknowledge_icip = policy["logging_mode"] == "full";
        let (status, created) = lab
            .owner(
                reqwest::Method::POST,
                "/agents/keys",
                Some(json!({"name": "field-agent", "policy": policy, "acknowledge_icip": acknowledge_icip})),
            )
            .await;
        assert_eq!(status, 201, "{created}");
        lab.secret = created["secret"].as_str().unwrap().to_owned();
        let gateway = Gateway::new(GatewayConfig {
            coordinator_url: coord,
            node_id: node["id"].as_str().unwrap().parse().unwrap(),
            node_token: Secret::new(lab.node_token.clone()),
            coord_ca_pem: None,
        })
        .unwrap();
        lab.gateway = format!("http://{}", serve(router(Arc::new(gateway))).await);
        lab
    }

    fn assert_no_secrets_logged(&self) {
        let text = String::from_utf8_lossy(&logs().0.lock().unwrap()).into_owned();
        assert!(!text.is_empty(), "log capture is not wired");
        for secret in [CREDENTIAL, &self.secret, &self.node_token] {
            assert!(!text.contains(secret), "a secret reached the logs");
        }
    }
}

fn chat_body(stream: bool) -> Value {
    json!({
        "model": "llama3.2:1b",
        "stream": stream,
        "messages": [{"role": "user", "content": "Say hello. My Medicare number is 2123 45670 1."}],
    })
}

#[tokio::test]
async fn non_streaming_completion_is_proxied_and_metered() {
    let lab = Lab::start(json!({})).await;
    let response = lab.chat(&lab.secret, chat_body(false)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["x-blaktail-data-location"],
        "Australia (self-hosted)"
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "Yaama");
    let seen = lab.mock.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].0.as_deref(),
        Some(format!("Bearer {CREDENTIAL}").as_str())
    );
    let state = lab.today().await;
    assert_eq!(state["today"]["requests"], 1);
    assert_eq!(state["today"]["tokens"], 12);
    assert_eq!(state["usage"]["days"][0]["prompt_tokens"], 9);
    lab.assert_no_secrets_logged();
}

#[tokio::test]
async fn streaming_is_passed_through_byte_for_byte_and_metered() {
    let lab = Lab::start(json!({"logging_mode": "metadata"})).await;
    let response = lab.chat(&lab.secret, chat_body(true)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let text = response.text().await.unwrap();
    assert_eq!(text, MOCK_SSE);
    let seen = lab.mock.seen.lock().unwrap().clone();
    assert_eq!(seen[0].1["stream_options"]["include_usage"], true);
    let state = lab.today().await;
    assert_eq!(state["today"]["tokens"], 13);
    let recent = &state["usage"]["recent"][0];
    assert_eq!(recent["status"], "ok");
    assert_eq!(recent["prompt_tokens"], 11);
    assert_eq!(recent["usage_estimated"], false);
    assert_eq!(recent["has_content"], false);
    lab.assert_no_secrets_logged();
}

#[tokio::test]
async fn bad_keys_and_exhausted_quotas_never_reach_the_upstream() {
    let lab = Lab::start(json!({"daily_request_quota": 1})).await;
    let response = lab.chat("btak_not-a-real-key", chat_body(false)).await;
    assert_eq!(response.status(), 401);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "invalid_api_key");
    let response = lab
        .http
        .post(format!("{}/v1/chat/completions", lab.gateway))
        .json(&chat_body(false))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(lab.chat(&lab.secret, chat_body(false)).await.status(), 200);
    let response = lab.chat(&lab.secret, chat_body(false)).await;
    assert_eq!(response.status(), 429);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "quota_exceeded");
    let mut other = chat_body(false);
    other["model"] = json!("gpt-unlisted");
    assert_eq!(lab.chat(&lab.secret, other).await.status(), 404);
    assert_eq!(lab.mock.seen.lock().unwrap().len(), 1);
    let state = lab.today().await;
    assert_eq!(state["today"]["requests"], 1);
    assert_eq!(state["today"]["denied"], 2);
    lab.assert_no_secrets_logged();
}

#[tokio::test]
async fn redaction_happens_before_forwarding_and_full_logs_store_redacted_text() {
    let lab = Lab::start(json!({
        "redact_patterns": ["\\b\\d{4} \\d{5} \\d\\b"],
        "logging_mode": "full",
        "log_retention_days": 7,
    }))
    .await;
    let response = lab.chat(&lab.secret, chat_body(false)).await;
    assert_eq!(response.status(), 200);
    let seen = lab.mock.seen.lock().unwrap().clone();
    let forwarded = seen[0].1["messages"][0]["content"].as_str().unwrap();
    assert_eq!(forwarded, "Say hello. My Medicare number is [REDACTED].");
    // The forwarded output limit never exceeds the coordinator's reservation.
    let limit = seen[0].1["max_tokens"].as_i64().unwrap();
    assert!((1..=4096).contains(&limit), "{limit}");
    let state = lab.today().await;
    let recent = &state["usage"]["recent"][0];
    assert_eq!(recent["has_content"], true);
    let (status, content) = lab
        .owner(
            reqwest::Method::GET,
            &format!(
                "/agents/requests/{}/content",
                recent["id"].as_str().unwrap()
            ),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let stored = content["request"].as_str().unwrap();
    assert!(stored.contains("[REDACTED]") && !stored.contains("45670"));
    assert_eq!(content["response"], "Yaama");
    lab.assert_no_secrets_logged();
}

#[tokio::test]
async fn models_lists_only_what_the_key_may_use() {
    let lab = Lab::start(json!({})).await;
    let response = lab
        .http
        .get(format!("{}/v1/models", lab.gateway))
        .bearer_auth(&lab.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["data"][0]["id"], "llama3.2:1b");
    assert_eq!(
        body["data"][0]["blaktail"]["data_location"],
        "Australia (self-hosted)"
    );
    let response = lab
        .http
        .get(format!("{}/v1/models", lab.gateway))
        .bearer_auth("btak_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}
