//! Onshore browser remote-access gateway (draft 13, ADR 0006).
//!
//! The gateway is an ordinary enrolled BlakTail node: `blaktaild` on the
//! same host owns its WireGuard interface and node credential, so every
//! connection it makes to a device crosses the overlay and is filtered by
//! the same policy and SSH rules as any peer. It authorises nothing itself.
//! A browser presents a single-use ticket; the gateway redeems it with the
//! coordinator using its node credential, then dials exactly the target,
//! port and OS user the coordinator names. It reports every few seconds and
//! ends the session as soon as the coordinator says so. It never logs or
//! stores terminal contents, keystrokes or passwords.

pub mod guac;
pub mod ssh;

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header::ORIGIN, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const START_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Config {
    /// Coordinator base URL.
    pub coord: String,
    /// blaktaild state directory holding this node's credential.
    pub state_dir: PathBuf,
    /// Console origins allowed to open a WebSocket.
    pub allowed_origins: Vec<String>,
    /// guacd address for RDP; RDP is refused when unset.
    pub guacd: Option<String>,
    pub coord_ca_pem: Option<Vec<u8>>,
}

struct Inner {
    coord: String,
    state_dir: PathBuf,
    allowed_origins: Vec<String>,
    guacd: Option<String>,
    http: reqwest::Client,
}

#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

#[derive(Deserialize)]
struct NodeCredential {
    node_id: Uuid,
    node_token: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    Ssh,
    Rdp,
}

#[derive(Deserialize)]
pub struct Redeemed {
    pub session_id: Uuid,
    pub kind: SessionKind,
    pub target_name: String,
    pub target_address: String,
    pub port: u16,
    pub os_user: String,
    #[serde(default)]
    pub host_key: Option<String>,
    #[serde(default)]
    pub certificate: Option<String>,
    pub max_end_at: i64,
    pub idle_timeout_seconds: i64,
    pub report_interval_seconds: i64,
}

#[derive(Deserialize)]
struct Decision {
    action: String,
    #[serde(default)]
    reason: Option<String>,
}

/// The browser's first message. Nothing in it names a target or user.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    ticket: String,
    #[serde(default = "default_cols")]
    cols: u32,
    #[serde(default = "default_rows")]
    rows: u32,
    /// RDP only, used once for the guacd handshake.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    width: Option<u32>,
    #[serde(default)]
    height: Option<u32>,
    #[serde(default)]
    dpi: Option<u32>,
}

fn default_cols() -> u32 {
    80
}

fn default_rows() -> u32 {
    24
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Control {
    Resize { cols: u32, rows: u32 },
}

#[derive(Serialize)]
struct Status<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    state: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_end_at: Option<i64>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self, Error> {
        let coord = config.coord.trim_end_matches('/').to_owned();
        let local = coord.starts_with("http://127.0.0.1") || coord.starts_with("http://localhost");
        if !coord.starts_with("https://") && !local {
            return Err(Error::Message(
                "coordinator must use HTTPS (HTTP is allowed only for localhost)".into(),
            ));
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(15));
        if let Some(pem) = &config.coord_ca_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(pem)
                    .map_err(|error| Error::Message(format!("invalid coordinator CA: {error}")))?,
            );
        }
        Ok(Self {
            inner: Arc::new(Inner {
                coord,
                state_dir: config.state_dir,
                allowed_origins: config
                    .allowed_origins
                    .into_iter()
                    .map(|origin| origin.trim_end_matches('/').to_owned())
                    .collect(),
                guacd: config.guacd,
                http: builder.build()?,
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/v1/session", get(upgrade))
            .with_state(self.clone())
    }

    fn credential(&self) -> Result<NodeCredential, Error> {
        let text = std::fs::read_to_string(self.inner.state_dir.join("state.json"))?;
        serde_json::from_str(&text)
            .map_err(|_| Error::Message("blaktaild state is unreadable".into()))
    }

    async fn redeem(&self, ticket: &str, public_key: &str) -> Result<Redeemed, Error> {
        let node = self.credential()?;
        let response = self
            .inner
            .http
            .post(format!(
                "{}/v1/nodes/{}/remote-sessions/redeem",
                self.inner.coord, node.node_id
            ))
            .bearer_auth(&node.node_token)
            .json(&serde_json::json!({ "ticket": ticket, "public_key": public_key }))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let message = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|body| body["error"].as_str().map(str::to_owned))
                .unwrap_or_default();
            return Err(Error::Message(match status {
                reqwest::StatusCode::GONE => {
                    "this session ticket was already used, expired or revoked; start a new session"
                        .into()
                }
                _ if !message.is_empty() => message,
                _ => format!("the coordinator refused the session ({status})"),
            }));
        }
        Ok(response.json().await?)
    }

    async fn report(
        &self,
        session_id: Uuid,
        bytes: (u64, u64),
        ended: Option<&str>,
    ) -> Result<Decision, Error> {
        let node = self.credential()?;
        Ok(self
            .inner
            .http
            .post(format!(
                "{}/v1/nodes/{}/remote-sessions/{session_id}/report",
                self.inner.coord, node.node_id
            ))
            .bearer_auth(&node.node_token)
            .json(&serde_json::json!({
                "bytes_to_target": bytes.0,
                "bytes_from_target": bytes.1,
                "ended": ended,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

/// Browsers always send `Origin`; only the console's may open a session.
/// Non-browser clients send none and still need a valid ticket.
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    match headers.get(ORIGIN).and_then(|value| value.to_str().ok()) {
        None => true,
        Some(origin) => allowed
            .iter()
            .any(|candidate| candidate == origin.trim_end_matches('/')),
    }
}

async fn upgrade(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers, &gateway.inner.allowed_origins) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    ws.max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move { gateway.run(socket).await })
}

async fn send_status(socket: &mut WebSocket, status: Status<'_>) {
    if let Ok(text) = serde_json::to_string(&status) {
        let _ = socket.send(Message::Text(text)).await;
    }
}

async fn close(socket: &mut WebSocket, reason: &str) {
    send_status(
        socket,
        Status {
            kind: "status",
            state: "closed",
            reason: Some(reason),
            target: None,
            os_user: None,
            max_end_at: None,
        },
    )
    .await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: reason.chars().take(100).collect::<String>().into(),
        })))
        .await;
}

/// Shared bookkeeping for one live session.
struct Live {
    session_id: Uuid,
    to_target: u64,
    from_target: u64,
    last_input: Instant,
    idle: Duration,
    deadline: tokio::time::Instant,
}

impl Live {
    fn new(redeemed: &Redeemed) -> Self {
        let remaining = (redeemed.max_end_at - unix_now()).max(0) as u64;
        Self {
            session_id: redeemed.session_id,
            to_target: 0,
            from_target: 0,
            last_input: Instant::now(),
            idle: Duration::from_secs(redeemed.idle_timeout_seconds.max(30) as u64),
            deadline: tokio::time::Instant::now() + Duration::from_secs(remaining),
        }
    }
}

enum Step {
    Continue,
    End(String),
}

impl Gateway {
    async fn run(self, mut socket: WebSocket) {
        let start = match tokio::time::timeout(START_TIMEOUT, socket.recv()).await {
            Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str::<Start>(&text).ok(),
            _ => None,
        };
        let Some(start) = start else {
            close(&mut socket, "expected a session ticket").await;
            return;
        };
        let key = ssh::ephemeral_key();
        let redeemed = match self.redeem(start.ticket.trim(), &key.public_openssh).await {
            Ok(redeemed) => redeemed,
            Err(error) => {
                tracing::info!(%error, "session ticket refused");
                close(&mut socket, &error.to_string()).await;
                return;
            }
        };
        tracing::info!(session_id = %redeemed.session_id, kind = ?redeemed.kind, "remote session redeemed");
        send_status(
            &mut socket,
            Status {
                kind: "status",
                state: "connecting",
                reason: None,
                target: Some(&redeemed.target_name),
                os_user: Some(&redeemed.os_user),
                max_end_at: Some(redeemed.max_end_at),
            },
        )
        .await;
        let mut live = Live::new(&redeemed);
        let reason = match redeemed.kind {
            SessionKind::Ssh => {
                self.ssh(&mut socket, &redeemed, &key, &start, &mut live)
                    .await
            }
            SessionKind::Rdp => self.rdp(&mut socket, &redeemed, start, &mut live).await,
        };
        let reported = self
            .report(
                live.session_id,
                (live.to_target, live.from_target),
                Some(gateway_end_reason(&reason)),
            )
            .await;
        if let Err(error) = reported {
            tracing::warn!(%error, session_id = %live.session_id, "could not report session end");
        }
        tracing::info!(session_id = %live.session_id, %reason, "remote session ended");
        close(&mut socket, &reason).await;
    }

    async fn tick(&self, live: &Live) -> Step {
        match self
            .report(live.session_id, (live.to_target, live.from_target), None)
            .await
        {
            Ok(decision) if decision.action == "continue" => Step::Continue,
            Ok(decision) => Step::End(decision.reason.unwrap_or_else(|| "ended".into())),
            // Fail closed: a coordinator that cannot confirm the session ends it.
            Err(error) => Step::End(format!("coordinator unavailable: {error}")),
        }
    }

    async fn ssh(
        &self,
        socket: &mut WebSocket,
        redeemed: &Redeemed,
        key: &ssh::SessionKey,
        start: &Start,
        live: &mut Live,
    ) -> String {
        let (Some(host_key), Some(certificate)) = (&redeemed.host_key, &redeemed.certificate)
        else {
            return "error".into();
        };
        let Ok(address) =
            format!("{}:{}", redeemed.target_address, redeemed.port).parse::<SocketAddr>()
        else {
            return "error".into();
        };
        let target = ssh::Target {
            address,
            host_key,
            user: &redeemed.os_user,
        };
        let shell = match ssh::open_shell(
            &target,
            key,
            certificate,
            start.cols.clamp(20, 500),
            start.rows.clamp(5, 200),
        )
        .await
        {
            Ok(shell) => shell,
            Err(ssh::SshError::HostKeyMismatch) => {
                tracing::warn!(session_id = %redeemed.session_id, "host key mismatch; refusing to authenticate");
                return "host_key_mismatch".into();
            }
            Err(ssh::SshError::Auth) => return "auth_failed".into(),
            Err(error) => {
                tracing::info!(%error, session_id = %redeemed.session_id, "SSH connect failed");
                return "connect_failed".into();
            }
        };
        send_status(
            socket,
            Status {
                kind: "status",
                state: "connected",
                reason: None,
                target: Some(&redeemed.target_name),
                os_user: Some(&redeemed.os_user),
                max_end_at: Some(redeemed.max_end_at),
            },
        )
        .await;
        let ssh::Shell { handle, channel } = shell;
        let (mut reader, writer) = channel.split();
        let mut report = tokio::time::interval(Duration::from_secs(
            redeemed.report_interval_seconds.clamp(2, 30) as u64,
        ));
        report.tick().await;
        let reason = loop {
            tokio::select! {
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        live.last_input = Instant::now();
                        live.to_target += bytes.len() as u64;
                        if writer.data(&bytes[..]).await.is_err() {
                            break "target_closed".to_string();
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(Control::Resize { cols, rows }) = serde_json::from_str(&text) {
                            let _ = writer.window_change(cols.clamp(20, 500), rows.clamp(5, 200), 0, 0).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "user_closed".to_string(),
                    Some(Ok(_)) => {}
                },
                message = reader.wait() => match message {
                    Some(russh::ChannelMsg::Data { data })
                    | Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        live.from_target += data.len() as u64;
                        if socket.send(Message::Binary(data.to_vec())).await.is_err() {
                            break "user_closed".to_string();
                        }
                    }
                    Some(russh::ChannelMsg::Eof)
                    | Some(russh::ChannelMsg::Close)
                    | Some(russh::ChannelMsg::ExitStatus { .. })
                    | None => break "target_closed".to_string(),
                    Some(_) => {}
                },
                _ = report.tick() => {
                    if live.last_input.elapsed() >= live.idle {
                        break "idle_timeout".to_string();
                    }
                    if let Step::End(reason) = self.tick(live).await {
                        break reason;
                    }
                }
                _ = tokio::time::sleep_until(live.deadline) => break "max_duration".to_string(),
            }
        };
        let _ = writer.close().await;
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "session ended", "en")
            .await;
        reason
    }

    async fn rdp(
        &self,
        socket: &mut WebSocket,
        redeemed: &Redeemed,
        start: Start,
        live: &mut Live,
    ) -> String {
        let Some(guacd) = &self.inner.guacd else {
            return "error".into();
        };
        let Some(password) = start.password else {
            return "error".into();
        };
        let params = guac::RdpParams {
            hostname: &redeemed.target_address,
            port: redeemed.port,
            username: &redeemed.os_user,
            password: &password,
            width: start.width.unwrap_or(1280),
            height: start.height.unwrap_or(720),
            dpi: start.dpi.unwrap_or(96),
        };
        let (stream, mut pending) = match guac::handshake(guacd, &params).await {
            Ok(connected) => connected,
            Err(error) => {
                tracing::info!(%error, session_id = %redeemed.session_id, "RDP handshake failed");
                return "connect_failed".into();
            }
        };
        drop(password);
        send_status(
            socket,
            Status {
                kind: "status",
                state: "connected",
                reason: None,
                target: Some(&redeemed.target_name),
                os_user: Some(&redeemed.os_user),
                max_end_at: Some(redeemed.max_end_at),
            },
        )
        .await;
        let (mut from_guacd, mut to_guacd) = stream.into_split();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut report = tokio::time::interval(Duration::from_secs(
            redeemed.report_interval_seconds.clamp(2, 30) as u64,
        ));
        report.tick().await;
        if let Ok(early) = pending.drain_complete() {
            if !early.is_empty() {
                live.from_target += early.len() as u64;
                let _ = socket.send(Message::Text(early)).await;
            }
        }
        loop {
            tokio::select! {
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(allowed) = guac::filter_client(&text) else {
                            break "error".into();
                        };
                        if allowed.contains("5.mouse,") || allowed.contains("3.key,") {
                            live.last_input = Instant::now();
                        }
                        live.to_target += allowed.len() as u64;
                        if to_guacd.write_all(allowed.as_bytes()).await.is_err() {
                            break "target_closed".into();
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "user_closed".into(),
                    Some(Ok(_)) => {}
                },
                read = from_guacd.read(&mut buffer) => match read {
                    Ok(0) | Err(_) => break "target_closed".into(),
                    Ok(read) => {
                        if pending.push(&buffer[..read]).is_err() {
                            break "error".into();
                        }
                        let Ok(complete) = pending.drain_complete() else {
                            break "error".into();
                        };
                        if !complete.is_empty() {
                            live.from_target += complete.len() as u64;
                            if socket.send(Message::Text(complete)).await.is_err() {
                                break "user_closed".into();
                            }
                        }
                    }
                },
                _ = report.tick() => {
                    if live.last_input.elapsed() >= live.idle {
                        break "idle_timeout".into();
                    }
                    if let Step::End(reason) = self.tick(live).await {
                        break reason;
                    }
                }
                _ = tokio::time::sleep_until(live.deadline) => break "max_duration".into(),
            }
        }
    }
}

/// Maps a local end reason onto the coordinator's fixed set.
fn gateway_end_reason(reason: &str) -> &'static str {
    match reason {
        "user_closed" => "user_closed",
        "idle_timeout" => "idle_timeout",
        "max_duration" => "max_duration",
        "target_closed" => "target_closed",
        "host_key_mismatch" => "host_key_mismatch",
        "connect_failed" => "connect_failed",
        "auth_failed" => "auth_failed",
        _ => "error",
    }
}

#[cfg(test)]
mod tests;
