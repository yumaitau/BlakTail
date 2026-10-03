//! WebSocket-over-TLS relay transport for networks that block UDP (ADR 0004).
//!
//! Each binary WebSocket message carries exactly one relay frame
//! (REGISTER/SEND/PING inbound, FORWARDED/OBSERVED outbound) with the same
//! HMAC capability tokens as UDP. Connections feed the same relay task as
//! UDP clients, so a UDP-only peer and a WSS-only peer can reach each other.
//!
//! Limits: frames above [`crate::MAX_SEND_FRAME`] close the connection; each
//! connection has a bounded outbound queue (excess frames are dropped, as
//! UDP would); handshakes must finish within [`HANDSHAKE_TIMEOUT`]; a
//! connection silent for [`IDLE_TIMEOUT`] is closed, and the server pings
//! every [`KEEPALIVE`], below the 60 s idle timeout of AWS ALB.

use crate::{Metrics, StreamEvent, MAX_SEND_FRAME};
use futures_util::{SinkExt, StreamExt};
use std::{
    fmt, io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
};
use tokio_tungstenite::tungstenite::{
    self,
    handshake::server::{ErrorResponse, Request, Response},
    http::StatusCode,
    protocol::WebSocketConfig,
    Message,
};

pub use rustls;
pub use rustls::pki_types::CertificateDer;

pub const DEFAULT_PATH: &str = "/v1/relay";
pub const KEEPALIVE: Duration = Duration::from_secs(20);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(50);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Outbound frames buffered per connection before frames are dropped.
pub const QUEUE_FRAMES: usize = 64;
pub const MAX_CONNECTIONS: usize = 4_096;
const MAX_PROXY_RESPONSE: usize = 8_192;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_SEND_FRAME))
        .max_frame_size(Some(MAX_SEND_FRAME))
        .max_write_buffer_size(QUEUE_FRAMES * (MAX_SEND_FRAME + 16))
}

/// rustls with the `ring` provider chosen explicitly: the workspace links
/// more than one provider, so the process default is ambiguous.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Loads a PEM certificate chain and private key into a TLS 1.2/1.3 server
/// configuration advertising HTTP/1.1 (WebSocket upgrades need it).
pub fn server_tls(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("WSS certificate is not valid PEM"))?;
    if certs.is_empty() {
        return Err(io::Error::other("WSS certificate file has no certificates"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| io::Error::other("WSS private key is not valid PEM"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[derive(Clone)]
pub struct WssServerConfig {
    /// Request path that upgrades; everything else gets 404.
    pub path: String,
    /// `None` serves plain WebSocket. Only for a listener behind a TLS
    /// terminating load balancer (ALB) or for tests on loopback.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub keepalive: Duration,
}

impl Default for WssServerConfig {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.into(),
            tls: None,
            max_connections: MAX_CONNECTIONS,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            keepalive: KEEPALIVE,
        }
    }
}

/// Accepts WebSocket relay clients and hands their frames to the relay task
/// created by [`crate::serve_with_streams`].
pub async fn serve_wss(
    listener: TcpListener,
    config: WssServerConfig,
    hub: mpsc::Sender<StreamEvent>,
    metrics: Arc<Metrics>,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(config.max_connections));
    let next_id = Arc::new(AtomicU64::new(1));
    let acceptor = config.tls.clone().map(tokio_rustls::TlsAcceptor::from);
    loop {
        let (tcp, remote) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            metrics.wss_rejected.fetch_add(1, Relaxed);
            drop(tcp);
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let config = config.clone();
        let hub = hub.clone();
        let metrics = metrics.clone();
        let acceptor = acceptor.clone();
        let id = next_id.fetch_add(1, Relaxed);
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor {
                Some(acceptor) => {
                    let handshake = tokio::time::timeout(config.handshake_timeout, async {
                        let tls = acceptor.accept(tcp).await?;
                        upgrade(tls, &config.path).await
                    })
                    .await;
                    match handshake {
                        Ok(Ok(ws)) => {
                            serve_connection(ws, id, remote, &config, hub, &metrics).await
                        }
                        _ => {
                            metrics.wss_rejected.fetch_add(1, Relaxed);
                        }
                    }
                }
                None => {
                    let handshake =
                        tokio::time::timeout(config.handshake_timeout, upgrade(tcp, &config.path))
                            .await;
                    match handshake {
                        Ok(Ok(ws)) => {
                            serve_connection(ws, id, remote, &config, hub, &metrics).await
                        }
                        _ => {
                            metrics.wss_rejected.fetch_add(1, Relaxed);
                        }
                    }
                }
            }
        });
    }
}

// The callback's error type is fixed by tungstenite.
#[allow(clippy::result_large_err)]
async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &str,
) -> io::Result<tokio_tungstenite::WebSocketStream<S>> {
    let path = path.to_owned();
    let check = move |request: &Request, response: Response| {
        if request.uri().path() == path {
            Ok(response)
        } else {
            let mut refused = ErrorResponse::new(None);
            *refused.status_mut() = StatusCode::NOT_FOUND;
            Err(refused)
        }
    };
    tokio_tungstenite::accept_hdr_async_with_config(stream, check, Some(ws_config()))
        .await
        .map_err(io::Error::other)
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    id: u64,
    remote: SocketAddr,
    config: &WssServerConfig,
    hub: mpsc::Sender<StreamEvent>,
    metrics: &Metrics,
) {
    let (tx, mut outbound) = mpsc::channel::<Vec<u8>>(QUEUE_FRAMES);
    if hub
        .send(StreamEvent::Open { id, remote, tx })
        .await
        .is_err()
    {
        return;
    }
    metrics.wss_connections.fetch_add(1, Relaxed);
    let (mut sink, mut stream) = ws.split();
    let mut keepalive = tokio::time::interval(config.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let idle = tokio::time::sleep(config.idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            message = stream.next() => {
                idle.as_mut().reset(tokio::time::Instant::now() + config.idle_timeout);
                match message {
                    Some(Ok(Message::Binary(frame))) => {
                        if hub.send(StreamEvent::Frame { id, frame: frame.to_vec() }).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    // Text, close, protocol errors and oversized frames end the connection.
                    _ => break,
                }
            }
            frame = outbound.recv() => {
                let Some(frame) = frame else { break };
                let sent = tokio::time::timeout(WRITE_TIMEOUT, sink.send(Message::binary(frame))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            }
            _ = keepalive.tick() => {
                let sent = tokio::time::timeout(WRITE_TIMEOUT, sink.send(Message::Ping(Default::default()))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            }
            _ = &mut idle => break,
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), sink.close()).await;
    metrics.wss_connections.fetch_sub(1, Relaxed);
    let _ = hub.send(StreamEvent::Closed { id }).await;
}

/// An explicit HTTP CONNECT proxy. Credentials come only from the
/// environment or configuration files and are never printed: `Debug` shows
/// the proxy address alone.
#[derive(Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    authorization: Option<String>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credentials", &self.authorization.is_some())
            .finish()
    }
}

impl ProxyConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            authorization: None,
        }
    }

    /// Adds HTTP Basic proxy credentials.
    pub fn with_basic_auth(mut self, user: &str, password: &str) -> Self {
        use base64::Engine as _;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        self.authorization = Some(format!("Basic {encoded}"));
        self
    }

    /// Parses `http://[user:password@]host:port`. Only plain-HTTP proxies
    /// that support CONNECT are accepted.
    pub fn parse(url: &str) -> io::Result<Self> {
        let rest = url
            .trim()
            .strip_prefix("http://")
            .ok_or_else(|| io::Error::other("relay proxy must be an http:// URL"))?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((userinfo, hostport)) => (Some(userinfo), hostport),
            None => (None, authority),
        };
        let (host, port) = split_host_port(hostport, 80)
            .ok_or_else(|| io::Error::other("relay proxy has no valid host and port"))?;
        let proxy = Self::new(host, port);
        Ok(match userinfo {
            Some(userinfo) => {
                let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                proxy.with_basic_auth(&percent_decode(user), &percent_decode(password))
            }
            None => proxy,
        })
    }

    /// `BLAKTAIL_RELAY_PROXY`, else `HTTPS_PROXY`/`https_proxy`. Separate
    /// credentials may be given in `BLAKTAIL_RELAY_PROXY_USER` with
    /// `BLAKTAIL_RELAY_PROXY_PASSWORD` or `BLAKTAIL_RELAY_PROXY_PASSWORD_FILE`.
    pub fn from_env() -> io::Result<Option<Self>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> io::Result<Option<Self>> {
        let Some(url) = ["BLAKTAIL_RELAY_PROXY", "HTTPS_PROXY", "https_proxy"]
            .iter()
            .find_map(|name| lookup(name).filter(|value| !value.trim().is_empty()))
        else {
            return Ok(None);
        };
        let mut proxy = Self::parse(&url)?;
        if let Some(user) = lookup("BLAKTAIL_RELAY_PROXY_USER").filter(|user| !user.is_empty()) {
            let password = match lookup("BLAKTAIL_RELAY_PROXY_PASSWORD_FILE") {
                Some(path) if !path.is_empty() => std::fs::read_to_string(path)?
                    .trim_end_matches(['\r', '\n'])
                    .to_owned(),
                _ => lookup("BLAKTAIL_RELAY_PROXY_PASSWORD").unwrap_or_default(),
            };
            proxy = proxy.with_basic_auth(&user, &password);
        }
        Ok(Some(proxy))
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_host_port(hostport: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return (!host.is_empty() && port != 0).then(|| (host.to_owned(), port));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (hostport, default_port),
    };
    (!host.is_empty() && !host.contains(':') && port != 0).then(|| (host.to_owned(), port))
}

/// A parsed relay WebSocket URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl RelayUrl {
    /// Accepts `wss://host[:port]/path`. Plain `ws://` is accepted only for
    /// loopback hosts (tests and local development). Credentials in the URL
    /// are rejected.
    pub fn parse(url: &str) -> io::Result<Self> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("wss://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("ws://") {
            (false, rest)
        } else {
            return Err(io::Error::other("relay WebSocket URL must use wss://"));
        };
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err(io::Error::other(
                "relay WebSocket URL must not embed credentials",
            ));
        }
        let (host, port) = split_host_port(authority, if tls { 443 } else { 80 })
            .ok_or_else(|| io::Error::other("relay WebSocket URL has no valid host"))?;
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !tls && !loopback {
            return Err(io::Error::other(
                "plain ws:// relay URLs are only allowed for loopback",
            ));
        }
        Ok(Self {
            tls,
            host,
            port,
            path: path.split(['?', '#']).next().unwrap_or("/").to_owned(),
        })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn request_url(&self) -> String {
        format!(
            "{}://{}{}",
            if self.tls { "wss" } else { "ws" },
            self.authority(),
            self.path
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    pub proxy: Option<ProxyConfig>,
    /// Extra trust anchors (a private relay CA) in addition to the public
    /// web PKI roots.
    pub extra_roots: Vec<CertificateDer<'static>>,
}

impl ClientOptions {
    /// Proxy from the environment plus an optional PEM CA bundle named by
    /// `BLAKTAIL_RELAY_WSS_CA_FILE`.
    pub fn from_env() -> io::Result<Self> {
        use rustls::pki_types::pem::PemObject;
        let extra_roots = match std::env::var("BLAKTAIL_RELAY_WSS_CA_FILE") {
            Ok(path) if !path.is_empty() => {
                let pem = std::fs::read(path)?;
                CertificateDer::pem_slice_iter(&pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| io::Error::other("relay CA file is not valid PEM"))?
            }
            _ => Vec::new(),
        };
        Ok(Self {
            proxy: ProxyConfig::from_env()?,
            extra_roots,
        })
    }

    fn tls_config(&self) -> io::Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for root in &self.extra_roots {
            roots.add(root.clone()).map_err(io::Error::other)?;
        }
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

pub type ClientStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// Opens a relay WebSocket, through an HTTP CONNECT proxy when configured.
/// Any non-101 answer, including redirects, is an error: the client never
/// follows a redirect away from the coordinator-approved endpoint.
pub async fn connect(url: &str, options: &ClientOptions) -> io::Result<ClientStream> {
    let target = RelayUrl::parse(url)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = match &options.proxy {
            Some(proxy) => {
                let mut tcp = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
                proxy_connect(&mut tcp, proxy, &target.authority()).await?;
                tcp
            }
            None => TcpStream::connect((target.host.as_str(), target.port)).await?,
        };
        let _ = tcp.set_nodelay(true);
        let connector = if target.tls {
            tokio_tungstenite::Connector::Rustls(options.tls_config()?)
        } else {
            tokio_tungstenite::Connector::Plain
        };
        let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
            target.request_url(),
            tcp,
            Some(ws_config()),
            Some(connector),
        )
        .await
        .map_err(|error| match error {
            tungstenite::Error::Http(response) => io::Error::other(format!(
                "relay refused the WebSocket upgrade with HTTP {}",
                response.status().as_u16()
            )),
            other => io::Error::other(other),
        })?;
        Ok(ws)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay WebSocket connect timed out"))?
}

async fn proxy_connect(
    tcp: &mut TcpStream,
    proxy: &ProxyConfig,
    authority: &str,
) -> io::Result<()> {
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(authorization) = &proxy.authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await?;
    // Read byte-wise up to the end of the headers so no tunnelled TLS byte
    // is consumed here.
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_PROXY_RESPONSE || tcp.read(&mut byte).await? == 0 {
            return Err(io::Error::other(
                "relay proxy closed or sent an oversized reply",
            ));
        }
        response.push(byte[0]);
    }
    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let status = std::str::from_utf8(status_line)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    match status {
        Some(200) => Ok(()),
        Some(407) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay proxy requires valid credentials",
        )),
        Some(code) => Err(io::Error::other(format!(
            "relay proxy refused CONNECT with HTTP {code}"
        ))),
        None => Err(io::Error::other("relay proxy sent an invalid reply")),
    }
}

/// A connected relay WebSocket as two bounded frame queues, driven by a
/// background task. Dropping the link (or the peer closing) ends the task.
pub struct WssLink {
    outbound: mpsc::Sender<Vec<u8>>,
    task: tokio::task::AbortHandle,
}

impl WssLink {
    /// Spawns the pump; inbound frames go to `inbound`.
    pub fn spawn(ws: ClientStream, inbound: mpsc::Sender<Vec<u8>>) -> Self {
        let (outbound, mut queue) = mpsc::channel::<Vec<u8>>(QUEUE_FRAMES);
        let task = tokio::spawn(async move {
            let (mut sink, mut stream) = ws.split();
            let idle = tokio::time::sleep(IDLE_TIMEOUT);
            tokio::pin!(idle);
            loop {
                tokio::select! {
                    message = stream.next() => {
                        idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                        match message {
                            Some(Ok(Message::Binary(frame))) => {
                                // Drop rather than block the socket when the
                                // consumer lags, as UDP would.
                                let _ = inbound.try_send(frame.to_vec());
                            }
                            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                            _ => break,
                        }
                    }
                    frame = queue.recv() => {
                        let Some(frame) = frame else { break };
                        let sent = tokio::time::timeout(WRITE_TIMEOUT, sink.send(Message::binary(frame))).await;
                        if !matches!(sent, Ok(Ok(()))) {
                            break;
                        }
                    }
                    _ = &mut idle => break,
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(1), sink.close()).await;
        });
        Self {
            outbound,
            task: task.abort_handle(),
        }
    }

    /// Queues a frame; false when the queue is full or the link is closed.
    pub fn send(&self, frame: Vec<u8>) -> bool {
        self.outbound.try_send(frame).is_ok()
    }

    pub fn is_closed(&self) -> bool {
        self.task.is_finished() || self.outbound.is_closed()
    }
}

impl Drop for WssLink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
