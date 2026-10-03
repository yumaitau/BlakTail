use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::HashMap,
    hash::Hash,
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::interval,
};

pub use blaktail_relay_proto::{
    is_australian_region, observed_frame, parse_observed, EXPIRY_LEN, FORWARDED, HEADER, ID_LEN,
    MAX_PAYLOAD, MAX_SEND_FRAME, OBSERVED, OBSERVED_FRAME, PING, REGISTER, REGISTER_FRAME, SEND,
    TOKEN_LEN,
};

pub mod wss;

const DEFAULT_IDLE_SECS: u64 = 120;
const DEFAULT_RATE_PER_SEC: u32 = 100;
const DEFAULT_RATE_BURST: u32 = 200;
const MAX_RATE_BUCKETS: usize = 65_536;
const SOURCE_RATE_MULTIPLIER: u32 = 10;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct RelayConfig {
    /// Shared HMAC secret. When set, REGISTER frames must carry a valid
    /// capability token minted by the coordinator.
    pub auth_secret: Vec<u8>,
    /// Seconds a registered client may stay silent before being reaped.
    pub idle_secs: u64,
    /// Sustained datagrams per second allowed per source IP.
    pub rate_per_sec: u32,
    /// Token bucket depth per source IP.
    pub rate_burst: u32,
    /// Cloud region. The relay refuses to start outside Australia.
    pub region: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            auth_secret: vec![],
            idle_secs: DEFAULT_IDLE_SECS,
            rate_per_sec: DEFAULT_RATE_PER_SEC,
            rate_burst: DEFAULT_RATE_BURST,
            region: "ap-southeast-2".into(),
        }
    }
}

/// Mint a REGISTER capability token for `node_id` valid until `expires_at`
/// (unix seconds). The coordinator hands these to nodes at registration.
pub fn mint_token(
    auth_secret: &[u8],
    node_id: &[u8; ID_LEN],
    expires_at_unix: u64,
) -> [u8; TOKEN_LEN] {
    let mut mac = HmacSha256::new_from_slice(auth_secret).expect("hmac accepts any key length");
    let mut expiry = [0u8; EXPIRY_LEN];
    expiry.copy_from_slice(&expires_at_unix.to_be_bytes());
    mac.update(node_id);
    mac.update(&expiry);
    let out = mac.finalize().into_bytes();
    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&out);
    token
}

fn verify_token(auth_secret: &[u8], node_id: &[u8], expires_at_unix: u64, token: &[u8]) -> bool {
    if token.len() != TOKEN_LEN || auth_secret.is_empty() {
        return false;
    }
    let mut mac = match HmacSha256::new_from_slice(auth_secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    let mut expiry = [0u8; EXPIRY_LEN];
    expiry.copy_from_slice(&expires_at_unix.to_be_bytes());
    mac.update(node_id);
    mac.update(&expiry);
    mac.verify_slice(token).is_ok()
}

/// Authenticated reachability probe: REGISTER then PING from a fresh socket,
/// returning the reflexive address the relay reports. A relay only answers a
/// PING from a live registration, so a reply proves the relay is up, accepts
/// this capability and can reach the prober. Sends at most three attempts
/// inside `wait`; never carries tunnel payload.
pub async fn probe(
    relay: SocketAddr,
    node_id: &[u8; ID_LEN],
    expires_at_unix: u64,
    token: &[u8; TOKEN_LEN],
    wait: Duration,
) -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind(if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    let mut register = Vec::with_capacity(REGISTER_FRAME);
    register.push(REGISTER);
    register.extend_from_slice(node_id);
    register.extend_from_slice(&expires_at_unix.to_be_bytes());
    register.extend_from_slice(token);
    let mut ping = vec![PING];
    ping.extend_from_slice(node_id);
    let attempt = wait / 3;
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        socket.send_to(&register, relay).await?;
        socket.send_to(&ping, relay).await?;
        let reply = tokio::time::timeout(attempt, async {
            loop {
                let (len, source) = socket.recv_from(&mut buf).await?;
                if source == relay {
                    if let Some(observed) = parse_observed(&buf[..len], node_id) {
                        return Ok::<_, io::Error>(observed);
                    }
                }
            }
        })
        .await;
        if let Ok(result) = reply {
            return result;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "relay did not answer the authenticated probe",
    ))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Where a registered client is reached: a UDP source address, or one
/// WebSocket connection (the HTTPS fallback, ADR 0004).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PeerAddr {
    Udp(SocketAddr),
    Stream(u64),
}

struct Client {
    addr: PeerAddr,
    /// Capability expiry (unix seconds) from the REGISTER token.
    expires_at: u64,
    last_seen: Instant,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Default)]
pub struct Metrics {
    pub registers_ok: std::sync::atomic::AtomicU64,
    pub registers_rejected: std::sync::atomic::AtomicU64,
    pub forwards: std::sync::atomic::AtomicU64,
    pub bytes_relayed: std::sync::atomic::AtomicU64,
    pub unknown_destination: std::sync::atomic::AtomicU64,
    pub rate_limited: std::sync::atomic::AtomicU64,
    pub oversized: std::sync::atomic::AtomicU64,
    /// Frames dropped because a WebSocket client's bounded queue was full.
    pub stream_queue_full: std::sync::atomic::AtomicU64,
    /// Open WebSocket relay connections.
    pub wss_connections: std::sync::atomic::AtomicI64,
    /// WebSocket connections refused (capacity, bad path, handshake timeout).
    pub wss_rejected: std::sync::atomic::AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        use std::sync::atomic::Ordering::*;
        format!(
            "# TYPE blaktail_relay_registers_total counter\n\
             blaktail_relay_registers_total{{result=\"ok\"}} {}\n\
             blaktail_relay_registers_total{{result=\"rejected\"}} {}\n\
             # TYPE blaktail_relay_forwards_total counter\n\
             blaktail_relay_forwards_total {}\n\
             # TYPE blaktail_relay_bytes_total counter\n\
             blaktail_relay_bytes_total {}\n\
             # TYPE blaktail_relay_dropped_total counter\n\
             blaktail_relay_dropped_total{{reason=\"unknown_destination\"}} {}\n\
             blaktail_relay_dropped_total{{reason=\"rate_limited\"}} {}\n\
             blaktail_relay_dropped_total{{reason=\"oversized\"}} {}\n\
             blaktail_relay_dropped_total{{reason=\"stream_queue_full\"}} {}\n\
             # TYPE blaktail_relay_wss_connections gauge\n\
             blaktail_relay_wss_connections {}\n\
             # TYPE blaktail_relay_wss_rejected_total counter\n\
             blaktail_relay_wss_rejected_total {}\n",
            self.registers_ok.load(Relaxed),
            self.registers_rejected.load(Relaxed),
            self.forwards.load(Relaxed),
            self.bytes_relayed.load(Relaxed),
            self.unknown_destination.load(Relaxed),
            self.rate_limited.load(Relaxed),
            self.oversized.load(Relaxed),
            self.stream_queue_full.load(Relaxed),
            self.wss_connections.load(Relaxed),
            self.wss_rejected.load(Relaxed),
        )
    }
}

/// Serves Prometheus text metrics over HTTP for dashboards and scrapes.
pub async fn serve_metrics(bind: SocketAddr, metrics: std::sync::Arc<Metrics>) -> io::Result<()> {
    serve_metrics_with_token(bind, metrics, None).await
}

pub async fn serve_metrics_with_token(
    bind: SocketAddr,
    metrics: std::sync::Arc<Metrics>,
    diagnostics_token: Option<Vec<u8>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    serve_metrics_listener(
        listener,
        metrics,
        std::sync::Arc::<[u8]>::from(diagnostics_token.unwrap_or_default()),
    )
    .await
}

async fn serve_metrics_listener(
    listener: TcpListener,
    metrics: std::sync::Arc<Metrics>,
    diagnostics_token: std::sync::Arc<[u8]>,
) -> io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        let diagnostics_token = diagnostics_token.clone();
        tokio::spawn(async move {
            let mut request = Vec::with_capacity(1_024);
            let Ok(Ok(())) = tokio::time::timeout(Duration::from_secs(2), async {
                let mut chunk = [0_u8; 512];
                loop {
                    let read = stream.read(&mut chunk).await?;
                    if read == 0 {
                        return Ok::<(), io::Error>(());
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        return Ok(());
                    }
                    if request.len() >= 8_192 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "metrics request line is too long",
                        ));
                    }
                }
            })
            .await
            else {
                return;
            };
            let request_text = String::from_utf8_lossy(&request);
            let request_line = request_text.lines().next().unwrap_or_default();
            let authorized = diagnostics_token.is_empty()
                || bearer_token(&request_text).is_some_and(|candidate| {
                    diagnostics_token_matches(candidate, &diagnostics_token)
                });
            let (status, content_type, body) = match request_line {
                "GET /livez HTTP/1.0" | "GET /livez HTTP/1.1" => (
                    "200 OK",
                    "application/json; charset=utf-8",
                    "{\"status\":\"ok\"}\n".into(),
                ),
                "GET /readyz HTTP/1.0" | "GET /readyz HTTP/1.1" => (
                    "200 OK",
                    "application/json; charset=utf-8",
                    "{\"status\":\"ready\"}\n".into(),
                ),
                "GET /metrics HTTP/1.0" | "GET /metrics HTTP/1.1" if authorized => (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    metrics.render(),
                ),
                "GET /diagnostics/readiness HTTP/1.0" | "GET /diagnostics/readiness HTTP/1.1"
                    if authorized =>
                {
                    (
                        "200 OK",
                        "application/json; charset=utf-8",
                        "{\"status\":\"ready\",\"udp\":\"bound\"}\n".into(),
                    )
                }
                "GET /metrics HTTP/1.0"
                | "GET /metrics HTTP/1.1"
                | "GET /diagnostics/readiness HTTP/1.0"
                | "GET /diagnostics/readiness HTTP/1.1" => (
                    "401 Unauthorized",
                    "application/json; charset=utf-8",
                    "{\"error\":\"authentication failed\"}\n".into(),
                ),
                _ => (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "not found\n".into(),
                ),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                let _ = stream.shutdown().await;
            }
        });
    }
}

fn bearer_token(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().strip_prefix("Bearer "))
            .flatten()
    })
}

fn diagnostics_token_matches(candidate: &str, expected: &[u8]) -> bool {
    let mut expected_mac = Hmac::<Sha256>::new_from_slice(expected).expect("HMAC accepts keys");
    expected_mac.update(b"blaktail-private-diagnostics");
    let expected_digest = expected_mac.finalize().into_bytes();
    let Ok(mut candidate_mac) = Hmac::<Sha256>::new_from_slice(candidate.as_bytes()) else {
        return false;
    };
    candidate_mac.update(b"blaktail-private-diagnostics");
    candidate_mac.verify_slice(&expected_digest).is_ok()
}

/// Relays opaque (normally WireGuard-encrypted) UDP payloads between enrolled
/// nodes. Clients REGISTER with an HMAC capability token bound to their node id
/// and an expiry; SEND frames are forwarded only between live registrations.
pub async fn serve(socket: UdpSocket, config: RelayConfig) -> io::Result<()> {
    if config.auth_secret.is_empty() {
        return Err(io::Error::other(
            "refusing to run an unauthenticated relay; set BLAKTAIL_RELAY_AUTH_SECRET",
        ));
    }
    if !is_australian_region(&config.region) {
        return Err(io::Error::other(
            "refusing to run the relay outside Australia; set BLAKTAIL_REGION to ap-southeast-2",
        ));
    }
    let metrics = std::sync::Arc::new(Metrics::default());
    serve_with_metrics(socket, config, metrics).await
}

pub async fn serve_with_metrics(
    socket: UdpSocket,
    config: RelayConfig,
    metrics: std::sync::Arc<Metrics>,
) -> io::Result<()> {
    // No stream listener: the sender is dropped, so the channel only closes.
    let (_, events) = stream_channel();
    serve_with_streams(socket, config, metrics, events).await
}

/// Events from WebSocket connections into the single relay task, so UDP and
/// WSS clients share one registration table and can relay to each other.
pub enum StreamEvent {
    Open {
        id: u64,
        remote: SocketAddr,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    },
    Frame {
        id: u64,
        frame: Vec<u8>,
    },
    Closed {
        id: u64,
    },
}

/// Bounded: a flood of WebSocket frames back-pressures the connection tasks
/// instead of growing memory.
pub fn stream_channel() -> (
    tokio::sync::mpsc::Sender<StreamEvent>,
    tokio::sync::mpsc::Receiver<StreamEvent>,
) {
    tokio::sync::mpsc::channel(1_024)
}

struct Hub {
    config: RelayConfig,
    metrics: std::sync::Arc<Metrics>,
    clients: HashMap<[u8; ID_LEN], Client>,
    source_buckets: HashMap<IpAddr, Bucket>,
    node_buckets: HashMap<[u8; ID_LEN], Bucket>,
    streams: HashMap<u64, (SocketAddr, tokio::sync::mpsc::Sender<Vec<u8>>)>,
}

impl Hub {
    fn remote(&self, peer: PeerAddr) -> Option<SocketAddr> {
        match peer {
            PeerAddr::Udp(address) => Some(address),
            PeerAddr::Stream(id) => self.streams.get(&id).map(|(remote, _)| *remote),
        }
    }

    /// Applies one frame from `source`; returns a packet to deliver.
    fn handle(&mut self, data: &[u8], source: PeerAddr) -> Option<(PeerAddr, Vec<u8>)> {
        use std::sync::atomic::Ordering::*;
        let metrics = self.metrics.clone();
        let source_addr = self.remote(source)?;
        if !admit(
            &mut self.source_buckets,
            source_addr.ip(),
            self.config
                .rate_per_sec
                .saturating_mul(SOURCE_RATE_MULTIPLIER),
            self.config
                .rate_burst
                .saturating_mul(SOURCE_RATE_MULTIPLIER),
        ) {
            metrics.rate_limited.fetch_add(1, Relaxed);
            return None;
        }
        let len = data.len();
        if len < HEADER {
            metrics.oversized.fetch_add(1, Relaxed);
            return None;
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&data[1..HEADER]);
        match data[0] {
            REGISTER => {
                if len != REGISTER_FRAME {
                    metrics.registers_rejected.fetch_add(1, Relaxed);
                    return None;
                }
                let mut expiry_bytes = [0u8; EXPIRY_LEN];
                expiry_bytes.copy_from_slice(&data[HEADER..HEADER + EXPIRY_LEN]);
                let expires_at = u64::from_be_bytes(expiry_bytes);
                let token_start = HEADER + EXPIRY_LEN;
                if !verify_token(
                    &self.config.auth_secret,
                    &id,
                    expires_at,
                    &data[token_start..len],
                ) {
                    metrics.registers_rejected.fetch_add(1, Relaxed);
                    return None;
                }
                // Tokens must still be live at registration time.
                if expires_at <= unix_now() {
                    metrics.registers_rejected.fetch_add(1, Relaxed);
                    return None;
                }
                // One UDP source address (or one WebSocket) represents one
                // enrolled node. Re-registration replaces stale identity there.
                self.clients
                    .retain(|known_id, client| *known_id == id || client.addr != source);
                self.clients.insert(
                    id,
                    Client {
                        addr: source,
                        expires_at,
                        last_seen: Instant::now(),
                    },
                );
                metrics.registers_ok.fetch_add(1, Relaxed);
                None
            }
            SEND => {
                if len > MAX_SEND_FRAME {
                    metrics.oversized.fetch_add(1, Relaxed);
                    return None;
                }
                // The sender must itself be a live registration.
                let Some(source_id) = self
                    .clients
                    .iter()
                    .find_map(|(known_id, client)| (client.addr == source).then_some(*known_id))
                else {
                    metrics.unknown_destination.fetch_add(1, Relaxed);
                    return None;
                };
                let now = unix_now();
                if self
                    .clients
                    .get(&source_id)
                    .is_some_and(|client| client.expires_at <= now)
                {
                    self.clients.remove(&source_id);
                    metrics.unknown_destination.fetch_add(1, Relaxed);
                    return None;
                }
                if let Some(client) = self.clients.get_mut(&source_id) {
                    client.last_seen = Instant::now();
                }
                if !admit(
                    &mut self.node_buckets,
                    source_id,
                    self.config.rate_per_sec,
                    self.config.rate_burst,
                ) {
                    metrics.rate_limited.fetch_add(1, Relaxed);
                    return None;
                }
                let Some(destination) = self.clients.get(&id) else {
                    metrics.unknown_destination.fetch_add(1, Relaxed);
                    return None;
                };
                if destination.expires_at <= now {
                    self.clients.remove(&id);
                    metrics.unknown_destination.fetch_add(1, Relaxed);
                    return None;
                }
                let mut packet = Vec::with_capacity(len);
                packet.push(FORWARDED);
                packet.extend_from_slice(&source_id);
                packet.extend_from_slice(&data[HEADER..len]);
                Some((destination.addr, packet))
            }
            PING => {
                if len != HEADER {
                    return None;
                }
                let registered_source = self
                    .clients
                    .get(&id)
                    .is_some_and(|client| client.addr == source && client.expires_at > unix_now());
                if !registered_source {
                    metrics.unknown_destination.fetch_add(1, Relaxed);
                    return None;
                }
                if let Some(client) = self.clients.get_mut(&id) {
                    client.last_seen = Instant::now();
                }
                if !admit(
                    &mut self.node_buckets,
                    id,
                    self.config.rate_per_sec,
                    self.config.rate_burst,
                ) {
                    metrics.rate_limited.fetch_add(1, Relaxed);
                    return None;
                }
                Some((source, observed_frame(&id, source_addr)))
            }
            _ => None,
        }
    }

    fn reap(&mut self) {
        let now = unix_now();
        let idle = Duration::from_secs(self.config.idle_secs);
        self.clients
            .retain(|_, client| client.expires_at > now && client.last_seen.elapsed() < idle);
        let bucket_idle = Duration::from_secs(self.config.idle_secs.max(60));
        self.source_buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < bucket_idle);
        self.node_buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < bucket_idle);
    }
}

/// Like [`serve_with_metrics`], also accepting WebSocket clients through
/// `events` (see [`wss::serve_wss`]).
pub async fn serve_with_streams(
    socket: UdpSocket,
    config: RelayConfig,
    metrics: std::sync::Arc<Metrics>,
    mut events: tokio::sync::mpsc::Receiver<StreamEvent>,
) -> io::Result<()> {
    if config.auth_secret.is_empty() {
        return Err(io::Error::other(
            "refusing to run an unauthenticated relay; set BLAKTAIL_RELAY_AUTH_SECRET",
        ));
    }
    if !is_australian_region(&config.region) {
        return Err(io::Error::other(
            "refusing to run the relay outside Australia; set BLAKTAIL_REGION to ap-southeast-2",
        ));
    }
    use std::sync::atomic::Ordering::*;
    let mut reap = interval(Duration::from_secs(config.idle_secs.max(1)));
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut hub = Hub {
        config,
        metrics: metrics.clone(),
        clients: HashMap::new(),
        source_buckets: HashMap::new(),
        node_buckets: HashMap::new(),
        streams: HashMap::new(),
    };
    let mut events_open = true;
    // Full-size receive buffer: a smaller buffer would truncate oversize
    // datagrams and let them masquerade as valid frames.
    let mut buf = vec![0u8; 65_535];
    loop {
        let outgoing = tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, source_addr) = received?;
                hub.handle(&buf[..len], PeerAddr::Udp(source_addr))
            }
            event = events.recv(), if events_open => match event {
                Some(StreamEvent::Open { id, remote, tx }) => {
                    hub.streams.insert(id, (remote, tx));
                    None
                }
                Some(StreamEvent::Frame { id, frame }) => hub.handle(&frame, PeerAddr::Stream(id)),
                Some(StreamEvent::Closed { id }) => {
                    hub.streams.remove(&id);
                    hub.clients.retain(|_, client| client.addr != PeerAddr::Stream(id));
                    None
                }
                None => {
                    events_open = false;
                    None
                }
            },
            _ = reap.tick() => {
                hub.reap();
                None
            }
        };
        let Some((destination, packet)) = outgoing else {
            continue;
        };
        let is_forward = packet[0] == FORWARDED;
        let packet_len = packet.len();
        let delivered = match destination {
            PeerAddr::Udp(address) => socket.send_to(&packet, address).await? == packet_len,
            PeerAddr::Stream(id) => match hub.streams.get(&id) {
                Some((_, tx)) => match tx.try_send(packet) {
                    Ok(()) => true,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        metrics.stream_queue_full.fetch_add(1, Relaxed);
                        false
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
                },
                None => false,
            },
        };
        if delivered && is_forward {
            metrics.forwards.fetch_add(1, Relaxed);
            metrics.bytes_relayed.fetch_add(packet_len as u64, Relaxed);
        }
    }
}

/// Token-bucket admission per source IP.
fn admit<K: Copy + Eq + Hash>(
    buckets: &mut HashMap<K, Bucket>,
    key: K,
    rate_per_sec: u32,
    rate_burst: u32,
) -> bool {
    if buckets.len() >= MAX_RATE_BUCKETS && !buckets.contains_key(&key) {
        return false;
    }
    let now = Instant::now();
    let bucket = buckets.entry(key).or_insert(Bucket {
        tokens: rate_burst as f64,
        last_refill: now,
    });
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rate_per_sec as f64).min(rate_burst as f64);
    bucket.last_refill = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::timeout;

    fn secret() -> Vec<u8> {
        b"test-relay-secret".to_vec()
    }

    fn register_frame(id: &[u8; ID_LEN], expires_in: u64, key: &[u8]) -> Vec<u8> {
        let expires_at = unix_now() + expires_in;
        let token = mint_token(key, id, expires_at);
        let mut frame = vec![REGISTER];
        frame.extend_from_slice(id);
        frame.extend_from_slice(&expires_at.to_be_bytes());
        frame.extend_from_slice(&token);
        frame
    }

    fn send_frame(dest: &[u8; ID_LEN], payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![SEND];
        frame.extend_from_slice(dest);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn only_known_au_regions_are_accepted() {
        for region in ["ap-southeast-2", "australiaeast", "australia-southeast1"] {
            assert!(is_australian_region(region));
        }
        for region in ["", "us-east-1", "ap-southeast-1", "europe-west1"] {
            assert!(!is_australian_region(region));
        }
    }

    #[tokio::test]
    async fn refuses_relay_outside_australia() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = serve(
            socket,
            RelayConfig {
                auth_secret: b"test-relay-secret".to_vec(),
                region: "us-east-1".into(),
                ..RelayConfig::default()
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("outside Australia"), "{error}");
    }

    #[tokio::test]
    async fn authenticated_round_trip() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        let bid = [0xBB; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;

        a.send_to(&send_frame(&bid, b"ping"), relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &buf[..n],
            [&[FORWARDED][..], &aid[..], &b"ping"[..]].concat()
        );
        task.abort();
    }

    #[tokio::test]
    async fn forged_or_absent_tokens_cannot_register() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];

        // Wrong secret.
        a.send_to(&register_frame(&aid, 300, b"wrong"), relay_addr)
            .await
            .unwrap();
        // Legacy unauthenticated frame shape.
        let legacy = [[REGISTER].as_slice(), &aid[..]].concat();
        a.send_to(&legacy, relay_addr).await.unwrap();
        // Expired token.
        a.send_to(&register_frame(&aid, 0, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // A second socket must not be able to send as the (unregistered) first one.
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bid = [0xBB; 16];
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        a.send_to(&send_frame(&bid, b"sneak"), relay_addr)
            .await
            .unwrap();

        let mut buf = [0u8; 1500];
        assert!(timeout(Duration::from_millis(200), b.recv_from(&mut buf))
            .await
            .is_err());
        task.abort();
    }

    #[tokio::test]
    async fn oversize_frames_are_dropped() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        let bid = [0xBB; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;

        a.send_to(&send_frame(&bid, &vec![7u8; MAX_PAYLOAD + 1]), relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 4000];
        assert!(timeout(Duration::from_millis(200), b.recv_from(&mut buf))
            .await
            .is_err());

        // Max-size frame still flows.
        a.send_to(&send_frame(&bid, &vec![7u8; MAX_PAYLOAD]), relay_addr)
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 1 + ID_LEN + MAX_PAYLOAD);
        task.abort();
    }

    #[tokio::test]
    async fn idle_clients_are_reaped() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                idle_secs: 1,
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        let bid = [0xBB; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        // Let the reaper tick past the idle window without refreshing A.
        tokio::time::sleep(Duration::from_millis(1400)).await;
        a.send_to(&send_frame(&bid, b"late"), relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 1500];
        assert!(timeout(Duration::from_millis(300), b.recv_from(&mut buf))
            .await
            .is_err());
        task.abort();
    }

    #[tokio::test]
    async fn authenticated_traffic_refreshes_idle_registration() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                idle_secs: 1,
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        let bid = [0xBB; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 128];
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(400)).await;
            a.send_to(&send_frame(&bid, b"a"), relay_addr)
                .await
                .unwrap();
            timeout(Duration::from_secs(1), b.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            b.send_to(&send_frame(&aid, b"b"), relay_addr)
                .await
                .unwrap();
            timeout(Duration::from_secs(1), a.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        }
        task.abort();
    }

    #[tokio::test]
    async fn rate_limit_blocks_floods() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                rate_per_sec: 5,
                rate_burst: 5,
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        let bid = [0xBB; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        b.send_to(&register_frame(&bid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // Burst of far more than the bucket depth; at most `burst` arrive.
        for i in 0..50u32 {
            let marker = format!("m{i}");
            a.send_to(&send_frame(&bid, marker.as_bytes()), relay_addr)
                .await
                .unwrap();
        }
        let mut seen = 0;
        let mut buf = [0u8; 1500];
        while let Ok(result) = timeout(Duration::from_millis(250), b.recv_from(&mut buf)).await {
            let (n, _) = result.unwrap();
            assert_eq!(&buf[1 + ID_LEN..n], format!("m{seen}").as_bytes());
            seen += 1;
        }
        assert!(
            seen <= 5,
            "rate limit failed to cap delivery at burst size ({seen})"
        );
        task.abort();
    }

    #[tokio::test]
    async fn observed_ping_reports_reflexive_address() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                ..RelayConfig::default()
            },
        ));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aid = [0xAA; 16];
        a.send_to(&register_frame(&aid, 300, &secret()), relay_addr)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        a.send_to(
            &[PING]
                .as_slice()
                .iter()
                .copied()
                .chain(aid)
                .collect::<Vec<u8>>(),
            relay_addr,
        )
        .await
        .unwrap();
        let mut buf = [0u8; 128];
        let (_n, _) = timeout(Duration::from_secs(1), a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf[0], OBSERVED);
        assert_eq!(&buf[1..17], &aid);
        assert_eq!(buf[17], 4);
        let port = u16::from_be_bytes([buf[34], buf[35]]);
        assert_eq!(port, a.local_addr().unwrap().port());
        // Knowing another node id does not authorize a reflexive probe.
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker
            .send_to(
                &[PING]
                    .as_slice()
                    .iter()
                    .copied()
                    .chain(aid)
                    .collect::<Vec<u8>>(),
                relay_addr,
            )
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(200), attacker.recv_from(&mut buf))
                .await
                .is_err()
        );
        // Unregistered ids get no reply.
        let ghost = [0x00; 16];
        a.send_to(
            &[PING]
                .as_slice()
                .iter()
                .copied()
                .chain(ghost)
                .collect::<Vec<u8>>(),
            relay_addr,
        )
        .await
        .unwrap();
        assert!(timeout(Duration::from_millis(200), a.recv_from(&mut buf))
            .await
            .is_err());
        task.abort();
    }

    #[test]
    fn metrics_render_contains_counters() {
        let metrics = Metrics::default();
        let text = metrics.render();
        assert!(text.contains("blaktail_relay_forwards_total 0"));
        assert!(text.contains("blaktail_relay_dropped_total{reason=\"oversized\"} 0"));
    }

    #[tokio::test]
    async fn metrics_server_only_serves_prometheus_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics_listener(
            listener,
            Arc::new(Metrics::default()),
            Arc::from(Vec::<u8>::new()),
        ));

        let mut valid = tokio::net::TcpStream::connect(address).await.unwrap();
        valid.write_all(b"GET /met").await.unwrap();
        tokio::task::yield_now().await;
        valid
            .write_all(b"rics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        valid.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("blaktail_relay_bytes_total"));

        let mut invalid = tokio::net::TcpStream::connect(address).await.unwrap();
        invalid
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        invalid.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 404 Not Found"));
        task.abort();
    }

    #[tokio::test]
    async fn health_is_minimal_and_private_diagnostics_require_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = b"relay-diagnostics-token-at-least-32-bytes";
        let task = tokio::spawn(serve_metrics_listener(
            listener,
            Arc::new(Metrics::default()),
            Arc::from(token.to_vec()),
        ));

        let request = async |request: &[u8]| {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        };
        let ready = request(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.contains("{\"status\":\"ready\"}"));
        assert!(!ready.contains("version"));

        let denied = request(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(denied.starts_with("HTTP/1.1 401 Unauthorized"));
        let authenticated = request(
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer relay-diagnostics-token-at-least-32-bytes\r\n\r\n",
        )
        .await;
        assert!(authenticated.starts_with("HTTP/1.1 200 OK"));
        assert!(authenticated.contains("blaktail_relay_forwards_total"));
        task.abort();
    }

    #[tokio::test]
    async fn every_server_entry_point_refuses_unauthenticated_config() {
        let config = RelayConfig::default();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(serve(relay, config.clone()).await.is_err());
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            serve_with_metrics(relay, config, Arc::new(Metrics::default()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn probe_proves_authenticated_reachability_only() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let task = tokio::spawn(serve(
            relay,
            RelayConfig {
                auth_secret: secret(),
                ..RelayConfig::default()
            },
        ));
        let id = [0x42; ID_LEN];
        let expires_at = unix_now() + 60;
        let token = mint_token(&secret(), &id, expires_at);
        let observed = probe(relay_addr, &id, expires_at, &token, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(observed.ip(), relay_addr.ip());
        assert_ne!(observed.port(), 0);

        // A capability minted with another secret gets no answer.
        let forged = mint_token(b"wrong-secret", &id, expires_at);
        let refused = probe(
            relay_addr,
            &id,
            expires_at,
            &forged,
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::TimedOut);

        task.abort();
        let _ = task.await;
        let gone = probe(
            relay_addr,
            &id,
            expires_at,
            &token,
            Duration::from_millis(300),
        )
        .await;
        assert!(gone.is_err());
    }

    #[test]
    fn observed_parser_rejects_other_ids_and_zero_ports() {
        let id = [7u8; ID_LEN];
        let mut frame = vec![OBSERVED];
        frame.extend_from_slice(&id);
        frame.push(4);
        frame.extend_from_slice(
            &std::net::Ipv4Addr::new(203, 0, 113, 9)
                .to_ipv6_mapped()
                .octets(),
        );
        frame.extend_from_slice(&3478u16.to_be_bytes());
        assert_eq!(
            parse_observed(&frame, &id),
            Some("203.0.113.9:3478".parse().unwrap())
        );
        assert_eq!(parse_observed(&frame, &[8u8; ID_LEN]), None);
        let len = frame.len();
        frame[len - 2..].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse_observed(&frame, &id), None);
    }
}
