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

/// Frame types.
pub const REGISTER: u8 = 1;
pub const SEND: u8 = 2;
pub const FORWARDED: u8 = 3;
/// Reflexive-address probe: [PING][id]; reply is [OBSERVED][id][sockaddr].
pub const PING: u8 = 4;
pub const OBSERVED: u8 = 5;

/// OBSERVED reply header: type + id + family(u8) + ip(16) + port(u16 BE).
pub const OBSERVED_FRAME: usize = 1 + ID_LEN + 1 + 16 + 2;

pub const ID_LEN: usize = 16;
pub const TOKEN_LEN: usize = 32;
pub const EXPIRY_LEN: usize = 8;
/// REGISTER frame: type + node id + token expiry (unix seconds, BE) + HMAC-SHA256 over (id || expiry).
pub const REGISTER_FRAME: usize = 1 + ID_LEN + EXPIRY_LEN + TOKEN_LEN;
/// SEND frame header: type + destination id.
pub const HEADER: usize = 1 + ID_LEN;
/// Encrypted WireGuard datagram ceiling; covers normal 1,500-byte underlays
/// while rejecting jumbo or amplification-oriented frames.
pub const MAX_PAYLOAD: usize = 2_048;
pub const MAX_SEND_FRAME: usize = HEADER + MAX_PAYLOAD;

const DEFAULT_IDLE_SECS: u64 = 120;
const DEFAULT_RATE_PER_SEC: u32 = 100;
const DEFAULT_RATE_BURST: u32 = 200;
const MAX_RATE_BUCKETS: usize = 65_536;
const SOURCE_RATE_MULTIPLIER: u32 = 10;

type HmacSha256 = Hmac<Sha256>;

pub fn is_australian_region(region: &str) -> bool {
    matches!(
        region.trim().to_ascii_lowercase().as_str(),
        "ap-southeast-2"
            | "australiaeast"
            | "australiasoutheast"
            | "australia-southeast1"
            | "australia-southeast2"
    )
}

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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Client {
    addr: SocketAddr,
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
             blaktail_relay_dropped_total{{reason=\"oversized\"}} {}\n",
            self.registers_ok.load(Relaxed),
            self.registers_rejected.load(Relaxed),
            self.forwards.load(Relaxed),
            self.bytes_relayed.load(Relaxed),
            self.unknown_destination.load(Relaxed),
            self.rate_limited.load(Relaxed),
            self.oversized.load(Relaxed),
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
    let mut clients: HashMap<[u8; ID_LEN], Client> = HashMap::new();
    let mut source_buckets: HashMap<IpAddr, Bucket> = HashMap::new();
    let mut node_buckets: HashMap<[u8; ID_LEN], Bucket> = HashMap::new();
    // Full-size receive buffer: a smaller buffer would truncate oversize
    // datagrams and let them masquerade as valid frames.
    let mut buf = vec![0u8; 65_535];
    let mut reap = interval(Duration::from_secs(config.idle_secs.max(1)));
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, source_addr) = received?;
                if !admit(
                    &mut source_buckets,
                    source_addr.ip(),
                    config.rate_per_sec.saturating_mul(SOURCE_RATE_MULTIPLIER),
                    config.rate_burst.saturating_mul(SOURCE_RATE_MULTIPLIER),
                ) {
                    metrics.rate_limited.fetch_add(1, Relaxed);
                    continue;
                }
                if len < HEADER {
                    metrics.oversized.fetch_add(1, Relaxed);
                    continue;
                }
                let mut id = [0u8; ID_LEN];
                id.copy_from_slice(&buf[1..HEADER]);
                match buf[0] {
                    REGISTER => {
                        if len != REGISTER_FRAME {
                            metrics.registers_rejected.fetch_add(1, Relaxed);
                            continue;
                        }
                        let mut expiry_bytes = [0u8; EXPIRY_LEN];
                        expiry_bytes.copy_from_slice(&buf[HEADER..HEADER + EXPIRY_LEN]);
                        let expires_at = u64::from_be_bytes(expiry_bytes);
                        let token_start = HEADER + EXPIRY_LEN;
                        if !verify_token(&config.auth_secret, &id, expires_at, &buf[token_start..len]) {
                            metrics.registers_rejected.fetch_add(1, Relaxed);
                            continue;
                        }
                        // Tokens must still be live at registration time.
                        if expires_at <= unix_now() {
                            metrics.registers_rejected.fetch_add(1, Relaxed);
                            continue;
                        }
                        // One UDP source address represents one enrolled node.
                        // Re-registration replaces stale identity at that address.
                        clients.retain(|known_id, client| {
                            *known_id == id || client.addr != source_addr
                        });
                        clients.insert(
                            id,
                            Client {
                                addr: source_addr,
                                expires_at,
                                last_seen: Instant::now(),
                            },
                        );
                        metrics.registers_ok.fetch_add(1, Relaxed);
                    }
                    SEND => {
                        if len > MAX_SEND_FRAME {
                            metrics.oversized.fetch_add(1, Relaxed);
                            continue;
                        }
                        // The sender must itself be a live registration.
                        let Some(source_id) = clients
                            .iter()
                            .find_map(|(known_id, client)| {
                                (client.addr == source_addr).then_some(*known_id)
                            })
                        else {
                            metrics.unknown_destination.fetch_add(1, Relaxed);
                            continue;
                        };
                        let now = unix_now();
                        if clients
                            .get(&source_id)
                            .is_some_and(|source| source.expires_at <= now)
                        {
                            clients.remove(&source_id);
                            metrics.unknown_destination.fetch_add(1, Relaxed);
                            continue;
                        }
                        if let Some(source) = clients.get_mut(&source_id) {
                            source.last_seen = Instant::now();
                        }
                        if !admit(
                            &mut node_buckets,
                            source_id,
                            config.rate_per_sec,
                            config.rate_burst,
                        ) {
                            metrics.rate_limited.fetch_add(1, Relaxed);
                            continue;
                        }
                        let Some(destination) = clients.get(&id) else {
                            metrics.unknown_destination.fetch_add(1, Relaxed);
                            continue;
                        };
                        if destination.expires_at <= now {
                            clients.remove(&id);
                            metrics.unknown_destination.fetch_add(1, Relaxed);
                            continue;
                        }
                        let mut packet = Vec::with_capacity(len);
                        packet.push(FORWARDED);
                        packet.extend_from_slice(&source_id);
                        packet.extend_from_slice(&buf[HEADER..len]);
                        if socket.send_to(&packet, destination.addr).await? == packet.len() {
                            metrics.forwards.fetch_add(1, Relaxed);
                            metrics.bytes_relayed.fetch_add(packet.len() as u64, Relaxed);
                        }
                    }
                    PING => {
                        if len != HEADER {
                            continue;
                        }
                        let registered_source = clients.get(&id).is_some_and(|client| {
                            client.addr == source_addr && client.expires_at > unix_now()
                        });
                        if !registered_source {
                            metrics.unknown_destination.fetch_add(1, Relaxed);
                            continue;
                        }
                        if let Some(client) = clients.get_mut(&id) {
                            client.last_seen = Instant::now();
                        }
                        if !admit(
                            &mut node_buckets,
                            id,
                            config.rate_per_sec,
                            config.rate_burst,
                        ) {
                            metrics.rate_limited.fetch_add(1, Relaxed);
                            continue;
                        }
                        let mut packet = Vec::with_capacity(OBSERVED_FRAME);
                        packet.push(OBSERVED);
                        packet.extend_from_slice(&id);
                        match source_addr.ip() {
                            IpAddr::V4(v4) => {
                                packet.push(4);
                                packet.extend_from_slice(&v4.to_ipv6_mapped().octets());
                            }
                            IpAddr::V6(v6) => {
                                packet.push(6);
                                packet.extend_from_slice(&v6.octets());
                            }
                        }
                        packet.extend_from_slice(&source_addr.port().to_be_bytes());
                        let _ = socket.send_to(&packet, source_addr).await;
                    }
                    _ => {}
                }
            }
            _ = reap.tick() => {
                let now = unix_now();
                clients.retain(|_, client| {
                    client.expires_at > now
                        && client.last_seen.elapsed() < Duration::from_secs(config.idle_secs)
                });
                let bucket_idle = Duration::from_secs(config.idle_secs.max(60));
                source_buckets.retain(|_, bucket| bucket.last_refill.elapsed() < bucket_idle);
                node_buckets.retain(|_, bucket| bucket.last_refill.elapsed() < bucket_idle);
            }
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
}
