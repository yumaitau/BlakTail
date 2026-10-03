use super::*;
use crate::{mint_token, RelayConfig, FORWARDED, ID_LEN, MAX_PAYLOAD, OBSERVED};
use blaktail_relay_proto::{ping_frame, register_frame, send_frame};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const SECRET: &[u8] = b"wss-test-relay-secret";

struct Relay {
    udp: SocketAddr,
    ws: SocketAddr,
    metrics: Arc<Metrics>,
    tasks: Vec<tokio::task::JoinHandle<io::Result<()>>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn relay(config: WssServerConfig) -> Relay {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = socket.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws = listener.local_addr().unwrap();
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = crate::stream_channel();
    let tasks = vec![
        tokio::spawn(crate::serve_with_streams(
            socket,
            RelayConfig {
                auth_secret: SECRET.to_vec(),
                ..RelayConfig::default()
            },
            metrics.clone(),
            rx,
        )),
        tokio::spawn(serve_wss(listener, config, tx, metrics.clone())),
    ];
    Relay {
        udp,
        ws,
        metrics,
        tasks,
    }
}

fn register(id: &[u8; ID_LEN]) -> Vec<u8> {
    let expires = crate::unix_now() + 300;
    register_frame(id, expires, &mint_token(SECRET, id, expires))
}

async fn ws_client(url: &str, options: &ClientOptions) -> ClientStream {
    connect(url, options).await.unwrap()
}

async fn next_binary(ws: &mut ClientStream) -> Vec<u8> {
    loop {
        match timeout(Duration::from_secs(2), ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(frame))) => return frame.to_vec(),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
}

async fn closes(ws: &mut ClientStream) -> bool {
    timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            }
        }
    })
    .await
    .is_ok()
}

fn counter(metrics: &Metrics, prefix: &str) -> u64 {
    metrics
        .render()
        .lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap()
}

fn tls_material() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let server = server_tls(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    (server, certified.cert.der().clone())
}

#[tokio::test]
async fn wss_and_udp_clients_relay_to_each_other_over_tls() {
    let (server, root) = tls_material();
    let relay = relay(WssServerConfig {
        tls: Some(server),
        ..Default::default()
    })
    .await;
    let options = ClientOptions {
        extra_roots: vec![root],
        ..Default::default()
    };
    let url = format!("wss://localhost:{}/v1/relay", relay.ws.port());
    let a = [0xAA; ID_LEN];
    let b = [0xBB; ID_LEN];
    let mut ws = ws_client(&url, &options).await;
    ws.send(Message::binary(register(&a))).await.unwrap();
    ws.send(Message::binary(ping_frame(&a))).await.unwrap();
    let observed = next_binary(&mut ws).await;
    assert_eq!(observed[0], OBSERVED);
    assert!(crate::parse_observed(&observed, &a).is_some());

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&register(&b), relay.udp).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // UDP -> WSS.
    udp.send_to(&send_frame(&a, b"from-udp").unwrap(), relay.udp)
        .await
        .unwrap();
    assert_eq!(
        next_binary(&mut ws).await,
        [&[FORWARDED][..], &b[..], b"from-udp"].concat()
    );
    // WSS -> UDP.
    ws.send(Message::binary(send_frame(&b, b"from-wss").unwrap()))
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let (len, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &buf[..len],
        [&[FORWARDED][..], &a[..], b"from-wss"].concat()
    );
    assert_eq!(
        counter(&relay.metrics, "blaktail_relay_wss_connections "),
        1
    );
    assert_eq!(counter(&relay.metrics, "blaktail_relay_forwards_total "), 2);
}

#[tokio::test]
async fn untrusted_certificates_are_refused() {
    let (server, _) = tls_material();
    let relay = relay(WssServerConfig {
        tls: Some(server),
        ..Default::default()
    })
    .await;
    let url = format!("wss://localhost:{}/v1/relay", relay.ws.port());
    assert!(connect(&url, &ClientOptions::default()).await.is_err());
}

#[tokio::test]
async fn two_wss_clients_exchange_frames_and_forged_tokens_are_refused() {
    let relay = relay(WssServerConfig::default()).await;
    let url = format!("ws://127.0.0.1:{}/v1/relay", relay.ws.port());
    let options = ClientOptions::default();
    let (a, b) = ([1; ID_LEN], [2; ID_LEN]);
    let mut first = ws_client(&url, &options).await;
    let mut second = ws_client(&url, &options).await;
    first.send(Message::binary(register(&a))).await.unwrap();
    // A token minted with the wrong secret registers nothing.
    let expires = crate::unix_now() + 300;
    let forged = register_frame(&b, expires, &mint_token(b"wrong", &b, expires));
    second.send(Message::binary(forged)).await.unwrap();
    second.send(Message::binary(ping_frame(&b))).await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), next_binary(&mut second))
            .await
            .is_err()
    );
    second.send(Message::binary(register(&b))).await.unwrap();
    second.send(Message::binary(ping_frame(&b))).await.unwrap();
    assert_eq!(next_binary(&mut second).await[0], OBSERVED);
    first
        .send(Message::binary(send_frame(&b, b"hello").unwrap()))
        .await
        .unwrap();
    assert_eq!(
        next_binary(&mut second).await,
        [&[FORWARDED][..], &a[..], b"hello"].concat()
    );
    // Closing a connection drops its registration.
    let before = counter(
        &relay.metrics,
        "blaktail_relay_dropped_total{reason=\"unknown_destination\"}",
    );
    second.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    first
        .send(Message::binary(send_frame(&b, b"gone").unwrap()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        counter(
            &relay.metrics,
            "blaktail_relay_dropped_total{reason=\"unknown_destination\"}"
        ),
        before + 1
    );
}

#[tokio::test]
async fn oversized_and_text_messages_close_the_connection() {
    let relay = relay(WssServerConfig::default()).await;
    let url = format!("ws://127.0.0.1:{}/v1/relay", relay.ws.port());
    // The client caps its own messages too, so write the oversized frame
    // with a client configured without limits.
    let tcp = TcpStream::connect(relay.ws).await.unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(url.as_str(), tcp)
        .await
        .unwrap();
    let _ = ws
        .send(Message::binary(vec![0u8; MAX_SEND_FRAME + 1]))
        .await;
    let closed = timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "oversized frame must end the connection");

    let mut text = ws_client(&url, &ClientOptions::default()).await;
    text.send(Message::text("hi")).await.unwrap();
    assert!(closes(&mut text).await);
    // A maximum-size payload still fits in one frame.
    assert!(send_frame(&[0; ID_LEN], &[0; MAX_PAYLOAD]).unwrap().len() <= MAX_SEND_FRAME);
}

#[tokio::test]
async fn slow_handshakes_wrong_paths_and_excess_connections_are_refused() {
    let relay = relay(WssServerConfig {
        handshake_timeout: Duration::from_millis(300),
        max_connections: 2,
        ..Default::default()
    })
    .await;
    // Slowloris: a partial request that never completes is dropped.
    let mut slow = TcpStream::connect(relay.ws).await.unwrap();
    slow.write_all(b"GET /v1/relay HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let read = timeout(Duration::from_secs(2), slow.read(&mut buf))
        .await
        .expect("server must drop the stalled handshake");
    assert!(matches!(read, Ok(0) | Err(_)));
    drop(slow);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let wrong = connect(
        &format!("ws://127.0.0.1:{}/elsewhere", relay.ws.port()),
        &ClientOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(wrong.to_string().contains("404"), "{wrong}");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://127.0.0.1:{}/v1/relay", relay.ws.port());
    let _one = ws_client(&url, &ClientOptions::default()).await;
    let _two = ws_client(&url, &ClientOptions::default()).await;
    assert!(connect(&url, &ClientOptions::default()).await.is_err());
    assert!(counter(&relay.metrics, "blaktail_relay_wss_rejected_total") >= 3);
}

#[tokio::test]
async fn idle_connections_are_closed() {
    let relay = relay(WssServerConfig {
        idle_timeout: Duration::from_millis(300),
        keepalive: Duration::from_secs(60),
        ..Default::default()
    })
    .await;
    let url = format!("ws://127.0.0.1:{}/v1/relay", relay.ws.port());
    let mut ws = ws_client(&url, &ClientOptions::default()).await;
    assert!(closes(&mut ws).await);
}

#[tokio::test]
async fn relay_drops_frames_for_a_stream_whose_queue_is_full() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = socket.local_addr().unwrap();
    let metrics = Arc::new(Metrics::default());
    let (events, rx) = crate::stream_channel();
    let task = tokio::spawn(crate::serve_with_streams(
        socket,
        RelayConfig {
            auth_secret: SECRET.to_vec(),
            ..RelayConfig::default()
        },
        metrics.clone(),
        rx,
    ));
    let (a, b) = ([1; ID_LEN], [2; ID_LEN]);
    // A stream whose consumer never drains its one-slot queue.
    let (tx, _never_read) = mpsc::channel(1);
    events
        .send(StreamEvent::Open {
            id: 7,
            remote: "127.0.0.1:9".parse().unwrap(),
            tx,
        })
        .await
        .unwrap();
    events
        .send(StreamEvent::Frame {
            id: 7,
            frame: register(&b),
        })
        .await
        .unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(&register(&a), udp_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..5 {
        udp.send_to(&send_frame(&b, b"x").unwrap(), udp_addr)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(counter(&metrics, "blaktail_relay_forwards_total "), 1);
    assert_eq!(
        counter(
            &metrics,
            "blaktail_relay_dropped_total{reason=\"stream_queue_full\"}"
        ),
        4
    );
    task.abort();
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:1/v1/relay\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let error = connect(
        &format!("ws://127.0.0.1:{}/v1/relay", address.port()),
        &ClientOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("302"), "{error}");
}

/// Tiny CONNECT proxy that requires `user:pa:ss` and records request heads.
async fn proxy() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                log.lock().unwrap().push(head.clone());
                use base64::Engine as _;
                let expected = format!(
                    "Proxy-Authorization: Basic {}",
                    base64::engine::general_purpose::STANDARD.encode("user:pa:ss")
                );
                if !head.contains(&expected) {
                    let _ = client
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await;
                    return;
                }
                let target = head.split_whitespace().nth(1).unwrap().to_owned();
                let mut upstream = TcpStream::connect(target).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (address, seen)
}

#[tokio::test]
async fn connect_proxy_carries_tls_websocket_with_credentials() {
    let (server, root) = tls_material();
    let relay = relay(WssServerConfig {
        tls: Some(server),
        ..Default::default()
    })
    .await;
    let (proxy_addr, seen) = proxy().await;
    let url = format!("wss://localhost:{}/v1/relay", relay.ws.port());
    let mut options = ClientOptions {
        extra_roots: vec![root],
        proxy: Some(ProxyConfig::new("127.0.0.1", proxy_addr.port())),
    };
    let refused = connect(&url, &options).await.unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);

    options.proxy = Some(
        ProxyConfig::parse(&format!(
            "http://user:pa%3Ass@127.0.0.1:{}",
            proxy_addr.port()
        ))
        .unwrap(),
    );
    assert!(!format!("{:?}", options.proxy).contains("pa"));
    let mut ws = ws_client(&url, &options).await;
    let id = [5; ID_LEN];
    ws.send(Message::binary(register(&id))).await.unwrap();
    ws.send(Message::binary(ping_frame(&id))).await.unwrap();
    assert_eq!(next_binary(&mut ws).await[0], OBSERVED);
    let requests = seen.lock().unwrap().clone();
    assert!(requests
        .last()
        .unwrap()
        .starts_with(&format!("CONNECT localhost:{} HTTP/1.1", relay.ws.port())));
}

#[tokio::test]
async fn wss_link_pumps_frames_both_ways() {
    let relay = relay(WssServerConfig::default()).await;
    let url = format!("ws://127.0.0.1:{}/v1/relay", relay.ws.port());
    let (inbound_tx, mut inbound) = mpsc::channel(8);
    let link = WssLink::spawn(ws_client(&url, &ClientOptions::default()).await, inbound_tx);
    let id = [3; ID_LEN];
    assert!(link.send(register(&id)));
    assert!(link.send(ping_frame(&id)));
    let reply = timeout(Duration::from_secs(2), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(crate::parse_observed(&reply, &id).is_some());
    assert!(!link.is_closed());
}

#[test]
fn proxy_settings_come_from_env_and_files_only() {
    let dir = std::env::temp_dir().join(format!("blaktail-proxy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("password");
    std::fs::write(&file, "from-file\n").unwrap();
    let env = |name: &str| match name {
        "HTTPS_PROXY" => Some("http://proxy.example.au:3128".to_owned()),
        "BLAKTAIL_RELAY_PROXY_USER" => Some("svc".to_owned()),
        "BLAKTAIL_RELAY_PROXY_PASSWORD_FILE" => Some(file.display().to_string()),
        _ => None,
    };
    let proxy = ProxyConfig::from_lookup(env).unwrap().unwrap();
    assert_eq!(
        (proxy.host.as_str(), proxy.port),
        ("proxy.example.au", 3128)
    );
    use base64::Engine as _;
    assert_eq!(
        proxy.authorization.as_deref(),
        Some(
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("svc:from-file")
            )
            .as_str()
        )
    );
    assert!(!format!("{proxy:?}").contains("from-file"));
    assert!(ProxyConfig::from_lookup(|_| None).unwrap().is_none());
    assert!(ProxyConfig::parse("https://proxy:443").is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn relay_urls_require_wss_except_on_loopback_and_reject_credentials() {
    let url = RelayUrl::parse("wss://relay.example.au/v1/relay?x=1").unwrap();
    assert_eq!(
        url,
        RelayUrl {
            tls: true,
            host: "relay.example.au".into(),
            port: 443,
            path: "/v1/relay".into()
        }
    );
    assert_eq!(RelayUrl::parse("wss://[::1]:8443/r").unwrap().port, 8443);
    assert!(RelayUrl::parse("ws://relay.example.au/v1/relay").is_err());
    assert!(RelayUrl::parse("ws://127.0.0.1:9/v1/relay").is_ok());
    assert!(RelayUrl::parse("wss://u:p@relay.example.au/").is_err());
    assert!(RelayUrl::parse("https://relay.example.au/").is_err());
}
