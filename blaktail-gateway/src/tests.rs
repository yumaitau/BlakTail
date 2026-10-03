//! Gateway tests against an in-process SSH server and a fake coordinator.

use super::*;
use axum::{extract::Path as UrlPath, routing::post, Json};
use futures_util::{SinkExt, StreamExt};
use russh::keys::ssh_key::{self, certificate, private::Ed25519Keypair, PrivateKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use std::sync::Mutex;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as WsMessage};

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// A tiny SSH server: trusts one user CA, logs in only the listed principal,
/// and answers `id` like a shell would.
#[derive(Clone)]
struct TestServer {
    ca: ssh_key::PublicKey,
    user: String,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &ssh_key::Certificate,
    ) -> Result<Auth, Self::Error> {
        let trusted = certificate
            .validate([&self.ca.fingerprint(ssh_key::HashAlg::Sha256)])
            .is_ok();
        let named = certificate.valid_principals().iter().any(|p| p == user);
        Ok(if trusted && named && user == self.user {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"$ ".to_vec())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.starts_with(b"id") {
            let reply = format!("uid=1000({0}) gid=1000({0})\r\n$ ", self.user);
            session.data(channel, reply.into_bytes())?;
        }
        Ok(())
    }
}

async fn ssh_server(host_key: PrivateKey, ca: ssh_key::PublicKey, user: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let handler = TestServer {
        ca,
        user: user.to_owned(),
    };
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    address
}

fn sign(ca: &PrivateKey, subject: &str, principal: &str) -> String {
    let subject = ssh_key::PublicKey::from_openssh(subject).unwrap();
    let now = unix_now() as u64;
    let mut builder = certificate::Builder::new(
        vec![1u8; 16],
        subject.key_data().clone(),
        now - 30,
        now + 600,
    )
    .unwrap();
    builder
        .cert_type(certificate::CertType::User)
        .unwrap()
        .valid_principal(principal)
        .unwrap()
        .extension("permit-pty", "")
        .unwrap();
    builder.sign(ca).unwrap().to_openssh().unwrap()
}

#[tokio::test]
async fn certificate_login_reaches_a_shell_with_the_pinned_host_key() {
    let ca = key(1);
    let host = key(2);
    let address = ssh_server(host.clone(), ca.public_key().clone(), "deploy").await;
    let session_key = ssh::ephemeral_key();
    let certificate = sign(&ca, &session_key.public_openssh, "deploy");
    let host_key = host.public_key().to_openssh().unwrap();
    let shell = ssh::open_shell(
        &ssh::Target {
            address,
            host_key: &host_key,
            user: "deploy",
        },
        &session_key,
        &certificate,
        80,
        24,
    )
    .await
    .unwrap();
    let (mut reader, writer) = shell.channel.split();
    writer.data(&b"id\n"[..]).await.unwrap();
    let mut seen = String::new();
    while !seen.contains("uid=1000(deploy)") {
        match reader.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                seen.push_str(&String::from_utf8_lossy(&data))
            }
            Some(_) => {}
            None => panic!("channel closed: {seen}"),
        }
    }
}

#[tokio::test]
async fn host_key_mismatch_fails_closed_before_login() {
    let ca = key(1);
    let address = ssh_server(key(2), ca.public_key().clone(), "deploy").await;
    let session_key = ssh::ephemeral_key();
    let certificate = sign(&ca, &session_key.public_openssh, "deploy");
    let reported = key(3).public_key().to_openssh().unwrap();
    let result = ssh::open_shell(
        &ssh::Target {
            address,
            host_key: &reported,
            user: "deploy",
        },
        &session_key,
        &certificate,
        80,
        24,
    )
    .await;
    assert_eq!(result.err(), Some(ssh::SshError::HostKeyMismatch));
}

#[tokio::test]
async fn certificate_for_another_user_is_refused() {
    let ca = key(1);
    let host = key(2);
    let address = ssh_server(host.clone(), ca.public_key().clone(), "deploy").await;
    let session_key = ssh::ephemeral_key();
    let certificate = sign(&ca, &session_key.public_openssh, "root");
    let host_key = host.public_key().to_openssh().unwrap();
    let result = ssh::open_shell(
        &ssh::Target {
            address,
            host_key: &host_key,
            user: "deploy",
        },
        &session_key,
        &certificate,
        80,
        24,
    )
    .await;
    assert_eq!(result.err(), Some(ssh::SshError::Auth));
}

#[test]
fn only_console_origins_may_open_a_browser_session() {
    let allowed = vec!["https://console.example.au".to_string()];
    let mut headers = HeaderMap::new();
    assert!(origin_allowed(&headers, &allowed));
    headers.insert(ORIGIN, "https://console.example.au".parse().unwrap());
    assert!(origin_allowed(&headers, &allowed));
    headers.insert(ORIGIN, "https://evil.example".parse().unwrap());
    assert!(!origin_allowed(&headers, &allowed));
}

// ---------------------------------------------------------------------------
// End to end through the WebSocket with a fake coordinator

struct FakeCoordinator {
    ca: PrivateKey,
    host_key: String,
    target: SocketAddr,
    terminate: Mutex<bool>,
    reports: Mutex<Vec<serde_json::Value>>,
    redeemed: Mutex<u32>,
}

async fn fake_coordinator(fake: Arc<FakeCoordinator>) -> String {
    let redeem_state = fake.clone();
    let report_state = fake.clone();
    let router = Router::new()
        .route(
            "/v1/nodes/:node/remote-sessions/redeem",
            post(move |Json(body): Json<serde_json::Value>| {
                let fake = redeem_state.clone();
                async move {
                    let mut redeemed = fake.redeemed.lock().unwrap();
                    if body["ticket"] != "good-ticket" || *redeemed > 0 {
                        return (StatusCode::GONE, Json(serde_json::json!({"error":"gone"})));
                    }
                    *redeemed += 1;
                    let certificate =
                        sign(&fake.ca, body["public_key"].as_str().unwrap(), "deploy");
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "session_id": Uuid::nil(),
                            "kind": "ssh",
                            "target_node_id": Uuid::nil(),
                            "target_name": "server",
                            "target_address": fake.target.ip().to_string(),
                            "port": fake.target.port(),
                            "os_user": "deploy",
                            "host_key": fake.host_key,
                            "certificate": certificate,
                            "max_end_at": unix_now() + 600,
                            "idle_timeout_seconds": 600,
                            "report_interval_seconds": 2,
                        })),
                    )
                }
            }),
        )
        .route(
            "/v1/nodes/:node/remote-sessions/:session/report",
            post(
                move |UrlPath((_, _)): UrlPath<(String, String)>,
                      Json(body): Json<serde_json::Value>| {
                    let fake = report_state.clone();
                    async move {
                        fake.reports.lock().unwrap().push(body);
                        let terminate = *fake.terminate.lock().unwrap();
                        Json(if terminate {
                            serde_json::json!({"action":"terminate","reason":"revoked"})
                        } else {
                            serde_json::json!({"action":"continue"})
                        })
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://127.0.0.1:{}", address.port())
}

async fn gateway(coord: String) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("state.json"),
        serde_json::json!({"node_id": Uuid::nil(), "node_token": "node-token", "coord": "x"})
            .to_string(),
    )
    .unwrap();
    let gateway = Gateway::new(Config {
        coord,
        state_dir: dir.path().to_path_buf(),
        allowed_origins: vec!["https://console.example.au".into()],
        guacd: None,
        coord_ca_pem: None,
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = gateway.router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("ws://127.0.0.1:{}/v1/session", address.port()), dir)
}

async fn lab(host_key_seed: u8) -> (Arc<FakeCoordinator>, String, tempfile::TempDir) {
    let ca = key(1);
    let host = key(2);
    let target = ssh_server(host, ca.public_key().clone(), "deploy").await;
    let fake = Arc::new(FakeCoordinator {
        ca,
        host_key: key(host_key_seed).public_key().to_openssh().unwrap(),
        target,
        terminate: Mutex::new(false),
        reports: Mutex::new(Vec::new()),
        redeemed: Mutex::new(0),
    });
    let coord = fake_coordinator(fake.clone()).await;
    let (url, dir) = gateway(coord).await;
    (fake, url, dir)
}

async fn next_text(
    socket: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
) -> (String, String) {
    let mut output = String::new();
    loop {
        match socket.next().await {
            Some(Ok(WsMessage::Text(text))) => return (text.to_string(), output),
            Some(Ok(WsMessage::Binary(bytes))) => output.push_str(&String::from_utf8_lossy(&bytes)),
            Some(Ok(_)) => {}
            other => panic!("socket ended: {other:?}"),
        }
    }
}

#[tokio::test]
async fn browser_session_runs_id_and_ends_when_revoked() {
    let (fake, url, _dir) = lab(2).await;
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", "https://console.example.au".parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(WsMessage::Text(
            serde_json::json!({"ticket":"good-ticket","cols":100,"rows":30}).to_string(),
        ))
        .await
        .unwrap();
    let (status, _) = next_text(&mut socket).await;
    assert!(status.contains("\"connecting\""), "{status}");
    let (status, _) = next_text(&mut socket).await;
    assert!(status.contains("\"connected\""), "{status}");
    socket
        .send(WsMessage::Binary(b"id\n".to_vec()))
        .await
        .unwrap();
    let mut output = String::new();
    while !output.contains("uid=1000(deploy)") {
        match socket.next().await {
            Some(Ok(WsMessage::Binary(bytes))) => output.push_str(&String::from_utf8_lossy(&bytes)),
            Some(Ok(_)) => {}
            other => panic!("socket ended: {other:?}"),
        }
    }
    // The coordinator revokes the session; the next report ends it.
    *fake.terminate.lock().unwrap() = true;
    let (status, _) = next_text(&mut socket).await;
    assert!(
        status.contains("\"closed\"") && status.contains("revoked"),
        "{status}"
    );
    let reports = fake.reports.lock().unwrap().clone();
    assert!(reports.iter().any(|report| report["bytes_to_target"] == 3));
}

async fn start(url: &str, ticket: &str) -> String {
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    socket
        .send(WsMessage::Text(
            serde_json::json!({ "ticket": ticket }).to_string(),
        ))
        .await
        .unwrap();
    loop {
        let (status, _) = next_text(&mut socket).await;
        if status.contains("\"closed\"") {
            return status;
        }
    }
}

#[tokio::test]
async fn used_or_unknown_tickets_never_connect() {
    let (fake, url, _dir) = lab(2).await;
    *fake.redeemed.lock().unwrap() = 1;
    let status = start(&url, "good-ticket").await;
    assert!(status.contains("already used"), "{status}");
    let status = start(&url, "made-up").await;
    assert!(status.contains("already used"), "{status}");
    assert!(fake.reports.lock().unwrap().is_empty());
}

#[tokio::test]
async fn host_key_mismatch_is_reported_and_closes_the_browser_session() {
    let (fake, url, _dir) = lab(9).await;
    let status = start(&url, "good-ticket").await;
    assert!(status.contains("host_key_mismatch"), "{status}");
    let reports = fake.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0]["ended"], "host_key_mismatch");
}

#[tokio::test]
async fn foreign_origins_cannot_upgrade() {
    let (_fake, url, _dir) = lab(2).await;
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(error.to_string().contains("403"), "{error}");
}
