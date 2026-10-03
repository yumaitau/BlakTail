//! End-to-end proxy tests: a real TLS listener in front of a real upstream,
//! driven with raw HTTP/1.1 so Host and absolute-form tricks are exact.

use crate::{
    access_log::AccessLog,
    oidc::{Oidc, OidcConfig},
    proxy::{ChallengeMap, Proxy},
    routes::{test_route, IngressConfig, RouteConfig, RouteTable, TargetPolicy},
    server,
    tls::{self, test_support::write_cert, CertStore},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const APP: &str = "app.example.org.au";
const OTHER: &str = "other.example.org.au";

/// Records what the upstream saw, and answers by path.
#[derive(Default)]
struct Upstream {
    hits: AtomicUsize,
    last: Mutex<Option<Seen>>,
}

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: hyper::HeaderMap,
    body_len: usize,
}

async fn upstream_service(
    state: Arc<Upstream>,
    mut req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    let headers = req.headers().clone();
    if path == "/ws" {
        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade.await {
                let mut io = TokioIo::new(upgraded);
                let mut buffer = [0u8; 64];
                while let Ok(n) = io.read(&mut buffer).await {
                    if n == 0 || io.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        *state.last.lock().unwrap() = Some(Seen {
            path,
            headers,
            body_len: 0,
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", "test")
            .body(Full::default())
            .unwrap());
    }
    let body_len = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().len(),
        Err(_) => usize::MAX,
    };
    *state.last.lock().unwrap() = Some(Seen {
        path: path.clone(),
        headers,
        body_len,
    });
    let response = match path.as_str() {
        "/leak" => Response::builder()
            .header("server", "nginx (office-box)")
            .header("x-powered-by", "Express")
            .header("x-internal-peer", "100.64.0.9")
            .header("x-node", "office-box.12345678.blaktail")
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"ok"))),
        "/redirect" => Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "http://169.254.169.254/latest/meta-data")
            .body(Full::default()),
        _ => Response::builder().body(Full::new(Bytes::from("hello from upstream"))),
    };
    Ok(response.unwrap())
}

async fn start_upstream() -> (SocketAddr, Arc<Upstream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = Arc::new(Upstream::default());
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let state = shared.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| upstream_service(state.clone(), req));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (address, state)
}

struct Lab {
    address: SocketAddr,
    plain: SocketAddr,
    routes: Arc<RouteTable>,
    roots: Arc<rustls::RootCertStore>,
    upstream: Arc<Upstream>,
    upstream_addr: SocketAddr,
    challenges: ChallengeMap,
    log_dir: PathBuf,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

fn config(routes: Vec<RouteConfig>) -> IngressConfig {
    IngressConfig {
        revision: 1,
        stale_after_secs: 30,
        routes,
    }
}

async fn lab_with(tune: impl Fn(&mut RouteConfig), oidc: Option<Arc<Oidc>>) -> Lab {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (upstream_addr, upstream) = start_upstream().await;
    let (other_addr, _) = start_upstream().await;
    let certs_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for name in [APP, OTHER] {
        let pem = write_cert(certs_dir.path(), &[name]);
        let der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        roots.add(CertificateDer::from(der.to_vec())).unwrap();
    }
    let routes = Arc::new(RouteTable::new(
        TargetPolicy::new(&["127.0.0.0/8".into()]).unwrap(),
    ));
    let mut app = test_route(APP, upstream_addr);
    tune(&mut app);
    routes.apply(&config(vec![app, test_route(OTHER, other_addr)]));
    let certs = Arc::new(CertStore::new(
        certs_dir.path().into(),
        data_dir.path().join("acme"),
    ));
    certs.refresh(&[
        (APP.into(), "operator_files".into()),
        (OTHER.into(), "operator_files".into()),
    ]);
    let log_dir = data_dir.path().join("logs");
    let challenges: ChallengeMap = Arc::default();
    let proxy = Arc::new(Proxy {
        routes: routes.clone(),
        log: AccessLog::start(log_dir.clone()),
        oidc,
        challenges: challenges.clone(),
    });
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        tls::server_config(tls::Resolver {
            certs,
            routes: routes.clone(),
        })
        .unwrap(),
    ));
    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = https.local_addr().unwrap();
    let plain_address = plain.local_addr().unwrap();
    tokio::spawn(server::serve_https(https, acceptor, proxy.clone(), 64));
    tokio::spawn(server::serve_plain(plain, proxy, 64));
    Lab {
        address,
        plain: plain_address,
        routes,
        roots: Arc::new(roots),
        upstream,
        upstream_addr,
        challenges,
        log_dir,
        _dirs: (certs_dir, data_dir),
    }
}

async fn lab() -> Lab {
    lab_with(|_| {}, None).await
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(lab: &Lab, sni: Option<&str>) -> std::io::Result<Tls> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(lab.roots.clone())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = match sni {
        Some(name) => ServerName::try_from(name.to_owned()).unwrap(),
        None => ServerName::IpAddress(lab.address.ip().into()),
    };
    let stream = TcpStream::connect(lab.address).await?;
    connector.connect(name, stream).await
}

#[derive(Debug)]
struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }
}

fn parse(raw: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Reply {
        status: head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await;
    raw
}

async fn send(lab: &Lab, sni: &str, request: &str) -> Reply {
    let mut stream = connect(lab, Some(sni)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    parse(&read_all(&mut stream).await)
}

fn get(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn serves_the_published_route_with_clean_forwarding_headers() {
    let lab = lab().await;
    let reply = send(
        &lab,
        APP,
        &format!(
            "GET /hello?x=1 HTTP/1.1\r\nHost: {APP}\r\nX-Forwarded-For: 10.9.9.9\r\nX-Real-IP: 10.9.9.9\r\nX-BlakTail-User: boss@example.org.au\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(reply.body, "hello from upstream");
    let seen = lab.upstream.last.lock().unwrap().clone().unwrap();
    assert_eq!(seen.path, "/hello?x=1");
    assert_eq!(seen.headers["host"], APP);
    assert_eq!(seen.headers["x-forwarded-for"], "127.0.0.1");
    assert_eq!(seen.headers["x-forwarded-proto"], "https");
    assert!(!seen.headers.contains_key("x-real-ip"));
    assert!(!seen.headers.contains_key("x-blaktail-user"));
}

#[tokio::test]
async fn wrong_host_or_server_name_is_rejected() {
    let lab = lab().await;
    // Host names another live route on a connection made for APP.
    let reply = send(&lab, APP, &get(OTHER, "/")).await;
    assert_eq!(reply.status, 421, "{reply:?}");
    // Unknown host.
    let reply = send(&lab, APP, &get("evil.example", "/")).await;
    assert_eq!(reply.status, 421);
    // Host with an unexpected port.
    let reply = send(&lab, APP, &get(&format!("{APP}:8443"), "/")).await;
    assert_eq!(reply.status, 400);
    // Two Host headers.
    let reply = send(
        &lab,
        APP,
        &format!("GET / HTTP/1.1\r\nHost: {APP}\r\nHost: {OTHER}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(reply.status, 400);
    // No route for the server name: the TLS handshake itself fails.
    assert!(connect(&lab, Some("evil.example.org.au")).await.is_err());
    // No server name at all (connecting by IP) fails too.
    assert!(connect(&lab, None).await.is_err());
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn absolute_form_and_host_tricks_cannot_change_the_target() {
    let lab = lab().await;
    for request in [
        format!("GET http://169.254.169.254/latest/meta-data HTTP/1.1\r\nHost: {APP}\r\nConnection: close\r\n\r\n"),
        format!("GET http://127.0.0.1:22/ HTTP/1.1\r\nHost: {APP}\r\nConnection: close\r\n\r\n"),
        format!("GET https://{OTHER}/ HTTP/1.1\r\nHost: {APP}\r\nConnection: close\r\n\r\n"),
        "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\nConnection: close\r\n\r\n".to_owned(),
    ] {
        let reply = send(&lab, APP, &request).await;
        assert!(
            [400, 405, 421].contains(&reply.status),
            "{request:?} gave {reply:?}"
        );
    }
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 0);
    // A matching absolute-form request still goes only to the published target.
    let reply = send(
        &lab,
        APP,
        &format!(
            "GET https://{APP}/via-absolute HTTP/1.1\r\nHost: {APP}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(reply.status, 200);
    let seen = lab.upstream.last.lock().unwrap().clone().unwrap();
    assert_eq!(seen.path, "/via-absolute");
}

#[tokio::test]
async fn responses_do_not_leak_internal_details_and_redirects_are_not_followed() {
    let lab = lab().await;
    let reply = send(&lab, APP, &get(APP, "/leak")).await;
    assert_eq!(reply.status, 200);
    let head = reply.head.to_ascii_lowercase();
    for leaked in [
        "server:",
        "x-powered-by",
        "100.64.",
        ".blaktail",
        "office-box",
        &lab.upstream_addr.port().to_string(),
    ] {
        assert!(!head.contains(leaked), "{leaked} leaked in {head}");
    }
    let reply = send(&lab, APP, &get(APP, "/redirect")).await;
    assert_eq!(reply.status, 302);
    assert_eq!(
        reply.header("location").as_deref(),
        Some("https://app.example.org.au/latest/meta-data")
    );
    // One hit each: the ingress never followed the redirect.
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 2);
    // Ingress error pages carry no detail either.
    let reply = send(&lab, APP, &get(OTHER, "/")).await;
    assert!(!reply.body.contains("127.0.0.1"));
    assert!(reply.header("server").is_none());
}

#[tokio::test]
async fn body_limits_apply_to_declared_and_chunked_bodies() {
    let lab = lab().await;
    let big = "x".repeat(2048);
    let reply = send(
        &lab,
        APP,
        &format!("POST /upload HTTP/1.1\r\nHost: {APP}\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n{big}"),
    )
    .await;
    assert_eq!(reply.status, 413);
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 0);
    let reply = send(
        &lab,
        APP,
        &format!("POST /upload HTTP/1.1\r\nHost: {APP}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n800\r\n{big}\r\n0\r\n\r\n"),
    )
    .await;
    assert_eq!(reply.status, 413, "{reply:?}");
    let small = "y".repeat(512);
    let reply = send(
        &lab,
        APP,
        &format!("POST /upload HTTP/1.1\r\nHost: {APP}\r\nContent-Length: 512\r\nConnection: close\r\n\r\n{small}"),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        lab.upstream.last.lock().unwrap().as_ref().unwrap().body_len,
        512
    );
}

#[tokio::test]
async fn request_rate_is_limited_per_route() {
    let lab = lab_with(|route| route.rate_limit_per_minute = 6, None).await;
    assert_eq!(send(&lab, APP, &get(APP, "/")).await.status, 200);
    let reply = send(&lab, APP, &get(APP, "/")).await;
    assert_eq!(reply.status, 429);
    assert_eq!(reply.header("retry-after").as_deref(), Some("10"));
    // Another route keeps its own budget.
    assert_eq!(send(&lab, OTHER, &get(OTHER, "/")).await.status, 200);
}

async fn open_websocket(lab: &Lab) -> Tls {
    let mut stream = connect(lab, Some(APP)).await.unwrap();
    stream
        .write_all(
            format!("GET /ws HTTP/1.1\r\nHost: {APP}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.to_ascii_lowercase().contains("upgrade: websocket"));
    stream
}

#[tokio::test]
async fn websockets_tunnel_and_close_when_the_route_is_withdrawn() {
    let lab = lab().await;
    let mut socket = open_websocket(&lab).await;
    socket.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    socket.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    // Emergency disable: the coordinator stops delivering the route.
    lab.routes.apply(&config(vec![]));
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "tunnel stayed open after the route was withdrawn"
    );
    // New requests on that name fail at the handshake.
    assert!(connect(&lab, Some(APP)).await.is_err());
}

#[tokio::test]
async fn connection_limit_counts_open_tunnels() {
    let lab = lab_with(|route| route.max_connections = 1, None).await;
    let _socket = open_websocket(&lab).await;
    let reply = send(&lab, APP, &get(APP, "/")).await;
    assert_eq!(reply.status, 503);
}

#[tokio::test]
async fn stale_config_serves_nothing() {
    let lab = lab().await;
    let mut stream = connect(&lab, Some(APP)).await.unwrap();
    lab.routes.expire_now();
    stream.write_all(get(APP, "/").as_bytes()).await.unwrap();
    let reply = parse(&read_all(&mut stream).await);
    assert_eq!(reply.status, 503);
    assert!(connect(&lab, Some(APP)).await.is_err());
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn plain_http_redirects_live_routes_and_answers_only_matching_challenges() {
    let lab = lab().await;
    lab.challenges
        .write()
        .unwrap()
        .insert("tok123".into(), (APP.into(), "tok123.thumb".into()));
    let plain = |request: String| async move {
        let mut stream = TcpStream::connect(lab.plain).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        parse(&read_all(&mut stream).await)
    };
    let reply = plain(get(APP, "/docs?a=1")).await;
    assert_eq!(reply.status, 308);
    assert_eq!(
        reply.header("location").as_deref(),
        Some("https://app.example.org.au/docs?a=1")
    );
    assert_eq!(plain(get("evil.example", "/")).await.status, 404);
    let reply = plain(get(APP, "/.well-known/acme-challenge/tok123")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "tok123.thumb");
    let reply = plain(get(OTHER, "/.well-known/acme-challenge/tok123")).await;
    assert_eq!(reply.status, 404);
    assert_eq!(lab.upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn access_logs_record_outcomes_without_target_or_query() {
    let lab = lab().await;
    send(&lab, APP, &get(APP, "/page?token=secret")).await;
    send(&lab, APP, &get("evil.example", "/")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let day = crate::access_log::civil_date(crate::access_log::unix_now());
    let served =
        std::fs::read_to_string(lab.log_dir.join(APP).join(format!("{day}.jsonl"))).unwrap();
    assert!(served.contains("\"outcome\":\"proxied\""), "{served}");
    assert!(served.contains("\"path\":\"/page\""));
    assert!(!served.contains("secret"));
    assert!(!served.contains(&lab.upstream_addr.port().to_string()));
    let rejected =
        std::fs::read_to_string(lab.log_dir.join("_rejected").join(format!("{day}.jsonl")))
            .unwrap();
    assert!(rejected.contains("rejected_host"));
}

// ---------- identity gate against a mock OpenID provider ----------

struct MockIdp {
    issuer: String,
    nonce: Arc<Mutex<String>>,
    email: Arc<Mutex<String>>,
}

async fn start_idp() -> MockIdp {
    use jsonwebtoken::{jwk::Jwk, Algorithm, EncodingKey, Header};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let key = rcgen::KeyPair::generate().unwrap();
    let encoding = EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap();
    let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::ES256).unwrap();
    jwk.common.key_id = Some("k1".into());
    let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
    let nonce = Arc::new(Mutex::new(String::new()));
    let email = Arc::new(Mutex::new("kim@example.org.au".to_owned()));
    let state = (
        issuer.clone(),
        jwks,
        nonce.clone(),
        email.clone(),
        Arc::new(encoding),
    );
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (issuer, jwks, nonce, email, encoding) = state.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let (issuer, jwks, nonce, email, encoding) = (
                        issuer.clone(),
                        jwks.clone(),
                        nonce.clone(),
                        email.clone(),
                        encoding.clone(),
                    );
                    async move {
                        let body = match req.uri().path() {
                            "/.well-known/openid-configuration" => serde_json::json!({
                                "issuer": issuer,
                                "authorization_endpoint": format!("{issuer}/authorize"),
                                "token_endpoint": format!("{issuer}/token"),
                                "jwks_uri": format!("{issuer}/jwks"),
                            })
                            .to_string(),
                            "/jwks" => jwks,
                            "/token" => {
                                let form = req.into_body().collect().await.unwrap().to_bytes();
                                let form = String::from_utf8_lossy(&form).into_owned();
                                assert!(form.contains("code_verifier="));
                                assert!(form.contains("client_secret=s3cret"));
                                let now = crate::access_log::unix_now();
                                let claims = serde_json::json!({
                                    "iss": issuer, "aud": "ingress-client", "sub": "user-1",
                                    "exp": now + 300, "iat": now,
                                    "email": email.lock().unwrap().clone(), "email_verified": true,
                                    "nonce": nonce.lock().unwrap().clone(),
                                });
                                let mut header = Header::new(Algorithm::ES256);
                                header.kid = Some("k1".into());
                                let token =
                                    jsonwebtoken::encode(&header, &claims, &encoding).unwrap();
                                serde_json::json!({"id_token": token, "access_token": "x", "token_type": "Bearer"}).to_string()
                            }
                            _ => String::new(),
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    MockIdp {
        issuer,
        nonce,
        email,
    }
}

fn cookie_pair(reply: &Reply) -> String {
    reply
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn identity_gate_requires_an_allowed_sign_in() {
    let idp = start_idp().await;
    let gate = Arc::new(
        Oidc::new(
            OidcConfig {
                issuer: idp.issuer.clone(),
                client_id: "ingress-client".into(),
                client_secret: "s3cret".into(),
            },
            vec![9; 32],
        )
        .unwrap(),
    );
    let lab = lab_with(
        |route| {
            route.auth_mode = "oidc".into();
            route.allowed_email_domains = vec!["example.org.au".into()];
        },
        Some(gate),
    )
    .await;
    // Anonymous API calls are refused; browsers are sent to sign in.
    let reply = send(
        &lab,
        APP,
        &format!(
            "POST /api HTTP/1.1\r\nHost: {APP}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(reply.status, 401);
    let login = send(&lab, APP, &get(APP, "/private?x=1")).await;
    assert_eq!(login.status, 302, "{login:?}");
    let location = url::Url::parse(&login.header("location").unwrap()).unwrap();
    assert!(location
        .as_str()
        .starts_with(&format!("{}/authorize", idp.issuer)));
    let params: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(
        params["redirect_uri"],
        format!("https://{APP}/.blaktail-ingress/callback")
    );
    assert_eq!(params["code_challenge_method"], "S256");
    *idp.nonce.lock().unwrap() = params["nonce"].clone();
    let flow = cookie_pair(&login);
    // A forged state is refused.
    let reply = send(
        &lab,
        APP,
        &format!("GET /.blaktail-ingress/callback?code=abc&state=forged HTTP/1.1\r\nHost: {APP}\r\nCookie: {flow}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(reply.status, 403);
    let callback = format!(
        "GET /.blaktail-ingress/callback?code=abc&state={} HTTP/1.1\r\nHost: {APP}\r\nCookie: {flow}\r\nConnection: close\r\n\r\n",
        params["state"]
    );
    let reply = send(&lab, APP, &callback).await;
    assert_eq!(reply.status, 303, "{reply:?}");
    assert_eq!(reply.header("location").as_deref(), Some("/private?x=1"));
    let session = cookie_pair(&reply);
    let reply = send(
        &lab,
        APP,
        &format!("GET /private HTTP/1.1\r\nHost: {APP}\r\nCookie: {session}; app=1\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(reply.status, 200);
    let seen = lab.upstream.last.lock().unwrap().clone().unwrap();
    assert_eq!(seen.headers["x-blaktail-user"], "kim@example.org.au");
    assert_eq!(
        seen.headers["cookie"], "app=1",
        "ingress cookie must not reach the target"
    );
    // The session does not carry over to another host.
    let reply = send(
        &lab,
        OTHER,
        &format!(
            "GET / HTTP/1.1\r\nHost: {OTHER}\r\nCookie: {session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(reply.status, 200, "other route is not gated");
    // An account outside the allowed domains cannot sign in.
    *idp.email.lock().unwrap() = "eve@evil.example".into();
    let login = send(&lab, APP, &get(APP, "/")).await;
    let location = url::Url::parse(&login.header("location").unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    *idp.nonce.lock().unwrap() = params["nonce"].clone();
    let reply = send(
        &lab,
        APP,
        &format!(
            "GET /.blaktail-ingress/callback?code=abc&state={} HTTP/1.1\r\nHost: {APP}\r\nCookie: {}\r\nConnection: close\r\n\r\n",
            params["state"],
            cookie_pair(&login)
        ),
    )
    .await;
    assert_eq!(reply.status, 403);
}
