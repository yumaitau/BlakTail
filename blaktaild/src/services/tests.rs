use super::*;
use rcgen::{
    BasicConstraints, CertificateSigningRequestParams, DnType, IsCa, Issuer, KeyUsagePurpose,
    PublicKeyData, SanType,
};
use std::sync::Mutex;
use tokio_rustls::TlsConnector;

const FQDN: &str = "wiki.svc.12345678.blaktail";

struct FakeApi {
    ca_pem: String,
    ca_key: KeyPair,
    services: Mutex<Option<Vec<AssignedService>>>,
    reports: Mutex<Vec<Vec<HealthEntry>>>,
    issued: Mutex<Vec<String>>,
    lifetime: i64,
}

impl FakeApi {
    fn new(services: Vec<AssignedService>) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test service CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_pem = params.self_signed(&ca_key).unwrap().pem();
        Self {
            ca_pem,
            ca_key,
            services: Mutex::new(Some(services)),
            reports: Mutex::new(Vec::new()),
            issued: Mutex::new(Vec::new()),
            lifetime: 24 * 60 * 60,
        }
    }

    fn last_report(&self) -> Vec<HealthEntry> {
        self.reports
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

impl ServiceApi for FakeApi {
    async fn assigned_services(
        &self,
        _state: &NodeState,
    ) -> Result<Option<Vec<AssignedService>>, Error> {
        Ok(self.services.lock().unwrap().clone())
    }

    async fn issue_certificate(
        &self,
        _state: &NodeState,
        _service: Uuid,
        csr_pem: &str,
    ) -> Result<IssuedCertificate, Error> {
        assert!(!csr_pem.contains("PRIVATE KEY"));
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, &self.ca_key).unwrap();
        let leaf = csr.signed_by(&issuer).unwrap();
        let serial = format!("{:02x}", self.issued.lock().unwrap().len() + 1);
        self.issued.lock().unwrap().push(serial.clone());
        Ok(IssuedCertificate {
            certificate_pem: leaf.pem(),
            ca_pem: self.ca_pem.clone(),
            serial,
            not_after: unix_now() + self.lifetime,
        })
    }

    async fn report_service_health(
        &self,
        _state: &NodeState,
        _listen_port: u16,
        entries: &[HealthEntry],
    ) -> Result<(), Error> {
        self.reports.lock().unwrap().push(entries.to_vec());
        Ok(())
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Loopback HTTP upstream answering every request with `ok`.
async fn upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
                // Hold the connection open so a revoke can be seen to cut it.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

fn state(listen: u16, allowed: &[&str], id: Uuid) -> NodeState {
    NodeState {
        node_id: Uuid::from_u128(rand::random()),
        node_token: "node-token".into(),
        coord: "https://coord.example".into(),
        interface: "blaktail0".into(),
        assigned_ip: "127.0.0.1/32".into(),
        assigned_ips: vec!["127.0.0.1/32".into()],
        dns_name: "host.12345678.blaktail".into(),
        credential_expires_at: i64::MAX,
        advertised_routes: vec![],
        exit_node: None,
        exit_node_active: false,
        router_previous_ipv4_forward: None,
        peers: vec![],
        relays: vec![],
        relay_token: String::new(),
        relay_expires_at: 0,
        relay_endpoint: None,
        relay_endpoint_reported_at: 0,
        relay_endpoints: vec![],
        active_relay: None,
        relay_failovers: 0,
        relay_link: None,
        dns_mode: None,
        org_dns: None,
        dns_degraded: None,
        control_revision: 0,
        published_shares: vec![],
        ssh_users_enforced: false,
        forward_filter: None,
        app_connector: false,
        agent_gateway: false,
        remote: Default::default(),
        public_ingress: false,
        traffic: None,
        acl_filter_enforced: false,
        router_previous_ipv6_forward: None,
        retiring_ips: Vec::new(),
        connector_routes: vec![],
        serve_services: true,
        serve_services_ports: Vec::new(),
        service_listen_port: Some(listen),
        service_access: vec![ServiceAccess {
            id,
            fqdn: FQDN.into(),
            allowed_sources: allowed.iter().map(|ip| (*ip).to_owned()).collect(),
        }],
        service_records: vec![],
    }
}

fn connector(ca_pem: &str) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Connects, completes TLS for `name` and sends one GET; returns the stream
/// and the first response bytes, or `None` when the listener refused.
async fn fetch(
    port: u16,
    ca_pem: &str,
    name: &str,
) -> Option<(tokio_rustls::client::TlsStream<TcpStream>, String)> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap();
    let mut tls = tokio::time::timeout(
        Duration::from_secs(5),
        connector(ca_pem).connect(server_name, tcp),
    )
    .await
    .ok()?
    .ok()?;
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes())
        .await
        .ok()?;
    let mut buffer = vec![0u8; 256];
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buffer))
        .await
        .ok()?
        .ok()?;
    Some((tls, String::from_utf8_lossy(&buffer[..read]).into_owned()))
}

/// Captures this thread's tracing output.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn csr_carries_only_the_node_generated_public_key_and_name() {
    let (key_pem, csr_pem) = new_key_and_csr(FQDN).unwrap();
    assert!(key_pem.contains("PRIVATE KEY"));
    assert!(!csr_pem.contains("PRIVATE KEY"));
    let csr = CertificateSigningRequestParams::from_pem(&csr_pem).unwrap();
    let key = KeyPair::from_pem(&key_pem).unwrap();
    assert_eq!(csr.public_key.der_bytes(), PublicKeyData::der_bytes(&key));
    assert_eq!(
        csr.params.subject_alt_names,
        vec![SanType::DnsName(FQDN.try_into().unwrap())]
    );
    // Every CSR gets a fresh key: renewal rotates the service key.
    let (other_key, _) = new_key_and_csr(FQDN).unwrap();
    assert_ne!(other_key, key_pem);
}

#[test]
fn renewal_happens_at_two_thirds_of_lifetime() {
    let day = 24 * 60 * 60;
    assert!(!renewal_due(1_000, 1_000 + day, 1_000));
    assert!(!renewal_due(1_000, 1_000 + day, 1_000 + day * 2 / 3 - 1));
    assert!(renewal_due(1_000, 1_000 + day, 1_000 + day * 2 / 3));
    assert!(renewal_due(1_000, 1_000 + day, 1_000 + day + 5));
}

#[tokio::test]
async fn listener_serves_allowed_sources_rejects_others_and_drops_on_revoke() {
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let logs = logs.clone();
            move || logs.clone()
        })
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let dir = tempfile::tempdir().unwrap();
    let id = Uuid::from_u128(rand::random());
    let target = upstream().await;
    let listen = free_port();
    let api = FakeApi::new(vec![AssignedService {
        id,
        fqdn: FQDN.into(),
        port: target,
        protocol: "http".into(),
    }]);
    let mut runtime = ServiceRuntime::default();

    // A port the operator did not list is refused outright: no
    // certificate, no route, no probe of the loopback port.
    let mut node = state(listen, &["127.0.0.1"], id);
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(runtime.routed(), 0);
    assert!(api.issued.lock().unwrap().is_empty());
    let report = api.last_report();
    assert!(!report[0].listening && !report[0].healthy);
    assert!(report[0].detail.contains("--serve-services-ports"));

    // Allow list names another overlay address only: 127.0.0.1 is unknown
    // and is dropped before TLS.
    node = state(listen, &["127.0.0.2"], id);
    node.serve_services_ports = vec![target];
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(runtime.routed(), 1);
    assert_eq!(
        runtime.listen_addrs(),
        vec![SocketAddr::from(([127, 0, 0, 1], listen))]
    );
    assert!(fetch(listen, &api.ca_pem, FQDN).await.is_none());
    let report = api.last_report();
    assert!(report[0].listening && report[0].healthy);
    assert_eq!(report[0].serial.as_deref(), Some("01"));

    // The key was made here, stored 0600, and is the certificate's key.
    let (key_path, cert_path, _) = paths(dir.path(), id);
    let key_pem = fs::read_to_string(&key_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(fs::read_to_string(&cert_path)
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    // Allowed source, right name: proxied to the loopback target.
    node = state(listen, &["127.0.0.1"], id);
    node.serve_services_ports = vec![target];
    runtime.manage(&api, &node, dir.path()).await;
    let (mut open, body) = fetch(listen, &api.ca_pem, FQDN).await.expect("served");
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.ends_with("ok"));
    assert_eq!(
        api.issued.lock().unwrap().len(),
        1,
        "no renewal while fresh"
    );

    // SNI for a name this node does not serve is refused.
    assert!(fetch(listen, &api.ca_pem, "other.svc.12345678.blaktail")
        .await
        .is_none());

    // Revoke (disable/delete/suspend all remove it from the list): the
    // route, the open connection and the listener go in one pass.
    *api.services.lock().unwrap() = Some(Vec::new());
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(runtime.routed(), 0);
    assert!(runtime.listen_addrs().is_empty());
    let mut buffer = [0u8; 16];
    let cut = tokio::time::timeout(Duration::from_secs(5), open.read(&mut buffer)).await;
    assert!(matches!(cut, Ok(Ok(0)) | Ok(Err(_))), "{cut:?}");
    tokio::time::sleep(Duration::from_millis(50)).await; // let the aborted accept task drop
    assert!(TcpStream::connect(("127.0.0.1", listen)).await.is_err());
    assert!(!key_path.exists(), "a withdrawn service's key is deleted");

    // Never a key in the logs.
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("service certificate issued"), "{logged}");
    assert!(!logged.contains("PRIVATE KEY"));
    for line in key_pem.lines().filter(|line| !line.starts_with("-----")) {
        assert!(!logged.contains(line));
    }
}

#[tokio::test]
async fn renews_when_due_and_refuses_routes_when_refused_or_unhealthy() {
    // A scoped subscriber here too, so this test never caches "no interest"
    // for callsites the log-capturing test relies on.
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    let dir = tempfile::tempdir().unwrap();
    let id = Uuid::from_u128(rand::random());
    let listen = free_port();
    let dead_port = free_port();
    let mut api = FakeApi::new(vec![AssignedService {
        id,
        fqdn: FQDN.into(),
        port: dead_port,
        protocol: "http".into(),
    }]);
    // A 3-second certificate is past two thirds after 2 seconds.
    api.lifetime = 3;
    let mut node = state(listen, &["127.0.0.1"], id);
    node.serve_services_ports = vec![dead_port];
    let mut runtime = ServiceRuntime::default();
    runtime.manage(&api, &node, dir.path()).await;
    let report = api.last_report();
    assert!(!report[0].healthy, "nothing listens on the target port");
    // A target that fails its HTTP probe is not routed.
    assert!(!report[0].listening);
    assert_eq!(runtime.routed(), 0);
    assert!(runtime.listen_addrs().is_empty());
    assert!(report[0].detail.contains(&dead_port.to_string()));
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(
        api.issued.lock().unwrap().len(),
        2,
        "renewed at 2/3 lifetime"
    );
    assert_eq!(runtime.held[&id].meta.serial, "02");

    // An https upstream is reported unhealthy rather than mis-proxied.
    let (healthy, detail) = probe_target(dead_port, "https", FQDN).await;
    assert!(!healthy && detail.contains("https"));

    // The coordinator refusing the node (revoked/suspended) stops everything.
    *api.services.lock().unwrap() = None;
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(runtime.routed(), 0);
    assert!(runtime.listen_addrs().is_empty());
    assert!(!paths(dir.path(), id).0.exists());

    // Opting out also stops serving.
    let live = upstream().await;
    node.serve_services_ports = vec![live];
    *api.services.lock().unwrap() = Some(vec![AssignedService {
        id,
        fqdn: FQDN.into(),
        port: live,
        protocol: "http".into(),
    }]);
    runtime.manage(&api, &node, dir.path()).await;
    assert_eq!(runtime.routed(), 1);
    let mut off = node.clone();
    off.serve_services = false;
    runtime.manage(&api, &off, dir.path()).await;
    assert_eq!(runtime.routed(), 0);
}
