use blaktail_ingress::{
    access_log::AccessLog,
    acme::Acme,
    coord::Coordinator,
    oidc::{Oidc, OidcConfig},
    proxy::Proxy,
    routes::{RouteTable, TargetPolicy},
    server, tls, Runtime,
};
use clap::Parser;
use rand::RngCore;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Organisation-operated public HTTPS ingress for BlakTail. Run it on an
/// onshore host next to `blaktaild up --public-ingress`.
#[derive(Parser)]
#[command(name = "blaktail-ingress", version)]
struct Cli {
    /// blaktaild state directory; its node identity is used to fetch routes.
    #[arg(
        long,
        env = "BLAKTAIL_INGRESS_AGENT_STATE_DIR",
        default_value = "/var/lib/blaktail"
    )]
    agent_state_dir: PathBuf,
    /// PEM trust bundle for a private coordinator CA.
    #[arg(long, env = "BLAKTAIL_COORD_CA")]
    coord_ca: Option<PathBuf>,
    #[arg(
        long,
        env = "BLAKTAIL_INGRESS_HTTPS_LISTEN",
        default_value = "0.0.0.0:443"
    )]
    https_listen: SocketAddr,
    /// Plain HTTP listener for ACME HTTP-01 and HTTPS redirects. `off` disables it.
    #[arg(
        long,
        env = "BLAKTAIL_INGRESS_HTTP_LISTEN",
        default_value = "0.0.0.0:80"
    )]
    http_listen: String,
    /// Operator certificates: `<dir>/<fqdn>/fullchain.pem` and `privkey.pem`.
    #[arg(
        long,
        env = "BLAKTAIL_INGRESS_CERT_DIR",
        default_value = "/etc/blaktail-ingress/certs"
    )]
    cert_dir: PathBuf,
    /// Ingress state: ACME account and certificates, cookie key, access logs.
    #[arg(
        long,
        env = "BLAKTAIL_INGRESS_DATA_DIR",
        default_value = "/var/lib/blaktail-ingress"
    )]
    data_dir: PathBuf,
    /// Access-log directory; defaults to `<data-dir>/access-logs`. `off` disables logging.
    #[arg(long, env = "BLAKTAIL_INGRESS_LOG_DIR")]
    log_dir: Option<String>,
    /// ACME directory URL, required for routes in `acme_http01` mode.
    #[arg(long, env = "BLAKTAIL_INGRESS_ACME_DIRECTORY")]
    acme_directory: Option<String>,
    /// Extra root CA (PEM) for a private or test ACME server.
    #[arg(long, env = "BLAKTAIL_INGRESS_ACME_ROOT")]
    acme_root: Option<PathBuf>,
    #[arg(long, env = "BLAKTAIL_INGRESS_ACME_CONTACT")]
    acme_contact: Option<String>,
    /// The organisation's OpenID Connect issuer, for routes with `oidc` auth.
    #[arg(long, env = "BLAKTAIL_INGRESS_OIDC_ISSUER")]
    oidc_issuer: Option<String>,
    #[arg(long, env = "BLAKTAIL_INGRESS_OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,
    /// File holding the OIDC client secret (never pass secrets as arguments).
    #[arg(long, env = "BLAKTAIL_INGRESS_OIDC_CLIENT_SECRET_FILE")]
    oidc_client_secret_file: Option<PathBuf>,
    /// Address ranges targets may be in. Defaults to the overlay, 100.64.0.0/10.
    #[arg(
        long = "allow-target-cidr",
        env = "BLAKTAIL_INGRESS_ALLOW_TARGET_CIDRS",
        value_delimiter = ','
    )]
    allow_target_cidrs: Vec<String>,
    #[arg(long, env = "BLAKTAIL_INGRESS_MAX_CONNECTIONS", default_value_t = 4096)]
    max_connections: usize,
}

fn read_or_create_key(path: &Path) -> std::io::Result<Vec<u8>> {
    if let Ok(key) = std::fs::read(path) {
        if key.len() >= 32 {
            return Ok(key);
        }
    }
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(&key)?;
    Ok(key)
}

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("blaktail-ingress: {message}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blaktail_ingress=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    std::fs::create_dir_all(&cli.data_dir)
        .unwrap_or_else(|e| fail(format!("cannot create {}: {e}", cli.data_dir.display())));

    let policy = TargetPolicy::new(&cli.allow_target_cidrs).unwrap_or_else(|e| fail(e));
    let routes = Arc::new(RouteTable::new(policy));
    let acme_dir = cli.data_dir.join("acme");
    let certs = Arc::new(tls::CertStore::new(cli.cert_dir.clone(), acme_dir.clone()));
    let challenges = Arc::default();
    let acme = cli.acme_directory.clone().map(|directory| {
        Arc::new(Acme::new(
            directory,
            cli.acme_root.clone(),
            cli.acme_contact.clone(),
            acme_dir,
            Arc::clone(&challenges),
        ))
    });
    let oidc = match (
        &cli.oidc_issuer,
        &cli.oidc_client_id,
        &cli.oidc_client_secret_file,
    ) {
        (Some(issuer), Some(client_id), Some(secret_file)) => {
            let secret = std::fs::read_to_string(secret_file)
                .unwrap_or_else(|e| fail(format!("cannot read OIDC client secret: {e}")));
            let key = read_or_create_key(&cli.data_dir.join("cookie.key"))
                .unwrap_or_else(|e| fail(format!("cannot create cookie key: {e}")));
            Some(Arc::new(
                Oidc::new(
                    OidcConfig {
                        issuer: issuer.clone(),
                        client_id: client_id.clone(),
                        client_secret: secret.trim().to_owned(),
                    },
                    key,
                )
                .unwrap_or_else(|e| fail(e)),
            ))
        }
        (None, None, None) => None,
        _ => fail(
            "set all of --oidc-issuer, --oidc-client-id and --oidc-client-secret-file, or none",
        ),
    };
    let log_dir = match cli.log_dir.as_deref() {
        Some("off") => None,
        Some(dir) => Some(PathBuf::from(dir)),
        None => Some(cli.data_dir.join("access-logs")),
    };
    let log = match &log_dir {
        Some(dir) => AccessLog::start(dir.clone()),
        None => AccessLog::disabled(),
    };
    let coordinator = Coordinator::new(cli.agent_state_dir.clone(), cli.coord_ca.as_deref())
        .unwrap_or_else(|e| fail(e));
    let runtime = Arc::new(Runtime::new(
        coordinator,
        routes.clone(),
        certs.clone(),
        acme,
        log_dir,
    ));
    let proxy = Arc::new(Proxy {
        routes: routes.clone(),
        log,
        oidc,
        challenges,
    });
    let tls_config = tls::server_config(tls::Resolver {
        certs,
        routes: routes.clone(),
    })
    .unwrap_or_else(|e| fail(e));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let https = tokio::net::TcpListener::bind(cli.https_listen)
        .await
        .unwrap_or_else(|e| fail(format!("cannot listen on {}: {e}", cli.https_listen)));
    tracing::info!(listen = %cli.https_listen, "HTTPS ingress listening");
    tokio::spawn(server::serve_https(
        https,
        acceptor,
        proxy.clone(),
        cli.max_connections,
    ));
    if cli.http_listen != "off" {
        let address: SocketAddr = cli
            .http_listen
            .parse()
            .unwrap_or_else(|_| fail("--http-listen must be host:port or off"));
        let plain = tokio::net::TcpListener::bind(address)
            .await
            .unwrap_or_else(|e| fail(format!("cannot listen on {address}: {e}")));
        tracing::info!(listen = %address, "HTTP (ACME and redirects) listening");
        tokio::spawn(server::serve_plain(
            plain,
            proxy.clone(),
            cli.max_connections,
        ));
    }
    tokio::spawn(runtime.clone().config_loop());
    tokio::spawn(runtime.clone().maintenance_loop());
    shutdown().await;
    tracing::info!("shutting down; public routes are no longer served");
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| fail(e));
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
