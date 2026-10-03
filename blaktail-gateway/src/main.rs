use blaktail_gateway::{Config, Gateway};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use tracing::info;

/// Onshore browser remote-access gateway. Runs beside `blaktaild` on an
/// enrolled node and dials devices only over that node's overlay.
#[derive(Parser)]
#[command(name = "blaktail-gateway", version)]
struct Cli {
    /// Coordinator URL.
    #[arg(long, env = "BLAKTAIL_GATEWAY_COORD")]
    coord: String,
    /// PEM trust bundle for a private coordinator CA.
    #[arg(long, env = "BLAKTAIL_COORD_CA")]
    coord_ca: Option<PathBuf>,
    /// blaktaild state directory holding this node's credential.
    #[arg(long, env = "BLAKTAIL_STATE_DIR", default_value = "/var/lib/blaktail")]
    state_dir: PathBuf,
    #[arg(long, env = "BLAKTAIL_GATEWAY_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    /// Console origin allowed to open sessions, for example
    /// https://console.example.org.au. Repeat for more than one.
    #[arg(
        long = "allowed-origin",
        env = "BLAKTAIL_GATEWAY_ALLOWED_ORIGINS",
        value_delimiter = ',',
        required = true
    )]
    allowed_origins: Vec<String>,
    /// guacd address for RDP, for example 127.0.0.1:4822. RDP is off without it.
    #[arg(long, env = "BLAKTAIL_GATEWAY_GUACD")]
    guacd: Option<String>,
    /// TLS certificate and key (PEM). Without them the gateway serves plain
    /// HTTP and must sit behind a TLS-terminating proxy.
    #[arg(long, env = "BLAKTAIL_GATEWAY_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "BLAKTAIL_GATEWAY_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    let coord_ca_pem = match &cli.coord_ca {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    let gateway = Gateway::new(Config {
        coord: cli.coord,
        state_dir: cli.state_dir,
        allowed_origins: cli.allowed_origins,
        guacd: cli.guacd,
        coord_ca_pem,
    })?;
    let router = gateway.router();
    info!(listen = %cli.listen, "starting BlakTail remote-access gateway");
    match (cli.tls_cert, cli.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(cli.listen, tls)
                .serve(router.into_make_service())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(cli.listen).await?;
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
