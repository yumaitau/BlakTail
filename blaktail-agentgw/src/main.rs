use blaktail_agentgw::{check_listen, router, Gateway, GatewayConfig, NodeIdentity, DEFAULT_PORT};
use clap::Parser;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

/// Organisation-run AI model gateway for the BlakTail agent network. Runs on
/// an enrolled node (enrol it with `blaktaild up --agent-gateway`) and listens
/// only on the overlay.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// blaktaild state file holding this node's id, token and coordinator.
    #[arg(
        long,
        env = "BLAKTAIL_AGENTGW_STATE",
        default_value = "/var/lib/blaktail/state.json"
    )]
    state_file: PathBuf,
    /// Listen address; defaults to this node's overlay address on port 8686.
    #[arg(long, env = "BLAKTAIL_AGENTGW_LISTEN")]
    listen: Option<SocketAddr>,
    /// PEM CA that signs the coordinator's certificate.
    #[arg(long, env = "BLAKTAIL_AGENTGW_COORD_CA")]
    coord_ca: Option<PathBuf>,
    /// Lab only: allow an RFC 1918 / ULA listen address. Never public.
    #[arg(long)]
    allow_private_listen: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let identity: NodeIdentity = serde_json::from_slice(&std::fs::read(&cli.state_file)?)
        .map_err(|_| "state file is not a blaktaild enrollment")?;
    let assigned: Option<IpAddr> = identity
        .assigned_ip
        .split('/')
        .next()
        .and_then(|ip| ip.parse().ok());
    let listen = match (cli.listen, assigned) {
        (Some(listen), _) => listen,
        (None, Some(ip)) => SocketAddr::new(ip, DEFAULT_PORT),
        (None, None) => return Err("no overlay address in the state file; pass --listen".into()),
    };
    check_listen(listen.ip(), assigned, cli.allow_private_listen)?;
    let coord_ca_pem = cli.coord_ca.map(std::fs::read).transpose()?;
    let gateway = Gateway::new(GatewayConfig {
        coordinator_url: identity.coord.clone(),
        node_id: identity.node_id,
        node_token: identity.node_token,
        coord_ca_pem,
    })?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, node_id = %identity.node_id, "agent gateway listening");
    axum::serve(
        listener,
        router(Arc::new(gateway)).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
