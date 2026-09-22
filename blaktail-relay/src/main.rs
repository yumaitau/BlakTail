use blaktail_config::{ConfigHandle, LoadedConfig, ReloadPlan, Service};
use blaktail_relay::{serve_metrics_with_token, RelayConfig};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::UdpSocket;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

#[derive(Clone, Debug, Parser)]
#[command(about = "Australia-pinned BlakTail UDP relay", version)]
struct Cli {
    #[arg(long, env = "BLAKTAIL_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long)]
    region: Option<String>,
    #[arg(long)]
    bind: Option<String>,
    #[arg(long)]
    metrics_bind: Option<String>,
    #[arg(long)]
    allow_public_metrics: bool,
    #[arg(long)]
    idle_secs: Option<u64>,
    #[arg(long)]
    rate_per_sec: Option<u32>,
    #[arg(long)]
    rate_burst: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let loaded = load_effective(&cli)?;
    let filter = tracing_subscriber::EnvFilter::new(&loaded.config.diagnostics.log_filter);
    let (filter_layer, filter_handle) = tracing_subscriber::reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
    for warning in &loaded.warnings {
        warn!(%warning, "configuration deprecation");
    }

    let config_handle = ConfigHandle::new(loaded.config.clone());
    #[cfg(unix)]
    {
        let cli = cli.clone();
        let config_handle = config_handle.clone();
        tokio::spawn(async move {
            let mut signal =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(signal) => signal,
                    Err(error) => {
                        warn!(%error, "configuration reload signal unavailable");
                        return;
                    }
                };
            while signal.recv().await.is_some() {
                let candidate = match load_effective(&cli) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        warn!(%error, "configuration reload rejected; active configuration unchanged");
                        continue;
                    }
                };
                match config_handle.plan_for_service(&candidate.config, Service::Relay) {
                    ReloadPlan::NoChange => info!("configuration reload found no changes"),
                    ReloadPlan::RestartRequired { fields } => {
                        warn!(
                            ?fields,
                            "configuration reload requires restart; active configuration unchanged"
                        )
                    }
                    ReloadPlan::Safe { ref fields } => {
                        let new_filter = tracing_subscriber::EnvFilter::new(
                            &candidate.config.diagnostics.log_filter,
                        );
                        if let Err(error) = filter_handle.reload(new_filter) {
                            warn!(%error, "configuration reload rejected; active configuration unchanged");
                            continue;
                        }
                        match config_handle
                            .commit_safe_for_service(candidate.config, Service::Relay)
                        {
                            Ok(_) => info!(?fields, "configuration reloaded atomically"),
                            Err(plan) => warn!(
                                ?plan,
                                "configuration changed during reload; restart required"
                            ),
                        }
                    }
                }
            }
        });
    }

    let config = loaded.config.relay.clone();
    let schema_version = loaded.config.schema_version;
    let bind = config.bind.parse::<SocketAddr>()?;
    let metrics_bind = config.metrics_bind.parse::<SocketAddr>()?;
    let secret = loaded
        .secret(
            config
                .auth_secret
                .as_ref()
                .expect("validated relay auth secret"),
            "relay.auth_secret",
        )?
        .as_bytes()
        .to_vec();
    let diagnostics_token = match config.diagnostics_token.as_ref() {
        Some(reference) => Some(
            loaded
                .secret(reference, "relay.diagnostics_token")?
                .as_bytes()
                .to_vec(),
        ),
        None => None,
    };
    drop(loaded);
    let relay_config = RelayConfig {
        auth_secret: secret,
        idle_secs: config.idle_seconds,
        rate_per_sec: config.rate_per_second,
        rate_burst: config.rate_burst,
        region: config.region.clone(),
    };
    let socket = UdpSocket::bind(bind).await?;
    info!(
        region = config.region,
        bind = %bind,
        metrics = %metrics_bind,
        schema_version,
        "starting Australia-pinned relay"
    );
    let metrics = Arc::new(blaktail_relay::Metrics::default());
    let mut metrics_task = tokio::spawn(serve_metrics_with_token(
        metrics_bind,
        metrics.clone(),
        diagnostics_token,
    ));
    let mut serve_task = tokio::spawn(blaktail_relay::serve_with_metrics(
        socket,
        relay_config,
        metrics,
    ));
    let result: std::io::Result<()> = tokio::select! {
        result = &mut serve_task => result?,
        result = &mut metrics_task => result?,
        signal = shutdown_signal() => {
            signal?;
            info!("shutdown signal received; stopping relay listeners");
            Ok(())
        }
    };
    serve_task.abort();
    metrics_task.abort();
    result?;
    Ok(())
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

fn load_effective(cli: &Cli) -> Result<LoadedConfig, blaktail_config::ConfigError> {
    let mut loaded = LoadedConfig::load(cli.config.as_deref(), Service::Relay)?;
    let config = &mut loaded.config.relay;
    if let Some(value) = &cli.region {
        config.region = value.clone();
    }
    if let Some(value) = &cli.bind {
        config.bind = value.clone();
    }
    if let Some(value) = &cli.metrics_bind {
        config.metrics_bind = value.clone();
    }
    if cli.allow_public_metrics {
        config.allow_public_metrics = true;
    }
    if let Some(value) = cli.idle_secs {
        config.idle_seconds = value;
    }
    if let Some(value) = cli.rate_per_sec {
        config.rate_per_second = value;
    }
    if let Some(value) = cli.rate_burst {
        config.rate_burst = value;
    }
    loaded.validate(Service::Relay)?;
    Ok(loaded)
}
