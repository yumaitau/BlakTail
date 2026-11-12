use axum_server::tls_rustls::RustlsConfig;
use blaktail_config::{ConfigHandle, LoadedConfig, ReloadPlan, SecretRef, Service};
use blaktail_coord::{CoordMetrics, Store};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

#[derive(Clone, Debug, Parser)]
#[command(about = "Self-hosted BlakTail coordination server", version)]
struct Cli {
    /// Versioned TOML configuration. Environment overrides remain deterministic.
    #[arg(long, global = true, env = "BLAKTAIL_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, global = true)]
    region: Option<String>,
    #[arg(long, global = true)]
    bind: Option<String>,
    #[arg(long, global = true)]
    metrics_bind: Option<String>,
    #[arg(long, global = true)]
    allow_public_metrics: bool,
    #[arg(long, global = true)]
    database_backend: Option<String>,
    #[arg(long, global = true)]
    database: Option<PathBuf>,
    /// PostgreSQL URL file. Secret values are never accepted on argv.
    #[arg(long, global = true)]
    database_url_file: Option<PathBuf>,
    #[arg(long, global = true)]
    database_storage: Option<String>,
    #[arg(long, global = true)]
    allow_unsafe_efs_sqlite: bool,
    #[arg(long, global = true)]
    tls_cert: Option<PathBuf>,
    /// TLS private-key file path. Secret values are never accepted on argv.
    #[arg(long, global = true)]
    tls_key: Option<PathBuf>,
    /// Comma-separated relay endpoints advertised to nodes.
    #[arg(long, global = true)]
    relays: Option<String>,
    /// Public console URL printed for browser-based headless enrollment.
    #[arg(long, global = true)]
    console_url: Option<String>,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Serve an already-migrated database. This is the default command.
    Serve,
    /// Apply coordinator database migrations without opening network listeners.
    Migrate,
    /// Validate a versioned policy document offline without a database.
    CheckPolicy {
        /// Path to a JSON policy document.
        policy: PathBuf,
    },
    /// Validate organisation DNS settings offline without a database.
    CheckDns {
        /// Path to a JSON DNS settings document.
        settings: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    if let Some(Command::CheckPolicy { policy }) = &cli.command {
        let document = std::fs::read_to_string(policy)?;
        match blaktail_coord::check_policy_document(&document) {
            Ok(report) => {
                println!(
                    "policy ok version={} defaults={} groups={} rules={} ssh={} tests={} tag_owners={}",
                    report.version,
                    report.defaults,
                    report.groups,
                    report.rules,
                    report.ssh,
                    report.tests,
                    report.tag_owners
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("blaktail-coord: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Some(Command::CheckDns { settings }) = &cli.command {
        let document = std::fs::read_to_string(settings)?;
        match blaktail_coord::check_dns_document(&document) {
            Ok(report) => {
                println!(
                    "dns ok managed={} resolvers={} split={} search={} records={}",
                    report.managed,
                    report.global_resolvers,
                    report.split,
                    report.search_domains,
                    report.records
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("blaktail-coord: {error}");
                std::process::exit(1);
            }
        }
    }
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

    if matches!(cli.command, Some(Command::Migrate)) {
        let config = &loaded.config.coordinator;
        match config.database_backend.as_str() {
            "sqlite" => {
                Store::open(&config.database).await?;
            }
            "postgres" => {
                let reference = config
                    .database_url
                    .as_ref()
                    .expect("validated coordinator PostgreSQL URL");
                let database_url = loaded
                    .secret(reference, "coordinator.database_url")?
                    .as_str("coordinator.database_url")?
                    .to_owned();
                Store::migrate_postgres(&database_url).await?;
            }
            _ => unreachable!("validated coordinator database backend"),
        }
        info!(
            schema_version = blaktail_coord::CURRENT_SCHEMA_VERSION,
            "coordinator database migration complete"
        );
        return Ok(());
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
                match config_handle.plan_for_service(&candidate.config, Service::Coordinator) {
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
                            .commit_safe_for_service(candidate.config, Service::Coordinator)
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

    let config = loaded.config.coordinator.clone();
    let schema_version = loaded.config.schema_version;
    let bind = config.bind.parse::<SocketAddr>()?;
    let metrics_bind = config.metrics_bind.parse::<SocketAddr>()?;
    let tls_key = match config
        .tls_key
        .as_ref()
        .expect("validated coordinator TLS key")
    {
        SecretRef::File { path, .. } => path,
        SecretRef::Environment { .. } => {
            return Err("coordinator TLS key must be a file reference".into())
        }
    };
    let auth_hmac_secret = loaded
        .secret(
            config
                .auth_hmac_secret
                .as_ref()
                .expect("validated coordinator auth secret"),
            "coordinator.auth_hmac_secret",
        )?
        .as_bytes()
        .to_vec();
    let relay_auth_secret = match config.relay_auth_secret.as_ref() {
        Some(reference) => loaded
            .secret(reference, "coordinator.relay_auth_secret")?
            .as_bytes()
            .to_vec(),
        None => Vec::new(),
    };
    let diagnostics_token = match config.diagnostics_token.as_ref() {
        Some(reference) => Some(
            loaded
                .secret(reference, "coordinator.diagnostics_token")?
                .as_bytes()
                .to_vec(),
        ),
        None => None,
    };
    let database_url = match config.database_url.as_ref() {
        Some(reference) => Some(
            loaded
                .secret(reference, "coordinator.database_url")?
                .as_str("coordinator.database_url")?
                .to_owned(),
        ),
        None => None,
    };
    drop(loaded);

    let tls = RustlsConfig::from_pem_file(&config.tls_cert, tls_key).await?;
    let store = match config.database_backend.as_str() {
        "sqlite" => Store::open_existing(&config.database).await?,
        "postgres" => {
            Store::open_existing_postgres(
                database_url
                    .as_deref()
                    .expect("validated coordinator PostgreSQL URL"),
            )
            .await?
        }
        _ => unreachable!("validated coordinator database backend"),
    };
    let metrics = Arc::new(CoordMetrics::default());
    let metrics_listener = tokio::net::TcpListener::bind(metrics_bind).await?;
    let metrics_router =
        blaktail_coord::metrics_app_with_token(store.clone(), metrics.clone(), diagnostics_token);
    let api_router = blaktail_coord::app_with_relays_console_and_metrics(
        store,
        config.region.clone(),
        auth_hmac_secret,
        relay_auth_secret,
        config.relays.clone(),
        config.console_url.trim_end_matches('/').to_owned(),
        metrics,
    );
    info!(
        region = config.region,
        bind = %bind,
        metrics = %metrics_bind,
        schema_version,
        "starting BlakTail coordination server"
    );

    let api_handle = axum_server::Handle::new();
    let api_shutdown = api_handle.clone();
    let (shutdown_tx, mut metrics_shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        match shutdown_signal().await {
            Ok(()) => {
                info!("shutdown signal received; draining coordinator listeners");
                api_shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
                let _ = shutdown_tx.send(true);
            }
            Err(error) => warn!(%error, "shutdown signal unavailable"),
        }
    });

    tokio::select! {
        result = axum_server::bind_rustls(bind, tls)
            .handle(api_handle)
            .serve(api_router.into_make_service_with_connect_info::<SocketAddr>()) => result?,
        result = axum::serve(metrics_listener, metrics_router.into_make_service())
            .with_graceful_shutdown(async move {
                if !*metrics_shutdown.borrow() {
                    let _ = metrics_shutdown.changed().await;
                }
            }) => result?,
    }
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
    let mut loaded = LoadedConfig::load(cli.config.as_deref(), Service::Coordinator)?;
    let config = &mut loaded.config.coordinator;
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
    if let Some(value) = &cli.database_backend {
        config.database_backend = value.clone();
    }
    if let Some(value) = &cli.database {
        config.database = value.clone();
    }
    if let Some(value) = &cli.database_url_file {
        config.database_url = Some(SecretRef::file(value));
    }
    if let Some(value) = &cli.database_storage {
        config.database_storage = value.clone();
    }
    if cli.allow_unsafe_efs_sqlite {
        config.allow_unsafe_efs_sqlite = true;
    }
    if let Some(value) = &cli.tls_cert {
        config.tls_cert = value.clone();
    }
    if let Some(value) = &cli.tls_key {
        config.tls_key = Some(SecretRef::file(value));
    }
    if let Some(value) = &cli.relays {
        config.relays = value
            .split(',')
            .map(str::trim)
            .filter(|relay| !relay.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = &cli.console_url {
        config.console_url = value.clone();
    }
    loaded.validate(Service::Coordinator)?;
    Ok(loaded)
}
