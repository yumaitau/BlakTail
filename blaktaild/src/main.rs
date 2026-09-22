use blaktail_config::{AgentConfig, ConfigHandle, LoadedConfig, ReloadPlan, Service};
use blaktaild::{
    apply_peer_map, configure_system_dns, disable_share, dns_domain, enable_share, put_share_file,
    ensure_private_key, load_shares, organisation_dns_managed, organisation_resolver_suffixes,
    overlay_ipv4, peer_key_hex, published_resolver_suffixes, read_state, remove_system_dns,
    restore_peers, sync_once, validate_advertised_routes, validate_interface, write_state,
    Coordinator, MagicDns, Network, Registration, RelayMesh, ShareServer, DIRECT_GRACE_SECS,
    DIRECT_RETRY_SECS, HANDSHAKE_FRESH_SECS,
};
use clap::{Parser, Subcommand};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read as _,
    path::PathBuf,
    process,
    time::{Duration, Instant},
};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "blaktaild",
    about = "BlakTail WireGuard node agent (Linux and macOS)",
    version
)]
struct Cli {
    #[arg(long, global = true, env = "BLAKTAIL_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, global = true, hide = true)]
    state_dir: Option<PathBuf>,
    /// PEM trust bundle for a private coordinator CA.
    #[arg(long, global = true, env = "BLAKTAIL_COORD_CA")]
    coord_ca: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Join a tailnet and keep WireGuard peers synchronized.
    Up {
        #[arg(long)]
        coord: Option<String>,
        /// Single-use join key. Omit for browser enrollment or pipe a key on stdin.
        #[arg(long, hide_env_values = true, env = "BLAKTAIL_JOIN_KEY")]
        join_key: Option<String>,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long)]
        name: Option<String>,
        /// Public UDP endpoint advertised to peers, for example 203.0.113.5:51820.
        #[arg(long)]
        endpoint: Option<String>,
        /// IPv4 CIDRs routed through this Linux node, comma separated. Use `none` to clear.
        #[arg(long, value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Advertise this Linux node as an IPv4 exit node (owner approval is still required).
        #[arg(long)]
        advertise_exit_node: bool,
        /// Approved exit node name, DNS name, or UUID. Use `none` to disable.
        #[arg(long)]
        exit_node: Option<String>,
        #[arg(long)]
        poll_seconds: Option<u64>,
        /// Exit after the first successful peer sync; launchd or systemd keeps syncing via `run`.
        #[arg(long)]
        exit_after_join: bool,
        /// Delete this node automatically after it has been offline for 24 hours.
        #[arg(long)]
        ephemeral: bool,
    },
    /// Resume the persisted enrollment and keep WireGuard peers synchronized.
    Run {
        #[arg(long)]
        poll_seconds: Option<u64>,
    },
    /// Renew this enrollment with a fresh join key without changing its tailnet IP.
    Reauth {
        /// Fresh join key. Omit to read it from stdin.
        #[arg(long, hide_env_values = true, env = "BLAKTAIL_JOIN_KEY")]
        join_key: Option<String>,
    },
    /// Show persisted node and peer status without exposing credentials.
    Status,
    /// Publish or withdraw a read-only HTTP/WebDAV folder on the overlay.
    Share {
        #[command(subcommand)]
        action: ShareCommand,
    },
    /// Stop the local tunnel while retaining enrollment for a later resume.
    Pause,
    /// Revoke this node and remove its WireGuard interface.
    Down,
}

#[derive(Subcommand)]
enum ShareCommand {
    /// Serve an absolute directory over the tailnet as HTTP and WebDAV.
    Enable {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
        /// Accept PUT of a single file. Omitted shares stay read-only.
        #[arg(long)]
        writable: bool,
    },
    /// Send one file to a peer share that was enabled with --writable.
    Send {
        #[arg(long)]
        url: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Stop serving a named share, or every share on this node.
    Disable {
        #[arg(long)]
        name: Option<String>,
    },
    /// List local and peer shares.
    List,
}

#[derive(Clone, Default)]
struct AgentOverrides {
    state_dir: Option<PathBuf>,
    coordinator_url: Option<String>,
    interface: Option<String>,
    poll_seconds: Option<u64>,
    advertised_routes: Option<Vec<String>>,
}

impl AgentOverrides {
    fn from_cli(cli: &Cli) -> Self {
        let mut overrides = Self {
            state_dir: cli.state_dir.clone(),
            ..Self::default()
        };
        match &cli.command {
            Command::Up {
                coord,
                interface,
                advertise_routes,
                poll_seconds,
                ..
            } => {
                overrides.coordinator_url = coord.clone();
                overrides.interface = interface.clone();
                overrides.poll_seconds = *poll_seconds;
                if !advertise_routes.is_empty() {
                    overrides.advertised_routes = Some(
                        (advertise_routes.len() == 1
                            && advertise_routes[0].eq_ignore_ascii_case("none"))
                        .then(Vec::new)
                        .unwrap_or_else(|| advertise_routes.clone()),
                    );
                }
            }
            Command::Run { poll_seconds } => overrides.poll_seconds = *poll_seconds,
            Command::Reauth { .. }
            | Command::Status
            | Command::Share { .. }
            | Command::Pause
            | Command::Down => {}
        }
        overrides
    }

    fn apply(&self, config: &mut AgentConfig) {
        if let Some(value) = &self.state_dir {
            config.state_dir = value.clone();
        }
        if let Some(value) = &self.coordinator_url {
            config.coordinator_url = Some(value.clone());
        }
        if let Some(value) = &self.interface {
            config.interface = value.clone();
        }
        if let Some(value) = self.poll_seconds {
            config.poll_seconds = value;
        }
        if let Some(value) = &self.advertised_routes {
            config.advertised_routes = value.clone();
        }
    }
}

#[tokio::main]
async fn main() {
    let mut cli = Cli::parse();
    let overrides = AgentOverrides::from_cli(&cli);
    let mut loaded = match LoadedConfig::load(cli.config.as_deref(), Service::Agent) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("blaktaild: {error}");
            std::process::exit(1);
        }
    };
    overrides.apply(&mut loaded.config.agent);
    if cli.state_dir.is_none() {
        cli.state_dir = Some(loaded.config.agent.state_dir.clone());
    }
    if let Err(error) = loaded.validate(Service::Agent) {
        eprintln!("blaktaild: {error}");
        std::process::exit(1);
    }
    let filter = tracing_subscriber::EnvFilter::new(&loaded.config.diagnostics.log_filter);
    let (filter_layer, filter_handle) = tracing_subscriber::reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
    for warning in &loaded.warnings {
        warn!(%warning, "configuration deprecation");
    }
    #[cfg(unix)]
    {
        let config_path = cli.config.clone();
        let overrides = overrides.clone();
        let config_handle = ConfigHandle::new(loaded.config.clone());
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
                let mut candidate = match LoadedConfig::load(config_path.as_deref(), Service::Agent)
                {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        warn!(%error, "configuration reload rejected; active configuration unchanged");
                        continue;
                    }
                };
                overrides.apply(&mut candidate.config.agent);
                if let Err(error) = candidate.validate(Service::Agent) {
                    warn!(%error, "configuration reload rejected; active configuration unchanged");
                    continue;
                }
                match config_handle.plan_for_service(&candidate.config, Service::Agent) {
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
                            .commit_safe_for_service(candidate.config, Service::Agent)
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
    if let Err(error) = run(cli, loaded.config.agent).await {
        eprintln!("blaktaild: {error}");
        std::process::exit(1);
    }
}

fn coordinator_client(
    coord: &str,
    ca_path: Option<&std::path::Path>,
) -> Result<Coordinator, blaktaild::Error> {
    match ca_path {
        Some(path) => {
            let pem = fs::read(path).map_err(|error| {
                blaktaild::Error::Message(format!(
                    "could not read coordinator CA {}: {error}",
                    path.display()
                ))
            })?;
            Coordinator::with_ca(coord, Some(&pem))
        }
        None => Coordinator::new(coord),
    }
}

fn detect_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            process::Command::new("hostname")
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "blaktail-node".into())
}

/// Join keys arrive on stdin (never argv) when the caller is another program.
fn resolve_optional_join_key(provided: Option<String>) -> Result<Option<String>, blaktaild::Error> {
    if let Some(key) = provided {
        let key = key.trim().to_owned();
        if key.is_empty() {
            return Err(blaktaild::Error::Message(
                "join key must not be empty".into(),
            ));
        }
        return Ok(Some(key));
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut key = String::new();
    std::io::stdin()
        .read_to_string(&mut key)
        .map_err(|e| blaktaild::Error::Message(format!("could not read join key: {e}")))?;
    let key = key.trim().to_owned();
    if key.is_empty() {
        return Ok(None);
    }
    Ok(Some(key))
}

fn resolve_join_key(provided: Option<String>) -> Result<String, blaktaild::Error> {
    resolve_optional_join_key(provided)?.ok_or_else(|| {
        blaktaild::Error::Message("a fresh join key must be passed or piped to stdin".into())
    })
}

async fn browser_join_key(
    coordinator: &Coordinator,
    name: &str,
    public_key: &str,
) -> Result<String, blaktaild::Error> {
    let authorization = coordinator
        .begin_device_authorization(name, public_key)
        .await?;
    println!(
        "Authenticate this device in a browser:\n{}\n\nCode: {}",
        authorization.verification_url, authorization.user_code
    );
    let mut device_code = authorization.device_code;
    let interval = Duration::from_secs(authorization.interval_seconds.clamp(1, 10));
    loop {
        if blaktaild_now() as i64 >= authorization.expires_at {
            device_code.zeroize();
            return Err(blaktaild::Error::Message(
                "browser enrollment expired; run blaktaild up again".into(),
            ));
        }
        match coordinator
            .device_authorization_approved(&device_code)
            .await
        {
            Ok(true) => return Ok(device_code),
            Ok(false) => tokio::time::sleep(interval).await,
            Err(error) => {
                device_code.zeroize();
                return Err(error);
            }
        }
    }
}

fn make_network() -> Box<dyn Network> {
    #[cfg(target_os = "macos")]
    {
        Box::new(blaktaild::MacOsNetwork::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(blaktaild::LinuxNetwork::default())
    }
}

async fn sync_loop(
    coordinator: &Coordinator,
    network: &mut dyn Network,
    state: &mut blaktaild::NodeState,
    state_dir: &std::path::Path,
    poll_seconds: u64,
    exit_after_join: bool,
) -> Result<(), blaktaild::Error> {
    let mut mesh: Option<RelayMesh> = None;
    let mut dns: Option<MagicDns> = None;
    let mut shares: Option<ShareServer> = None;
    let mut paths: HashMap<Uuid, PeerPath> = HashMap::new();
    loop {
        match sync_once(coordinator, network, state, state_dir).await {
            Ok(changes) if changes > 0 => info!(changes, "WireGuard peers synchronized"),
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "peer synchronization failed; retaining existing tunnel configuration")
            }
        }
        manage_magic_dns(&mut dns, state, state_dir).await;
        manage_shares(&mut shares, coordinator, state, state_dir).await;
        manage_paths(network, &mut mesh, state, &mut paths).await;
        report_relay_endpoint(coordinator, mesh.as_ref(), state, state_dir).await;
        if exit_after_join {
            if let Some(active) = mesh.take() {
                active.stop();
            }
            info!("initial peer sync complete; leaving MagicDNS resolver files for the service manager");
            return Ok(());
        }
        let previous_assigned_ips = state.assigned_ips.clone();
        let previous_addresses = state.interface_addresses();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { info!("stopping peer sync; interface remains configured"); break; }
            result = coordinator.wait_for_control_update(state, 25) => {
                match result {
                    Ok(Some(desired)) => {
                        match apply_peer_map(
                            network,
                            state,
                            state_dir,
                            desired,
                            previous_assigned_ips,
                            previous_addresses,
                        ) {
                            Ok(changes) if changes > 0 => info!(changes, "WireGuard peers synchronized"),
                            Ok(_) => {}
                            Err(error) => warn!(%error, "peer synchronization failed; retaining existing tunnel configuration"),
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(%error, "control update wait failed; falling back to snapshot poll");
                        tokio::time::sleep(Duration::from_secs(poll_seconds.max(1))).await;
                        if let Err(error) = sync_once(coordinator, network, state, state_dir).await {
                            warn!(%error, "peer synchronization failed; retaining existing tunnel configuration");
                        }
                    }
                }
            }
        }
    }
    if let Some(active) = mesh.take() {
        active.stop();
    }
    if let Some(active) = shares.take() {
        active.stop();
    }
    shutdown_magic_dns(&mut dns, state, state_dir);
    Ok(())
}

async fn manage_shares(
    server: &mut Option<ShareServer>,
    coordinator: &Coordinator,
    state: &blaktaild::NodeState,
    state_dir: &std::path::Path,
) {
    let local = match load_shares(state_dir) {
        Ok(shares) => shares,
        Err(error) => {
            warn!(%error, "could not read local share configuration");
            return;
        }
    };
    let enabled = local.iter().any(|share| share.enabled);
    if !enabled {
        if let Some(active) = server.take() {
            active.stop();
        }
        return;
    }
    let Ok(bind_ip) = overlay_ipv4(state) else {
        warn!("cannot serve shares without a tailnet IPv4 address");
        return;
    };
    if server
        .as_ref()
        .is_some_and(|active| active.matches(bind_ip, &local))
    {
        return;
    }
    if let Some(active) = server.take() {
        active.stop();
    }
    match ShareServer::spawn(bind_ip, &local).await {
        Ok(created) => {
            info!(address = %created.listen_addr(), "overlay file share listening");
            if let Err(error) = coordinator.publish_shares(state, &local).await {
                warn!(%error, "could not publish shares to the coordinator");
            }
            *server = Some(created);
        }
        Err(error) => warn!(%error, "could not bind overlay file share"),
    }
}

async fn manage_magic_dns(
    dns: &mut Option<MagicDns>,
    state: &mut blaktaild::NodeState,
    state_dir: &std::path::Path,
) {
    let Some(domain) = dns_domain(&state.dns_name) else {
        return;
    };
    if dns.as_ref().is_some_and(|active| !active.matches(state)) {
        let old_domain = dns
            .as_ref()
            .map(|active| active.domain().to_owned())
            .expect("active resolver checked");
        if let Err(error) = remove_system_dns(
            state_dir,
            &state.interface,
            &old_domain,
            &organisation_resolver_suffixes(state),
            state.dns_mode.as_deref(),
        ) {
            warn!(%error, "could not remove stale MagicDNS configuration");
            return;
        }
        if let Some(active) = dns.take() {
            active.stop();
        }
        state.dns_mode = None;
    }
    if dns.is_none() {
        let created = match MagicDns::spawn(state).await {
            Ok(created) => created,
            Err(error) => {
                warn!(%error, "could not bind local MagicDNS resolver");
                return;
            }
        };
        let mode = if organisation_dns_managed(state) {
            let extras = published_resolver_suffixes(state);
            match configure_system_dns(
                state_dir,
                &state.interface,
                created.bind_ip(),
                &domain,
                &extras,
            ) {
                Ok(mode) => mode,
                Err(error) => {
                    warn!(%error, "could not configure system MagicDNS routing; resolver stays on the overlay address");
                    "listener-only".into()
                }
            }
        } else {
            "listener-only".into()
        };
        info!(%domain, mode, "MagicDNS resolver active");
        state.dns_mode = Some(mode);
        if let Err(error) = write_state(state_dir, state) {
            warn!(%error, "could not persist MagicDNS configuration state");
        }
        *dns = Some(created);
    }
    if let Some(active) = dns.as_ref() {
        active.update(state);
        if organisation_dns_managed(state) {
            let extras = published_resolver_suffixes(state);
            if let Err(error) = configure_system_dns(
                state_dir,
                &state.interface,
                active.bind_ip(),
                &domain,
                &extras,
            ) {
                warn!(%error, "could not refresh published DNS search and split routing");
            }
        } else if state
            .dns_mode
            .as_deref()
            .is_some_and(|mode| mode != "listener-only")
        {
            if let Err(error) = remove_system_dns(
                state_dir,
                &state.interface,
                &domain,
                &organisation_resolver_suffixes(state),
                state.dns_mode.as_deref(),
            ) {
                warn!(%error, "could not restore the previous system resolver after managed DNS was disabled");
                return;
            }
            info!("organisation DNS unmanaged; previous system resolver restored");
            state.dns_mode = Some("listener-only".into());
            if let Err(error) = write_state(state_dir, state) {
                warn!(%error, "could not persist MagicDNS restore state");
            }
        }
    }
}

fn shutdown_magic_dns(
    dns: &mut Option<MagicDns>,
    state: &mut blaktaild::NodeState,
    state_dir: &std::path::Path,
) {
    let Some(active) = dns.take() else {
        return;
    };
    let domain = active.domain().to_owned();
    active.stop();
    match remove_system_dns(
        state_dir,
        &state.interface,
        &domain,
        &organisation_resolver_suffixes(state),
        state.dns_mode.as_deref(),
    ) {
        Ok(()) => {
            state.dns_mode = None;
            if let Err(error) = write_state(state_dir, state) {
                warn!(%error, "could not persist MagicDNS shutdown state");
            }
        }
        Err(error) => warn!(%error, "could not remove MagicDNS configuration"),
    }
}

const RELAY_ENDPOINT_REPORT_SECS: u64 = 60;

#[derive(Clone, Copy, Debug)]
enum PeerPath {
    Direct { since: Instant },
    Relayed { since: Instant },
    DirectProbe { since: Instant, baseline: u64 },
    PeerDirect { last_fresh: Instant },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathAction {
    None,
    MaintainRelay,
    MaintainPeerDirect,
    UseRelay,
    ProbeNativeDirect,
    DirectRecovered,
    PeerDirectRecovered,
}

fn path_action(
    path: PeerPath,
    direct_handshake_fresh: bool,
    latest_handshake: u64,
    has_native_endpoint: bool,
    peer_endpoint: Option<std::net::SocketAddr>,
    peer_direct_reachable: bool,
) -> PathAction {
    match path {
        PeerPath::Direct { since }
            if !direct_handshake_fresh && since.elapsed().as_secs() >= DIRECT_GRACE_SECS =>
        {
            PathAction::UseRelay
        }
        PeerPath::Relayed { .. } if peer_endpoint.is_some() && peer_direct_reachable => {
            PathAction::PeerDirectRecovered
        }
        PeerPath::Relayed { since, .. } if since.elapsed().as_secs() >= DIRECT_RETRY_SECS => {
            if has_native_endpoint {
                PathAction::ProbeNativeDirect
            } else {
                PathAction::MaintainRelay
            }
        }
        PeerPath::Relayed { .. } => PathAction::MaintainRelay,
        PeerPath::DirectProbe { baseline, .. } if latest_handshake > baseline => {
            PathAction::DirectRecovered
        }
        PeerPath::DirectProbe { since, .. } if since.elapsed().as_secs() >= DIRECT_GRACE_SECS => {
            PathAction::UseRelay
        }
        PeerPath::PeerDirect { .. } if peer_endpoint.is_none() => PathAction::UseRelay,
        PeerPath::PeerDirect { .. } if direct_handshake_fresh => PathAction::MaintainPeerDirect,
        PeerPath::PeerDirect { last_fresh }
            if last_fresh.elapsed().as_secs() >= DIRECT_GRACE_SECS =>
        {
            PathAction::UseRelay
        }
        PeerPath::PeerDirect { .. } => PathAction::MaintainPeerDirect,
        _ => PathAction::None,
    }
}

/// Keeps each peer on its best available transport. Failed direct paths move
/// to a relay-assisted localhost forwarder. Encrypted relay traffic continues
/// while that forwarder attempts a coordinator-mediated UDP hole punch.
async fn manage_paths(
    network: &mut dyn Network,
    mesh: &mut Option<RelayMesh>,
    state: &blaktaild::NodeState,
    paths: &mut HashMap<Uuid, PeerPath>,
) {
    let now_unix = blaktaild_now();
    if state.relays.is_empty() || state.relay_token.is_empty() || state.relay_expires_at <= now_unix
    {
        disable_relay(network, mesh, state, paths);
        return;
    }
    let interface = &state.interface;
    let failed_relay = mesh.as_ref().and_then(|active| {
        (!active.relay_healthy()).then(|| {
            let address = active.relay_addr();
            warn!(%address, "relay health probe expired; trying another endpoint");
            address
        })
    });
    if failed_relay.is_some() {
        if let Some(active) = mesh.take() {
            active.stop();
        }
    }
    if mesh.is_none() {
        let Some(relay_addr) = resolve_relay(&state.relays, failed_relay).await else {
            warn!("could not resolve any advertised relay; direct paths only");
            return;
        };
        let listen = match network.listen_endpoint(interface) {
            Ok(Some(listen)) => listen,
            Ok(None) => return,
            Err(error) => {
                warn!(%error, "could not read WireGuard listen port; direct paths only");
                return;
            }
        };
        match RelayMesh::spawn(
            relay_addr,
            listen,
            state.node_id,
            &state.relay_token,
            state.relay_expires_at,
            state.exit_node.as_ref().map(|_| 51_820),
        ) {
            Ok(created) => *mesh = Some(created),
            Err(error) => warn!(%error, "could not start relay client; direct paths only"),
        }
    } else if let Some(active) = mesh.as_ref() {
        active.update_credentials(&state.relay_token, state.relay_expires_at);
    }
    let Some(mesh) = mesh.as_ref() else {
        return;
    };

    let handshakes = network.latest_handshakes(interface).unwrap_or_default();
    let current_peers: HashSet<Uuid> = state.peers.iter().map(|peer| peer.id).collect();
    let removed: Vec<Uuid> = paths
        .keys()
        .filter(|peer_id| !current_peers.contains(peer_id))
        .copied()
        .collect();
    for peer_id in removed {
        mesh.drop_forwarder(peer_id);
        paths.remove(&peer_id);
    }

    for peer in &state.peers {
        let stamp = handshakes
            .get(&peer_key_hex(&peer.wg_public_key).unwrap_or_default())
            .copied()
            .unwrap_or(0);
        let fresh = stamp > now_unix.saturating_sub(HANDSHAKE_FRESH_SECS);
        let path = paths.entry(peer.id).or_insert_with(|| PeerPath::Direct {
            since: Instant::now(),
        });
        let current = *path;
        let peer_endpoint = peer
            .relay_endpoint
            .as_deref()
            .and_then(|endpoint| endpoint.parse::<std::net::SocketAddr>().ok());
        let peer_direct_reachable =
            peer_endpoint.is_some_and(|endpoint| mesh.peer_direct_reachable(peer.id, endpoint));
        let next = match path_action(
            current,
            fresh,
            stamp,
            peer.endpoint.is_some(),
            peer_endpoint,
            peer_direct_reachable,
        ) {
            PathAction::UseRelay => {
                if switch_to_relay(network, mesh, interface, peer).await {
                    Some(PeerPath::Relayed {
                        since: Instant::now(),
                    })
                } else {
                    Some(PeerPath::Direct {
                        since: Instant::now(),
                    })
                }
            }
            PathAction::MaintainRelay => {
                if switch_to_relay(network, mesh, interface, peer).await {
                    Some(current)
                } else {
                    Some(PeerPath::Direct {
                        since: Instant::now(),
                    })
                }
            }
            PathAction::PeerDirectRecovered => {
                let endpoint = peer_endpoint.expect("action requires peer endpoint");
                if switch_to_peer_direct(network, mesh, interface, peer, endpoint).await {
                    info!(peer = %peer.name, %endpoint, "peer-direct UDP path established");
                    Some(PeerPath::PeerDirect {
                        last_fresh: Instant::now(),
                    })
                } else {
                    let _ = switch_to_relay(network, mesh, interface, peer).await;
                    Some(PeerPath::Relayed {
                        since: Instant::now(),
                    })
                }
            }
            PathAction::MaintainPeerDirect => {
                let endpoint = peer_endpoint.expect("action requires peer endpoint");
                if switch_to_peer_direct(network, mesh, interface, peer, endpoint).await {
                    Some(if fresh {
                        PeerPath::PeerDirect {
                            last_fresh: Instant::now(),
                        }
                    } else {
                        current
                    })
                } else {
                    let _ = switch_to_relay(network, mesh, interface, peer).await;
                    Some(PeerPath::Relayed {
                        since: Instant::now(),
                    })
                }
            }
            PathAction::ProbeNativeDirect => {
                let endpoint = peer.endpoint.as_deref().expect("action requires endpoint");
                match network.set_peer_endpoint(interface, &peer.wg_public_key, endpoint) {
                    Ok(()) => {
                        mesh.drop_forwarder(peer.id);
                        info!(peer = %peer.name, "probing direct path");
                        Some(PeerPath::DirectProbe {
                            since: Instant::now(),
                            baseline: stamp,
                        })
                    }
                    Err(error) => {
                        warn!(%error, peer = %peer.name, "could not probe direct endpoint");
                        Some(current)
                    }
                }
            }
            PathAction::DirectRecovered => {
                info!(peer = %peer.name, "direct path recovered; leaving relay");
                Some(PeerPath::Direct {
                    since: Instant::now(),
                })
            }
            PathAction::None => None,
        };
        if let Some(next) = next {
            paths.insert(peer.id, next);
        }
    }
}

async fn switch_to_relay(
    network: &mut dyn Network,
    mesh: &RelayMesh,
    interface: &str,
    peer: &blaktaild::Peer,
) -> bool {
    let already_relayed = mesh.has_forwarder(peer.id);
    match mesh.ensure_forwarder(peer.id).await {
        Ok(port) => {
            let peer_endpoint = peer
                .relay_endpoint
                .as_deref()
                .and_then(|endpoint| endpoint.parse::<std::net::SocketAddr>().ok());
            if !mesh.use_relay(peer.id, peer_endpoint) {
                return false;
            }
            let local = format!("127.0.0.1:{port}");
            if let Err(error) = network.set_peer_endpoint(interface, &peer.wg_public_key, &local) {
                warn!(%error, peer = %peer.name, "could not switch to relay path");
                mesh.drop_forwarder(peer.id);
                false
            } else {
                if !already_relayed {
                    info!(peer = %peer.name, %local, "using relay-assisted path");
                }
                true
            }
        }
        Err(error) => {
            warn!(%error, peer = %peer.name, "relay forwarder failed");
            false
        }
    }
}

async fn switch_to_peer_direct(
    network: &mut dyn Network,
    mesh: &RelayMesh,
    interface: &str,
    peer: &blaktaild::Peer,
    endpoint: std::net::SocketAddr,
) -> bool {
    match mesh.ensure_forwarder(peer.id).await {
        Ok(port) => {
            if !mesh.use_peer_direct(peer.id, endpoint) {
                return false;
            }
            let local = format!("127.0.0.1:{port}");
            if let Err(error) = network.set_peer_endpoint(interface, &peer.wg_public_key, &local) {
                warn!(%error, peer = %peer.name, "could not use peer-direct path");
                mesh.drop_forwarder(peer.id);
                false
            } else {
                true
            }
        }
        Err(error) => {
            warn!(%error, peer = %peer.name, "peer-direct forwarder failed");
            false
        }
    }
}

async fn report_relay_endpoint(
    coordinator: &Coordinator,
    mesh: Option<&RelayMesh>,
    state: &mut blaktaild::NodeState,
    state_dir: &std::path::Path,
) {
    let Some(endpoint) = mesh.and_then(RelayMesh::observed_endpoint) else {
        return;
    };
    let now = blaktaild_now();
    let endpoint_text = endpoint.to_string();
    let unchanged = state.relay_endpoint.as_deref() == Some(endpoint_text.as_str());
    if unchanged
        && now.saturating_sub(state.relay_endpoint_reported_at) < RELAY_ENDPOINT_REPORT_SECS
    {
        return;
    }
    match coordinator.report_relay_endpoint(state, endpoint).await {
        Ok(()) => {
            if !unchanged {
                info!(%endpoint, "reported reflexive UDP endpoint");
            }
            state.relay_endpoint = Some(endpoint_text);
            state.relay_endpoint_reported_at = now;
            if let Err(error) = write_state(state_dir, state) {
                warn!(%error, "could not persist reported relay endpoint");
            }
        }
        Err(error) => warn!(%error, "could not report reflexive UDP endpoint"),
    }
}

fn disable_relay(
    network: &mut dyn Network,
    mesh: &mut Option<RelayMesh>,
    state: &blaktaild::NodeState,
    paths: &mut HashMap<Uuid, PeerPath>,
) {
    if let Some(active) = mesh.take() {
        for peer in &state.peers {
            if active.has_forwarder(peer.id) {
                if let Some(endpoint) = peer.endpoint.as_deref() {
                    let _ =
                        network.set_peer_endpoint(&state.interface, &peer.wg_public_key, endpoint);
                }
            }
        }
        active.stop();
    }
    paths.clear();
}

async fn resolve_relay(
    relays: &[String],
    excluded: Option<std::net::SocketAddr>,
) -> Option<std::net::SocketAddr> {
    let mut fallback = None;
    for relay in relays {
        if let Ok(mut addresses) = tokio::net::lookup_host(relay).await {
            for address in &mut addresses {
                fallback.get_or_insert(address);
                if Some(address) != excluded {
                    return Some(address);
                }
            }
        }
    }
    fallback
}

fn blaktaild_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn run(cli: Cli, operator_config: AgentConfig) -> Result<(), blaktaild::Error> {
    let state_dir = cli
        .state_dir
        .as_deref()
        .expect("agent state directory resolved before run");
    match cli.command {
        Command::Up {
            coord,
            join_key,
            interface,
            name,
            endpoint,
            advertise_routes,
            advertise_exit_node,
            exit_node,
            poll_seconds,
            exit_after_join,
            ephemeral,
        } => {
            let coord = coord
                .or_else(|| operator_config.coordinator_url.clone())
                .ok_or_else(|| {
                    blaktaild::Error::Message(
                        "coordinator URL is required via --coord, agent.coordinator_url, or BLAKTAIL_AGENT_COORD_URL"
                            .into(),
                    )
                })?;
            let interface = interface.unwrap_or_else(|| operator_config.interface.clone());
            let poll_seconds = poll_seconds.unwrap_or(operator_config.poll_seconds);
            let advertise_routes = if advertise_routes.is_empty() {
                operator_config.advertised_routes.clone()
            } else {
                advertise_routes
            };
            validate_interface(&interface)?;
            let routes_were_supplied = !advertise_routes.is_empty() || advertise_exit_node;
            let clear_routes =
                advertise_routes.len() == 1 && advertise_routes[0].eq_ignore_ascii_case("none");
            if advertise_routes
                .iter()
                .any(|route| route.eq_ignore_ascii_case("none"))
                && (!clear_routes || advertise_exit_node)
            {
                return Err(blaktaild::Error::Message(
                    "--advertise-routes none cannot be combined with other routes".into(),
                ));
            }
            let mut requested_routes = if clear_routes {
                Vec::new()
            } else {
                advertise_routes
            };
            if advertise_exit_node {
                requested_routes.push("0.0.0.0/0".into());
            }
            let requested_routes = validate_advertised_routes(&requested_routes)?;
            let exit_node_was_supplied = exit_node.is_some();
            let requested_exit_node = exit_node.and_then(|value| {
                let value = value.trim();
                (!value.is_empty() && !value.eq_ignore_ascii_case("none")).then(|| value.to_owned())
            });
            #[cfg(target_os = "macos")]
            if !requested_routes.is_empty() || requested_exit_node.is_some() {
                return Err(blaktaild::Error::Message(
                    "subnet and exit-node routing is currently supported on Linux only".into(),
                ));
            }
            let (key_path, public_key) = ensure_private_key(state_dir)?;
            let coordinator = coordinator_client(&coord, cli.coord_ca.as_deref())?;
            let name = name.unwrap_or_else(detect_hostname);
            let resumed = state_dir.join("state.json").exists();
            let mut previous_routes = Vec::new();
            let mut routes_changed = false;
            let mut state = match read_state(state_dir) {
                Ok(mut existing) if existing.coord == coord && existing.interface == interface => {
                    previous_routes = existing.advertised_routes.clone();
                    if routes_were_supplied && requested_routes != existing.advertised_routes {
                        existing.advertised_routes = requested_routes.clone();
                        routes_changed = true;
                    }
                    if exit_node_was_supplied {
                        existing.exit_node = requested_exit_node.clone();
                        existing.exit_node_active = false;
                        for peer in &mut existing.peers {
                            peer.allowed_ips.retain(|route| route != "0.0.0.0/0");
                        }
                    }
                    existing
                }
                Ok(_) => return Err(blaktaild::Error::Message(
                    "existing enrollment uses a different coordinator or interface; run down first"
                        .into(),
                )),
                Err(blaktaild::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    let mut join_key = match resolve_optional_join_key(join_key)? {
                        Some(join_key) => join_key,
                        None => browser_join_key(&coordinator, &name, &public_key).await?,
                    };
                    let registration = coordinator
                        .register(Registration {
                            join_key: &join_key,
                            name: &name,
                            public_key: &public_key,
                            endpoint: endpoint.as_deref(),
                            interface: &interface,
                            advertised_routes: &requested_routes,
                            exit_node: requested_exit_node.clone(),
                            ephemeral,
                        })
                        .await;
                    join_key.zeroize();
                    registration?
                }
                Err(error) => return Err(error),
            };
            let mut network = make_network();
            let interface_addresses = state.interface_addresses();
            if let Err(error) = network.setup(&interface, &key_path, &interface_addresses) {
                if !resumed {
                    let _ = coordinator.revoke(&state).await;
                }
                return Err(error);
            }
            let previous_ipv4_forward = state.router_previous_ipv4_forward;
            match network.configure_router(
                &interface,
                &previous_routes,
                &state.advertised_routes,
                state.router_previous_ipv4_forward,
            ) {
                Ok(original) => state.router_previous_ipv4_forward = original,
                Err(error) => {
                    if !resumed {
                        let _ = coordinator.revoke(&state).await;
                    }
                    let _ = network.down(&interface);
                    return Err(error);
                }
            }
            if routes_changed {
                if let Err(error) = coordinator
                    .update_advertised_routes(&state, &state.advertised_routes)
                    .await
                {
                    let _ = network.configure_router(
                        &interface,
                        &state.advertised_routes,
                        &previous_routes,
                        previous_ipv4_forward,
                    );
                    let _ = network.down(&interface);
                    return Err(error);
                }
            }
            write_state(state_dir, &state)?;
            let restored = restore_peers(network.as_mut(), &state, state_dir)?;
            if restored > 0 {
                info!(restored, "restored persisted WireGuard peers");
            }
            let addresses = state.interface_addresses().join(",");
            info!(node_id = %state.node_id, %addresses, interface, "tailnet joined");
            println!(
                "joined\nnode: {}\ninterface: {}\naddress: {}\nipv6 address: {}\ncoordinator: {}",
                state.node_id,
                state.interface,
                state.assigned_ip,
                state.ipv6_address().unwrap_or("unavailable"),
                state.coord
            );
            sync_loop(
                &coordinator,
                network.as_mut(),
                &mut state,
                state_dir,
                poll_seconds,
                exit_after_join,
            )
            .await?;
        }
        Command::Run { poll_seconds } => {
            let poll_seconds = poll_seconds.unwrap_or(operator_config.poll_seconds);
            let mut state = read_state(state_dir)?;
            validate_interface(&state.interface)?;
            let (key_path, _) = ensure_private_key(state_dir)?;
            let coordinator = coordinator_client(&state.coord, cli.coord_ca.as_deref())?;
            let mut network = make_network();
            network.setup(&state.interface, &key_path, &state.interface_addresses())?;
            state.router_previous_ipv4_forward = network.configure_router(
                &state.interface,
                &state.advertised_routes,
                &state.advertised_routes,
                state.router_previous_ipv4_forward,
            )?;
            write_state(state_dir, &state)?;
            let restored = restore_peers(network.as_mut(), &state, state_dir)?;
            if restored > 0 {
                info!(restored, "restored persisted WireGuard peers");
            }
            info!(node_id = %state.node_id, interface = %state.interface, "resuming enrollment");
            sync_loop(
                &coordinator,
                network.as_mut(),
                &mut state,
                state_dir,
                poll_seconds,
                false,
            )
            .await?;
        }
        Command::Reauth { join_key } => {
            let mut state = read_state(state_dir)?;
            let coordinator = coordinator_client(&state.coord, cli.coord_ca.as_deref())?;
            let mut join_key = resolve_join_key(join_key)?;
            let result = coordinator.reauth(&mut state, &join_key).await;
            join_key.zeroize();
            result?;
            write_state(state_dir, &state)?;
            println!(
                "node credential renewed\n{}",
                credential_status(state.credential_expires_at, blaktaild_now() as i64)
            );
        }
        Command::Status => {
            let state = read_state(state_dir)?;
            println!(
                "joined\nnode: {}\ninterface: {}\naddress: {}\nipv6 address: {}\ndns: {}\ncoordinator: {}\ncredential: {}\nadvertised routes: {}\nexit node: {}\npeers: {}",
                state.node_id,
                state.interface,
                state.assigned_ip,
                state.ipv6_address().unwrap_or("unavailable"),
                if state.dns_name.is_empty() { "unknown" } else { &state.dns_name },
                state.coord,
                credential_status(state.credential_expires_at, blaktaild_now() as i64),
                if state.advertised_routes.is_empty() {
                    "none".into()
                } else {
                    state.advertised_routes.join(",")
                },
                state.exit_node.as_deref().map_or_else(
                    || "none".to_owned(),
                    |exit| format!(
                        "{exit} ({})",
                        if state.exit_node_active { "active" } else { "pending approval or unavailable" }
                    )
                ),
                state.peers.len()
            );
            if let Some(dns) = &state.org_dns {
                println!("dns revision: {}", dns.revision);
                println!("dns managed: {}", if dns.managed { "yes" } else { "no" });
            }
            match state.dns_degraded.as_deref() {
                Some(reason) => println!("dns health: degraded ({reason})"),
                None => println!("dns health: ok"),
            }
            match load_shares(state_dir) {
                Ok(shares) if !shares.is_empty() => {
                    for share in shares {
                        println!(
                            "share: {} {} {}",
                            if share.enabled { "enabled" } else { "disabled" },
                            share.url(&state.dns_name),
                            share.path
                        );
                    }
                }
                _ => {}
            }
            for share in &state.published_shares {
                println!("peer share: {}", share.url());
            }
            for peer in state.peers {
                println!(
                    "  {} {} {} {}",
                    peer.name,
                    peer.endpoint.as_deref().unwrap_or("endpoint unknown"),
                    peer.allowed_ips.join(","),
                    peer.ingress_summary()
                );
            }
        }
        Command::Share { action } => {
            let state = read_state(state_dir)?;
            let coordinator = coordinator_client(&state.coord, cli.coord_ca.as_deref())?;
            match action {
                ShareCommand::Enable {
                    path,
                    name,
                    writable,
                } => {
                    let share = enable_share(state_dir, &path, name.as_deref(), !writable)?;
                    let shares = load_shares(state_dir)?;
                    coordinator.publish_shares(&state, &shares).await?;
                    println!("share enabled {}", share.url(&state.dns_name));
                }
                ShareCommand::Disable { name } => {
                    let shares = disable_share(state_dir, name.as_deref())?;
                    coordinator.publish_shares(&state, &shares).await?;
                    println!("share disabled");
                }
                ShareCommand::Send { url, file } => {
                    let bytes = std::fs::read(&file)?;
                    let status = put_share_file(&url, &bytes).await?;
                    println!("sent {} ({status})", file.display());
                }
                ShareCommand::List => {
                    for share in load_shares(state_dir)? {
                        println!(
                            "{} {} {}",
                            if share.enabled { "enabled" } else { "disabled" },
                            share.url(&state.dns_name),
                            share.path
                        );
                    }
                    for share in &state.published_shares {
                        println!("peer {}", share.url());
                    }
                }
            }
        }
        Command::Pause => {
            let state = read_state(state_dir)?;
            if let Some(domain) = dns_domain(&state.dns_name) {
                remove_system_dns(
                    state_dir,
                    &state.interface,
                    &domain,
                    &organisation_resolver_suffixes(&state),
                    state.dns_mode.as_deref(),
                )?;
            }
            let mut network = make_network();
            network.configure_router(
                &state.interface,
                &state.advertised_routes,
                &[],
                state.router_previous_ipv4_forward,
            )?;
            network.down(&state.interface)?;
            println!(
                "tunnel paused; enrollment for node {} retained",
                state.node_id
            );
        }
        Command::Down => {
            let state = read_state(state_dir)?;
            if let Some(domain) = dns_domain(&state.dns_name) {
                remove_system_dns(
                    state_dir,
                    &state.interface,
                    &domain,
                    &organisation_resolver_suffixes(&state),
                    state.dns_mode.as_deref(),
                )?;
            }
            let coordinator = coordinator_client(&state.coord, cli.coord_ca.as_deref())?;
            let mut network = make_network();
            network.configure_router(
                &state.interface,
                &state.advertised_routes,
                &[],
                state.router_previous_ipv4_forward,
            )?;
            coordinator.revoke(&state).await?;
            network.down(&state.interface)?;
            fs::remove_file(state_dir.join("state.json"))?;
            println!("node revoked and {} removed", state.interface);
        }
    }
    Ok(())
}

fn credential_status(expires_at: i64, now: i64) -> String {
    if expires_at == 0 {
        return "expiry unknown; run the agent to refresh status".into();
    }
    if expires_at <= now {
        return format!("expired at Unix {expires_at}; run blaktaild reauth");
    }
    let days = (expires_at - now + 86_399) / 86_400;
    format!("expires at Unix {expires_at} (in {days} day(s))")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_is_distinct_from_destructive_down() {
        let paused = Cli::try_parse_from(["blaktaild", "pause"]).expect("pause command");
        let down = Cli::try_parse_from(["blaktaild", "down"]).expect("down command");
        assert!(matches!(paused.command, Command::Pause));
        assert!(matches!(down.command, Command::Down));
    }

    #[test]
    fn relayed_handshake_does_not_masquerade_as_direct_recovery() {
        let candidate = std::net::SocketAddr::from(([198, 51, 100, 1], 40_001));
        let path = PeerPath::Relayed {
            since: Instant::now(),
        };
        assert_eq!(
            path_action(path, true, 100, true, Some(candidate), false),
            PathAction::MaintainRelay
        );
    }

    #[test]
    fn relayed_path_uses_proven_peer_direct_or_retries_native() {
        let candidate = std::net::SocketAddr::from(([198, 51, 100, 1], 40_001));
        let path = PeerPath::Relayed {
            since: Instant::now() - Duration::from_secs(DIRECT_RETRY_SECS + 1),
        };
        assert_eq!(
            path_action(path, true, 100, true, Some(candidate), true),
            PathAction::PeerDirectRecovered
        );
        assert_eq!(
            path_action(path, true, 100, true, Some(candidate), false),
            PathAction::ProbeNativeDirect
        );
        assert_eq!(
            path_action(path, true, 100, false, Some(candidate), false),
            PathAction::MaintainRelay
        );
        let waiting = PeerPath::Relayed {
            since: Instant::now(),
        };
        assert_eq!(
            path_action(waiting, true, 100, true, Some(candidate), false),
            PathAction::MaintainRelay
        );
    }

    #[test]
    fn direct_probe_requires_new_handshake_or_falls_back() {
        let probing = PeerPath::DirectProbe {
            since: Instant::now(),
            baseline: 100,
        };
        assert_eq!(
            path_action(probing, true, 101, true, Some(candidate()), false),
            PathAction::DirectRecovered
        );
        let timed_out = PeerPath::DirectProbe {
            since: Instant::now() - Duration::from_secs(DIRECT_GRACE_SECS + 1),
            baseline: 100,
        };
        assert_eq!(
            path_action(timed_out, false, 100, true, None, false),
            PathAction::UseRelay
        );
    }

    #[test]
    fn stale_direct_path_falls_back_after_grace() {
        let path = PeerPath::Direct {
            since: Instant::now() - Duration::from_secs(DIRECT_GRACE_SECS + 1),
        };
        assert_eq!(
            path_action(path, false, 0, true, Some(candidate()), false),
            PathAction::UseRelay
        );
        assert_eq!(
            path_action(path, true, 100, true, Some(candidate()), false),
            PathAction::None
        );
    }

    #[test]
    fn peer_direct_path_returns_to_relay_when_stale_or_candidate_disappears() {
        let healthy = PeerPath::PeerDirect {
            last_fresh: Instant::now(),
        };
        assert_eq!(
            path_action(healthy, true, 100, true, Some(candidate()), true),
            PathAction::MaintainPeerDirect
        );
        assert_eq!(
            path_action(healthy, false, 100, true, None, false),
            PathAction::UseRelay
        );
        let stale = PeerPath::PeerDirect {
            last_fresh: Instant::now() - Duration::from_secs(DIRECT_GRACE_SECS + 1),
        };
        assert_eq!(
            path_action(stale, false, 100, true, Some(candidate()), false),
            PathAction::UseRelay
        );
    }

    #[tokio::test]
    async fn relay_resolution_rotates_away_from_failed_address() {
        let first = std::net::SocketAddr::from(([127, 0, 0, 1], 3478));
        let second = std::net::SocketAddr::from(([127, 0, 0, 2], 3478));
        let relays = vec![first.to_string(), second.to_string()];
        assert_eq!(resolve_relay(&relays, None).await, Some(first));
        assert_eq!(resolve_relay(&relays, Some(first)).await, Some(second));
        assert_eq!(resolve_relay(&relays[..1], Some(first)).await, Some(first));
    }

    #[test]
    fn credential_status_is_actionable() {
        assert!(credential_status(0, 100).contains("unknown"));
        assert!(credential_status(99, 100).contains("reauth"));
        assert!(credential_status(86_500, 100).contains("1 day"));
    }

    #[test]
    fn non_secret_cli_overrides_form_the_validated_agent_config() {
        let cli = Cli::parse_from([
            "blaktaild",
            "--state-dir",
            "/tmp/blaktail-test",
            "up",
            "--coord",
            "https://coord.example",
            "--interface",
            "bt-test0",
            "--poll-seconds",
            "15",
            "--advertise-routes",
            "10.10.0.0/16,fd00::/64",
        ]);
        let overrides = AgentOverrides::from_cli(&cli);
        let mut config = AgentConfig::default();
        overrides.apply(&mut config);
        assert_eq!(config.state_dir, PathBuf::from("/tmp/blaktail-test"));
        assert_eq!(
            config.coordinator_url.as_deref(),
            Some("https://coord.example")
        );
        assert_eq!(config.interface, "bt-test0");
        assert_eq!(config.poll_seconds, 15);
        assert_eq!(config.advertised_routes, ["10.10.0.0/16", "fd00::/64"]);
    }

    #[test]
    fn clear_routes_flag_overrides_file_routes_without_becoming_invalid_cidr() {
        let cli = Cli::parse_from([
            "blaktaild",
            "up",
            "--coord",
            "https://coord.example",
            "--advertise-routes",
            "none",
        ]);
        let overrides = AgentOverrides::from_cli(&cli);
        let mut config = AgentConfig {
            advertised_routes: vec!["10.10.0.0/16".into()],
            ..AgentConfig::default()
        };
        overrides.apply(&mut config);
        assert!(config.advertised_routes.is_empty());
    }

    fn candidate() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([198, 51, 100, 1], 40_001))
    }
}
