use crate::{jail, Error, NodeState};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::AbortHandle,
};

pub const DEFAULT_SHARE_PORT: u16 = 5647;
pub const SHARES_FILE: &str = "shares.json";
const MAX_SHARES: usize = 4;
const MAX_LABEL_LEN: usize = 32;
const MAX_PATH_LEN: usize = 512;
const MAX_LISTING: usize = 200;
const MAX_HEADER: usize = 8_192;
const MAX_PUT_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 64;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalShare {
    pub label: String,
    pub path: String,
    #[serde(default = "default_share_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Operating-system user who published the folder. Blank on Windows.
    #[serde(default, rename = "as")]
    pub as_user: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedShare {
    pub node_id: String,
    pub dns_name: String,
    pub label: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub read_only: bool,
    /// `ro` or `rw` when drive policy is in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

fn default_share_port() -> u16 {
    DEFAULT_SHARE_PORT
}

fn default_true() -> bool {
    true
}

impl LocalShare {
    pub fn url(&self, dns_name: &str) -> String {
        format!("http://{dns_name}:{}/{}/", self.port, self.label)
    }
}

impl PublishedShare {
    pub fn url(&self) -> String {
        format!("http://{}:{}/{}/", self.dns_name, self.port, self.label)
    }
}

/// Who may touch the files behind the overlay listener.
/// `open` keeps the earlier behaviour: the network policy is the gate and
/// each share's read-only flag decides writes. `locked` applies drive grants.
#[derive(Clone, Debug)]
pub struct ShareGate {
    enforce: bool,
    self_ips: Vec<IpAddr>,
    local: BTreeMap<String, bool>,
    callers: BTreeMap<(IpAddr, String), bool>,
}

impl ShareGate {
    pub fn open() -> Self {
        Self {
            enforce: false,
            self_ips: Vec::new(),
            local: BTreeMap::new(),
            callers: BTreeMap::new(),
        }
    }

    /// `local` and `callers` entries are `(label, "ro"|"rw")`. Caller rows
    /// are `(address, label, "ro"|"rw")`.
    pub fn locked(
        self_ips: Vec<IpAddr>,
        local: &[(String, String)],
        callers: &[(String, String, String)],
    ) -> Self {
        let writable = |access: &str| access == "rw";
        Self {
            enforce: true,
            self_ips,
            local: local
                .iter()
                .map(|(label, access)| (label.clone(), writable(access)))
                .collect(),
            callers: callers
                .iter()
                .filter_map(|(address, label, access)| {
                    let ip = address.parse().ok()?;
                    Some(((ip, label.clone()), writable(access)))
                })
                .collect(),
        }
    }

    pub fn fingerprint(&self) -> String {
        if !self.enforce {
            return "open".into();
        }
        let mut rows = Vec::new();
        for (label, writable) in &self.local {
            rows.push(format!("self:{label}:{writable}"));
        }
        for ((ip, label), writable) in &self.callers {
            rows.push(format!("{ip}:{label}:{writable}"));
        }
        rows.join("|")
    }

    fn view(&self, peer: Option<IpAddr>, shares: &[LocalShare]) -> Vec<LocalShare> {
        let enabled = shares.iter().filter(|share| share.enabled);
        if !self.enforce {
            return enabled.cloned().collect();
        }
        let Some(peer) = peer else {
            return Vec::new();
        };
        let self_peer = peer.is_loopback() || self.self_ips.contains(&peer);
        enabled
            .filter_map(|share| {
                let writable = if self_peer {
                    self.local.get(&share.label).copied()
                } else {
                    self.callers.get(&(peer, share.label.clone())).copied()
                }?;
                let mut share = share.clone();
                if !writable {
                    share.read_only = true;
                }
                Some(share)
            })
            .collect()
    }
}

pub struct ShareServer {
    task: AbortHandle,
    listen_addr: SocketAddr,
    fingerprint: String,
}

impl ShareServer {
    pub async fn spawn(bind_ip: IpAddr, shares: &[LocalShare]) -> Result<Self, Error> {
        Self::spawn_with_gate(bind_ip, shares, ShareGate::open()).await
    }

    pub async fn spawn_with_gate(
        bind_ip: IpAddr,
        shares: &[LocalShare],
        gate: ShareGate,
    ) -> Result<Self, Error> {
        let enabled = shares
            .iter()
            .filter(|share| share.enabled)
            .cloned()
            .collect::<Vec<_>>();
        if enabled.is_empty() {
            return Err(Error::Message("no enabled shares to serve".into()));
        }
        let port = enabled[0].port;
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, port)).await?;
        let listen_addr = listener.local_addr()?;
        let fingerprint = format!("{}#{}", fingerprint_shares(&enabled), gate.fingerprint());
        let served = Arc::new(enabled);
        let gate = Arc::new(gate);
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let shares = served.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, Some(peer.ip()), &shares, &gate).await;
                    drop(permit);
                });
            }
        });
        Ok(Self {
            task: task.abort_handle(),
            listen_addr,
            fingerprint,
        })
    }

    pub fn matches(&self, bind_ip: IpAddr, shares: &[LocalShare], gate: &ShareGate) -> bool {
        let enabled = shares
            .iter()
            .filter(|share| share.enabled)
            .cloned()
            .collect::<Vec<_>>();
        self.listen_addr.ip() == bind_ip
            && self.fingerprint
                == format!("{}#{}", fingerprint_shares(&enabled), gate.fingerprint())
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for ShareServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn overlay_ipv4(state: &NodeState) -> Result<IpAddr, Error> {
    state
        .interface_addresses()
        .into_iter()
        .filter_map(|address| address.split('/').next()?.parse::<IpAddr>().ok())
        .find(IpAddr::is_ipv4)
        .ok_or_else(|| Error::Message("assigned tailnet IPv4 address is invalid".into()))
}

pub fn shares_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SHARES_FILE)
}

pub fn load_shares(state_dir: &Path) -> Result<Vec<LocalShare>, Error> {
    let path = shares_path(state_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let parsed: Vec<LocalShare> = serde_json::from_str(&fs::read_to_string(path)?)?;
    canonical_shares(parsed)
}

pub fn save_shares(state_dir: &Path, shares: &[LocalShare]) -> Result<(), Error> {
    fs::create_dir_all(state_dir)?;
    let path = shares_path(state_dir);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&path)?;
    file.write_all(serde_json::to_string_pretty(shares)?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn enable_share(
    state_dir: &Path,
    path: &Path,
    label: Option<&str>,
    read_only: bool,
) -> Result<LocalShare, Error> {
    let share = validate_local_share_mode(path, label, DEFAULT_SHARE_PORT, read_only)?;
    let mut shares = load_shares(state_dir)?;
    if let Some(existing) = shares
        .iter_mut()
        .find(|candidate| candidate.label == share.label)
    {
        *existing = share.clone();
    } else {
        if shares.len() >= MAX_SHARES {
            return Err(Error::Message(format!(
                "a node may publish at most {MAX_SHARES} shares"
            )));
        }
        shares.push(share.clone());
    }
    let shares = canonical_shares(shares)?;
    save_shares(state_dir, &shares)?;
    Ok(share)
}

pub fn disable_share(state_dir: &Path, label: Option<&str>) -> Result<Vec<LocalShare>, Error> {
    let mut shares = load_shares(state_dir)?;
    if shares.is_empty() {
        return Ok(shares);
    }
    match label {
        Some(label) => {
            let wanted = canonical_label(label)?;
            let mut found = false;
            for share in &mut shares {
                if share.label == wanted {
                    share.enabled = false;
                    found = true;
                }
            }
            if !found {
                return Err(Error::Message(format!("share {wanted} is not configured")));
            }
        }
        None => {
            for share in &mut shares {
                share.enabled = false;
            }
        }
    }
    save_shares(state_dir, &shares)?;
    Ok(shares)
}

pub fn validate_local_share(
    path: &Path,
    label: Option<&str>,
    port: u16,
) -> Result<LocalShare, Error> {
    validate_local_share_mode(path, label, port, true)
}

pub fn validate_local_share_mode(
    path: &Path,
    label: Option<&str>,
    port: u16,
    read_only: bool,
) -> Result<LocalShare, Error> {
    if !(1024..=65535).contains(&port) {
        return Err(Error::Message(
            "share port must be between 1024 and 65535".into(),
        ));
    }
    if !path.is_absolute() {
        return Err(Error::Message("share path must be absolute".into()));
    }
    let rendered = path.to_string_lossy();
    if rendered.len() > MAX_PATH_LEN || rendered.contains('\0') {
        return Err(Error::Message("share path is not acceptable".into()));
    }
    let metadata = fs::metadata(path)
        .map_err(|_| Error::Message(format!("share path {} does not exist", path.display())))?;
    if !metadata.is_dir() {
        return Err(Error::Message("share path must be a directory".into()));
    }
    let canonical = fs::canonicalize(path)?;
    let label = match label {
        Some(label) => canonical_label(label)?,
        None => label_from_path(&canonical)?,
    };
    Ok(LocalShare {
        label,
        path: canonical.to_string_lossy().into_owned(),
        port,
        read_only,
        enabled: true,
        as_user: String::new(),
    })
}

fn canonical_shares(shares: Vec<LocalShare>) -> Result<Vec<LocalShare>, Error> {
    if shares.len() > MAX_SHARES {
        return Err(Error::Message(format!(
            "a node may publish at most {MAX_SHARES} shares"
        )));
    }
    let mut canonical = Vec::new();
    let mut ports = Vec::new();
    for share in shares {
        let label = canonical_label(&share.label)?;
        if canonical
            .iter()
            .any(|existing: &LocalShare| existing.label == label)
        {
            return Err(Error::Message(format!("duplicate share label {label}")));
        }
        if !(1024..=65535).contains(&share.port) {
            return Err(Error::Message(
                "share port must be between 1024 and 65535".into(),
            ));
        }
        ports.push(share.port);
        canonical.push(LocalShare {
            label,
            path: share.path,
            port: share.port,
            read_only: share.read_only,
            enabled: share.enabled,
            as_user: share.as_user,
        });
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > 1 {
        return Err(Error::Message(
            "all shares on a node must use the same TCP port".into(),
        ));
    }
    Ok(canonical)
}

fn canonical_label(label: &str) -> Result<String, Error> {
    let label = label.trim().to_ascii_lowercase();
    if label.is_empty()
        || label.len() > MAX_LABEL_LEN
        || label.starts_with('-')
        || label.ends_with('-')
        || !label.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'(' | b')' | b' ')
        })
    {
        return Err(Error::Message(
            "share name must be 1-32 letters, digits, hyphens, underscores, parentheses, or spaces"
                .into(),
        ));
    }
    Ok(label)
}

fn label_from_path(path: &Path) -> Result<String, Error> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Message("share path must end with a usable directory name".into()))?;
    canonical_label(name)
}

fn fingerprint_shares(shares: &[LocalShare]) -> String {
    shares
        .iter()
        .map(|share| {
            format!(
                "{}:{}:{}:{}:{}",
                share.label, share.path, share.port, share.enabled, share.read_only
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

pub fn drive_share(state_dir: &Path, path: &Path, name: &str) -> Result<LocalShare, Error> {
    let mut share = validate_local_share_mode(path, Some(name), DEFAULT_SHARE_PORT, false)?;
    share.as_user = sharing_as();
    let mut shares = load_shares(state_dir)?;
    if let Some(port) = shares.first().map(|existing| existing.port) {
        share.port = port;
    }
    if let Some(existing) = shares
        .iter_mut()
        .find(|candidate| candidate.label == share.label)
    {
        *existing = share.clone();
    } else {
        if shares.len() >= MAX_SHARES {
            return Err(Error::Message(format!(
                "a node may publish at most {MAX_SHARES} shares"
            )));
        }
        shares.push(share.clone());
    }
    let shares = canonical_shares(shares)?;
    save_shares(state_dir, &shares)?;
    Ok(share)
}

pub fn drive_unshare(state_dir: &Path, name: &str) -> Result<Vec<LocalShare>, Error> {
    let wanted = canonical_label(name)?;
    let mut shares = load_shares(state_dir)?;
    let before = shares.len();
    shares.retain(|share| share.label != wanted);
    if shares.len() == before {
        return Err(Error::Message(format!("share {wanted} is not configured")));
    }
    save_shares(state_dir, &shares)?;
    Ok(shares)
}

pub fn drive_rename(state_dir: &Path, from: &str, to: &str) -> Result<LocalShare, Error> {
    let from = canonical_label(from)?;
    let to = canonical_label(to)?;
    let mut shares = load_shares(state_dir)?;
    if shares.iter().any(|share| share.label == to) && from != to {
        return Err(Error::Message(format!("share {to} already exists")));
    }
    let Some(share) = shares.iter_mut().find(|share| share.label == from) else {
        return Err(Error::Message(format!("share {from} is not configured")));
    };
    share.label = to;
    let updated = share.clone();
    let shares = canonical_shares(shares)?;
    save_shares(state_dir, &shares)?;
    Ok(updated)
}

pub fn format_drive_list(shares: &[LocalShare]) -> String {
    let rows = shares
        .iter()
        .filter(|share| share.enabled)
        .collect::<Vec<_>>();
    let name_width = rows
        .iter()
        .map(|share| share.label.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let path_width = rows
        .iter()
        .map(|share| share.path.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let mut out = format!(
        "{:<name_width$}  {:<path_width$}  as\n{:-<name_width$}  {:-<path_width$}  ----\n",
        "name", "path", "", ""
    );
    for share in rows {
        out.push_str(&format!(
            "{:<name_width$}  {:<path_width$}  {}\n",
            share.label, share.path, share.as_user
        ));
    }
    out
}

fn sharing_as() -> String {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        let record = unsafe { libc::getpwuid(uid) };
        if !record.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr((*record).pw_name) };
            if let Ok(name) = name.to_str() {
                return name.to_owned();
            }
        }
    }
    String::new()
}

async fn handle_client(
    mut stream: TcpStream,
    peer: Option<IpAddr>,
    shares: &[LocalShare],
    gate: &ShareGate,
) -> Result<(), Error> {
    let shares = gate.view(peer, shares);
    let mut buffer = vec![0u8; MAX_HEADER];
    let length = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut buffer))
        .await
        .map_err(|_| Error::Message("share request timed out".into()))??;
    if length == 0 {
        return Ok(());
    }
    let Some(header_end) = buffer[..length]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        write_plain(&mut stream, 400, "Bad Request", "bad request\n", true).await?;
        return Ok(());
    };
    let separator = 4;
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| Error::Message("share request is not UTF-8".into()))?;
    let mut parsed = match parse_request(header) {
        Some(parsed) => parsed,
        None => {
            write_plain(&mut stream, 400, "Bad Request", "bad request\n", true).await?;
            return Ok(());
        }
    };
    // Only PUT reads a body, and it streams the rest from the socket.
    let body_start = header_end + separator;
    parsed.body = buffer[body_start..length].to_vec();
    if gate.enforce && shares.is_empty() {
        write_plain(&mut stream, 403, "Forbidden", "forbidden\n", true).await?;
        return Ok(());
    }
    if parsed
        .content_length
        .is_some_and(|needed| needed > MAX_PUT_BYTES)
    {
        write_plain(
            &mut stream,
            413,
            "Payload Too Large",
            "file is too large\n",
            true,
        )
        .await?;
        return Ok(());
    }
    match parsed.method.as_str() {
        "OPTIONS" => {
            write_response(
                &mut stream,
                200,
                "OK",
                &[
                    ("DAV", "1"),
                    ("Allow", ALLOWED_METHODS),
                    ("MS-Author-Via", "DAV"),
                    ("Content-Length", "0"),
                ],
                b"",
                false,
            )
            .await?;
        }
        "GET" | "HEAD" => {
            serve_get(&mut stream, &shares, &parsed.path, parsed.method == "HEAD").await?;
        }
        "PROPFIND" => {
            serve_propfind(&mut stream, &shares, &parsed.path, parsed.depth.as_deref()).await?;
        }
        "PUT" => {
            serve_put(
                &mut stream,
                &shares,
                &parsed.path,
                parsed.content_length,
                std::mem::take(&mut parsed.body),
            )
            .await?;
        }
        "MKCOL" => {
            serve_mkcol(&mut stream, &shares, &parsed.path).await?;
        }
        "DELETE" => {
            serve_delete(&mut stream, &shares, &parsed.path).await?;
        }
        "MOVE" => {
            serve_move(
                &mut stream,
                &shares,
                &parsed.path,
                parsed.destination.as_deref(),
            )
            .await?;
        }
        "POST" | "COPY" | "PROPPATCH" | "LOCK" | "UNLOCK" => {
            write_response(
                &mut stream,
                403,
                "Forbidden",
                &[
                    ("Allow", ALLOWED_METHODS),
                    ("DAV", "1"),
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "10"),
                ],
                b"read-only\n",
                true,
            )
            .await?;
        }
        _ => {
            write_plain(
                &mut stream,
                405,
                "Method Not Allowed",
                "method not allowed\n",
                true,
            )
            .await?;
        }
    }
    Ok(())
}

const ALLOWED_METHODS: &str = "OPTIONS, GET, HEAD, PROPFIND, PUT, MKCOL, DELETE, MOVE";

struct ParsedRequest {
    method: String,
    path: String,
    depth: Option<String>,
    content_length: Option<usize>,
    destination: Option<String>,
    body: Vec<u8>,
}

fn parse_request(raw: &str) -> Option<ParsedRequest> {
    let header = raw
        .split("\r\n\r\n")
        .next()
        .or_else(|| raw.split("\n\n").next())?;
    let mut lines = header.split('\n');
    let first = lines.next()?.trim_end_matches('\r');
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next().unwrap_or("/");
    let path = percent_decode(target.split('?').next().unwrap_or("/"))?;
    let mut depth = None;
    let mut content_length = None;
    let mut destination = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("depth") {
            depth = Some(value.trim().to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        } else if name.eq_ignore_ascii_case("destination") {
            destination = destination_path(value.trim());
        }
    }
    Some(ParsedRequest {
        method,
        path,
        depth,
        content_length,
        destination,
        body: Vec::new(),
    })
}

fn destination_path(value: &str) -> Option<String> {
    let path = value
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
        .unwrap_or(value);
    percent_decode(path.split('?').next().unwrap_or(path))
}

/// A request path split at its share label. Every component below the
/// label has passed `jail::safe_component`: no `..`, no dot-files, no
/// separators or stream names.
enum Located<'a> {
    Index,
    Share(&'a LocalShare, Vec<String>),
    NotFound,
    Forbidden,
}

fn locate<'a>(shares: &'a [LocalShare], path: &str) -> Located<'a> {
    if path.contains('\0') {
        return Located::Forbidden;
    }
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    let Some(label) = parts.next() else {
        return Located::Index;
    };
    let Some(share) = shares
        .iter()
        .find(|share| share.enabled && share.label == label)
    else {
        return Located::NotFound;
    };
    let rest = parts.map(str::to_owned).collect::<Vec<_>>();
    if rest.iter().any(|part| !jail::safe_component(part)) {
        return Located::Forbidden;
    }
    Located::Share(share, rest)
}

/// Open the share root (refusing a root that was swapped for a link or
/// junction since it was enabled) and walk `parts` without following links.
fn walk(share: &LocalShare, parts: &[String]) -> io::Result<jail::Dir> {
    let mut dir = jail::open_root(Path::new(&share.path)).inspect_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            tracing::warn!(label = %share.label, %error, "refusing share whose folder moved");
        }
    })?;
    for part in parts {
        dir = dir.descend(part)?;
    }
    Ok(dir)
}

enum JailError {
    Bad,
    Escape,
    MissingParent,
}

/// The pinned parent directory and final name of one child of the share.
/// The share root itself is refused.
fn parent_dir(share: &LocalShare, parts: &[String]) -> Result<(jail::Dir, String), JailError> {
    let Some((name, parents)) = parts.split_last() else {
        return Err(JailError::Bad);
    };
    match walk(share, parents) {
        Ok(dir) => Ok((dir, name.clone())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(JailError::MissingParent),
        Err(_) => Err(JailError::Escape),
    }
}

/// The writable share and child path for a write verb, or the response
/// already sent.
async fn write_target<'a>(
    stream: &mut TcpStream,
    shares: &'a [LocalShare],
    path: &str,
) -> Result<Option<(&'a LocalShare, Vec<String>)>, Error> {
    match locate(shares, path) {
        Located::Share(share, _) if share.read_only => {
            write_plain(stream, 403, "Forbidden", "read-only\n", true).await?;
            Ok(None)
        }
        Located::Share(share, parts) if !parts.is_empty() => Ok(Some((share, parts))),
        Located::NotFound => {
            write_plain(stream, 404, "Not Found", "not found\n", true).await?;
            Ok(None)
        }
        _ => {
            write_plain(stream, 403, "Forbidden", "forbidden\n", true).await?;
            Ok(None)
        }
    }
}

async fn serve_mkcol(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
) -> Result<(), Error> {
    let Some((share, parts)) = write_target(stream, shares, path).await? else {
        return Ok(());
    };
    let created = match parent_dir(share, &parts) {
        Ok((dir, name)) => match dir.kind(&name) {
            Ok(Some(_)) => {
                return write_plain(stream, 405, "Method Not Allowed", "already exists\n", true)
                    .await;
            }
            Ok(None) => dir.mkdir(&name).is_ok(),
            Err(_) => false,
        },
        Err(JailError::MissingParent) => {
            return write_plain(stream, 409, "Conflict", "parent is missing\n", true).await;
        }
        Err(_) => false,
    };
    if created {
        write_plain(stream, 201, "Created", "created\n", true).await
    } else {
        write_plain(stream, 403, "Forbidden", "forbidden\n", true).await
    }
}

async fn serve_delete(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
) -> Result<(), Error> {
    let Some((share, parts)) = write_target(stream, shares, path).await? else {
        return Ok(());
    };
    let (dir, name) = match parent_dir(share, &parts) {
        Ok(found) => found,
        Err(JailError::MissingParent) => {
            return write_plain(stream, 404, "Not Found", "not found\n", true).await;
        }
        Err(_) => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    let removed = match dir.kind(&name) {
        Ok(None) => return write_plain(stream, 404, "Not Found", "not found\n", true).await,
        Ok(Some(jail::Kind::File)) => dir.remove_file(&name),
        Ok(Some(jail::Kind::Dir)) => dir.remove_dir(&name),
        Ok(Some(jail::Kind::Other)) | Err(_) => {
            return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await;
        }
    };
    match removed {
        Ok(()) => write_plain(stream, 204, "No Content", "", false).await,
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
            write_plain(stream, 403, "Forbidden", "directory is not empty\n", true).await
        }
        Err(_) => write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    }
}

async fn serve_move(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
    destination: Option<&str>,
) -> Result<(), Error> {
    let Some(destination) = destination else {
        write_plain(stream, 400, "Bad Request", "destination required\n", true).await?;
        return Ok(());
    };
    let Some((share, source_parts)) = write_target(stream, shares, path).await? else {
        return Ok(());
    };
    let target_parts = match locate(shares, destination) {
        Located::Share(target, parts) if target.label == share.label && !parts.is_empty() => parts,
        _ => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    let (source_dir, source_name) = match parent_dir(share, &source_parts) {
        Ok(found) => found,
        Err(JailError::MissingParent) => {
            return write_plain(stream, 404, "Not Found", "not found\n", true).await;
        }
        Err(_) => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    let source_kind = match source_dir.kind(&source_name) {
        Ok(None) => return write_plain(stream, 404, "Not Found", "not found\n", true).await,
        Ok(Some(kind @ (jail::Kind::File | jail::Kind::Dir))) => kind,
        _ => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    let (target_dir, target_name) = match parent_dir(share, &target_parts) {
        Ok(found) => found,
        Err(JailError::MissingParent) => {
            return write_plain(stream, 409, "Conflict", "parent is missing\n", true).await;
        }
        Err(_) => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    let replaced = match target_dir.kind(&target_name) {
        Ok(None) => false,
        // A file may replace a file; nothing replaces a folder or a link.
        Ok(Some(jail::Kind::File)) if source_kind == jail::Kind::File => true,
        _ => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    if source_dir
        .rename(&source_name, &target_dir, &target_name)
        .is_err()
    {
        return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await;
    }
    if replaced {
        write_plain(stream, 204, "No Content", "", false).await
    } else {
        write_plain(stream, 201, "Created", "created\n", true).await
    }
}

async fn serve_put(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
    content_length: Option<usize>,
    mut body: Vec<u8>,
) -> Result<(), Error> {
    let Some((share, parts)) = write_target(stream, shares, path).await? else {
        return Ok(());
    };
    let Some(needed) = content_length else {
        return write_plain(stream, 411, "Length Required", "length required\n", true).await;
    };
    if needed > MAX_PUT_BYTES {
        return write_plain(
            stream,
            413,
            "Payload Too Large",
            "file is too large\n",
            true,
        )
        .await;
    }
    let (dir, name) = match parent_dir(share, &parts) {
        Ok(found) => found,
        Err(JailError::MissingParent) => {
            return write_plain(stream, 409, "Conflict", "parent is missing\n", true).await;
        }
        Err(_) => return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await,
    };
    if !matches!(dir.kind(&name), Ok(None | Some(jail::Kind::File))) {
        return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await;
    }
    // A fresh random name, created exclusively next to the target, so a
    // planted link or an old partial file can never be written through.
    let temporary = format!(".blaktail-partial-{:032x}", rand::random::<u128>());
    let Ok(mut file) = dir.create_new(&temporary) else {
        return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await;
    };
    body.truncate(needed);
    let mut written = body.len();
    let mut stored = file.write_all(&body).is_ok();
    let mut chunk = vec![0u8; 64 * 1024];
    while stored && written < needed {
        let want = chunk.len().min(needed - written);
        let read =
            match tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut chunk[..want])).await {
                Ok(Ok(read)) if read > 0 => read,
                _ => break,
            };
        stored = file.write_all(&chunk[..read]).is_ok();
        written += read;
    }
    let complete = stored && written == needed && file.sync_all().is_ok();
    drop(file);
    if !complete || dir.rename(&temporary, &dir, &name).is_err() {
        let _ = dir.remove_file(&temporary);
        if written < needed {
            return Ok(());
        }
        return write_plain(stream, 403, "Forbidden", "forbidden\n", true).await;
    }
    write_plain(stream, 201, "Created", "created\n", true).await
}

/// Send one file to a writable peer share. `url` is the file URL, not the folder.
pub async fn put_share_file(url: &str, bytes: &[u8]) -> Result<u16, Error> {
    if bytes.len() > MAX_PUT_BYTES {
        return Err(Error::Message("file is too large to send".into()));
    }
    let url = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Message("share send only uses overlay HTTP".into()))?;
    let (host, path) = url
        .split_once('/')
        .ok_or_else(|| Error::Message("share URL needs a file path".into()))?;
    let address: SocketAddr = host
        .parse()
        .map_err(|_| Error::Message("share URL host must be host:port".into()))?;
    let mut stream = TcpStream::connect(address).await?;
    let request = format!(
        "PUT /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(bytes).await?;
    let mut response = [0u8; 64];
    let read = stream.read(&mut response).await?;
    let text = String::from_utf8_lossy(&response[..read]);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if status != 201 && status != 204 {
        return Err(Error::Message(format!("share send failed ({status})")));
    }
    Ok(status)
}

async fn serve_get(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
    head: bool,
) -> Result<(), Error> {
    match resolve_request(shares, path) {
        ShareResponse::Index => {
            let body = index_page(shares);
            write_plain_typed(
                stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                body.as_bytes(),
                !head,
            )
            .await
        }
        ShareResponse::Directory { share, rest, dir } => {
            let body = listing_page(share, &rest.join("/"), &dir);
            write_plain_typed(
                stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                body.as_bytes(),
                !head,
            )
            .await
        }
        ShareResponse::File { mut file, name } => {
            let length = file.metadata()?.len();
            write_response(
                stream,
                200,
                "OK",
                &[
                    ("Content-Type", content_type(&name)),
                    ("Content-Length", &length.to_string()),
                    ("Cache-Control", "no-store"),
                ],
                b"",
                false,
            )
            .await?;
            if head {
                return Ok(());
            }
            // Stream from the handle that was opened inside the share, never
            // from the path again, and never more than was announced.
            let mut remaining = length;
            let mut chunk = vec![0u8; 64 * 1024];
            while remaining > 0 {
                let want = chunk
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let read = std::io::Read::read(&mut file, &mut chunk[..want])?;
                if read == 0 {
                    break;
                }
                stream.write_all(&chunk[..read]).await?;
                remaining -= read as u64;
            }
            Ok(())
        }
        ShareResponse::NotFound => {
            write_plain(stream, 404, "Not Found", "not found\n", !head).await
        }
        ShareResponse::Forbidden => {
            write_plain(stream, 403, "Forbidden", "forbidden\n", !head).await
        }
    }
}

async fn serve_propfind(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
    depth: Option<&str>,
) -> Result<(), Error> {
    let depth = match depth.unwrap_or("1") {
        "0" => 0,
        "1" => 1,
        "infinity" => {
            write_response(
                stream,
                403,
                "Forbidden",
                &[
                    ("DAV", "1"),
                    ("Allow", ALLOWED_METHODS),
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "32"),
                ],
                b"depth infinity is not supported\n",
                true,
            )
            .await?;
            return Ok(());
        }
        _ => {
            write_plain(stream, 400, "Bad Request", "invalid depth\n", true).await?;
            return Ok(());
        }
    };
    let xml = match dav_document(shares, path, depth) {
        DavDocument::Xml(body) => body,
        DavDocument::NotFound => {
            write_plain(stream, 404, "Not Found", "not found\n", true).await?;
            return Ok(());
        }
        DavDocument::Forbidden => {
            write_plain(stream, 403, "Forbidden", "forbidden\n", true).await?;
            return Ok(());
        }
    };
    write_response(
        stream,
        207,
        "Multi-Status",
        &[
            ("DAV", "1"),
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("Content-Length", &xml.len().to_string()),
        ],
        xml.as_bytes(),
        true,
    )
    .await
}

enum ShareResponse<'a> {
    Index,
    Directory {
        share: &'a LocalShare,
        rest: Vec<String>,
        dir: jail::Dir,
    },
    File {
        file: fs::File,
        name: String,
    },
    NotFound,
    Forbidden,
}

fn io_response<'a>(error: &io::Error) -> ShareResponse<'a> {
    if error.kind() == io::ErrorKind::NotFound {
        ShareResponse::NotFound
    } else {
        ShareResponse::Forbidden
    }
}

fn resolve_request<'a>(shares: &'a [LocalShare], path: &str) -> ShareResponse<'a> {
    let (share, rest) = match locate(shares, path) {
        Located::Index => return ShareResponse::Index,
        Located::NotFound => return ShareResponse::NotFound,
        Located::Forbidden => return ShareResponse::Forbidden,
        Located::Share(share, rest) => (share, rest),
    };
    let Some((last, parents)) = rest.split_last() else {
        return match walk(share, &[]) {
            Ok(dir) => ShareResponse::Directory { share, rest, dir },
            Err(error) => io_response(&error),
        };
    };
    let dir = match walk(share, parents) {
        Ok(dir) => dir,
        Err(error) => return io_response(&error),
    };
    match dir.kind(last) {
        Ok(Some(jail::Kind::Dir)) => match dir.descend(last) {
            Ok(dir) => ShareResponse::Directory { share, rest, dir },
            Err(error) => io_response(&error),
        },
        Ok(Some(jail::Kind::File)) => match dir.open_file(last) {
            Ok(file) => ShareResponse::File {
                file,
                name: last.clone(),
            },
            Err(error) => io_response(&error),
        },
        Ok(Some(jail::Kind::Other)) => ShareResponse::Forbidden,
        Ok(None) => ShareResponse::NotFound,
        Err(error) => io_response(&error),
    }
}

fn index_page(shares: &[LocalShare]) -> String {
    let mut body = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>BlakTail shares</title></head><body><h1>BlakTail shares</h1><ul>",
    );
    for share in shares.iter().filter(|share| share.enabled) {
        body.push_str(&format!(
            "<li><a href=\"/{}/\">{}/</a></li>",
            escape(&share.label),
            escape(&share.label)
        ));
    }
    body.push_str("</ul></body></html>\n");
    body
}

/// Files and folders a listing shows. Links, devices and dot-files are
/// never listed, matching what a request can open.
fn visible_entries(dir: &jail::Dir) -> Vec<jail::Entry> {
    let mut entries = dir.entries(usize::MAX);
    entries.retain(|entry| entry.kind != jail::Kind::Other);
    entries.truncate(MAX_LISTING);
    entries
}

fn listing_page(share: &LocalShare, relative: &str, directory: &jail::Dir) -> String {
    let prefix = collection_href(&share.label, relative);
    let mut body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><ul>",
        escape(&share.label),
        escape(&prefix)
    );
    if !relative.is_empty() {
        body.push_str(&format!(
            "<li><a href=\"/{}/\">../</a></li>",
            escape(&share.label)
        ));
    }
    for entry in visible_entries(directory) {
        let suffix = if entry.kind == jail::Kind::Dir {
            "/"
        } else {
            ""
        };
        body.push_str(&format!(
            "<li><a href=\"{}{}{suffix}\">{}{suffix}</a></li>",
            escape(&prefix),
            escape(&entry.name),
            escape(&entry.name)
        ));
    }
    body.push_str("</ul></body></html>\n");
    body
}

enum DavDocument {
    Xml(String),
    NotFound,
    Forbidden,
}

fn dav_document(shares: &[LocalShare], path: &str, depth: u8) -> DavDocument {
    match resolve_request(shares, path) {
        ShareResponse::Index => {
            let mut xml = dav_header();
            xml.push_str(&dav_collection("/", "BlakTail shares", None));
            if depth > 0 {
                for share in shares.iter().filter(|share| share.enabled) {
                    let modified = walk(share, &[])
                        .and_then(|dir| dir.metadata())
                        .and_then(|metadata| metadata.modified())
                        .ok();
                    xml.push_str(&dav_collection(
                        &format!("/{}/", share.label),
                        &share.label,
                        modified,
                    ));
                }
            }
            xml.push_str("</D:multistatus>\n");
            DavDocument::Xml(xml)
        }
        ShareResponse::Directory { share, rest, dir } => {
            let rest = rest.join("/");
            let href = collection_href(&share.label, &rest);
            let display = rest
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(&share.label)
                .to_owned();
            let mut xml = dav_header();
            xml.push_str(&dav_collection(
                &href,
                &display,
                dir.metadata().and_then(|metadata| metadata.modified()).ok(),
            ));
            if depth > 0 {
                for entry in visible_entries(&dir) {
                    let child = format!("{href}{}", entry.name);
                    if entry.kind == jail::Kind::Dir {
                        xml.push_str(&dav_collection(
                            &format!("{child}/"),
                            &entry.name,
                            entry.modified,
                        ));
                    } else {
                        xml.push_str(&dav_file(
                            &child,
                            &entry.name,
                            content_type(&entry.name),
                            entry.len,
                            entry.modified,
                        ));
                    }
                }
            }
            xml.push_str("</D:multistatus>\n");
            DavDocument::Xml(xml)
        }
        ShareResponse::File { file, name } => {
            let href = if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            };
            let metadata = file.metadata().ok();
            let mut xml = dav_header();
            xml.push_str(&dav_file(
                href.trim_end_matches('/'),
                &name,
                content_type(&name),
                metadata.as_ref().map(fs::Metadata::len).unwrap_or(0),
                metadata.and_then(|metadata| metadata.modified().ok()),
            ));
            xml.push_str("</D:multistatus>\n");
            DavDocument::Xml(xml)
        }
        ShareResponse::NotFound => DavDocument::NotFound,
        ShareResponse::Forbidden => DavDocument::Forbidden,
    }
}

fn collection_href(label: &str, relative: &str) -> String {
    if relative.is_empty() {
        format!("/{label}/")
    } else {
        format!("/{label}/{}/", relative.trim_end_matches('/'))
    }
}

fn dav_header() -> String {
    String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">")
}

fn dav_collection(href: &str, display: &str, modified: Option<SystemTime>) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>{}</D:displayname>{}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        escape_xml(&href_encode(href)),
        escape_xml(display),
        dav_mtime(modified)
    )
}

fn dav_file(
    href: &str,
    display: &str,
    content_type: &str,
    length: u64,
    modified: Option<SystemTime>,
) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop><D:resourcetype/><D:displayname>{}</D:displayname><D:getcontentlength>{length}</D:getcontentlength><D:getcontenttype>{}</D:getcontenttype>{}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        escape_xml(&href_encode(href)),
        escape_xml(display),
        escape_xml(content_type),
        dav_mtime(modified)
    )
}

fn dav_mtime(modified: Option<SystemTime>) -> String {
    let Some(modified) = modified else {
        return String::new();
    };
    format!(
        "<D:getlastmodified>{}</D:getlastmodified>",
        http_date(modified)
    )
}

pub(crate) fn href_encode(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn http_date(time: SystemTime) -> String {
    http_date_secs(
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn http_date_secs(secs: u64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let hour = tod / 3_600;
    let min = (tod % 3_600) / 60;
    let sec = tod % 60;
    let (year, month, day) = civil_from_unix_days(days);
    format!(
        "{}, {day:02} {} {year} {hour:02}:{min:02}:{sec:02} GMT",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[month as usize - 1],
    )
}

fn civil_from_unix_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn content_type(name: &str) -> &'static str {
    match Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" | "md" | "csv" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

async fn write_plain(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    send_body: bool,
) -> Result<(), Error> {
    write_plain_typed(
        stream,
        status,
        reason,
        "text/plain",
        body.as_bytes(),
        send_body,
    )
    .await
}

async fn write_plain_typed(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    send_body: bool,
) -> Result<(), Error> {
    write_response(
        stream,
        status,
        reason,
        &[
            ("Content-Type", content_type),
            ("Content-Length", &body.len().to_string()),
            ("Cache-Control", "no-store"),
        ],
        body,
        send_body,
    )
    .await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    send_body: bool,
) -> Result<(), Error> {
    let mut header = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }
    header.push_str("Connection: close\r\n\r\n");
    stream.write_all(header.as_bytes()).await?;
    if send_body {
        stream.write_all(body).await?;
    }
    Ok(())
}

fn percent_decode(path: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(path.len());
    let raw = path.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'%' if index + 2 < raw.len() => {
                let hex = std::str::from_utf8(&raw[index + 1..index + 3]).ok()?;
                bytes.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(bytes).ok()
}

fn escape(value: &str) -> String {
    escape_xml(value)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream as Client;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blaktail-share-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    // Probing a free port then binding races with parallel tests, so retry.
    async fn spawn_on_free_port(mut share: LocalShare) -> ShareServer {
        for _ in 0..20 {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            share.port = probe.local_addr().unwrap().port();
            drop(probe);
            if let Ok(server) = ShareServer::spawn(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                std::slice::from_ref(&share),
            )
            .await
            {
                return server;
            }
        }
        panic!("no free localhost port for share test");
    }

    // Parallel tests can read the same clock value; a counter cannot collide.
    static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn rejects_relative_and_duplicate_labels() {
        let root = temp_dir();
        assert!(validate_local_share(Path::new("relative"), None, DEFAULT_SHARE_PORT).is_err());
        let share = enable_share(&root, &root, Some("Files"), true).unwrap();
        assert_eq!(share.label, "files");
        assert!(share.enabled);
        let again = enable_share(&root, &root, Some("files"), true).unwrap();
        assert_eq!(again.label, "files");
        assert_eq!(load_shares(&root).unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jail_rejects_parent_segments() {
        let root = temp_dir();
        let share = validate_local_share(&root, Some("files"), DEFAULT_SHARE_PORT).unwrap();
        assert!(matches!(
            resolve_request(&[share], "/files/../etc/passwd"),
            ShareResponse::Forbidden
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn http_lists_and_reads_files_without_escaping() {
        let root = temp_dir();
        fs::write(root.join("note.txt"), "hello-share").unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("inner.txt"), "inner").unwrap();
        let share = validate_local_share(&root, Some("files"), DEFAULT_SHARE_PORT).unwrap();
        let server = spawn_on_free_port(share).await;
        let listing = http_get(server.listen_addr(), "/files/").await;
        assert!(listing.contains("note.txt"), "{listing}");
        assert!(listing.contains("nested/"), "{listing}");
        let file = http_get(server.listen_addr(), "/files/note.txt").await;
        assert_eq!(file, "hello-share");
        let escaped = http_exchange(server.listen_addr(), "GET", "/files/../note.txt", &[]).await;
        assert!(escaped.starts_with("HTTP/1.1 403"), "{escaped}");
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn webdav_lists_read_only_and_rejects_writes() {
        let root = temp_dir();
        fs::write(root.join("note.txt"), "hello-share").unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("inner.txt"), "inner").unwrap();
        let share = validate_local_share(&root, Some("files"), DEFAULT_SHARE_PORT).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();

        let options = http_exchange(addr, "OPTIONS", "/files/", &[]).await;
        assert!(options.starts_with("HTTP/1.1 200"), "{options}");
        assert!(options.contains("DAV: 1"), "{options}");
        assert!(
            options.contains("Allow: OPTIONS, GET, HEAD, PROPFIND, PUT, MKCOL, DELETE, MOVE"),
            "{options}"
        );

        let head = http_exchange(addr, "HEAD", "/files/note.txt", &[]).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("Content-Length: 11"), "{head}");
        assert!(!head.contains("hello-share"), "{head}");

        let propfind = http_exchange(addr, "PROPFIND", "/files", &[("Depth", "1")]).await;
        assert!(propfind.starts_with("HTTP/1.1 207"), "{propfind}");
        assert!(propfind.contains("<D:collection/>"), "{propfind}");
        assert!(propfind.contains("/files/note.txt"), "{propfind}");
        assert!(propfind.contains("/files/nested/"), "{propfind}");
        assert!(
            propfind.contains("<D:getcontentlength>11</D:getcontentlength>"),
            "{propfind}"
        );

        let nested = http_exchange(addr, "PROPFIND", "/files/nested/", &[("Depth", "1")]).await;
        assert!(nested.contains("/files/nested/inner.txt"), "{nested}");

        let infinity = http_exchange(addr, "PROPFIND", "/files/", &[("Depth", "infinity")]).await;
        assert!(infinity.starts_with("HTTP/1.1 403"), "{infinity}");

        let put = http_exchange(addr, "PUT", "/files/note.txt", &[]).await;
        assert!(put.starts_with("HTTP/1.1 403"), "{put}");
        assert!(put.contains("read-only"), "{put}");

        let writable =
            validate_local_share_mode(&root, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let writable_server = spawn_on_free_port(writable).await;
        let write_addr = writable_server.listen_addr();
        let sent = put_share_file(
            &format!("http://{write_addr}/drop/arrived.txt"),
            b"from-peer",
        )
        .await;
        assert_eq!(sent.unwrap(), 201);
        assert_eq!(fs::read(root.join("arrived.txt")).unwrap(), b"from-peer");
        let escaped = http_exchange(write_addr, "PUT", "/drop/../arrived.txt", &[]).await;
        assert!(escaped.starts_with("HTTP/1.1 403"), "{escaped}");

        writable_server.stop();
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn http_dates_match_rfc_examples() {
        assert_eq!(http_date_secs(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date_secs(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let response = http_exchange(addr, "GET", path, &[]).await;
        response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    }

    async fn http_exchange(
        addr: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> String {
        let mut client = Client::connect(addr).await.unwrap();
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: share\r\nConnection: close\r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut body = Vec::new();
        client.read_to_end(&mut body).await.unwrap();
        String::from_utf8_lossy(&body).into_owned()
    }

    async fn spawn_gated(mut share: LocalShare, gate: ShareGate) -> ShareServer {
        for _ in 0..20 {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            share.port = probe.local_addr().unwrap().port();
            drop(probe);
            if let Ok(server) = ShareServer::spawn_with_gate(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                std::slice::from_ref(&share),
                gate.clone(),
            )
            .await
            {
                return server;
            }
        }
        panic!("no free localhost port for share test");
    }

    #[test]
    fn drive_commands_round_trip_names() {
        let root = temp_dir();
        let folder = root.join("Docs");
        fs::create_dir_all(&folder).unwrap();
        let share = drive_share(&root, &folder, " Company-Docs ").unwrap();
        assert_eq!(share.label, "company-docs");
        assert!(!share.read_only);
        #[cfg(unix)]
        assert!(!share.as_user.is_empty());
        let listed = format_drive_list(&load_shares(&root).unwrap());
        assert!(listed.contains("company-docs"), "{listed}");
        assert!(listed.contains("name"), "{listed}");
        let renamed = drive_rename(&root, "company-docs", "notes").unwrap();
        assert_eq!(renamed.label, "notes");
        drive_unshare(&root, "notes").unwrap();
        assert!(load_shares(&root).unwrap().is_empty());
        assert!(drive_unshare(&root, "notes").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn webdav_creates_moves_and_deletes() {
        let root = temp_dir();
        let share =
            validate_local_share_mode(&root, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();
        let mkcol = http_exchange(addr, "MKCOL", "/drop/folder", &[]).await;
        assert!(mkcol.starts_with("HTTP/1.1 201"), "{mkcol}");
        assert!(root.join("folder").is_dir());
        let again = http_exchange(addr, "MKCOL", "/drop/folder", &[]).await;
        assert!(again.starts_with("HTTP/1.1 405"), "{again}");
        let sent = put_share_file(&format!("http://{addr}/drop/folder/a.txt"), b"abc")
            .await
            .unwrap();
        assert_eq!(sent, 201);
        let moved = http_exchange(
            addr,
            "MOVE",
            "/drop/folder/a.txt",
            &[("Destination", &format!("http://{addr}/drop/folder/b.txt"))],
        )
        .await;
        assert!(moved.starts_with("HTTP/1.1 201"), "{moved}");
        assert_eq!(fs::read(root.join("folder").join("b.txt")).unwrap(), b"abc");
        let deleted = http_exchange(addr, "DELETE", "/drop/folder/b.txt", &[]).await;
        assert!(deleted.starts_with("HTTP/1.1 204"), "{deleted}");
        let dir = http_exchange(addr, "DELETE", "/drop/folder", &[]).await;
        assert!(dir.starts_with("HTTP/1.1 204"), "{dir}");
        let root_del = http_exchange(addr, "DELETE", "/drop/", &[]).await;
        assert!(root_del.starts_with("HTTP/1.1 403"), "{root_del}");
        let copy = http_exchange(addr, "COPY", "/drop/folder", &[]).await;
        assert!(copy.starts_with("HTTP/1.1 403"), "{copy}");
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn drive_gate_uses_local_grant_on_loopback() {
        let root = temp_dir();
        fs::write(root.join("note.txt"), "hello-share").unwrap();
        let share =
            validate_local_share_mode(&root, Some("files"), DEFAULT_SHARE_PORT, false).unwrap();
        let denied = spawn_gated(share.clone(), ShareGate::locked(vec![], &[], &[])).await;
        let hidden = http_exchange(denied.listen_addr(), "GET", "/files/note.txt", &[]).await;
        assert!(hidden.starts_with("HTTP/1.1 403"), "{hidden}");
        denied.stop();

        let allowed = spawn_gated(
            share,
            ShareGate::locked(vec![], &[("files".into(), "ro".into())], &[]),
        )
        .await;
        let body = http_exchange(allowed.listen_addr(), "GET", "/files/note.txt", &[]).await;
        assert!(body.contains("hello-share"), "{body}");
        let put = http_exchange(allowed.listen_addr(), "PUT", "/files/other.txt", &[]).await;
        assert!(put.starts_with("HTTP/1.1 403"), "{put}");
        assert!(!root.join("other.txt").exists());
        allowed.stop();
        fs::remove_dir_all(root).unwrap();
    }

    /// Directory link: a symlink on Unix, a junction on Windows (no admin
    /// rights needed). `false` when the platform refused to make one.
    fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|output| output.status.success())
        }
    }

    /// File symlink. Windows needs a privilege or developer mode for this,
    /// so callers skip that part when it returns `false`.
    fn link_file(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }

    fn remove_link(link: &Path) {
        // A junction or directory symlink is removed as a directory on
        // Windows and as a file on Unix; neither touches the target.
        let _ = fs::remove_dir(link).or_else(|_| fs::remove_file(link));
    }

    fn status_of(response: &str) -> &str {
        response.get(9..12).unwrap_or("")
    }

    #[tokio::test]
    async fn swapped_share_root_is_refused() {
        let base = temp_dir();
        let shared = base.join("shared");
        let outside = base.join("outside");
        fs::create_dir_all(&shared).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(shared.join("note.txt"), "inside").unwrap();
        fs::write(outside.join("private.key"), "fake-test-secret").unwrap();
        let share =
            validate_local_share_mode(&shared, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();
        assert_eq!(http_get(addr, "/drop/note.txt").await, "inside");

        // The folder's owner swaps it for a link to somewhere private.
        fs::rename(&shared, base.join("shared-old")).unwrap();
        assert!(
            link_dir(&outside, &shared),
            "could not create a directory link"
        );
        for (method, path) in [
            ("GET", "/drop/private.key"),
            ("HEAD", "/drop/private.key"),
            ("GET", "/drop/"),
            ("PROPFIND", "/drop/"),
            ("PROPFIND", "/drop/private.key"),
            ("DELETE", "/drop/private.key"),
            ("MKCOL", "/drop/made"),
        ] {
            let response = http_exchange(addr, method, path, &[("Depth", "1")]).await;
            assert_eq!(status_of(&response), "403", "{method} {path}: {response}");
            assert!(!response.contains("fake-test-secret"), "{response}");
            assert!(!response.contains("private.key"), "{response}");
        }
        assert!(
            put_share_file(&format!("http://{addr}/drop/planted.txt"), b"x")
                .await
                .is_err()
        );
        assert!(!outside.join("planted.txt").exists());
        assert!(!outside.join("made").exists());
        assert!(outside.join("private.key").exists());
        server.stop();
        remove_link(&shared);
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn links_inside_the_share_are_not_followed() {
        let base = temp_dir();
        let shared = base.join("shared");
        let outside = base.join("outside");
        fs::create_dir_all(&shared).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(shared.join("note.txt"), "inside").unwrap();
        fs::write(outside.join("private.key"), "fake-test-secret").unwrap();
        assert!(
            link_dir(&outside, &shared.join("inner")),
            "could not create a directory link"
        );
        let file_link = link_file(&outside.join("private.key"), &shared.join("key.txt"));
        let share =
            validate_local_share_mode(&shared, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();

        let listing = http_get(addr, "/drop/").await;
        assert!(listing.contains("note.txt"), "{listing}");
        assert!(!listing.contains("inner"), "{listing}");
        assert!(!listing.contains("key.txt"), "{listing}");
        let propfind = http_exchange(addr, "PROPFIND", "/drop/", &[("Depth", "1")]).await;
        assert!(propfind.contains("note.txt"), "{propfind}");
        assert!(!propfind.contains("inner"), "{propfind}");
        assert!(!propfind.contains("key.txt"), "{propfind}");
        for (method, path) in [
            ("GET", "/drop/inner/private.key"),
            ("GET", "/drop/inner/"),
            ("PROPFIND", "/drop/inner/"),
            ("PROPFIND", "/drop/inner/private.key"),
            ("DELETE", "/drop/inner/private.key"),
            ("DELETE", "/drop/inner"),
            ("MKCOL", "/drop/inner/made"),
        ] {
            let response = http_exchange(addr, method, path, &[("Depth", "1")]).await;
            assert_eq!(status_of(&response), "403", "{method} {path}: {response}");
            assert!(!response.contains("fake-test-secret"), "{response}");
        }
        assert!(
            put_share_file(&format!("http://{addr}/drop/inner/planted.txt"), b"x")
                .await
                .is_err()
        );
        // PUT onto the junction or link name itself is refused too.
        assert!(put_share_file(&format!("http://{addr}/drop/inner"), b"x")
            .await
            .is_err());
        let moved = http_exchange(
            addr,
            "MOVE",
            "/drop/note.txt",
            &[("Destination", &format!("http://{addr}/drop/inner/note.txt"))],
        )
        .await;
        assert_eq!(status_of(&moved), "403", "{moved}");
        if file_link {
            let read = http_exchange(addr, "GET", "/drop/key.txt", &[]).await;
            assert_eq!(status_of(&read), "403", "{read}");
            assert!(!read.contains("fake-test-secret"), "{read}");
            // A PUT over a planted link must not write through it.
            assert!(
                put_share_file(&format!("http://{addr}/drop/key.txt"), b"overwritten")
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            fs::read(outside.join("private.key")).unwrap(),
            b"fake-test-secret"
        );
        assert!(!outside.join("planted.txt").exists());
        assert!(!outside.join("made").exists());
        assert!(!outside.join("note.txt").exists());
        server.stop();
        remove_link(&shared.join("inner"));
        if file_link {
            remove_link(&shared.join("key.txt"));
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn dot_files_are_hidden_and_denied() {
        let root = temp_dir();
        fs::write(root.join("note.txt"), "inside").unwrap();
        fs::write(root.join(".env"), "fake-test-secret").unwrap();
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::write(root.join(".ssh").join("id"), "fake-test-secret").unwrap();
        let share =
            validate_local_share_mode(&root, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();
        let listing = http_get(addr, "/drop/").await;
        assert!(
            listing.contains("note.txt") && !listing.contains(".env"),
            "{listing}"
        );
        for (method, path) in [
            ("GET", "/drop/.env"),
            ("HEAD", "/drop/.env"),
            ("GET", "/drop/.ssh/id"),
            ("GET", "/drop/.ssh/"),
            ("PROPFIND", "/drop/.env"),
            ("PROPFIND", "/drop/.ssh/"),
            ("GET", "/drop/%2eenv"),
            ("DELETE", "/drop/.env"),
            ("MKCOL", "/drop/.config"),
            ("GET", "/drop/note.txt:stream"),
            ("GET", "/drop/..%5cnote.txt"),
        ] {
            let response = http_exchange(addr, method, path, &[("Depth", "1")]).await;
            assert_eq!(status_of(&response), "403", "{method} {path}: {response}");
            assert!(!response.contains("fake-test-secret"), "{response}");
        }
        assert!(
            put_share_file(&format!("http://{addr}/drop/.ssh/authorized_keys"), b"x")
                .await
                .is_err()
        );
        assert!(!root.join(".ssh").join("authorized_keys").exists());
        assert!(root.join(".env").exists());
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn get_streams_large_files_and_put_leaves_no_partial() {
        let root = temp_dir();
        let big = vec![b'z'; 300 * 1024];
        fs::write(root.join("big.bin"), &big).unwrap();
        let share =
            validate_local_share_mode(&root, Some("drop"), DEFAULT_SHARE_PORT, false).unwrap();
        let server = spawn_on_free_port(share).await;
        let addr = server.listen_addr();
        let response = http_exchange(addr, "GET", "/drop/big.bin", &[]).await;
        assert!(response.contains("Content-Length: 307200"));
        assert_eq!(response.split("\r\n\r\n").nth(1).unwrap().len(), big.len());
        let sent = put_share_file(&format!("http://{addr}/drop/new.bin"), &big)
            .await
            .unwrap();
        assert_eq!(sent, 201);
        assert_eq!(fs::read(root.join("new.bin")).unwrap(), big);
        let missing = http_exchange(addr, "PUT", "/drop/nolength.txt", &[]).await;
        assert_eq!(status_of(&missing), "411", "{missing}");
        let leftovers = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains("partial"))
            .count();
        assert_eq!(leftovers, 0);
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }
}
