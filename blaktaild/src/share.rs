use crate::{Error, NodeState};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write as _,
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedShare {
    pub node_id: String,
    pub dns_name: String,
    pub label: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub read_only: bool,
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

pub struct ShareServer {
    task: AbortHandle,
    listen_addr: SocketAddr,
    fingerprint: String,
}

impl ShareServer {
    pub async fn spawn(bind_ip: IpAddr, shares: &[LocalShare]) -> Result<Self, Error> {
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
        let fingerprint = fingerprint_shares(&enabled);
        let served = Arc::new(enabled);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shares = served.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, &shares).await;
                });
            }
        });
        Ok(Self {
            task: task.abort_handle(),
            listen_addr,
            fingerprint,
        })
    }

    pub fn matches(&self, bind_ip: IpAddr, shares: &[LocalShare]) -> bool {
        let enabled = shares
            .iter()
            .filter(|share| share.enabled)
            .cloned()
            .collect::<Vec<_>>();
        self.listen_addr.ip() == bind_ip && self.fingerprint == fingerprint_shares(&enabled)
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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
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
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::Message(
            "share name must be 1-32 letters, digits, or hyphens".into(),
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
                "{}:{}:{}:{}",
                share.label, share.path, share.port, share.enabled
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

async fn handle_client(mut stream: TcpStream, shares: &[LocalShare]) -> Result<(), Error> {
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
    let body_start = header_end + separator;
    parsed.body = buffer[body_start..length].to_vec();
    if let Some(needed) = parsed.content_length {
        if needed > MAX_PUT_BYTES {
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
        while parsed.body.len() < needed {
            let mut chunk = [0u8; 8192];
            let read = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Message("share request timed out".into()))??;
            if read == 0 {
                break;
            }
            parsed.body.extend_from_slice(&chunk[..read]);
        }
        parsed.body.truncate(needed);
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
            serve_get(&mut stream, shares, &parsed.path, parsed.method == "HEAD").await?;
        }
        "PROPFIND" => {
            serve_propfind(&mut stream, shares, &parsed.path, parsed.depth.as_deref()).await?;
        }
        "PUT" => {
            serve_put(&mut stream, shares, &parsed.path, &parsed.body).await?;
        }
        "POST" | "DELETE" | "MKCOL" | "MOVE" | "COPY" | "PROPPATCH" | "LOCK" | "UNLOCK" => {
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

const ALLOWED_METHODS: &str = "OPTIONS, GET, HEAD, PROPFIND, PUT";

struct ParsedRequest {
    method: String,
    path: String,
    depth: Option<String>,
    content_length: Option<usize>,
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
        }
    }
    Some(ParsedRequest {
        method,
        path,
        depth,
        content_length,
        body: Vec::new(),
    })
}

fn share_for_path<'a>(shares: &'a [LocalShare], path: &str) -> Option<&'a LocalShare> {
    shares.iter().filter(|share| share.enabled).find(|share| {
        path == format!("/{}", share.label) || path.starts_with(&format!("/{}/", share.label))
    })
}

fn resolve_put_path(share: &LocalShare, url_path: &str) -> Result<PathBuf, Error> {
    let prefix = format!("/{}", share.label);
    let rest = url_path
        .strip_prefix(&prefix)
        .unwrap_or("")
        .trim_start_matches('/');
    if rest.is_empty()
        || rest.ends_with('/')
        || rest
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Message("share file path is not acceptable".into()));
    }
    let root = fs::canonicalize(&share.path)?;
    let target = root.join(rest);
    let parent = target
        .parent()
        .ok_or_else(|| Error::Message("share file path is not acceptable".into()))?;
    let parent = fs::canonicalize(parent)?;
    if !parent.starts_with(&root) {
        return Err(Error::Message("share file path escapes the folder".into()));
    }
    if target.exists() {
        let existing = fs::canonicalize(&target)?;
        if !existing.starts_with(&root) {
            return Err(Error::Message("share file path escapes the folder".into()));
        }
    }
    Ok(target)
}

async fn serve_put(
    stream: &mut TcpStream,
    shares: &[LocalShare],
    path: &str,
    body: &[u8],
) -> Result<(), Error> {
    let Some(share) = share_for_path(shares, path) else {
        write_plain(stream, 404, "Not Found", "not found\n", true).await?;
        return Ok(());
    };
    if share.read_only {
        write_plain(stream, 403, "Forbidden", "read-only\n", true).await?;
        return Ok(());
    }
    if body.len() > MAX_PUT_BYTES {
        write_plain(
            stream,
            413,
            "Payload Too Large",
            "file is too large\n",
            true,
        )
        .await?;
        return Ok(());
    }
    let target = match resolve_put_path(share, path) {
        Ok(target) => target,
        Err(_) => {
            write_plain(stream, 403, "Forbidden", "forbidden\n", true).await?;
            return Ok(());
        }
    };
    let temporary = target.with_extension("blaktail-partial");
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, &target)?;
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
        ShareResponse::Index(body) => {
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
        ShareResponse::Listing(body) => {
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
        ShareResponse::File { path, content_type } => {
            if head {
                let length = fs::metadata(&path)?.len();
                write_response(
                    stream,
                    200,
                    "OK",
                    &[
                        ("Content-Type", content_type),
                        ("Content-Length", &length.to_string()),
                        ("Cache-Control", "no-store"),
                    ],
                    b"",
                    false,
                )
                .await
            } else {
                let bytes = fs::read(&path)?;
                write_plain_typed(stream, 200, "OK", content_type, &bytes, true).await
            }
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

enum ShareResponse {
    Index(String),
    Listing(String),
    File {
        path: PathBuf,
        content_type: &'static str,
    },
    NotFound,
    Forbidden,
}

fn resolve_request(shares: &[LocalShare], path: &str) -> ShareResponse {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return ShareResponse::Index(index_page(shares));
    }
    let (label, rest) = match trimmed.split_once('/') {
        Some((label, rest)) => (label, rest.trim_start_matches('/')),
        None => (trimmed, ""),
    };
    let Some(share) = shares
        .iter()
        .find(|share| share.enabled && share.label == label)
    else {
        return ShareResponse::NotFound;
    };
    let root = match fs::canonicalize(&share.path) {
        Ok(root) => root,
        Err(_) => return ShareResponse::NotFound,
    };
    if rest.contains('\0') || rest.split('/').any(|part| part == "..") {
        return ShareResponse::Forbidden;
    }
    let target = if rest.is_empty() {
        root.clone()
    } else {
        root.join(rest)
    };
    let Ok(canonical) = fs::canonicalize(&target) else {
        return ShareResponse::NotFound;
    };
    if !canonical.starts_with(&root) {
        return ShareResponse::Forbidden;
    }
    let Ok(metadata) = fs::metadata(&canonical) else {
        return ShareResponse::NotFound;
    };
    if metadata.is_dir() {
        return ShareResponse::Listing(listing_page(share, rest, &canonical));
    }
    if !metadata.is_file() {
        return ShareResponse::Forbidden;
    }
    ShareResponse::File {
        path: canonical,
        content_type: content_type(rest),
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

fn listing_page(share: &LocalShare, relative: &str, directory: &Path) -> String {
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
    for entry in list_visible_entries(directory) {
        let suffix = if entry.is_dir { "/" } else { "" };
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

struct DirEntry {
    name: String,
    is_dir: bool,
    path: PathBuf,
}

fn list_visible_entries(directory: &Path) -> Vec<DirEntry> {
    let mut entries = fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            if name.starts_with('.') {
                return None;
            }
            Some(DirEntry {
                is_dir: entry.path().is_dir(),
                path: entry.path(),
                name,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries.into_iter().take(MAX_LISTING).collect()
}

enum DavDocument {
    Xml(String),
    NotFound,
    Forbidden,
}

fn dav_document(shares: &[LocalShare], path: &str, depth: u8) -> DavDocument {
    match resolve_request(shares, path) {
        ShareResponse::Index(_) => {
            let mut xml = dav_header();
            xml.push_str(&dav_collection("/", "BlakTail shares", None));
            if depth > 0 {
                for share in shares.iter().filter(|share| share.enabled) {
                    xml.push_str(&dav_collection(
                        &format!("/{}/", share.label),
                        &share.label,
                        fs::metadata(&share.path).ok().as_ref(),
                    ));
                }
            }
            xml.push_str("</D:multistatus>\n");
            DavDocument::Xml(xml)
        }
        ShareResponse::Listing(_) => {
            let trimmed = path.trim_start_matches('/');
            let (label, rest) = match trimmed.split_once('/') {
                Some((label, rest)) => (label, rest.trim_start_matches('/')),
                None => (trimmed, ""),
            };
            let Some(share) = shares
                .iter()
                .find(|share| share.enabled && share.label == label)
            else {
                return DavDocument::NotFound;
            };
            let root = match fs::canonicalize(&share.path) {
                Ok(root) => root,
                Err(_) => return DavDocument::NotFound,
            };
            let target = if rest.is_empty() {
                root.clone()
            } else {
                root.join(rest)
            };
            let Ok(canonical) = fs::canonicalize(&target) else {
                return DavDocument::NotFound;
            };
            let href = collection_href(&share.label, rest);
            let display = if rest.is_empty() {
                share.label.clone()
            } else {
                Path::new(rest)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&share.label)
                    .to_owned()
            };
            let mut xml = dav_header();
            xml.push_str(&dav_collection(
                &href,
                &display,
                fs::metadata(&canonical).ok().as_ref(),
            ));
            if depth > 0 {
                for entry in list_visible_entries(&canonical) {
                    let child = format!("{href}{}", entry.name);
                    if entry.is_dir {
                        xml.push_str(&dav_collection(
                            &format!("{child}/"),
                            &entry.name,
                            fs::metadata(&entry.path).ok().as_ref(),
                        ));
                    } else {
                        xml.push_str(&dav_file(
                            &child,
                            &entry.name,
                            content_type(&entry.name),
                            fs::metadata(&entry.path).ok().as_ref(),
                        ));
                    }
                }
            }
            xml.push_str("</D:multistatus>\n");
            DavDocument::Xml(xml)
        }
        ShareResponse::File {
            path: file,
            content_type,
        } => {
            let name = file
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("file");
            let href = if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            };
            let mut xml = dav_header();
            xml.push_str(&dav_file(
                href.trim_end_matches('/'),
                name,
                content_type,
                fs::metadata(&file).ok().as_ref(),
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

fn dav_collection(href: &str, display: &str, metadata: Option<&fs::Metadata>) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>{}</D:displayname>{}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        escape_xml(&href_encode(href)),
        escape_xml(display),
        dav_mtime(metadata)
    )
}

fn dav_file(
    href: &str,
    display: &str,
    content_type: &str,
    metadata: Option<&fs::Metadata>,
) -> String {
    let length = metadata.map(fs::Metadata::len).unwrap_or(0);
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop><D:resourcetype/><D:displayname>{}</D:displayname><D:getcontentlength>{length}</D:getcontentlength><D:getcontenttype>{}</D:getcontenttype>{}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        escape_xml(&href_encode(href)),
        escape_xml(display),
        escape_xml(content_type),
        dav_mtime(metadata)
    )
}

fn dav_mtime(metadata: Option<&fs::Metadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    format!(
        "<D:getlastmodified>{}</D:getlastmodified>",
        http_date(modified)
    )
}

fn href_encode(path: &str) -> String {
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
            UuidLike::now()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    struct UuidLike;
    impl UuidLike {
        fn now() -> u128 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        }
    }

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
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut share = validate_local_share(&root, Some("files"), DEFAULT_SHARE_PORT).unwrap();
        share.port = port;
        let served = vec![share];
        let server = ShareServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST), &served)
            .await
            .unwrap();
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
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut share = validate_local_share(&root, Some("files"), DEFAULT_SHARE_PORT).unwrap();
        share.port = port;
        let server = ShareServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST), &[share])
            .await
            .unwrap();
        let addr = server.listen_addr();

        let options = http_exchange(addr, "OPTIONS", "/files/", &[]).await;
        assert!(options.starts_with("HTTP/1.1 200"), "{options}");
        assert!(options.contains("DAV: 1"), "{options}");
        assert!(
            options.contains("Allow: OPTIONS, GET, HEAD, PROPFIND, PUT"),
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

        let write_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let write_port = write_probe.local_addr().unwrap().port();
        drop(write_probe);
        let mut writable =
            validate_local_share_mode(&root, Some("drop"), write_port, false).unwrap();
        writable.port = write_port;
        let writable_server = ShareServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST), &[writable])
            .await
            .unwrap();
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
}
