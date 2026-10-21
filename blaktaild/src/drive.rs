//! Loopback folder browser. One namespace for this node's shares and the
//! peers already on the peer map. It proxies file verbs to the overlay
//! listener and never dials an address that map did not publish.
use crate::{dns_domain, overlay_ipv4, Error, LocalShare, NodeState, PublishedShare};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::AbortHandle,
};

pub const BROWSER_PORT: u16 = 8080;
const MAX_HEADER: usize = 8_192;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_LISTING: usize = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct DriveView {
    #[serde(default)]
    pub access: bool,
    #[serde(default)]
    pub share: bool,
    #[serde(default)]
    pub local: Vec<DriveGrantShare>,
    #[serde(default)]
    pub callers: Vec<DriveCaller>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DriveGrantShare {
    pub label: String,
    pub access: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DriveCaller {
    pub address: String,
    pub label: String,
    pub access: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogShare {
    pub domain: String,
    pub machine: String,
    pub label: String,
    pub origin: SocketAddr,
    pub read_only: bool,
}

pub struct DriveBrowser {
    task: AbortHandle,
    listen_addr: SocketAddr,
    fingerprint: String,
}

impl DriveBrowser {
    pub async fn spawn(shares: Vec<CatalogShare>) -> Result<Self, Error> {
        Self::listen(SocketAddr::from(([127, 0, 0, 1], BROWSER_PORT)), shares).await
    }

    pub async fn listen(addr: SocketAddr, shares: Vec<CatalogShare>) -> Result<Self, Error> {
        if !addr.ip().is_loopback() {
            return Err(Error::Message(
                "folder browser binds to loopback only".into(),
            ));
        }
        let listener = TcpListener::bind(addr).await?;
        let listen_addr = listener.local_addr()?;
        let fingerprint = fingerprint(&shares);
        let served = Arc::new(shares);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shares = served.clone();
                tokio::spawn(async move {
                    let _ = handle(stream, &shares).await;
                });
            }
        });
        Ok(Self {
            task: task.abort_handle(),
            listen_addr,
            fingerprint,
        })
    }

    pub fn matches(&self, shares: &[CatalogShare]) -> bool {
        self.fingerprint == fingerprint(shares)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for DriveBrowser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn catalog(state: &NodeState, local: &[LocalShare]) -> Vec<CatalogShare> {
    let mut names = vec![(state.node_id.to_string(), state.dns_name.clone())];
    for share in &state.published_shares {
        if !names.iter().any(|(id, _)| id == &share.node_id) {
            names.push((share.node_id.clone(), share.dns_name.clone()));
        }
    }
    let machines = machine_names(&names);
    let mut shares = Vec::new();
    if let Ok(ip) = overlay_ipv4(state) {
        let domain = domain_of(&state.dns_name);
        let machine = machines
            .get(&state.node_id.to_string())
            .cloned()
            .unwrap_or_else(|| first_label(&state.dns_name));
        for share in local {
            let Some(read_only) = local_mode(state, share) else {
                continue;
            };
            shares.push(CatalogShare {
                domain: domain.clone(),
                machine: machine.clone(),
                label: share.label.clone(),
                origin: SocketAddr::new(ip, share.port),
                read_only,
            });
        }
    }
    for share in &state.published_shares {
        let Some(read_only) = published_mode(state, share) else {
            continue;
        };
        let Some(peer) = state
            .peers
            .iter()
            .find(|peer| peer.id.to_string() == share.node_id)
        else {
            continue;
        };
        let Some(ip) = ipv4_host(&peer.allowed_ips) else {
            continue;
        };
        let Some(machine) = machines.get(&share.node_id).cloned() else {
            continue;
        };
        shares.push(CatalogShare {
            domain: domain_of(&share.dns_name),
            machine,
            label: share.label.clone(),
            origin: SocketAddr::new(ip, share.port),
            read_only,
        });
    }
    shares.sort_by(|left, right| {
        (
            left.domain.as_str(),
            left.machine.as_str(),
            left.label.as_str(),
        )
            .cmp(&(
                right.domain.as_str(),
                right.machine.as_str(),
                right.label.as_str(),
            ))
    });
    shares
}

fn local_mode(state: &NodeState, share: &LocalShare) -> Option<bool> {
    if !share.enabled {
        return None;
    }
    match &state.drive {
        None => Some(share.read_only),
        Some(drive) => {
            let row = drive.local.iter().find(|row| row.label == share.label)?;
            Some(share.read_only || row.access != "rw")
        }
    }
}

fn published_mode(state: &NodeState, share: &PublishedShare) -> Option<bool> {
    match &state.drive {
        None => Some(share.read_only),
        Some(_) => {
            let access = share.access.as_deref()?;
            Some(share.read_only || access != "rw")
        }
    }
}

fn machine_names(rows: &[(String, String)]) -> BTreeMap<String, String> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, dns) in rows {
        grouped
            .entry(first_label(dns))
            .or_default()
            .push(id.clone());
    }
    let mut names = BTreeMap::new();
    for (label, ids) in grouped {
        if ids.len() == 1 {
            names.insert(ids[0].clone(), label);
            continue;
        }
        let mut used = BTreeSet::new();
        for id in ids {
            let hex: String = id.chars().filter(|byte| *byte != '-').collect();
            let short = &hex[..hex.len().min(8)];
            let mut machine = format!("{label}-{short}");
            if !used.insert(machine.clone()) {
                machine = format!("{label}-{hex}");
                used.insert(machine.clone());
            }
            names.insert(id, machine);
        }
    }
    names
}

fn first_label(dns: &str) -> String {
    let dns = dns.trim().trim_end_matches('.');
    let label = dns.split('.').next().unwrap_or("node");
    if label.is_empty() {
        "node".into()
    } else {
        label.to_ascii_lowercase()
    }
}

fn domain_of(dns: &str) -> String {
    dns_domain(dns).unwrap_or_else(|| "blaktail".into())
}

fn ipv4_host(addresses: &[String]) -> Option<IpAddr> {
    addresses.iter().find_map(|address| {
        let host = address.split('/').next()?.trim();
        let ip: IpAddr = host.parse().ok()?;
        ip.is_ipv4().then_some(ip)
    })
}

fn fingerprint(shares: &[CatalogShare]) -> String {
    let mut rows: Vec<_> = shares
        .iter()
        .map(|share| {
            format!(
                "{} {} {} {} {}",
                share.domain, share.machine, share.label, share.origin, share.read_only
            )
        })
        .collect();
    rows.sort();
    rows.join("\n")
}

enum Target<'a> {
    Index,
    Page(String),
    Proxy {
        share: &'a CatalogShare,
        rest: String,
        directory: bool,
    },
    Missing,
    Rejected,
}

fn locate<'a>(shares: &'a [CatalogShare], path: &str) -> Target<'a> {
    let directory = path.ends_with('/') || path == "/";
    let parts: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts
        .iter()
        .any(|part| *part == "." || *part == ".." || part.contains('\0'))
    {
        return Target::Rejected;
    }
    match parts.as_slice() {
        [] => Target::Index,
        [domain] => {
            let mut machines = BTreeSet::new();
            for share in shares.iter().filter(|share| share.domain == *domain) {
                machines.insert(share.machine.as_str());
            }
            if machines.is_empty() {
                Target::Missing
            } else {
                let mut body = page_start(domain);
                for machine in machines {
                    let href = format!("/{domain}/{machine}/");
                    body.push_str(&format!(
                        "<li><a href=\"{}\">{}/</a></li>",
                        escape(&href),
                        escape(machine)
                    ));
                }
                body.push_str("</ul></body></html>\n");
                Target::Page(body)
            }
        }
        [domain, machine] => {
            let found: Vec<_> = shares
                .iter()
                .filter(|share| share.domain == *domain && share.machine == *machine)
                .collect();
            if found.is_empty() {
                Target::Missing
            } else {
                let mut body = page_start(&format!("{domain}/{machine}"));
                for share in found {
                    let href = format!("/{domain}/{machine}/{}/", share.label);
                    body.push_str(&format!(
                        "<li><a href=\"{}\">{}/</a></li>",
                        escape(&href),
                        escape(&share.label)
                    ));
                }
                body.push_str("</ul></body></html>\n");
                Target::Page(body)
            }
        }
        [domain, machine, label, rest @ ..] => {
            let Some(share) = shares.iter().find(|share| {
                share.domain == *domain && share.machine == *machine && share.label == *label
            }) else {
                return Target::Missing;
            };
            Target::Proxy {
                share,
                rest: rest.join("/"),
                directory: directory || rest.is_empty(),
            }
        }
    }
}

fn page_start(title: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1><ul>",
        escape(title),
        escape(title)
    )
}

fn index_page(shares: &[CatalogShare]) -> String {
    let mut body = page_start("BlakTail folders");
    let mut seen = BTreeSet::new();
    for share in shares {
        let href = format!("/{}/{}/{}/", share.domain, share.machine, share.label);
        if !seen.insert(href.clone()) {
            continue;
        }
        body.push_str(&format!(
            "<li><a href=\"{}\">{}</a></li>",
            escape(&href),
            escape(&href)
        ));
    }
    body.push_str("</ul></body></html>\n");
    body
}

struct Request {
    method: String,
    path: String,
    depth: Option<String>,
    destination: Option<String>,
    overwrite: Option<String>,
    content_length: Option<usize>,
    body: Vec<u8>,
}

async fn handle(mut stream: TcpStream, shares: &[CatalogShare]) -> Result<(), Error> {
    let mut buffer = vec![0u8; MAX_HEADER];
    let length = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut buffer))
        .await
        .map_err(|_| Error::Message("folder browser timed out".into()))??;
    if length == 0 {
        return Ok(());
    }
    let Some(header_end) = buffer[..length]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        return write_plain(&mut stream, 400, "Bad Request", "bad request\n").await;
    };
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| Error::Message("folder browser request is not UTF-8".into()))?;
    let Some(mut parsed) = parse_request(header) else {
        return write_plain(&mut stream, 400, "Bad Request", "bad request\n").await;
    };
    parsed.body = buffer[header_end + 4..length].to_vec();
    if let Some(needed) = parsed.content_length {
        if needed > MAX_BODY {
            return write_plain(&mut stream, 413, "Payload Too Large", "file is too large\n").await;
        }
        while parsed.body.len() < needed {
            let mut chunk = [0u8; 8192];
            let read = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Message("folder browser timed out".into()))??;
            if read == 0 {
                break;
            }
            parsed.body.extend_from_slice(&chunk[..read]);
        }
        parsed.body.truncate(needed);
    }
    if parsed.method == "OPTIONS" {
        return write_response(
            &mut stream,
            200,
            "OK",
            &[
                ("DAV", "1"),
                (
                    "Allow",
                    "OPTIONS, GET, HEAD, PROPFIND, PUT, MKCOL, DELETE, MOVE",
                ),
                ("Content-Length", "0"),
            ],
            b"",
        )
        .await;
    }
    if !matches!(
        parsed.method.as_str(),
        "GET" | "HEAD" | "PROPFIND" | "PUT" | "MKCOL" | "DELETE" | "MOVE"
    ) {
        return write_plain(
            &mut stream,
            405,
            "Method Not Allowed",
            "method not allowed\n",
        )
        .await;
    }
    match locate(shares, &parsed.path) {
        Target::Rejected => write_plain(&mut stream, 403, "Forbidden", "forbidden\n").await,
        Target::Missing => write_plain(&mut stream, 404, "Not Found", "not found\n").await,
        Target::Index => {
            let body = index_page(shares);
            write_html(&mut stream, parsed.method != "HEAD", &body).await
        }
        Target::Page(body) => write_html(&mut stream, parsed.method != "HEAD", &body).await,
        Target::Proxy {
            share,
            rest,
            directory,
        } => {
            if share.read_only
                && matches!(parsed.method.as_str(), "PUT" | "MKCOL" | "DELETE" | "MOVE")
            {
                return write_plain(&mut stream, 403, "Forbidden", "read-only\n").await;
            }
            proxy(&mut stream, share, &parsed, &rest, directory).await
        }
    }
}

fn parse_request(raw: &str) -> Option<Request> {
    let mut lines = raw.split('\n');
    let mut parts = lines.next()?.trim_end_matches('\r').split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next().unwrap_or("/");
    let path = percent_decode(target.split('?').next().unwrap_or("/"))?;
    let mut depth = None;
    let mut destination = None;
    let mut overwrite = None;
    let mut content_length = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("depth") {
            depth = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("destination") {
            destination = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("overwrite") {
            overwrite = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
    }
    Some(Request {
        method,
        path,
        depth,
        destination,
        overwrite,
        content_length,
        body: Vec::new(),
    })
}

async fn proxy(
    client: &mut TcpStream,
    share: &CatalogShare,
    parsed: &Request,
    rest: &str,
    directory: bool,
) -> Result<(), Error> {
    let method = parsed.method.as_str();
    let body = &parsed.body;
    let origin_path = if rest.is_empty() {
        format!("/{}/", share.label)
    } else if directory {
        format!("/{}/{}/", share.label, rest)
    } else {
        format!("/{}/{}", share.label, rest)
    };
    let mut request = format!(
        "{method} {origin_path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        share.origin
    );
    if let Some(depth) = &parsed.depth {
        request.push_str(&format!("Depth: {depth}\r\n"));
    }
    if let Some(destination) = &parsed.destination {
        let Some(rewritten) = rewrite_destination(destination, share) else {
            return write_plain(client, 403, "Forbidden", "forbidden\n").await;
        };
        request.push_str(&format!("Destination: {rewritten}\r\n"));
    }
    if let Some(overwrite) = &parsed.overwrite {
        request.push_str(&format!("Overwrite: {overwrite}\r\n"));
    }
    if !body.is_empty() || method == "PUT" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let connected =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(share.origin)).await;
    let mut origin = match connected {
        Ok(Ok(stream)) => stream,
        _ => {
            return write_plain(client, 502, "Bad Gateway", "folder is unreachable\n").await;
        }
    };
    origin.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        origin.write_all(body).await?;
    }
    let rewrite = method == "PROPFIND" || (method == "GET" && directory);
    if !rewrite {
        tokio::io::copy(&mut origin, client).await?;
        return Ok(());
    }
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = tokio::time::timeout(REQUEST_TIMEOUT, origin.read(&mut chunk))
            .await
            .map_err(|_| Error::Message("folder browser timed out".into()))??;
        if read == 0 {
            break;
        }
        if buffered.len() + read > MAX_LISTING {
            return write_plain(client, 502, "Bad Gateway", "listing is too large\n").await;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buffered);
    let adjusted = adjust_listing(&text, share);
    client.write_all(adjusted.as_bytes()).await?;
    Ok(())
}

fn rewrite_destination(value: &str, share: &CatalogShare) -> Option<String> {
    let path = value
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
        .unwrap_or(value);
    let path = percent_decode(path.split('?').next().unwrap_or(path))?;
    let prefix = format!("/{}/{}/{}", share.domain, share.machine, share.label);
    let rest = path.strip_prefix(&prefix)?;
    Some(format!("/{}{rest}", share.label))
}

fn adjust_listing(raw: &str, share: &CatalogShare) -> String {
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return raw.to_owned();
    };
    let body = rewrite_listing(body, share);
    let mut headers = Vec::new();
    let mut saw_length = false;
    for (index, line) in head.split("\r\n").enumerate() {
        if index > 0 && line.to_ascii_lowercase().starts_with("content-length:") {
            headers.push(format!("Content-Length: {}", body.len()));
            saw_length = true;
        } else {
            headers.push(line.to_owned());
        }
    }
    if !saw_length {
        headers.push(format!("Content-Length: {}", body.len()));
    }
    format!("{}\r\n\r\n{body}", headers.join("\r\n"))
}

fn rewrite_listing(body: &str, share: &CatalogShare) -> String {
    let from = format!("/{}/", share.label);
    let to = format!("/{}/{}/{}/", share.domain, share.machine, share.label);
    body.replace(&from, &to).replace(
        &format!("/{}\"", share.label),
        &format!("/{}/{}/{}\"", share.domain, share.machine, share.label),
    )
}

fn percent_decode(value: &str) -> Option<String> {
    let raw = value.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
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
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn write_html(stream: &mut TcpStream, send_body: bool, body: &str) -> Result<(), Error> {
    write_response(
        stream,
        200,
        "OK",
        &[
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", &body.len().to_string()),
            ("Cache-Control", "no-store"),
        ],
        if send_body { body.as_bytes() } else { b"" },
    )
    .await
}

async fn write_plain(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), Error> {
    write_response(
        stream,
        status,
        reason,
        &[
            ("Content-Type", "text/plain"),
            ("Content-Length", &body.len().to_string()),
            ("Cache-Control", "no-store"),
        ],
        body.as_bytes(),
    )
    .await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
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
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::ShareServer;
    use std::fs;

    fn state_with(extra: serde_json::Value) -> NodeState {
        let mut value = serde_json::json!({
            "node_id": "00000000-0000-0000-0000-000000000001",
            "node_token": "t",
            "coord": "http://127.0.0.1",
            "interface": "blaktail0",
            "assigned_ip": "100.64.0.1/32",
            "dns_name": "self.abcdef12.blaktail",
            "peers": [],
            "published_shares": []
        });
        if let (Some(base), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            for (key, item) in extra {
                base.insert(key.clone(), item.clone());
            }
        }
        serde_json::from_value(value).unwrap()
    }

    fn local_share(label: &str, read_only: bool) -> LocalShare {
        LocalShare {
            label: label.into(),
            path: "/tmp/notes".into(),
            port: 5647,
            read_only,
            enabled: true,
            as_user: "ada".into(),
        }
    }

    #[test]
    fn catalog_uses_peer_map_and_disambiguates_names() {
        let state = state_with(serde_json::json!({
            "peers": [
                {
                    "id": "11111111-0000-0000-0000-000000000002",
                    "name": "store",
                    "wg_public_key": "k",
                    "endpoint": null,
                    "allowed_ips": ["100.64.0.2/32"],
                    "dns_name": "host.abcdef12.blaktail"
                },
                {
                    "id": "22222222-0000-0000-0000-000000000003",
                    "name": "other",
                    "wg_public_key": "k",
                    "endpoint": null,
                    "allowed_ips": ["100.64.0.3/32"],
                    "dns_name": "host.99999999.blaktail"
                }
            ],
            "published_shares": [
                {
                    "node_id": "11111111-0000-0000-0000-000000000002",
                    "dns_name": "host.abcdef12.blaktail",
                    "label": "files",
                    "port": 5647,
                    "read_only": true
                },
                {
                    "node_id": "00000000-0000-0000-0000-000000000004",
                    "dns_name": "ghost.abcdef12.blaktail",
                    "label": "secret",
                    "port": 5647,
                    "read_only": true
                },
                {
                    "node_id": "22222222-0000-0000-0000-000000000003",
                    "dns_name": "host.99999999.blaktail",
                    "label": "files",
                    "port": 5647,
                    "read_only": false
                }
            ]
        }));
        let shares = catalog(&state, &[local_share("notes", false)]);
        assert!(shares.iter().any(|share| share.label == "notes"
            && share.machine == "self"
            && share.origin == "100.64.0.1:5647".parse::<SocketAddr>().unwrap()));
        assert!(shares.iter().any(|share| {
            share.label == "files"
                && share.machine == "host-11111111"
                && share.read_only
                && share.origin.ip().to_string() == "100.64.0.2"
        }));
        assert!(shares.iter().any(|share| {
            share.machine == "host-22222222" && share.origin.ip().to_string() == "100.64.0.3"
        }));
        assert!(!shares.iter().any(|share| share.label == "secret"));
    }

    #[test]
    fn catalog_hides_shares_a_drive_grant_omits() {
        let mut state = state_with(serde_json::json!({
            "published_shares": [{
                "node_id": "00000000-0000-0000-0000-000000000002",
                "dns_name": "store.abcdef12.blaktail",
                "label": "files",
                "port": 5647,
                "read_only": false,
                "access": "ro"
            }],
            "peers": [{
                "id": "00000000-0000-0000-0000-000000000002",
                "name": "store",
                "wg_public_key": "k",
                "endpoint": null,
                "allowed_ips": ["100.64.0.2/32"],
                "dns_name": "store.abcdef12.blaktail"
            }]
        }));
        state.drive = Some(DriveView {
            access: true,
            share: true,
            local: vec![DriveGrantShare {
                label: "notes".into(),
                access: "rw".into(),
            }],
            callers: vec![],
        });
        let shares = catalog(
            &state,
            &[local_share("notes", false), local_share("hidden", false)],
        );
        assert!(shares
            .iter()
            .any(|share| share.label == "notes" && !share.read_only));
        assert!(!shares.iter().any(|share| share.label == "hidden"));
        assert!(shares
            .iter()
            .any(|share| share.label == "files" && share.read_only));
    }

    #[tokio::test]
    async fn browser_proxies_a_peer_share_and_rewrites_listings() {
        let root = std::env::temp_dir().join(format!(
            "blaktail-drive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("note.txt"), "hello-share").unwrap();
        let share =
            crate::share::validate_local_share(&root, Some("files"), crate::DEFAULT_SHARE_PORT)
                .unwrap();
        let server = spawn_share(share).await;
        let entry = CatalogShare {
            domain: "abcdef12.blaktail".into(),
            machine: "store".into(),
            label: "files".into(),
            origin: server.listen_addr(),
            read_only: true,
        };
        let browser = DriveBrowser::listen("127.0.0.1:0".parse().unwrap(), vec![entry])
            .await
            .unwrap();
        let listing = http(
            browser.listen_addr(),
            "GET",
            "/abcdef12.blaktail/store/files/",
        )
        .await;
        assert!(listing.contains("note.txt"), "{listing}");
        assert!(
            listing.contains("/abcdef12.blaktail/store/files/"),
            "{listing}"
        );
        let file = http(
            browser.listen_addr(),
            "GET",
            "/abcdef12.blaktail/store/files/note.txt",
        )
        .await;
        assert!(file.contains("hello-share"), "{file}");
        let propfind = http_headers(
            browser.listen_addr(),
            "PROPFIND",
            "/abcdef12.blaktail/store/files/",
            &[("Depth", "1")],
        )
        .await;
        assert!(
            propfind.contains("/abcdef12.blaktail/store/files/note.txt"),
            "{propfind}"
        );
        let escaped = http(
            browser.listen_addr(),
            "GET",
            "/abcdef12.blaktail/store/files/../note.txt",
        )
        .await;
        assert!(escaped.starts_with("HTTP/1.1 403"), "{escaped}");
        let missing = http(
            browser.listen_addr(),
            "GET",
            "/abcdef12.blaktail/nope/files/",
        )
        .await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        let denied = http(
            browser.listen_addr(),
            "PUT",
            "/abcdef12.blaktail/store/files/x.txt",
        )
        .await;
        assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
        browser.stop();
        server.stop();
        fs::remove_dir_all(root).unwrap();
    }

    async fn spawn_share(mut share: LocalShare) -> ShareServer {
        for _ in 0..20 {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            share.port = probe.local_addr().unwrap().port();
            drop(probe);
            if let Ok(server) = ShareServer::spawn(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                std::slice::from_ref(&share),
            )
            .await
            {
                return server;
            }
        }
        panic!("no free localhost port for drive test");
    }

    async fn http(addr: SocketAddr, method: &str, path: &str) -> String {
        http_headers(addr, method, path, &[]).await
    }

    async fn http_headers(
        addr: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> String {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: browser\r\nConnection: close\r\n");
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
