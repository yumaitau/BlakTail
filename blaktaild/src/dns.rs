use crate::{Error, NodeState, OrgDnsSnapshot};
#[cfg(test)]
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, task::AbortHandle};

const SPLIT_FORWARD_TIMEOUT: Duration = Duration::from_millis(800);

const DNS_PORT: u16 = 53;
const DNS_HEADER_LEN: usize = 12;
const DNS_TTL_SECS: u32 = 30;
const MANAGED_MARKER: &str = "# Managed by blaktaild";
pub const MODE_MACOS_RESOLVER: &str = "macos-resolver";
pub const MODE_SYSTEMD_RESOLVED: &str = "systemd-resolved";
pub const MODE_RESOLVCONF: &str = "resolvconf";
pub const MODE_RESOLV_CONF: &str = "resolv-conf";

#[derive(Clone, Default)]
struct Records {
    domain: String,
    addresses: HashMap<String, Vec<IpAddr>>,
    split: Vec<(String, Vec<SocketAddr>)>,
}

enum DnsAction {
    Reply(Vec<u8>),
    Forward(Vec<SocketAddr>),
}

pub struct MagicDns {
    records: Arc<Mutex<Records>>,
    task: AbortHandle,
    bind_ip: IpAddr,
    listen_addr: SocketAddr,
    domain: String,
}

impl MagicDns {
    pub async fn spawn(state: &NodeState) -> Result<Self, Error> {
        let bind_ip = state_ip(state)?;
        let domain = dns_domain(&state.dns_name).ok_or_else(|| {
            Error::Message("coordinator returned an invalid MagicDNS name".into())
        })?;
        Self::spawn_at(SocketAddr::new(bind_ip, DNS_PORT), state, domain).await
    }

    async fn spawn_at(bind: SocketAddr, state: &NodeState, domain: String) -> Result<Self, Error> {
        let socket = UdpSocket::bind(bind).await?;
        let listen_addr = socket.local_addr()?;
        let bind_ip = listen_addr.ip();
        let records = Arc::new(Mutex::new(records_from_state(state, &domain)));
        let task_records = records.clone();
        let task = tokio::spawn(async move {
            let mut request = [0u8; 1_232];
            loop {
                let (length, source) = match socket.recv_from(&mut request).await {
                    Ok(received) => received,
                    Err(_) => return,
                };
                let query = request[..length].to_vec();
                let records = match task_records.lock() {
                    Ok(records) => records.clone(),
                    Err(_) => return,
                };
                match dns_action(&query, &records) {
                    Some(DnsAction::Reply(response)) => {
                        let _ = socket.send_to(&response, source).await;
                    }
                    Some(DnsAction::Forward(resolvers)) => {
                        if let Some(response) = forward_query(&query, &resolvers).await {
                            let _ = socket.send_to(&response, source).await;
                        }
                    }
                    None => {}
                }
            }
        });
        Ok(Self {
            records,
            task: task.abort_handle(),
            bind_ip,
            listen_addr,
            domain,
        })
    }

    pub fn matches(&self, state: &NodeState) -> bool {
        state_ip(state).ok() == Some(self.bind_ip)
            && dns_domain(&state.dns_name).as_deref() == Some(self.domain.as_str())
    }

    pub fn update(&self, state: &NodeState) {
        if let Ok(mut records) = self.records.lock() {
            *records = records_from_state(state, &self.domain);
        }
    }

    pub fn bind_ip(&self) -> IpAddr {
        self.bind_ip
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for MagicDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn dns_domain(dns_name: &str) -> Option<String> {
    let (_, domain) = dns_name.trim_end_matches('.').split_once('.')?;
    valid_domain(domain).then(|| domain.to_ascii_lowercase())
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.ends_with(".blaktail")
        && labels_are_safe(domain)
}

fn valid_published_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix.len() <= 253
        && suffix != "blaktail"
        && !suffix.ends_with(".blaktail")
        && labels_are_safe(suffix)
}

fn labels_are_safe(name: &str) -> bool {
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

pub fn organisation_dns_managed(state: &NodeState) -> bool {
    state.org_dns.as_ref().is_none_or(|dns| dns.managed)
}

pub fn published_resolver_suffixes(state: &NodeState) -> Vec<String> {
    if !organisation_dns_managed(state) {
        return Vec::new();
    }
    organisation_resolver_suffixes(state)
}

pub fn organisation_resolver_suffixes(state: &NodeState) -> Vec<String> {
    let Some(snapshot) = &state.org_dns else {
        return Vec::new();
    };
    let mut suffixes = Vec::new();
    let mut push = |value: &str| {
        let value = value.trim_end_matches('.').to_ascii_lowercase();
        if !valid_published_suffix(&value) || suffixes.iter().any(|existing| existing == &value) {
            return;
        }
        suffixes.push(value);
    };
    for domain in &snapshot.search_domains {
        push(domain);
    }
    for route in &snapshot.split {
        push(&route.suffix);
    }
    suffixes
}

fn state_ip(state: &NodeState) -> Result<IpAddr, Error> {
    let addresses = state
        .interface_addresses()
        .into_iter()
        .filter_map(|address| address.split('/').next()?.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
        .ok_or_else(|| Error::Message("assigned tailnet address is invalid".into()))
}

fn records_from_state(state: &NodeState, domain: &str) -> Records {
    let mut addresses = HashMap::new();
    for address in state.interface_addresses() {
        insert_record(&mut addresses, &state.dns_name, &address, domain);
    }
    for peer in &state.peers {
        for address in &peer.allowed_ips {
            insert_record(&mut addresses, &peer.dns_name, address, domain);
        }
    }
    let mut split = Vec::new();
    if let Some(snapshot) = &state.org_dns {
        if snapshot.managed {
            for record in &snapshot.records {
                insert_extra_record(&mut addresses, record);
            }
            split = split_from_snapshot(snapshot);
        }
    }
    Records {
        domain: domain.into(),
        addresses,
        split,
    }
}

fn split_from_snapshot(snapshot: &crate::OrgDnsSnapshot) -> Vec<(String, Vec<SocketAddr>)> {
    snapshot
        .split
        .iter()
        .filter_map(|route| {
            let suffix = route.suffix.trim_end_matches('.').to_ascii_lowercase();
            if !valid_published_suffix(&suffix) {
                return None;
            }
            let resolvers = route
                .resolvers
                .iter()
                .filter_map(|value| parse_resolver(value))
                .collect::<Vec<_>>();
            (!resolvers.is_empty()).then_some((suffix, resolvers))
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum DnsAdopt {
    Keep { reason: String },
    Take { clear_degraded: bool },
}

pub fn adopt_org_dns_snapshot(state: &mut NodeState, incoming: Option<OrgDnsSnapshot>) {
    let Some(next) = incoming else {
        return;
    };
    match decide_org_dns(state.org_dns.as_ref(), &next, || {
        probe_new_resolvers(state.org_dns.as_ref(), &next)
    }) {
        DnsAdopt::Keep { reason } => {
            tracing::warn!(%reason, "keeping last-known-good organisation DNS");
            state.dns_degraded = Some(reason);
        }
        DnsAdopt::Take { clear_degraded } => {
            state.org_dns = Some(next);
            if clear_degraded {
                state.dns_degraded = None;
            }
        }
    }
}

pub fn decide_org_dns(
    current: Option<&OrgDnsSnapshot>,
    next: &OrgDnsSnapshot,
    new_resolvers_ok: impl FnOnce() -> bool,
) -> DnsAdopt {
    if current.is_some_and(|value| value == next) {
        return DnsAdopt::Take {
            clear_degraded: false,
        };
    }
    if !next.managed {
        return DnsAdopt::Take {
            clear_degraded: true,
        };
    }
    let added = added_resolvers(current, next);
    if added.is_empty() || new_resolvers_ok() {
        return DnsAdopt::Take {
            clear_degraded: true,
        };
    }
    if let Some(previous) = current {
        return DnsAdopt::Keep {
            reason: format!(
                "kept DNS revision {} because new resolvers did not answer",
                previous.revision
            ),
        };
    }
    DnsAdopt::Take {
        clear_degraded: false,
    }
}

fn snapshot_resolvers(snapshot: &OrgDnsSnapshot) -> Vec<SocketAddr> {
    snapshot
        .split
        .iter()
        .flat_map(|route| route.resolvers.iter())
        .chain(snapshot.global_resolvers.iter())
        .filter_map(|value| parse_resolver(value))
        .collect()
}

fn added_resolvers(current: Option<&OrgDnsSnapshot>, next: &OrgDnsSnapshot) -> Vec<SocketAddr> {
    let previous = current
        .map(snapshot_resolvers)
        .unwrap_or_default()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    snapshot_resolvers(next)
        .into_iter()
        .filter(|resolver| !previous.contains(resolver))
        .collect()
}

fn probe_new_resolvers(current: Option<&OrgDnsSnapshot>, next: &OrgDnsSnapshot) -> bool {
    let added = added_resolvers(current, next);
    if added.is_empty() {
        return true;
    }
    let qname = next
        .records
        .first()
        .map(|record| record.name.as_str())
        .or_else(|| next.split.first().map(|route| route.suffix.as_str()))
        .unwrap_or(".");
    added
        .iter()
        .any(|resolver| probe_resolver(*resolver, qname))
}

fn probe_resolver(resolver: SocketAddr, name: &str) -> bool {
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = StdUdpSocket::bind(bind) else {
        return false;
    };
    if socket
        .set_read_timeout(Some(Duration::from_millis(800)))
        .is_err()
        || socket.connect(resolver).is_err()
    {
        return false;
    }
    let query = encode_probe_query(name);
    if socket.send(&query).is_err() {
        return false;
    }
    let mut buffer = [0u8; 512];
    socket.recv(&mut buffer).is_ok()
}

fn encode_probe_query(name: &str) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        query.push(u8::try_from(label.len()).unwrap_or(0));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn parse_resolver(value: &str) -> Option<SocketAddr> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return (address.port() != 0).then_some(address);
    }
    Some(SocketAddr::new(value.parse().ok()?, 53))
}

fn split_resolvers(name: &str, records: &Records) -> Option<Vec<SocketAddr>> {
    if name == "blaktail" || name.ends_with(".blaktail") {
        return None;
    }
    records
        .split
        .iter()
        .filter(|(suffix, _)| name == suffix.as_str() || name.ends_with(&format!(".{suffix}")))
        .max_by_key(|(suffix, _)| suffix.len())
        .map(|(_, resolvers)| resolvers.clone())
        .filter(|resolvers| !resolvers.is_empty())
}

async fn forward_query(query: &[u8], resolvers: &[SocketAddr]) -> Option<Vec<u8>> {
    for resolver in resolvers {
        let bind = if resolver.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let Ok(upstream) = UdpSocket::bind(bind).await else {
            continue;
        };
        if upstream.send_to(query, *resolver).await.is_err() {
            continue;
        }
        let mut response = [0u8; 1_232];
        if let Ok(Ok((length, _))) =
            tokio::time::timeout(SPLIT_FORWARD_TIMEOUT, upstream.recv_from(&mut response)).await
        {
            return Some(response[..length].to_vec());
        }
    }
    None
}

fn insert_record(
    records: &mut HashMap<String, Vec<IpAddr>>,
    name: &str,
    address: &str,
    domain: &str,
) {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !name.ends_with(&format!(".{domain}")) {
        return;
    }
    let Some((address, prefix)) = address.split_once('/') else {
        return;
    };
    let Some(address) = address.parse::<IpAddr>().ok() else {
        return;
    };
    let host_prefix = if address.is_ipv4() { "32" } else { "128" };
    if prefix != host_prefix {
        return;
    }
    let mut insert = |key: String| {
        let values = records.entry(key).or_default();
        if !values.contains(&address) {
            values.push(address);
        }
    };
    if let Some((label, _)) = name.split_once('.') {
        insert(label.into());
    }
    insert(name);
}

fn insert_extra_record(records: &mut HashMap<String, Vec<IpAddr>>, record: &crate::OrgDnsRecord) {
    let name = record.name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.ends_with(".blaktail") {
        return;
    }
    let Ok(address) = record.value.parse::<IpAddr>() else {
        return;
    };
    let expected = match record.record_type.to_ascii_uppercase().as_str() {
        "A" => address.is_ipv4(),
        "AAAA" => address.is_ipv6(),
        _ => return,
    };
    if !expected {
        return;
    }
    let values = records.entry(name).or_default();
    if !values.contains(&address) {
        values.push(address);
    }
}

fn address_for_query(addresses: &[IpAddr], query_type: u16) -> Option<IpAddr> {
    addresses.iter().copied().find(|address| {
        matches!(
            (query_type, address),
            (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
        )
    })
}

fn dns_action(query: &[u8], records: &Records) -> Option<DnsAction> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let questions = u16::from_be_bytes([query[4], query[5]]);
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || questions != 1 {
        return error_response(query, 1).map(DnsAction::Reply);
    }
    let (name, name_end) = parse_name(query, DNS_HEADER_LEN)?;
    if name_end + 4 > query.len() {
        return error_response(query, 1).map(DnsAction::Reply);
    }
    let name = name.to_ascii_lowercase();
    let in_magic = magic_name(&name, &records.domain);
    if !in_magic && !records.addresses.contains_key(&name) {
        if let Some(resolvers) = split_resolvers(&name, records) {
            return Some(DnsAction::Forward(resolvers));
        }
    }
    answer(query, records).map(DnsAction::Reply)
}

fn magic_name(name: &str, domain: &str) -> bool {
    !name.contains('.') || name == domain || name.ends_with(&format!(".{domain}"))
}

fn answer(query: &[u8], records: &Records) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let questions = u16::from_be_bytes([query[4], query[5]]);
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || questions != 1 {
        return error_response(query, 1);
    }
    let (name, name_end) = parse_name(query, DNS_HEADER_LEN)?;
    if name_end + 4 > query.len() {
        return error_response(query, 1);
    }
    let question_end = name_end + 4;
    let query_type = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
    let query_class = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
    let name = name.to_ascii_lowercase();
    let addresses = records.addresses.get(&name);
    let in_magic = magic_name(&name, &records.domain);
    let in_domain = in_magic || addresses.is_some();
    let address = addresses.and_then(|addresses| address_for_query(addresses, query_type));
    let response_code = if !in_domain {
        5 // REFUSED: this authoritative stub never forwards public DNS.
    } else if addresses.is_none() {
        3 // NXDOMAIN prevents a private name from leaking to another resolver.
    } else {
        0
    };
    let has_answer = response_code == 0 && query_class == 1 && address.is_some();
    let mut response = Vec::with_capacity(question_end + 28);
    response.extend_from_slice(&query[..2]);
    let response_flags = 0x8000 | 0x0400 | (flags & 0x0100) | response_code;
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(has_answer as u16).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]);
    if let Some(address) = address.filter(|_| has_answer) {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&DNS_TTL_SECS.to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
        }
    }
    Some(response)
}

fn error_response(query: &[u8], response_code: u16) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let mut response = Vec::with_capacity(DNS_HEADER_LEN);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&(0x8000 | (flags & 0x0100) | response_code).to_be_bytes());
    response.extend_from_slice(&[0; 8]);
    Some(response)
}

fn parse_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut encoded_len = 0usize;
    loop {
        let length = *packet.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > packet.len() {
            return None;
        }
        encoded_len += length + 1;
        if encoded_len > 255 {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + length]).ok()?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        labels.push(label);
        offset += length;
    }
    Some((labels.join("."), offset))
}

#[cfg(any(not(target_os = "macos"), test))]
fn managed_resolv_conf(
    original: &str,
    dns_ip: IpAddr,
    domain: &str,
    extra_search: &[String],
) -> String {
    let search = original
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("search ")
                .or_else(|| line.strip_prefix("domain "))
        })
        .unwrap_or("");
    let mut suffixes = Vec::new();
    let mut push = |suffix: &str| {
        let suffix = suffix.trim();
        if suffix.is_empty()
            || suffix == domain
            || suffixes.iter().any(|existing| existing == suffix)
        {
            return;
        }
        suffixes.push(suffix.to_owned());
    };
    for suffix in extra_search {
        push(suffix);
    }
    for suffix in search.split_whitespace() {
        push(suffix);
    }
    suffixes.truncate(5);
    let mut content = format!("{MANAGED_MARKER}\nsearch {domain}");
    for suffix in &suffixes {
        content.push(' ');
        content.push_str(suffix);
    }
    content.push_str(&format!("\nnameserver {dns_ip}\n"));
    for line in original.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("search ") && !trimmed.starts_with("domain ") {
            content.push_str(line);
            content.push('\n');
        }
    }
    content
}

pub fn configure_system_dns(
    state_dir: &Path,
    interface: &str,
    dns_ip: IpAddr,
    domain: &str,
    extra_suffixes: &[String],
) -> Result<String, Error> {
    if !valid_domain(domain) {
        return Err(Error::Message("invalid MagicDNS search domain".into()));
    }
    let extras = extra_suffixes
        .iter()
        .map(|suffix| suffix.trim_end_matches('.').to_ascii_lowercase())
        .filter(|suffix| valid_published_suffix(suffix))
        .collect::<Vec<_>>();
    configure_platform_dns(state_dir, interface, dns_ip, domain, &extras)
}

pub fn remove_system_dns(
    state_dir: &Path,
    interface: &str,
    domain: &str,
    extra_suffixes: &[String],
    mode: Option<&str>,
) -> Result<(), Error> {
    remove_platform_dns(state_dir, interface, domain, extra_suffixes, mode)
}

#[cfg(target_os = "macos")]
fn configure_platform_dns(
    _state_dir: &Path,
    _interface: &str,
    dns_ip: IpAddr,
    domain: &str,
    extra_suffixes: &[String],
) -> Result<String, Error> {
    let directory = Path::new("/etc/resolver");
    fs::create_dir_all(directory)?;
    let search = std::iter::once(domain)
        .chain(extra_suffixes.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let desired = format!(
        "{MANAGED_MARKER}\nnameserver {dns_ip}\nport {DNS_PORT}\nsearch {search}\nsearch_order 1\ntimeout 1\n"
    );
    let path = directory.join(domain);
    refuse_unmanaged_file(&path)?;
    write_atomic(&path, desired.as_bytes(), 0o644)?;
    let tld = directory.join("blaktail");
    refuse_unmanaged_file(&tld)?;
    write_atomic(&tld, desired.as_bytes(), 0o644)?;
    for suffix in extra_suffixes {
        let extra = directory.join(suffix);
        refuse_unmanaged_file(&extra)?;
        write_atomic(&extra, desired.as_bytes(), 0o644)?;
    }
    let _ = configure_macos_search(dns_ip, domain, extra_suffixes);
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name == domain
                || name == "blaktail"
                || extra_suffixes.iter().any(|suffix| suffix == name)
            {
                continue;
            }
            let path = entry.path();
            if fs::read_to_string(&path)
                .ok()
                .is_some_and(|content| content.starts_with(MANAGED_MARKER))
            {
                let _ = remove_managed_file(&path);
            }
        }
    }
    Ok(MODE_MACOS_RESOLVER.into())
}

#[cfg(target_os = "macos")]
fn remove_platform_dns(
    _state_dir: &Path,
    _interface: &str,
    domain: &str,
    extra_suffixes: &[String],
    mode: Option<&str>,
) -> Result<(), Error> {
    if mode.is_some() && mode != Some(MODE_MACOS_RESOLVER) {
        return Ok(());
    }
    if valid_domain(domain) {
        remove_managed_file(&Path::new("/etc/resolver").join(domain))?;
    }
    remove_managed_file(Path::new("/etc/resolver/blaktail"))?;
    for suffix in extra_suffixes {
        if valid_published_suffix(suffix) {
            remove_managed_file(&Path::new("/etc/resolver").join(suffix))?;
        }
    }
    let _ = remove_macos_search();
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_macos_search(
    dns_ip: IpAddr,
    domain: &str,
    extra_suffixes: &[String],
) -> Result<(), Error> {
    let search = std::iter::once(domain)
        .chain(extra_suffixes.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "d.init\nd.add ServerAddresses * {dns_ip}\nd.add SearchDomains * {search}\nd.add SupplementalMatchDomains * {search}\nset State:/Network/Service/BlakTail/DNS\n"
    );
    run_scutil(&script)
}

#[cfg(target_os = "macos")]
fn remove_macos_search() -> Result<(), Error> {
    run_scutil("remove State:/Network/Service/BlakTail/DNS\n")
}

#[cfg(target_os = "macos")]
fn run_scutil(script: &str) -> Result<(), Error> {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::Message(format!("could not execute scutil: {error}")))?;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = write!(stdin, "{script}");
    }
    let status = child
        .wait()
        .map_err(|error| Error::Message(format!("scutil failed: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Message("scutil exited unsuccessfully".into()))
    }
}

#[cfg(not(target_os = "macos"))]
fn configure_platform_dns(
    state_dir: &Path,
    interface: &str,
    dns_ip: IpAddr,
    domain: &str,
    extra_suffixes: &[String],
) -> Result<String, Error> {
    if run_quiet("resolvectl", &["dns", interface, &dns_ip.to_string()]).is_ok() {
        let mut domains = vec![domain.to_owned(), format!("~{domain}")];
        for suffix in extra_suffixes {
            domains.push(suffix.clone());
            domains.push(format!("~{suffix}"));
        }
        let mut args = vec!["domain", interface];
        args.extend(domains.iter().map(String::as_str));
        if run_quiet("resolvectl", &args).is_ok() {
            return Ok(MODE_SYSTEMD_RESOLVED.into());
        }
        let _ = run_quiet("resolvectl", &["revert", interface]);
    }

    let search = std::iter::once(domain)
        .chain(extra_suffixes.iter().map(String::as_str))
        .take(6)
        .collect::<Vec<_>>()
        .join(" ");
    let mut child = Command::new("resolvconf")
        .args(["-a", &format!("{interface}.blaktail")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(ref mut child) = child {
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = write!(stdin, "nameserver {dns_ip}\nsearch {search}\n");
        }
        if child.wait().is_ok_and(|status| status.success()) {
            return Ok(MODE_RESOLVCONF.into());
        }
    }

    configure_resolv_conf(state_dir, dns_ip, domain, extra_suffixes)?;
    Ok(MODE_RESOLV_CONF.into())
}

#[cfg(not(target_os = "macos"))]
fn remove_platform_dns(
    state_dir: &Path,
    interface: &str,
    _domain: &str,
    _extra_suffixes: &[String],
    mode: Option<&str>,
) -> Result<(), Error> {
    match mode {
        Some(MODE_SYSTEMD_RESOLVED) => run_quiet("resolvectl", &["revert", interface]),
        Some(MODE_RESOLVCONF) => run_quiet("resolvconf", &["-d", &format!("{interface}.blaktail")]),
        Some(MODE_RESOLV_CONF) => restore_resolv_conf(state_dir),
        _ => Ok(()),
    }
}

#[cfg(not(target_os = "macos"))]
fn configure_resolv_conf(
    state_dir: &Path,
    dns_ip: IpAddr,
    domain: &str,
    extra_search: &[String],
) -> Result<(), Error> {
    let path = Path::new("/etc/resolv.conf");
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::Message(
            "resolvectl and resolvconf failed; refusing to replace symlinked /etc/resolv.conf"
                .into(),
        ));
    }
    let backup = resolv_backup(state_dir);
    let current = fs::read_to_string(path)?;
    if backup.exists() && !current.starts_with(MANAGED_MARKER) {
        return Err(Error::Message(format!(
            "/etc/resolv.conf changed after BlakTail configured it; preserved backup at {}",
            backup.display()
        )));
    }
    if !backup.exists() && current.starts_with(MANAGED_MARKER) {
        return Err(Error::Message(
            "managed /etc/resolv.conf exists but its BlakTail backup is missing".into(),
        ));
    }
    if !backup.exists() {
        fs::copy(path, &backup)?;
    }
    let original = fs::read_to_string(&backup)?;
    let content = managed_resolv_conf(&original, dns_ip, domain, extra_search);
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    write_atomic(path, content.as_bytes(), mode)
}

#[cfg(not(target_os = "macos"))]
fn restore_resolv_conf(state_dir: &Path) -> Result<(), Error> {
    let path = Path::new("/etc/resolv.conf");
    let backup = resolv_backup(state_dir);
    if !backup.exists() {
        return Ok(());
    }
    if !fs::read_to_string(path)?.starts_with(MANAGED_MARKER) {
        return Err(Error::Message(format!(
            "/etc/resolv.conf changed after BlakTail configured it; preserved backup at {}",
            backup.display()
        )));
    }
    fs::copy(&backup, path)?;
    fs::remove_file(backup)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn resolv_backup(state_dir: &Path) -> PathBuf {
    state_dir.join("resolv.conf.before-blaktail")
}

#[cfg(not(target_os = "macos"))]
fn run_quiet(program: &str, args: &[&str]) -> Result<(), Error> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| Error::Message(format!("could not execute {program}: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Message(format!("{program} exited unsuccessfully")))
    }
}

#[cfg(target_os = "macos")]
fn refuse_unmanaged_file(path: &Path) -> Result<(), Error> {
    if path.exists() && !fs::read_to_string(path)?.starts_with(MANAGED_MARKER) {
        return Err(Error::Message(format!(
            "refusing to replace unmanaged resolver file {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_managed_file(path: &Path) -> Result<(), Error> {
    if !path.exists() {
        return Ok(());
    }
    if !fs::read_to_string(path)?.starts_with(MANAGED_MARKER) {
        return Err(Error::Message(format!(
            "refusing to remove unmanaged resolver file {}",
            path.display()
        )));
    }
    fs::remove_file(path)?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let temporary = PathBuf::from(format!("{}.blaktail.tmp", path.display()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Peer;
    use uuid::Uuid;

    fn state() -> NodeState {
        NodeState {
            node_id: Uuid::from_u128(1),
            node_token: "secret".into(),
            coord: "http://localhost:3000".into(),
            interface: "blaktail0".into(),
            assigned_ip: "100.64.0.1/32".into(),
            assigned_ips: vec!["100.64.0.1/32".into(), "fd12:3456:789a:bcde::1/128".into()],
            dns_name: "self.12345678.blaktail".into(),
            credential_expires_at: 1,
            advertised_routes: vec![],
            exit_node: None,
            exit_node_active: false,
            router_previous_ipv4_forward: None,
            peers: vec![Peer {
                id: Uuid::from_u128(2),
                name: "peer".into(),
                wg_public_key: "key".into(),
                endpoint: None,
                allowed_ips: vec!["100.64.0.2/32".into(), "fd12:3456:789a:bcde::2/128".into()],
                dns_name: "peer.12345678.blaktail".into(),
                tags: vec![],
                relay_endpoint: None,
                ingress: None,
            }],
            relays: vec![],
            relay_token: String::new(),
            relay_expires_at: 0,
            relay_endpoint: None,
            relay_endpoint_reported_at: 0,
            dns_mode: None,
            org_dns: None,
            dns_degraded: None,
            control_revision: 0,
            published_shares: vec![],
            ssh_users_enforced: false,
        }
    }

    fn query(name: &str, query_type: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&query_type.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn answers_fqdn_and_short_a_records_without_forwarding_public_dns() {
        let state = state();
        let records = records_from_state(&state, "12345678.blaktail");
        for name in ["peer.12345678.blaktail", "peer"] {
            let request = query(name, 1);
            let response = answer(&request, &records).unwrap();
            assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
            assert_eq!(response.len(), request.len() + 16);
            assert_eq!(
                u16::from_be_bytes([response[request.len() + 10], response[request.len() + 11]]),
                4
            );
            assert_eq!(&response[response.len() - 4..], &[100, 64, 0, 2]);
        }
        let private_missing = answer(&query("missing.12345678.blaktail", 1), &records).unwrap();
        assert_eq!(private_missing[3] & 0x0f, 3);
        let public = answer(&query("example.com", 1), &records).unwrap();
        assert_eq!(public[3] & 0x0f, 5);
    }

    #[test]
    fn answers_aaaa_for_dual_stack_peers() {
        let state = state();
        assert_eq!(
            state_ip(&state).unwrap(),
            "100.64.0.1".parse::<IpAddr>().unwrap()
        );
        let records = records_from_state(&state, "12345678.blaktail");
        let request = query("peer.12345678.blaktail", 28);
        let response = answer(&request, &records).unwrap();
        assert_eq!(response[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(response.len(), request.len() + 28);
        assert_eq!(
            u16::from_be_bytes([response[request.len() + 10], response[request.len() + 11]]),
            16
        );
        assert_eq!(
            &response[response.len() - 16..],
            &"fd12:3456:789a:bcde::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[tokio::test]
    async fn udp_stub_serves_live_record_updates() {
        let mut state = state();
        let dns = MagicDns::spawn_at(
            "127.0.0.1:0".parse().unwrap(),
            &state,
            "12345678.blaktail".into(),
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut response = [0u8; 512];
        client
            .send_to(&query("peer.12345678.blaktail", 1), dns.listen_addr())
            .await
            .unwrap();
        let length = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[length - 4..length], &[100, 64, 0, 2]);

        state.peers[0].allowed_ips[0] = "100.64.0.9/32".into();
        dns.update(&state);
        client
            .send_to(&query("peer", 1), dns.listen_addr())
            .await
            .unwrap();
        let length = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[length - 4..length], &[100, 64, 0, 9]);
        dns.stop();
    }

    #[tokio::test]
    async fn udp_stub_serves_aaaa_over_ipv6_transport() {
        let state = state();
        let dns = MagicDns::spawn_at(
            "[::1]:0".parse().unwrap(),
            &state,
            "12345678.blaktail".into(),
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut response = [0u8; 512];
        client
            .send_to(&query("peer.12345678.blaktail", 28), dns.listen_addr())
            .await
            .unwrap();
        let length = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            &response[length - 16..length],
            &"fd12:3456:789a:bcde::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        dns.stop();
    }

    #[test]
    fn answers_published_extra_records_without_forwarding_public_dns() {
        let mut state = state();
        state.org_dns = Some(crate::OrgDnsSnapshot {
            revision: 3,
            managed: true,
            records: vec![
                crate::OrgDnsRecord {
                    name: "wiki.internal.example".into(),
                    record_type: "A".into(),
                    value: "10.0.0.10".into(),
                },
                crate::OrgDnsRecord {
                    name: "wiki.internal.example".into(),
                    record_type: "AAAA".into(),
                    value: "fd12:3456:789a:bcde::10".into(),
                },
            ],
            search_domains: vec!["internal.example".into()],
            split: vec![],
            global_resolvers: vec![],
        });
        let records = records_from_state(&state, "12345678.blaktail");
        let a = answer(&query("wiki.internal.example", 1), &records).unwrap();
        assert_eq!(a[3] & 0x0f, 0);
        assert_eq!(&a[a.len() - 4..], &[10, 0, 0, 10]);
        let aaaa = answer(&query("wiki.internal.example", 28), &records).unwrap();
        assert_eq!(aaaa[3] & 0x0f, 0);
        assert_eq!(
            &aaaa[aaaa.len() - 16..],
            &"fd12:3456:789a:bcde::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        let peer = answer(&query("peer.12345678.blaktail", 1), &records).unwrap();
        assert_eq!(&peer[peer.len() - 4..], &[100, 64, 0, 2]);
        let short_extra = answer(&query("wiki", 1), &records).unwrap();
        assert_eq!(short_extra[3] & 0x0f, 3);
        let missing_extra = answer(&query("missing.internal.example", 1), &records).unwrap();
        assert_eq!(missing_extra[3] & 0x0f, 5);
        let public = answer(&query("example.com", 1), &records).unwrap();
        assert_eq!(public[3] & 0x0f, 5);
        let private_missing = answer(&query("missing.12345678.blaktail", 1), &records).unwrap();
        assert_eq!(private_missing[3] & 0x0f, 3);
    }

    #[test]
    fn domain_is_scoped_and_path_safe() {
        assert_eq!(
            dns_domain("node.12345678.blaktail"),
            Some("12345678.blaktail".into())
        );
        assert_eq!(dns_domain("node.example.com"), None);
        assert_eq!(dns_domain("node.../etc.blaktail"), None);
    }

    #[test]
    fn resolv_conf_fallback_preserves_upstream_servers_and_adds_search_first() {
        let original = "search office.example\nnameserver 192.0.2.53\noptions edns0\n";
        let managed = managed_resolv_conf(
            original,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            "12345678.blaktail",
            &[],
        );
        assert!(managed.starts_with(
            "# Managed by blaktaild\nsearch 12345678.blaktail office.example\nnameserver 100.64.0.1\n"
        ));
        assert!(managed.contains("nameserver 192.0.2.53\n"));
        assert!(managed.contains("options edns0\n"));
    }

    #[test]
    fn resolv_conf_prepends_published_search_domains() {
        let original = "search office.example leftover.example\nnameserver 192.0.2.53\n";
        let managed = managed_resolv_conf(
            original,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            "12345678.blaktail",
            &["internal.example".into(), "12345678.blaktail".into()],
        );
        assert!(managed.starts_with(
            "# Managed by blaktaild\nsearch 12345678.blaktail internal.example office.example leftover.example\nnameserver 100.64.0.1\n"
        ));
    }

    fn snapshot_with_split() -> crate::OrgDnsSnapshot {
        crate::OrgDnsSnapshot {
            revision: 4,
            managed: true,
            records: vec![crate::OrgDnsRecord {
                name: "wiki.internal.example".into(),
                record_type: "A".into(),
                value: "10.0.0.10".into(),
            }],
            search_domains: vec!["internal.example".into()],
            split: vec![crate::OrgDnsSplit {
                suffix: "internal.example".into(),
                resolvers: vec!["127.0.0.1:53535".into()],
            }],
            global_resolvers: vec![],
        }
    }

    #[test]
    fn split_suffix_without_local_record_forwards_and_never_forwards_blaktail() {
        let mut state = state();
        state.org_dns = Some(snapshot_with_split());
        let records = records_from_state(&state, "12345678.blaktail");
        assert!(matches!(
            dns_action(&query("missing.internal.example", 1), &records),
            Some(DnsAction::Forward(resolvers))
                if resolvers == vec!["127.0.0.1:53535".parse().unwrap()]
        ));
        assert!(matches!(
            dns_action(&query("wiki.internal.example", 1), &records),
            Some(DnsAction::Reply(response)) if response[3] & 0x0f == 0
        ));
        assert!(matches!(
            dns_action(&query("example.com", 1), &records),
            Some(DnsAction::Reply(response)) if response[3] & 0x0f == 5
        ));
        assert!(matches!(
            dns_action(&query("missing.12345678.blaktail", 1), &records),
            Some(DnsAction::Reply(response)) if response[3] & 0x0f == 3
        ));
        assert_eq!(
            published_resolver_suffixes(&state),
            vec!["internal.example".to_string()]
        );
    }

    #[tokio::test]
    async fn udp_stub_forwards_split_names_to_published_resolvers() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut packet = [0u8; 1_232];
            loop {
                let Ok((length, source)) = upstream.recv_from(&mut packet).await else {
                    return;
                };
                let mut records = Records::default();
                records.addresses.insert(
                    "split.internal.example".into(),
                    vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))],
                );
                if let Some(response) = answer(&packet[..length], &records) {
                    let _ = upstream.send_to(&response, source).await;
                }
            }
        });

        let mut state = state();
        state.org_dns = Some(crate::OrgDnsSnapshot {
            revision: 5,
            managed: true,
            records: vec![],
            search_domains: vec!["internal.example".into()],
            split: vec![crate::OrgDnsSplit {
                suffix: "internal.example".into(),
                resolvers: vec![upstream_addr.to_string()],
            }],
            global_resolvers: vec![],
        });
        let dns = MagicDns::spawn_at(
            "127.0.0.1:0".parse().unwrap(),
            &state,
            "12345678.blaktail".into(),
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut response = [0u8; 512];
        client
            .send_to(&query("split.internal.example", 1), dns.listen_addr())
            .await
            .unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[length - 4..length], &[10, 9, 8, 7]);
        client
            .send_to(&query("example.com", 1), dns.listen_addr())
            .await
            .unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response[3] & 0x0f, 5);
        assert_eq!(length, query("example.com", 1).len());
        dns.stop();
    }

    fn snapshot(revision: i64, resolvers: &[&str]) -> crate::OrgDnsSnapshot {
        crate::OrgDnsSnapshot {
            revision,
            managed: true,
            records: vec![crate::OrgDnsRecord {
                name: "wiki.internal.example".into(),
                record_type: "A".into(),
                value: "10.0.0.10".into(),
            }],
            search_domains: vec!["internal.example".into()],
            split: vec![crate::OrgDnsSplit {
                suffix: "internal.example".into(),
                resolvers: resolvers.iter().map(|value| (*value).to_string()).collect(),
            }],
            global_resolvers: vec![],
        }
    }

    #[test]
    fn decide_keeps_last_known_good_when_new_resolvers_fail() {
        let current = snapshot(4, &["10.0.0.53"]);
        let next = snapshot(5, &["203.0.113.1"]);
        assert_eq!(
            decide_org_dns(Some(&current), &next, || false),
            DnsAdopt::Keep {
                reason: "kept DNS revision 4 because new resolvers did not answer".into(),
            }
        );
    }

    #[test]
    fn decide_takes_when_new_resolvers_answer() {
        let current = snapshot(4, &["10.0.0.53"]);
        let next = snapshot(5, &["10.0.0.54"]);
        assert_eq!(
            decide_org_dns(Some(&current), &next, || true),
            DnsAdopt::Take {
                clear_degraded: true
            }
        );
    }

    #[test]
    fn decide_takes_record_only_updates_without_probing() {
        let current = snapshot(4, &["10.0.0.53"]);
        let mut next = current.clone();
        next.revision = 5;
        next.records[0].value = "10.0.0.11".into();
        assert_eq!(
            decide_org_dns(Some(&current), &next, || panic!("must not probe")),
            DnsAdopt::Take {
                clear_degraded: true
            }
        );
    }

    #[test]
    fn decide_adopts_first_snapshot_even_when_resolvers_are_dead() {
        let next = snapshot(1, &["203.0.113.1"]);
        assert_eq!(
            decide_org_dns(None, &next, || false),
            DnsAdopt::Take {
                clear_degraded: false
            }
        );
    }

    #[test]
    fn adopt_keeps_previous_snapshot_and_sets_degraded() {
        let mut state = state();
        state.org_dns = Some(snapshot(4, &["10.0.0.53"]));
        adopt_org_dns_snapshot(&mut state, Some(snapshot(5, &["203.0.113.1"])));
        assert_eq!(state.org_dns.as_ref().map(|dns| dns.revision), Some(4));
        assert!(state
            .dns_degraded
            .as_deref()
            .is_some_and(|reason| reason.contains("revision 4")));
    }

    #[test]
    fn decide_takes_unmanaged_snapshot_without_probing() {
        let current = snapshot(4, &["10.0.0.53"]);
        let mut next = snapshot(5, &["203.0.113.1"]);
        next.managed = false;
        assert_eq!(
            decide_org_dns(Some(&current), &next, || panic!("must not probe")),
            DnsAdopt::Take {
                clear_degraded: true
            }
        );
    }

    #[test]
    fn unmanaged_snapshot_drops_extras_and_keeps_peer_names() {
        let mut state = state();
        state.org_dns = Some(crate::OrgDnsSnapshot {
            revision: 6,
            managed: false,
            records: vec![crate::OrgDnsRecord {
                name: "wiki.internal.example".into(),
                record_type: "A".into(),
                value: "10.0.0.10".into(),
            }],
            search_domains: vec!["internal.example".into()],
            split: vec![crate::OrgDnsSplit {
                suffix: "internal.example".into(),
                resolvers: vec!["10.0.0.53".into()],
            }],
            global_resolvers: vec![],
        });
        let records = records_from_state(&state, "12345678.blaktail");
        let extra = answer(&query("wiki.internal.example", 1), &records).unwrap();
        assert_eq!(extra[3] & 0x0f, 5);
        let peer = answer(&query("peer.12345678.blaktail", 1), &records).unwrap();
        assert_eq!(&peer[peer.len() - 4..], &[100, 64, 0, 2]);
        assert!(published_resolver_suffixes(&state).is_empty());
        assert_eq!(
            organisation_resolver_suffixes(&state),
            vec!["internal.example".to_string()]
        );
        assert!(!organisation_dns_managed(&state));
    }
}
