use crate::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DEFAULT_DNS_JSON: &str =
    r#"{"managed":true,"global_resolvers":[],"split":[],"search_domains":[],"records":[]}"#;
const MAX_GLOBAL_RESOLVERS: usize = 8;
const MAX_SPLIT_ROUTES: usize = 32;
const MAX_RESOLVERS_PER_SPLIT: usize = 4;
const MAX_SEARCH_DOMAINS: usize = 6;
const MAX_RECORDS: usize = 64;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAMESERVER_GROUPS: usize = 16;
const MAX_GROUP_NAME_LEN: usize = 64;
const MAX_MATCH_DOMAINS: usize = 16;
const MAX_ZONES: usize = 16;
const MAX_ZONE_RECORDS: usize = 256;
const MAX_TXT_LEN: usize = 1024;
const MAX_CNAME_CHAIN: usize = 8;
pub const MIN_TTL: u32 = 30;
pub const MAX_TTL: u32 = 86_400;
pub const DEFAULT_TTL: u32 = 300;
pub const DEVICE_TAGS: &[&str] = &["office", "ranger", "store"];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgDnsSettings {
    #[serde(default = "default_managed")]
    pub managed: bool,
    #[serde(default)]
    pub global_resolvers: Vec<String>,
    #[serde(default)]
    pub split: Vec<SplitDnsRoute>,
    #[serde(default)]
    pub search_domains: Vec<String>,
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    /// Added after the first DNS release; omitted when empty so legacy
    /// documents round-trip unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameserver_groups: Vec<NameserverGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<DnsZone>,
}

fn default_managed() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

/// Ordered resolvers for a set of match domains, assigned to every device or
/// to devices carrying one of `tags`. Groups never replace a device's default
/// resolver, so at least one match domain is required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameserverGroup {
    pub name: String,
    pub resolvers: Vec<String>,
    pub match_domains: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub all_devices: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl NameserverGroup {
    pub fn applies_to(&self, device_tags: &[String]) -> bool {
        self.enabled && (self.all_devices || self.tags.iter().any(|tag| device_tags.contains(tag)))
    }
}

/// A zone the agent stub answers authoritatively from published records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsZone {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub records: Vec<ZoneRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: ZoneRecordType,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ZoneRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
}

impl ZoneRecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Txt => "TXT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitDnsRoute {
    pub suffix: String,
    pub resolvers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgDnsAgentView {
    pub revision: i64,
    pub managed: bool,
    pub magic_dns_suffix: String,
    pub global_resolvers: Vec<String>,
    pub split: Vec<SplitDnsRoute>,
    pub search_domains: Vec<String>,
    pub records: Vec<DnsRecord>,
    /// Full zone data for agents that understand it. Older agents ignore this
    /// key and use `records` plus the empty-resolver `split` entries that
    /// route each zone to their local stub.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<AgentZone>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentZone {
    pub name: String,
    pub records: Vec<ZoneRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRoutePreview {
    pub name: String,
    pub split_suffix: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgDnsResponse {
    pub revision: i64,
    pub etag: String,
    pub has_previous: bool,
    pub magic_dns_suffix: String,
    pub dns: OrgDnsSettings,
    #[serde(default)]
    pub record_preview: Vec<DnsRoutePreview>,
    #[serde(default)]
    pub applied: i64,
    #[serde(default)]
    pub enrolled: i64,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsCheckReport {
    pub managed: bool,
    pub global_resolvers: usize,
    pub split: usize,
    pub search_domains: usize,
    pub records: usize,
    pub nameserver_groups: usize,
    pub zones: usize,
    pub warnings: Vec<String>,
}

pub fn check_dns_document(document: &str) -> Result<DnsCheckReport, String> {
    let settings: OrgDnsSettings =
        serde_json::from_str(document).map_err(|error| error.to_string())?;
    let settings = settings.canonicalise().map_err(|error| error.to_string())?;
    Ok(DnsCheckReport {
        managed: settings.managed,
        global_resolvers: settings.global_resolvers.len(),
        split: settings.split.len(),
        search_domains: settings.search_domains.len(),
        records: settings.records.len(),
        nameserver_groups: settings.nameserver_groups.len(),
        zones: settings.zones.len(),
        warnings: settings.warnings(),
    })
}

pub fn default_settings() -> OrgDnsSettings {
    serde_json::from_str(DEFAULT_DNS_JSON).expect("default DNS JSON is valid")
}

pub fn organisation_magic_dns_suffix(org_id: &str) -> String {
    let prefix: String = org_id
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(8)
        .collect();
    let prefix = if prefix.len() == 8 {
        prefix
    } else {
        crate::hash(org_id)[..8].into()
    };
    format!("{prefix}.blaktail")
}

impl OrgDnsSettings {
    pub fn canonicalise(self) -> Result<Self, ApiError> {
        if self.global_resolvers.len() > MAX_GLOBAL_RESOLVERS {
            return Err(ApiError::BadRequest(format!(
                "global resolvers are limited to {MAX_GLOBAL_RESOLVERS}"
            )));
        }
        if self.split.len() > MAX_SPLIT_ROUTES {
            return Err(ApiError::BadRequest(format!(
                "split DNS routes are limited to {MAX_SPLIT_ROUTES}"
            )));
        }
        if self.search_domains.len() > MAX_SEARCH_DOMAINS {
            return Err(ApiError::BadRequest(format!(
                "search domains are limited to {MAX_SEARCH_DOMAINS}"
            )));
        }
        if self.records.len() > MAX_RECORDS {
            return Err(ApiError::BadRequest(format!(
                "extra records are limited to {MAX_RECORDS}"
            )));
        }

        let mut canonical = OrgDnsSettings {
            managed: self.managed,
            global_resolvers: self
                .global_resolvers
                .iter()
                .map(|resolver| parse_resolver(resolver))
                .collect::<Result<Vec<_>, _>>()?,
            split: Vec::new(),
            search_domains: Vec::new(),
            records: Vec::new(),
            nameserver_groups: Vec::new(),
            zones: Vec::new(),
        };
        let mut seen_suffixes = BTreeSet::new();
        canonical.split = self
            .split
            .iter()
            .map(|route| {
                if route.resolvers.is_empty() {
                    return Err(ApiError::BadRequest(format!(
                        "split suffix {} must list at least one resolver",
                        route.suffix
                    )));
                }
                if route.resolvers.len() > MAX_RESOLVERS_PER_SPLIT {
                    return Err(ApiError::BadRequest(format!(
                        "split suffix {} is limited to {MAX_RESOLVERS_PER_SPLIT} resolvers",
                        route.suffix
                    )));
                }
                let suffix = canonicalize_domain(&route.suffix)?;
                reject_private_suffix(&suffix)?;
                if !seen_suffixes.insert(suffix.clone()) {
                    return Err(ApiError::BadRequest(format!(
                        "duplicate split suffix {suffix}"
                    )));
                }
                Ok(SplitDnsRoute {
                    suffix,
                    resolvers: route
                        .resolvers
                        .iter()
                        .map(|resolver| parse_resolver(resolver))
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        canonical.search_domains = self
            .search_domains
            .iter()
            .map(|domain| -> Result<String, ApiError> {
                let domain = canonicalize_domain(domain)?;
                reject_private_suffix(&domain)?;
                Ok(domain)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if unique_count(&canonical.search_domains) != canonical.search_domains.len() {
            return Err(ApiError::BadRequest(
                "search domains must be unique after canonicalisation".into(),
            ));
        }
        let approved_zones = approved_zones(&canonical);
        canonical.records = self
            .records
            .iter()
            .map(|record| {
                let name = canonicalize_domain(&record.name)?;
                reject_private_suffix(&name)?;
                if !zone_contains(&approved_zones, &name) {
                    return Err(ApiError::BadRequest(format!(
                        "record {name} must sit under a configured split suffix or search domain"
                    )));
                }
                let value = match record.record_type {
                    DnsRecordType::A => parse_ipv4(&record.value)?,
                    DnsRecordType::Aaaa => parse_ipv6(&record.value)?,
                };
                Ok(DnsRecord {
                    name,
                    record_type: record.record_type,
                    value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen_records = BTreeSet::new();
        for record in &canonical.records {
            if !seen_records.insert((
                record.name.clone(),
                record.record_type,
                record.value.clone(),
            )) {
                return Err(ApiError::BadRequest(format!(
                    "duplicate {} record for {}",
                    record_type_name(record.record_type),
                    record.name
                )));
            }
        }
        canonical.nameserver_groups = canonical_groups(&self.nameserver_groups, &canonical.split)?;
        canonical.zones = canonical_zones(&self.zones)?;
        let forwarded: Vec<&str> = canonical
            .split
            .iter()
            .map(|route| route.suffix.as_str())
            .chain(
                canonical
                    .nameserver_groups
                    .iter()
                    .flat_map(|group| group.match_domains.iter().map(String::as_str)),
            )
            .collect();
        for zone in &canonical.zones {
            if forwarded.contains(&zone.name.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "zone {} is also a forwarded suffix; a suffix is either answered locally or forwarded",
                    zone.name
                )));
            }
            if let Some(record) = canonical
                .records
                .iter()
                .find(|record| zone_contains(std::slice::from_ref(&zone.name), &record.name))
            {
                return Err(ApiError::BadRequest(format!(
                    "extra record {} sits inside zone {}; move it into the zone",
                    record.name, zone.name
                )));
            }
        }
        Ok(canonical)
    }

    /// Advisory findings that do not block publishing.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for resolver in self
            .split
            .iter()
            .flat_map(|route| route.resolvers.iter())
            .chain(
                self.nameserver_groups
                    .iter()
                    .flat_map(|group| group.resolvers.iter()),
            )
            .collect::<BTreeSet<_>>()
        {
            if resolver
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
            {
                warnings.push(format!(
                    "resolver {resolver} is a loopback address; each device would query itself"
                ));
            }
        }
        for (index, group) in self.nameserver_groups.iter().enumerate() {
            if !group.enabled {
                continue;
            }
            for earlier in self.nameserver_groups[..index]
                .iter()
                .filter(|earlier| earlier.enabled)
            {
                let covers = earlier.all_devices
                    || (!group.all_devices
                        && group.tags.iter().all(|tag| earlier.tags.contains(tag)));
                for domain in group
                    .match_domains
                    .iter()
                    .filter(|domain| earlier.match_domains.contains(domain))
                {
                    if covers {
                        warnings.push(format!(
                            "group {:?} never answers {domain}: earlier group {:?} wins for the same devices",
                            group.name, earlier.name
                        ));
                    } else {
                        warnings.push(format!(
                            "{domain} is in groups {:?} and {:?}; devices in both use {:?}",
                            earlier.name, group.name, earlier.name
                        ));
                    }
                }
            }
        }
        let local_names: BTreeSet<&str> = self
            .zones
            .iter()
            .filter(|zone| zone.enabled)
            .flat_map(|zone| zone.records.iter().map(|record| record.name.as_str()))
            .chain(self.records.iter().map(|record| record.name.as_str()))
            .collect();
        for zone in self.zones.iter().filter(|zone| zone.enabled) {
            if zone.records.is_empty() {
                warnings.push(format!(
                    "zone {} has no records; every name in it answers NXDOMAIN",
                    zone.name
                ));
            }
            for record in &zone.records {
                match record.record_type {
                    ZoneRecordType::A | ZoneRecordType::Aaaa => {
                        if let Ok(address) = record.value.parse::<IpAddr>() {
                            if let Some(reason) = address_warning(address) {
                                warnings.push(format!(
                                    "{} {} {}: {reason}",
                                    record.name,
                                    record.record_type.as_str(),
                                    record.value
                                ));
                            }
                        }
                    }
                    ZoneRecordType::Cname => {
                        let target = record.value.as_str();
                        let served_by_blaktail = local_names.contains(target)
                            || target.ends_with(".blaktail")
                            || target == "blaktail";
                        if !served_by_blaktail {
                            warnings.push(format!(
                                "{} CNAME {target}: the target is not a BlakTail name, so devices finish the lookup with their own resolver",
                                record.name
                            ));
                        }
                    }
                    ZoneRecordType::Txt => {}
                }
            }
        }
        for record in &self.records {
            if let Ok(address) = record.value.parse::<IpAddr>() {
                if let Some(reason) = address_warning(address) {
                    warnings.push(format!("{} {}: {reason}", record.name, record.value));
                }
            }
        }
        warnings
    }

    /// Per-device snapshot. Groups and zones are flattened into the legacy
    /// `split`/`records` keys so agents that predate them keep resolving.
    pub fn agent_view(
        &self,
        org_id: &str,
        revision: i64,
        device_tags: &[String],
    ) -> OrgDnsAgentView {
        let mut split = self.split.clone();
        for group in self
            .nameserver_groups
            .iter()
            .filter(|group| group.applies_to(device_tags))
        {
            for domain in &group.match_domains {
                if !split.iter().any(|route| &route.suffix == domain) {
                    split.push(SplitDnsRoute {
                        suffix: domain.clone(),
                        resolvers: group.resolvers.clone(),
                    });
                }
            }
        }
        let mut records = self.records.clone();
        let mut zones = Vec::new();
        for zone in self.zones.iter().filter(|zone| zone.enabled) {
            split.push(SplitDnsRoute {
                suffix: zone.name.clone(),
                resolvers: Vec::new(),
            });
            for record in &zone.records {
                let record_type = match record.record_type {
                    ZoneRecordType::A => DnsRecordType::A,
                    ZoneRecordType::Aaaa => DnsRecordType::Aaaa,
                    ZoneRecordType::Cname | ZoneRecordType::Txt => continue,
                };
                records.push(DnsRecord {
                    name: record.name.clone(),
                    record_type,
                    value: record.value.clone(),
                });
            }
            zones.push(AgentZone {
                name: zone.name.clone(),
                records: zone.records.clone(),
            });
        }
        OrgDnsAgentView {
            revision,
            managed: self.managed,
            magic_dns_suffix: organisation_magic_dns_suffix(org_id),
            global_resolvers: self.global_resolvers.clone(),
            split,
            search_domains: self.search_domains.clone(),
            records,
            zones,
        }
    }

    /// Mirrors the agent stub's decision for `name` on a device with `device_tags`.
    pub fn explain(&self, name: &str, device_tags: &[String]) -> Result<DnsExplanation, ApiError> {
        let trimmed = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let short = !trimmed.is_empty() && !trimmed.contains('.');
        let name = if short {
            trimmed
        } else {
            canonicalize_domain(name)?
        };
        let mut explanation = DnsExplanation {
            name: name.clone(),
            managed: self.managed,
            answer: "not_handled",
            matched_suffix: None,
            zone: None,
            nameserver_group: None,
            resolvers: Vec::new(),
            records: Vec::new(),
            detail: String::new(),
            candidates: Vec::new(),
        };
        if short || name == "blaktail" || name.ends_with(".blaktail") {
            explanation.answer = "magic_dns";
            explanation.detail = "MagicDNS answers this name from the coordinator's device list; unknown names are NXDOMAIN and are never forwarded.".into();
            return Ok(explanation);
        }
        if !self.managed {
            explanation.answer = "unmanaged";
            explanation.detail = "Organisation DNS is unmanaged: only MagicDNS names are answered and the device's own resolver handles everything else.".into();
            return Ok(explanation);
        }
        let under = |suffix: &str| name == suffix || name.ends_with(&format!(".{suffix}"));
        for zone in self
            .zones
            .iter()
            .filter(|zone| zone.enabled && under(&zone.name))
        {
            explanation.candidates.push(DnsCandidate {
                suffix: zone.name.clone(),
                source: "zone",
                label: zone.name.clone(),
                applies: true,
            });
        }
        for group in &self.nameserver_groups {
            for domain in group.match_domains.iter().filter(|domain| under(domain)) {
                explanation.candidates.push(DnsCandidate {
                    suffix: domain.clone(),
                    source: "group",
                    label: group.name.clone(),
                    applies: group.applies_to(device_tags),
                });
            }
        }
        for route in self.split.iter().filter(|route| under(&route.suffix)) {
            explanation.candidates.push(DnsCandidate {
                suffix: route.suffix.clone(),
                source: "split",
                label: route.suffix.clone(),
                applies: true,
            });
        }
        let legacy: Vec<_> = self
            .records
            .iter()
            .filter(|record| record.name == name)
            .collect();
        if !legacy.is_empty() {
            explanation.answer = "legacy_record";
            explanation.records = legacy
                .iter()
                .map(|record| ZoneRecord {
                    name: record.name.clone(),
                    record_type: match record.record_type {
                        DnsRecordType::A => ZoneRecordType::A,
                        DnsRecordType::Aaaa => ZoneRecordType::Aaaa,
                    },
                    value: record.value.clone(),
                    ttl: 30,
                })
                .collect();
            explanation.detail =
                "The device answers this name locally from an extra record.".into();
            return Ok(explanation);
        }
        // Stable max: the first candidate wins ties (zone, then groups in order).
        let mut best: Option<&DnsCandidate> = None;
        for candidate in explanation.candidates.iter().filter(|c| c.applies) {
            if best.is_none_or(|current| candidate.suffix.len() > current.suffix.len()) {
                best = Some(candidate);
            }
        }
        let Some(best) = best.cloned() else {
            explanation.detail = "No zone, nameserver group or split suffix matches this name for this device, so BlakTail refuses it and the device's normal resolver answers.".into();
            return Ok(explanation);
        };
        explanation.matched_suffix = Some(best.suffix.clone());
        match best.source {
            "zone" => {
                explanation.zone = Some(best.suffix.clone());
                let zone = self
                    .zones
                    .iter()
                    .find(|zone| zone.name == best.suffix)
                    .expect("candidate zone exists");
                explanation.records = zone
                    .records
                    .iter()
                    .filter(|record| record.name == name)
                    .cloned()
                    .collect();
                if explanation.records.is_empty() {
                    explanation.answer = "zone_nxdomain";
                    explanation.detail = format!(
                        "Zone {} is authoritative here and has no record for this name, so the device answers NXDOMAIN without asking any other resolver.",
                        best.suffix
                    );
                } else {
                    explanation.answer = "zone";
                    explanation.detail = format!("The device answers from zone {}.", best.suffix);
                }
            }
            "group" => {
                let group = self
                    .nameserver_groups
                    .iter()
                    .find(|group| {
                        group.applies_to(device_tags) && group.match_domains.contains(&best.suffix)
                    })
                    .expect("candidate group exists");
                explanation.answer = "forward";
                explanation.nameserver_group = Some(group.name.clone());
                explanation.resolvers = group.resolvers.clone();
                explanation.detail = format!(
                    "Forwarded to nameserver group {:?} for {}, trying resolvers in order.",
                    group.name, best.suffix
                );
            }
            _ => {
                let route = self
                    .split
                    .iter()
                    .find(|route| route.suffix == best.suffix)
                    .expect("candidate split exists");
                explanation.answer = "forward";
                explanation.resolvers = route.resolvers.clone();
                explanation.detail = format!(
                    "Forwarded to the split DNS resolvers for {}, trying them in order.",
                    best.suffix
                );
            }
        }
        Ok(explanation)
    }

    pub fn resolver_for(&self, name: &str) -> Result<Option<&SplitDnsRoute>, ApiError> {
        longest_split_match(name, &self.split)
    }

    pub fn record_preview(&self) -> Vec<DnsRoutePreview> {
        self.records
            .iter()
            .map(|record| DnsRoutePreview {
                name: record.name.clone(),
                split_suffix: self
                    .resolver_for(&record.name)
                    .ok()
                    .flatten()
                    .map(|route| route.suffix.clone()),
            })
            .collect()
    }
}

fn longest_split_match<'a>(
    name: &str,
    routes: &'a [SplitDnsRoute],
) -> Result<Option<&'a SplitDnsRoute>, ApiError> {
    let name = canonicalize_domain(name)?;
    Ok(routes
        .iter()
        .filter(|route| name == route.suffix || name.ends_with(&format!(".{}", route.suffix)))
        .max_by_key(|route| route.suffix.len()))
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsExplanation {
    pub name: String,
    pub managed: bool,
    pub answer: &'static str,
    pub matched_suffix: Option<String>,
    pub zone: Option<String>,
    pub nameserver_group: Option<String>,
    pub resolvers: Vec<String>,
    pub records: Vec<ZoneRecord>,
    pub detail: String,
    pub candidates: Vec<DnsCandidate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsCandidate {
    pub suffix: String,
    pub source: &'static str,
    pub label: String,
    pub applies: bool,
}

fn canonical_groups(
    groups: &[NameserverGroup],
    split: &[SplitDnsRoute],
) -> Result<Vec<NameserverGroup>, ApiError> {
    if groups.len() > MAX_NAMESERVER_GROUPS {
        return Err(ApiError::BadRequest(format!(
            "nameserver groups are limited to {MAX_NAMESERVER_GROUPS}"
        )));
    }
    let mut names = BTreeSet::new();
    groups
        .iter()
        .map(|group| {
            let name = group.name.trim().to_owned();
            if name.is_empty()
                || name.chars().count() > MAX_GROUP_NAME_LEN
                || name.chars().any(char::is_control)
            {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group names must be 1-{MAX_GROUP_NAME_LEN} printable characters"
                )));
            }
            if !names.insert(name.to_lowercase()) {
                return Err(ApiError::BadRequest(format!(
                    "duplicate nameserver group {name:?}"
                )));
            }
            if group.resolvers.is_empty() || group.resolvers.len() > MAX_RESOLVERS_PER_SPLIT {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group {name:?} needs 1-{MAX_RESOLVERS_PER_SPLIT} resolvers"
                )));
            }
            let resolvers = group
                .resolvers
                .iter()
                .map(|resolver| parse_resolver(resolver))
                .collect::<Result<Vec<_>, _>>()?;
            if unique_count(&resolvers) != resolvers.len() {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group {name:?} lists a resolver twice"
                )));
            }
            if group.match_domains.is_empty() || group.match_domains.len() > MAX_MATCH_DOMAINS {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group {name:?} needs 1-{MAX_MATCH_DOMAINS} match domains; groups never replace a device's default resolver"
                )));
            }
            let match_domains = group
                .match_domains
                .iter()
                .map(|domain| {
                    let domain = canonicalize_domain(domain)?;
                    reject_private_suffix(&domain)?;
                    if split.iter().any(|route| route.suffix == domain) {
                        return Err(ApiError::BadRequest(format!(
                            "{domain} is already a split suffix; keep it in one place"
                        )));
                    }
                    Ok(domain)
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            if unique_count(&match_domains) != match_domains.len() {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group {name:?} lists a match domain twice"
                )));
            }
            let mut tags = group
                .tags
                .iter()
                .map(|tag| {
                    let tag = tag.trim().to_ascii_lowercase();
                    if DEVICE_TAGS.contains(&tag.as_str()) {
                        Ok(tag)
                    } else {
                        Err(ApiError::BadRequest(format!(
                            "unknown device tag {tag:?}; use one of {}",
                            DEVICE_TAGS.join(", ")
                        )))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            tags.sort();
            tags.dedup();
            if group.all_devices != tags.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "nameserver group {name:?} must target either all devices or at least one tag"
                )));
            }
            Ok(NameserverGroup {
                name,
                resolvers,
                match_domains,
                enabled: group.enabled,
                all_devices: group.all_devices,
                tags,
            })
        })
        .collect()
}

fn canonical_zones(zones: &[DnsZone]) -> Result<Vec<DnsZone>, ApiError> {
    if zones.len() > MAX_ZONES {
        return Err(ApiError::BadRequest(format!(
            "zones are limited to {MAX_ZONES}"
        )));
    }
    let mut canonical = Vec::with_capacity(zones.len());
    for zone in zones {
        let name = canonicalize_domain(&zone.name)?;
        reject_private_suffix(&name)?;
        for existing in &canonical {
            let existing: &DnsZone = existing;
            if existing.name == name {
                return Err(ApiError::BadRequest(format!("duplicate zone {name}")));
            }
            if zone_contains(std::slice::from_ref(&existing.name), &name)
                || zone_contains(std::slice::from_ref(&name), &existing.name)
            {
                return Err(ApiError::BadRequest(format!(
                    "zones {} and {name} overlap; nested zones are not supported",
                    existing.name
                )));
            }
        }
        if zone.records.len() > MAX_ZONE_RECORDS {
            return Err(ApiError::BadRequest(format!(
                "zone {name} is limited to {MAX_ZONE_RECORDS} records"
            )));
        }
        let records = zone
            .records
            .iter()
            .map(|record| canonical_zone_record(&name, record))
            .collect::<Result<Vec<_>, _>>()?;
        check_zone_records(&name, &records)?;
        canonical.push(DnsZone {
            name,
            enabled: zone.enabled,
            records,
        });
    }
    Ok(canonical)
}

fn canonical_zone_record(zone: &str, record: &ZoneRecord) -> Result<ZoneRecord, ApiError> {
    let raw = record.name.trim().trim_end_matches('.');
    let name = if raw == "@" {
        zone.to_owned()
    } else if !raw.is_empty() && !raw.contains('.') {
        canonicalize_domain(&format!("{raw}.{zone}"))?
    } else {
        let name = canonicalize_domain(raw)?;
        if !zone_contains(&[zone.to_owned()], &name) {
            return Err(ApiError::BadRequest(format!(
                "record {name} is outside zone {zone}"
            )));
        }
        name
    };
    if !(MIN_TTL..=MAX_TTL).contains(&record.ttl) {
        return Err(ApiError::BadRequest(format!(
            "record {name} TTL must be {MIN_TTL}-{MAX_TTL} seconds"
        )));
    }
    let value = match record.record_type {
        ZoneRecordType::A => {
            let value = parse_ipv4(&record.value)?;
            reject_unusable_address(&name, &value)?;
            value
        }
        ZoneRecordType::Aaaa => {
            let value = parse_ipv6(&record.value)?;
            reject_unusable_address(&name, &value)?;
            value
        }
        ZoneRecordType::Cname => {
            let target = canonicalize_domain(&record.value)?;
            if target == name {
                return Err(ApiError::BadRequest(format!(
                    "CNAME {name} cannot point at itself"
                )));
            }
            target
        }
        ZoneRecordType::Txt => {
            let value = record.value.clone();
            if value.is_empty()
                || value.len() > MAX_TXT_LEN
                || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            {
                return Err(ApiError::BadRequest(format!(
                    "TXT {name} must be 1-{MAX_TXT_LEN} printable ASCII characters"
                )));
            }
            value
        }
    };
    Ok(ZoneRecord {
        name,
        record_type: record.record_type,
        value,
        ttl: record.ttl,
    })
}

fn check_zone_records(zone: &str, records: &[ZoneRecord]) -> Result<(), ApiError> {
    let mut seen = BTreeSet::new();
    for record in records {
        if !seen.insert((&record.name, record.record_type, &record.value)) {
            return Err(ApiError::BadRequest(format!(
                "duplicate {} record for {}",
                record.record_type.as_str(),
                record.name
            )));
        }
        if record.record_type != ZoneRecordType::Cname {
            continue;
        }
        if record.name == zone {
            return Err(ApiError::BadRequest(format!(
                "zone apex {zone} cannot be a CNAME"
            )));
        }
        if records
            .iter()
            .filter(|other| other.name == record.name)
            .count()
            > 1
        {
            return Err(ApiError::BadRequest(format!(
                "{} has a CNAME, so it cannot have any other record",
                record.name
            )));
        }
        let mut current = record.value.as_str();
        for _ in 0..=MAX_CNAME_CHAIN {
            if current == record.name {
                return Err(ApiError::BadRequest(format!(
                    "CNAME loop through {}",
                    record.name
                )));
            }
            match records
                .iter()
                .find(|other| other.name == current && other.record_type == ZoneRecordType::Cname)
            {
                Some(next) => current = next.value.as_str(),
                None => break,
            }
        }
    }
    Ok(())
}

fn reject_unusable_address(name: &str, value: &str) -> Result<(), ApiError> {
    let address: IpAddr = value
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("{name} has an invalid address")))?;
    let unusable = address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(ip) if ip.is_broadcast());
    if unusable {
        return Err(ApiError::BadRequest(format!(
            "{name} cannot point at unspecified, multicast or broadcast address {value}"
        )));
    }
    Ok(())
}

fn address_warning(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(ip) if ip.is_loopback() => {
            Some("loopback target; each device would connect to itself")
        }
        IpAddr::V6(ip) if ip.is_loopback() => {
            Some("loopback target; each device would connect to itself")
        }
        IpAddr::V4(ip) if ip.is_link_local() => {
            Some("link-local target; it is not reachable across BlakTail")
        }
        IpAddr::V6(ip) if (ip.segments()[0] & 0xffc0) == 0xfe80 => {
            Some("link-local target; it is not reachable across BlakTail")
        }
        _ => None,
    }
}

pub fn parse_settings(json: &str) -> Result<OrgDnsSettings, ApiError> {
    if json.trim().is_empty() {
        return Ok(default_settings());
    }
    let settings: OrgDnsSettings = serde_json::from_str(json)
        .map_err(|error| ApiError::BadRequest(format!("invalid DNS settings: {error}")))?;
    settings.canonicalise()
}

fn parse_resolver(value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let address: IpAddr = trimmed.parse().map_err(|_| {
        ApiError::BadRequest(format!(
            "resolver {trimmed:?} must be an IPv4 or IPv6 address"
        ))
    })?;
    match address {
        IpAddr::V4(ip) => Ok(ip.to_string()),
        IpAddr::V6(ip) => Ok(ip.to_string()),
    }
}

fn parse_ipv4(value: &str) -> Result<String, ApiError> {
    let ip: Ipv4Addr = value.trim().parse().map_err(|_| {
        ApiError::BadRequest(format!("A record value {value:?} must be an IPv4 address"))
    })?;
    Ok(ip.to_string())
}

fn parse_ipv6(value: &str) -> Result<String, ApiError> {
    let ip: Ipv6Addr = value.trim().parse().map_err(|_| {
        ApiError::BadRequest(format!(
            "AAAA record value {value:?} must be an IPv6 address"
        ))
    })?;
    Ok(ip.to_string())
}

fn canonicalize_domain(input: &str) -> Result<String, ApiError> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "." {
        return Err(ApiError::BadRequest(
            "root and empty DNS names are not allowed".into(),
        ));
    }
    if trimmed.contains('*') {
        return Err(ApiError::BadRequest(
            "wildcard DNS names are not allowed".into(),
        ));
    }
    let ascii = idna::domain_to_ascii(trimmed).map_err(|_| {
        ApiError::BadRequest(format!("DNS name {trimmed:?} failed IDNA canonicalisation"))
    })?;
    if ascii.len() > MAX_DOMAIN_LEN {
        return Err(ApiError::BadRequest(format!(
            "DNS name {ascii} exceeds {MAX_DOMAIN_LEN} characters"
        )));
    }
    if ascii.starts_with('.') || ascii.ends_with('.') || ascii.contains("..") {
        return Err(ApiError::BadRequest(format!(
            "DNS name {ascii} has an empty label"
        )));
    }
    let unicode = idna::domain_to_unicode(&ascii).0;
    if mixed_scripts(&unicode) {
        return Err(ApiError::BadRequest(format!(
            "DNS name {trimmed:?} mixes Latin with another letter script"
        )));
    }
    for label in ascii.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(ApiError::BadRequest(format!(
                "DNS label {label:?} must be 1-{MAX_LABEL_LEN} characters"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ApiError::BadRequest(format!(
                "DNS label {label:?} cannot start or end with a hyphen"
            )));
        }
    }
    Ok(ascii)
}

fn reject_private_suffix(domain: &str) -> Result<(), ApiError> {
    if domain == "blaktail" || domain.ends_with(".blaktail") {
        return Err(ApiError::BadRequest(
            "organisation MagicDNS suffixes stay coordinator-authoritative and cannot be forwarded or impersonated".into(),
        ));
    }
    Ok(())
}

fn approved_zones(settings: &OrgDnsSettings) -> Vec<String> {
    settings
        .split
        .iter()
        .map(|route| route.suffix.clone())
        .chain(settings.search_domains.iter().cloned())
        .collect()
}

fn zone_contains(zones: &[String], name: &str) -> bool {
    zones
        .iter()
        .any(|zone| name == zone || name.ends_with(&format!(".{zone}")))
}

fn unique_count(values: &[String]) -> usize {
    values.iter().collect::<BTreeSet<_>>().len()
}

fn mixed_scripts(name: &str) -> bool {
    let mut latin = false;
    let mut other_letters = false;
    for character in name.chars() {
        if character.is_ascii_alphabetic() {
            latin = true;
        } else if character.is_alphabetic() {
            other_letters = true;
        }
    }
    latin && other_letters
}

fn record_type_name(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_settings() -> OrgDnsSettings {
        serde_json::from_str(
            r#"{
                "managed": true,
                "global_resolvers": ["1.1.1.1", "2606:4700:4700::1111"],
                "split": [{"suffix": "internal.example.", "resolvers": ["10.0.0.53"]}],
                "search_domains": ["Internal.example"],
                "records": [
                    {"name": "wiki.internal.example", "type": "A", "value": "10.0.0.10"},
                    {"name": "wiki.internal.example", "type": "AAAA", "value": "fd00::10"}
                ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn accepts_canonical_split_search_and_records() {
        let report =
            check_dns_document(&serde_json::to_string(&valid_settings()).unwrap()).unwrap();
        assert!(report.managed);
        assert_eq!(report.split, 1);
        assert_eq!(report.records, 2);
        let canonical = valid_settings().canonicalise().unwrap();
        assert_eq!(canonical.split[0].suffix, "internal.example");
        assert_eq!(canonical.search_domains[0], "internal.example");
        assert_eq!(
            longest_split_match("wiki.internal.example", &canonical.split)
                .unwrap()
                .unwrap()
                .suffix,
            "internal.example"
        );
        assert_eq!(
            longest_split_match("nested.corp.internal.example", &canonical.split)
                .unwrap()
                .unwrap()
                .suffix,
            "internal.example"
        );
    }

    #[test]
    fn longest_suffix_wins_for_nested_zones() {
        let settings: OrgDnsSettings = serde_json::from_str(
            r#"{
                "split": [
                    {"suffix": "example", "resolvers": ["10.0.0.53"]},
                    {"suffix": "corp.example", "resolvers": ["10.0.0.54"]}
                ]
            }"#,
        )
        .unwrap();
        let canonical = settings.canonicalise().unwrap();
        assert_eq!(
            longest_split_match("db.corp.example", &canonical.split)
                .unwrap()
                .unwrap()
                .resolvers[0],
            "10.0.0.54"
        );
        assert_eq!(
            longest_split_match("www.example", &canonical.split)
                .unwrap()
                .unwrap()
                .resolvers[0],
            "10.0.0.53"
        );
        assert!(longest_split_match("other.test", &canonical.split)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_private_suffix_leaks_and_wrong_families() {
        for document in [
            r#"{"split":[{"suffix":"abc.blaktail","resolvers":["1.1.1.1"]}]}"#,
            r#"{"search_domains":["blaktail"]}"#,
            r#"{"records":[{"name":"node.12345678.blaktail","type":"A","value":"10.0.0.1"}]}"#,
            r#"{"global_resolvers":["resolver.example"]}"#,
            r#"{"split":[{"suffix":"internal.example","resolvers":["10.0.0.53"]}],"records":[{"name":"wiki.internal.example","type":"A","value":"fd00::1"}]}"#,
            r#"{"split":[{"suffix":"internal.example","resolvers":["10.0.0.53"]}],"records":[{"name":"wiki.internal.example","type":"AAAA","value":"10.0.0.1"}]}"#,
            r#"{"records":[{"name":"orphan.example","type":"A","value":"10.0.0.1"}]}"#,
            r#"{"split":[{"suffix":"*","resolvers":["1.1.1.1"]}]}"#,
            r#"{"search_domains":["."]}"#,
            r#"{"split":[{"suffix":"internal.example","resolvers":["10.0.0.53"]},{"suffix":"INTERNAL.example.","resolvers":["10.0.0.54"]}]}"#,
        ] {
            assert!(
                check_dns_document(document).is_err(),
                "expected rejection for {document}"
            );
        }
    }

    #[test]
    fn rejects_mixed_script_confusable_labels() {
        assert!(check_dns_document(
            r#"{"search_domains":["exаmple"]}"# // Cyrillic а
        )
        .is_err());
    }

    const LEGACY: &str = r#"{"managed":true,"global_resolvers":["1.1.1.1"],"split":[{"suffix":"internal.example","resolvers":["10.0.0.53"]}],"search_domains":["internal.example"],"records":[{"name":"wiki.internal.example","type":"A","value":"10.0.0.10"}]}"#;

    fn workspace() -> OrgDnsSettings {
        parse_settings(
            r#"{
                "split": [{"suffix": "legacy.example", "resolvers": ["10.9.0.53"]}],
                "nameserver_groups": [
                    {"name": "Office AD", "resolvers": ["10.0.0.53", "10.0.0.54"],
                     "match_domains": ["corp.example", "dc.apps.example"], "tags": ["office"]},
                    {"name": "Everyone", "resolvers": ["10.0.1.53"],
                     "match_domains": ["corp.example", "shared.example"], "all_devices": true}
                ],
                "zones": [{"name": "Apps.Example.", "records": [
                    {"name": "wiki", "type": "A", "value": "10.0.0.10"},
                    {"name": "wiki.apps.example", "type": "AAAA", "value": "fd00::10", "ttl": 60},
                    {"name": "docs", "type": "CNAME", "value": "wiki.apps.example"},
                    {"name": "@", "type": "TXT", "value": "v=blaktail"}
                ]}]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn legacy_documents_round_trip_and_agent_view_is_unchanged() {
        let settings = parse_settings(LEGACY).unwrap();
        assert_eq!(serde_json::to_string(&settings).unwrap(), LEGACY);
        for tags in [vec![], vec!["office".to_owned()]] {
            let view = serde_json::to_value(settings.agent_view(
                "12345678-0000-0000-0000-000000000000",
                4,
                &tags,
            ))
            .unwrap();
            assert_eq!(
                view,
                serde_json::json!({
                    "revision": 4,
                    "managed": true,
                    "magic_dns_suffix": "12345678.blaktail",
                    "global_resolvers": ["1.1.1.1"],
                    "split": [{"suffix": "internal.example", "resolvers": ["10.0.0.53"]}],
                    "search_domains": ["internal.example"],
                    "records": [{"name": "wiki.internal.example", "type": "A", "value": "10.0.0.10"}],
                })
            );
        }
    }

    #[test]
    fn workspace_canonicalises_zones_and_groups() {
        let settings = workspace();
        let zone = &settings.zones[0];
        assert_eq!(zone.name, "apps.example");
        assert!(zone.enabled);
        let names: Vec<_> = zone
            .records
            .iter()
            .map(|record| record.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "wiki.apps.example",
                "wiki.apps.example",
                "docs.apps.example",
                "apps.example"
            ]
        );
        assert_eq!(zone.records[0].ttl, DEFAULT_TTL);
        assert_eq!(zone.records[1].ttl, 60);
        assert!(settings.nameserver_groups[0].enabled);
        let reparsed = parse_settings(&serde_json::to_string(&settings).unwrap()).unwrap();
        assert_eq!(reparsed, settings);
    }

    #[test]
    fn agent_view_applies_groups_by_tag_and_flattens_zones_for_old_agents() {
        let settings = workspace();
        let office = settings.agent_view("org", 2, &["office".to_owned()]);
        let ranger = settings.agent_view("org", 2, &["ranger".to_owned()]);
        let suffixes = |view: &OrgDnsAgentView| {
            view.split
                .iter()
                .map(|route| (route.suffix.clone(), route.resolvers.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            suffixes(&office),
            vec![
                ("legacy.example".into(), vec!["10.9.0.53".to_owned()]),
                (
                    "corp.example".into(),
                    vec!["10.0.0.53".into(), "10.0.0.54".into()]
                ),
                (
                    "dc.apps.example".into(),
                    vec!["10.0.0.53".into(), "10.0.0.54".into()]
                ),
                ("shared.example".into(), vec!["10.0.1.53".into()]),
                ("apps.example".into(), vec![]),
            ]
        );
        assert_eq!(
            suffixes(&ranger),
            vec![
                ("legacy.example".into(), vec!["10.9.0.53".to_owned()]),
                ("corp.example".into(), vec!["10.0.1.53".into()]),
                ("shared.example".into(), vec!["10.0.1.53".into()]),
                ("apps.example".into(), vec![]),
            ]
        );
        // Old agents answer only A/AAAA, via the legacy records key.
        assert_eq!(office.records.len(), 2);
        assert_eq!(office.zones[0].records.len(), 4);
        let json = serde_json::to_value(&office).unwrap();
        assert!(json["zones"][0]["records"][2]["type"] == "CNAME");
    }

    #[test]
    fn explain_uses_longest_suffix_per_device() {
        let settings = workspace();
        let office = ["office".to_owned()];
        let wiki = settings.explain("wiki.apps.example", &office).unwrap();
        assert_eq!(wiki.answer, "zone");
        assert_eq!(wiki.records.len(), 2);
        assert_eq!(
            settings
                .explain("missing.apps.example", &office)
                .unwrap()
                .answer,
            "zone_nxdomain"
        );
        let dc = settings.explain("host.dc.apps.example", &office).unwrap();
        assert_eq!(dc.answer, "forward");
        assert_eq!(dc.matched_suffix.as_deref(), Some("dc.apps.example"));
        assert_eq!(dc.nameserver_group.as_deref(), Some("Office AD"));
        // Ranger devices are not in Office AD, so the zone answers authoritatively.
        assert_eq!(
            settings
                .explain("host.dc.apps.example", &[])
                .unwrap()
                .answer,
            "zone_nxdomain"
        );
        let corp = settings.explain("db.corp.example", &office).unwrap();
        assert_eq!(corp.nameserver_group.as_deref(), Some("Office AD"));
        let corp = settings
            .explain("db.corp.example", &["ranger".into()])
            .unwrap();
        assert_eq!(corp.nameserver_group.as_deref(), Some("Everyone"));
        assert_eq!(corp.resolvers, ["10.0.1.53"]);
        assert_eq!(
            settings.explain("example.com", &office).unwrap().answer,
            "not_handled"
        );
        assert_eq!(
            settings
                .explain("laptop.abcd1234.blaktail", &office)
                .unwrap()
                .answer,
            "magic_dns"
        );
    }

    #[test]
    fn rejects_unsafe_zones_groups_and_records() {
        let zone = |records: &str| {
            format!(r#"{{"zones":[{{"name":"apps.example","records":[{records}]}}]}}"#)
        };
        for document in [
            r#"{"zones":[{"name":"x.blaktail"}]}"#.to_owned(),
            r#"{"zones":[{"name":"*.example"}]}"#.to_owned(),
            r#"{"zones":[{"name":"apps.example"},{"name":"a.apps.example"}]}"#.to_owned(),
            r#"{"zones":[{"name":"apps.example"},{"name":"APPS.example."}]}"#.to_owned(),
            r#"{"split":[{"suffix":"apps.example","resolvers":["10.0.0.53"]}],"zones":[{"name":"apps.example"}]}"#.to_owned(),
            r#"{"split":[{"suffix":"example","resolvers":["10.0.0.53"]}],"records":[{"name":"a.apps.example","type":"A","value":"10.0.0.1"}],"zones":[{"name":"apps.example"}]}"#.to_owned(),
            zone(r#"{"name":"www","type":"A","value":"10.0.0.1"},{"name":"www","type":"CNAME","value":"x.example"}"#),
            zone(r#"{"name":"@","type":"CNAME","value":"x.example"}"#),
            zone(r#"{"name":"a","type":"CNAME","value":"b.apps.example"},{"name":"b","type":"CNAME","value":"a.apps.example"}"#),
            zone(r#"{"name":"a","type":"CNAME","value":"a.apps.example"}"#),
            zone(r#"{"name":"a","type":"TXT","value":"café"}"#),
            zone(r#"{"name":"a","type":"A","value":"10.0.0.1","ttl":5}"#),
            zone(r#"{"name":"a.other.example","type":"A","value":"10.0.0.1"}"#),
            zone(r#"{"name":"a","type":"A","value":"0.0.0.0"}"#),
            zone(r#"{"name":"a","type":"AAAA","value":"ff02::1"}"#),
            zone(r#"{"name":"a","type":"A","value":"fd00::1"}"#),
            zone(r#"{"name":"a","type":"MX","value":"mail.example"}"#),
            zone(r#"{"name":"a","type":"A","value":"10.0.0.1"},{"name":"a","type":"A","value":"10.0.0.1"}"#),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":[],"all_devices":true}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["corp.example"]}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["corp.example"],"all_devices":true,"tags":["office"]}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["corp.example"],"tags":["visitors"]}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["abc.blaktail"],"all_devices":true}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["dns.example"],"match_domains":["corp.example"],"all_devices":true}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53","10.0.0.53"],"match_domains":["corp.example"],"all_devices":true}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["corp.example"],"all_devices":true},{"name":"G","resolvers":["10.0.0.54"],"match_domains":["x.example"],"all_devices":true}]}"#.to_owned(),
            r#"{"split":[{"suffix":"corp.example","resolvers":["10.0.0.53"]}],"nameserver_groups":[{"name":"g","resolvers":["10.0.0.54"],"match_domains":["corp.example"],"all_devices":true}]}"#.to_owned(),
            r#"{"nameserver_groups":[{"name":"g","resolvers":["10.0.0.53"],"match_domains":["corp.example"],"all_devices":true,"priority":1}]}"#.to_owned(),
        ] {
            assert!(
                check_dns_document(&document).is_err(),
                "expected rejection for {document}"
            );
        }
    }

    #[test]
    fn warns_about_loopback_link_local_shadowed_groups_and_external_cnames() {
        let settings = parse_settings(
            r#"{
                "nameserver_groups": [
                    {"name": "All", "resolvers": ["127.0.0.1"], "match_domains": ["corp.example"], "all_devices": true},
                    {"name": "Office", "resolvers": ["10.0.0.53"], "match_domains": ["corp.example"], "tags": ["office"]}
                ],
                "zones": [{"name": "apps.example", "records": [
                    {"name": "self", "type": "A", "value": "127.0.0.1"},
                    {"name": "ll", "type": "AAAA", "value": "fe80::1"},
                    {"name": "out", "type": "CNAME", "value": "www.example.com"}
                ]}, {"name": "empty.example"}]
            }"#,
        )
        .unwrap();
        let warnings = settings.warnings().join("\n");
        for needle in [
            "resolver 127.0.0.1 is a loopback",
            "group \"Office\" never answers corp.example",
            "self.apps.example A 127.0.0.1",
            "link-local",
            "out.apps.example CNAME www.example.com",
            "zone empty.example has no records",
        ] {
            assert!(
                warnings.contains(needle),
                "missing {needle:?} in {warnings}"
            );
        }
    }
}
