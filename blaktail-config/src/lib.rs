use regex::Regex;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Write as _,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
};
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Service {
    Coordinator,
    Relay,
    Agent,
    Console,
    All,
}

impl fmt::Display for Service {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Coordinator => "coordinator",
            Self::Relay => "relay",
            Self::Agent => "agent",
            Self::Console => "console",
            Self::All => "all",
        })
    }
}

impl FromStr for Service {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "coordinator" | "coord" => Ok(Self::Coordinator),
            "relay" => Ok(Self::Relay),
            "agent" | "blaktaild" => Ok(Self::Agent),
            "console" => Ok(Self::Console),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "unknown service {value:?}; expected coordinator, relay, agent, console, or all"
            )),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum SecretRef {
    File {
        path: PathBuf,
        fingerprint: Option<[u8; 32]>,
    },
    Environment {
        name: String,
        fingerprint: Option<[u8; 32]>,
    },
}

impl SecretRef {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File {
            path: path.into(),
            fingerprint: None,
        }
    }

    fn environment(name: impl Into<String>) -> Self {
        Self::Environment {
            name: name.into(),
            fingerprint: None,
        }
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::File { .. } => "<redacted:file>",
            Self::Environment { .. } => "<redacted:environment>",
        })
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::File { .. } => "<redacted:file>",
            Self::Environment { .. } => "<redacted:environment>",
        })
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let Some(path) = value.strip_prefix("file:") else {
            return Err(D::Error::custom(
                "secret references in configuration files must use file:/path",
            ));
        };
        if path.trim().is_empty() {
            return Err(D::Error::custom("secret file path must not be empty"));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(D::Error::custom("secret file path must be absolute"));
        }
        Ok(Self::File {
            path,
            fingerprint: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeploymentConfig {
    pub profile: String,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            profile: "production".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiagnosticsConfig {
    pub log_filter: String,
    pub support_log_lines: usize,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            log_filter: "info".into(),
            support_log_lines: 200,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub region: String,
    pub bind: String,
    pub metrics_bind: String,
    pub allow_public_metrics: bool,
    pub diagnostics_token: Option<SecretRef>,
    pub database_backend: String,
    pub database: PathBuf,
    pub database_url: Option<SecretRef>,
    pub database_storage: String,
    pub allow_unsafe_efs_sqlite: bool,
    pub tls_mode: String,
    pub tls_cert: PathBuf,
    pub tls_key: Option<SecretRef>,
    pub auth_hmac_secret: Option<SecretRef>,
    pub relay_auth_secret: Option<SecretRef>,
    pub relays: Vec<String>,
    pub console_url: String,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            bind: "0.0.0.0:8443".into(),
            metrics_bind: "127.0.0.1:9701".into(),
            allow_public_metrics: false,
            diagnostics_token: None,
            database_backend: "sqlite".into(),
            database: "blaktail-coord.sqlite3".into(),
            database_url: None,
            database_storage: "local".into(),
            allow_unsafe_efs_sqlite: false,
            tls_mode: "files".into(),
            tls_cert: PathBuf::new(),
            tls_key: None,
            auth_hmac_secret: None,
            relay_auth_secret: None,
            relays: Vec::new(),
            console_url: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    pub region: String,
    pub bind: String,
    pub metrics_bind: String,
    pub allow_public_metrics: bool,
    pub diagnostics_token: Option<SecretRef>,
    pub auth_secret: Option<SecretRef>,
    pub idle_seconds: u64,
    pub rate_per_second: u32,
    pub rate_burst: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            bind: "0.0.0.0:3478".into(),
            metrics_bind: "127.0.0.1:9702".into(),
            allow_public_metrics: false,
            diagnostics_token: None,
            auth_secret: None,
            idle_seconds: 120,
            rate_per_second: 100,
            rate_burst: 200,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub state_dir: PathBuf,
    pub coordinator_url: Option<String>,
    pub interface: String,
    pub poll_seconds: u64,
    pub advertised_routes: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            state_dir: "/var/lib/blaktail".into(),
            coordinator_url: None,
            interface: "blaktail0".into(),
            poll_seconds: 30,
            advertised_routes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleConfig {
    pub region: String,
    pub port: u16,
    pub database_url: Option<SecretRef>,
    pub base_url: String,
    pub trusted_origins: Vec<String>,
    pub coordinator_url: String,
    pub coordinator_ca_file: Option<PathBuf>,
    pub auth_secret: Option<SecretRef>,
    pub coordinator_auth_secret: Option<SecretRef>,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            port: 3000,
            database_url: None,
            base_url: String::new(),
            trusted_origins: Vec::new(),
            coordinator_url: String::new(),
            coordinator_ca_file: None,
            auth_secret: None,
            coordinator_auth_secret: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RootConfig {
    pub schema_version: u32,
    pub deployment: DeploymentConfig,
    pub diagnostics: DiagnosticsConfig,
    pub coordinator: CoordinatorConfig,
    pub relay: RelayConfig,
    pub agent: AgentConfig,
    pub console: ConsoleConfig,
}

impl Default for RootConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            deployment: DeploymentConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
            coordinator: CoordinatorConfig::default(),
            relay: RelayConfig::default(),
            agent: AgentConfig::default(),
            console: ConsoleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Violation {
    pub field: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse configuration file {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("configuration environment override {field}: {message}")]
    Environment { field: String, message: String },
    #[error("configuration invalid:\n{0}")]
    Invalid(ValidationDisplay),
    #[error("could not read secret for {field}: {message}")]
    Secret { field: String, message: String },
    #[error("support bundle output {path}: {source}")]
    SupportOutput {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("support bundle confirmation did not match preview digest")]
    SupportConfirmation,
}

#[derive(Debug)]
pub struct ValidationDisplay(Vec<Violation>);

impl fmt::Display for ValidationDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, violation) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str("\n")?;
            }
            write!(formatter, "- {violation}")?;
        }
        Ok(())
    }
}

pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self, field: &str) -> Result<&str, ConfigError> {
        std::str::from_utf8(&self.0).map_err(|_| ConfigError::Secret {
            field: field.into(),
            message: "value is not valid UTF-8".into(),
        })
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct EnvironmentValues(BTreeMap<String, String>);

impl Drop for EnvironmentValues {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

pub struct LoadedConfig {
    pub config: RootConfig,
    pub sources: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    environment: EnvironmentValues,
    file_present: bool,
}

impl LoadedConfig {
    pub fn load(path: Option<&Path>, service: Service) -> Result<Self, ConfigError> {
        let environment = std::env::vars()
            .filter(|(name, _)| {
                ENVIRONMENT_OVERRIDES
                    .iter()
                    .any(|(supported, _, _)| name == supported)
            })
            .collect::<BTreeMap<_, _>>();
        Self::load_with_environment(path, service, environment)
    }

    pub fn load_with_environment(
        path: Option<&Path>,
        service: Service,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let mut environment = EnvironmentValues(environment);
        let mut config = RootConfig::default();
        let mut sources = default_sources(&config);
        if let Some(path) = path {
            let input =
                Zeroizing::new(
                    fs::read_to_string(path).map_err(|source| ConfigError::Read {
                        path: path.to_owned(),
                        source,
                    })?,
                );
            config = parse_root_config(&input).map_err(|message| ConfigError::Parse {
                path: path.to_owned(),
                message,
            })?;
            let value = toml::from_str::<toml::Value>(&input).map_err(|_| ConfigError::Parse {
                path: path.to_owned(),
                message: "configuration source index could not be built".into(),
            })?;
            mark_toml_sources(&value, "", &mut sources);
        }
        let mut warnings = Vec::new();
        apply_environment(
            &mut config,
            service,
            &environment.0,
            &mut sources,
            &mut warnings,
        )?;
        fingerprint_secrets(&mut config, service, &environment.0);
        let secret_environment = take_secret_environment(&config, &mut environment.0);
        Ok(Self {
            config,
            sources,
            warnings,
            environment: secret_environment,
            file_present: path.is_some(),
        })
    }

    pub fn validate(&self, service: Service) -> Result<(), ConfigError> {
        let violations = self.violations(service);
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(ValidationDisplay(violations)))
        }
    }

    pub fn violations(&self, service: Service) -> Vec<Violation> {
        let mut violations = Vec::new();
        if self.config.schema_version != SCHEMA_VERSION {
            violation(
                &mut violations,
                "schema_version",
                format!(
                    "expected {SCHEMA_VERSION}, found {}",
                    self.config.schema_version
                ),
            );
        }
        if self.file_present
            && self
                .sources
                .get("schema_version")
                .is_none_or(|source| source != "file")
        {
            violation(
                &mut violations,
                "schema_version",
                "must be explicit in a configuration file",
            );
        }
        if !matches!(
            self.config.deployment.profile.as_str(),
            "production" | "development" | "e2e"
        ) {
            violation(
                &mut violations,
                "deployment.profile",
                "must be production, development, or e2e",
            );
        }
        validate_diagnostics(&self.config.diagnostics, &mut violations);
        if matches!(service, Service::Coordinator | Service::All) {
            validate_coordinator(self, &mut violations);
        }
        if matches!(service, Service::Relay | Service::All) {
            validate_relay(self, &mut violations);
        }
        if matches!(service, Service::Agent | Service::All) {
            validate_agent(self, &mut violations);
        }
        if matches!(service, Service::Console | Service::All) {
            validate_console(self, &mut violations);
        }
        violations
    }

    pub fn secret(&self, reference: &SecretRef, field: &str) -> Result<SecretValue, ConfigError> {
        let bytes = match reference {
            SecretRef::File { path, .. } => {
                fs::read(path).map_err(|error| ConfigError::Secret {
                    field: field.into(),
                    message: format!("file could not be read: {error}"),
                })?
            }
            SecretRef::Environment { name, .. } => self
                .environment
                .0
                .get(name)
                .map(|value| value.as_bytes().to_vec())
                .ok_or_else(|| ConfigError::Secret {
                    field: field.into(),
                    message: format!("environment variable {name} is not set"),
                })?,
        };
        let mut value = bytes;
        trim_secret_newlines(&mut value);
        Ok(SecretValue(value))
    }

    pub fn redacted_dump(&self, service: Service) -> Result<String, ConfigError> {
        let config = serde_json::to_value(&self.config).expect("configuration is serializable");
        let selected = select_service(config, service);
        let sources = self
            .sources
            .iter()
            .filter(|(path, _)| path_selected(path, service))
            .map(|(path, source)| (path.clone(), source.clone()))
            .collect::<BTreeMap<_, _>>();
        serde_json::to_string_pretty(&serde_json::json!({
            "config": selected,
            "effective_sources": sources,
            "warnings": self.warnings,
        }))
        .map_err(|error| ConfigError::Environment {
            field: "dump-config".into(),
            message: error.to_string(),
        })
    }
}

fn parse_root_config(input: &str) -> Result<RootConfig, String> {
    let deserializer = toml::Deserializer::new(input);
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let path = error.path().to_string();
        let raw = error.inner().message();
        let safe = if raw.starts_with("unknown field")
            || raw.starts_with("missing field")
            || raw.starts_with("duplicate field")
            || raw.starts_with("duplicate key")
            || raw.starts_with("secret reference")
            || raw.starts_with("secret file path")
        {
            raw.to_owned()
        } else {
            "value has an invalid type or format".into()
        };
        if path.is_empty() || path == "." {
            safe
        } else {
            format!("{path}: {safe}")
        }
    })
}

fn fingerprint_secrets(
    config: &mut RootConfig,
    service: Service,
    environment: &BTreeMap<String, String>,
) {
    if matches!(service, Service::Coordinator | Service::All) {
        fingerprint_secret(&mut config.coordinator.diagnostics_token, environment);
        fingerprint_secret(&mut config.coordinator.database_url, environment);
        fingerprint_secret(&mut config.coordinator.tls_key, environment);
        fingerprint_secret(&mut config.coordinator.auth_hmac_secret, environment);
        fingerprint_secret(&mut config.coordinator.relay_auth_secret, environment);
    }
    if matches!(service, Service::Relay | Service::All) {
        fingerprint_secret(&mut config.relay.diagnostics_token, environment);
        fingerprint_secret(&mut config.relay.auth_secret, environment);
    }
    if matches!(service, Service::Console | Service::All) {
        fingerprint_secret(&mut config.console.database_url, environment);
        fingerprint_secret(&mut config.console.auth_secret, environment);
        fingerprint_secret(&mut config.console.coordinator_auth_secret, environment);
    }
}

fn fingerprint_secret(reference: &mut Option<SecretRef>, environment: &BTreeMap<String, String>) {
    let Some(reference) = reference else {
        return;
    };
    match reference {
        SecretRef::File { path, fingerprint } => {
            let Ok(mut bytes) = fs::read(path) else {
                return;
            };
            trim_secret_newlines(&mut bytes);
            *fingerprint = Some(Sha256::digest(&bytes).into());
            bytes.zeroize();
        }
        SecretRef::Environment { name, fingerprint } => {
            let Some(value) = environment.get(name) else {
                return;
            };
            let mut bytes = value.as_bytes();
            while bytes
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                bytes = &bytes[..bytes.len() - 1];
            }
            *fingerprint = Some(Sha256::digest(bytes).into());
        }
    }
}

fn trim_secret_newlines(value: &mut Vec<u8>) {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
}

fn take_secret_environment(
    config: &RootConfig,
    environment: &mut BTreeMap<String, String>,
) -> EnvironmentValues {
    let references = [
        config.coordinator.diagnostics_token.as_ref(),
        config.coordinator.database_url.as_ref(),
        config.coordinator.tls_key.as_ref(),
        config.coordinator.auth_hmac_secret.as_ref(),
        config.coordinator.relay_auth_secret.as_ref(),
        config.relay.diagnostics_token.as_ref(),
        config.relay.auth_secret.as_ref(),
        config.console.database_url.as_ref(),
        config.console.auth_secret.as_ref(),
        config.console.coordinator_auth_secret.as_ref(),
    ];
    let mut secrets = BTreeMap::new();
    for reference in references.into_iter().flatten() {
        if let SecretRef::Environment { name, .. } = reference {
            if let Some(value) = environment.remove(name) {
                secrets.insert(name.clone(), value);
            }
        }
    }
    EnvironmentValues(secrets)
}

fn select_service(mut value: serde_json::Value, service: Service) -> serde_json::Value {
    if service == Service::All {
        return value;
    }
    let section = service.to_string();
    let object = value
        .as_object_mut()
        .expect("root configuration serializes to object");
    object.retain(|key, _| {
        matches!(
            key.as_str(),
            "schema_version" | "deployment" | "diagnostics"
        ) || key == &section
    });
    value
}

fn path_selected(path: &str, service: Service) -> bool {
    service == Service::All
        || path == "schema_version"
        || path.starts_with("deployment.")
        || path.starts_with("diagnostics.")
        || path.starts_with(&format!("{}.", service))
}

fn default_sources(config: &RootConfig) -> BTreeMap<String, String> {
    let value = serde_json::to_value(config).expect("default configuration is serializable");
    let mut paths = BTreeSet::new();
    collect_json_paths(&value, "", &mut paths);
    paths
        .into_iter()
        .map(|path| (path, "default".into()))
        .collect()
}

fn collect_json_paths(value: &serde_json::Value, prefix: &str, paths: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                let path = join_path(prefix, key);
                collect_json_paths(value, &path, paths);
            }
        }
        _ => {
            paths.insert(prefix.into());
        }
    }
}

fn mark_toml_sources(value: &toml::Value, prefix: &str, sources: &mut BTreeMap<String, String>) {
    match value {
        toml::Value::Table(values) => {
            for (key, value) in values {
                let path = join_path(prefix, key);
                mark_toml_sources(value, &path, sources);
            }
        }
        _ => {
            sources.insert(prefix.into(), "file".into());
        }
    }
}

fn join_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.into()
    } else {
        format!("{prefix}.{key}")
    }
}

fn env<'a>(environment: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    environment
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn mark_env(sources: &mut BTreeMap<String, String>, field: &str, name: &str) {
    sources.insert(field.into(), format!("environment:{name}"));
}

fn set_string(
    target: &mut String,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) {
    if let Some(value) = env(environment, name) {
        *target = value.into();
        mark_env(sources, field, name);
    }
}

fn set_path(
    target: &mut PathBuf,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) {
    if let Some(value) = env(environment, name) {
        *target = value.into();
        mark_env(sources, field, name);
    }
}

fn set_bool(
    target: &mut bool,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    if let Some(value) = env(environment, name) {
        *target = match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => true,
            "0" | "false" | "no" => false,
            _ => {
                return Err(ConfigError::Environment {
                    field: field.into(),
                    message: format!("{name} must be true or false"),
                })
            }
        };
        mark_env(sources, field, name);
    }
    Ok(())
}

fn set_u64(
    target: &mut u64,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    if let Some(value) = env(environment, name) {
        *target = value.parse::<u64>().map_err(|_| ConfigError::Environment {
            field: field.into(),
            message: format!("{name} must be an unsigned integer"),
        })?;
        mark_env(sources, field, name);
    }
    Ok(())
}

fn set_u32(
    target: &mut u32,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let mut value = u64::from(*target);
    set_u64(&mut value, environment, name, field, sources)?;
    *target = u32::try_from(value).map_err(|_| ConfigError::Environment {
        field: field.into(),
        message: format!("{name} exceeds the supported range"),
    })?;
    Ok(())
}

fn set_usize(
    target: &mut usize,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let mut value = *target as u64;
    set_u64(&mut value, environment, name, field, sources)?;
    *target = usize::try_from(value).map_err(|_| ConfigError::Environment {
        field: field.into(),
        message: format!("{name} exceeds the supported range"),
    })?;
    Ok(())
}

fn set_list(
    target: &mut Vec<String>,
    environment: &BTreeMap<String, String>,
    name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) {
    if let Some(value) = env(environment, name) {
        *target = value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
        mark_env(sources, field, name);
    }
}

fn set_secret(
    target: &mut Option<SecretRef>,
    environment: &BTreeMap<String, String>,
    value_name: &str,
    file_name: &str,
    field: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    match (env(environment, value_name), env(environment, file_name)) {
        (Some(_), Some(_)) => Err(ConfigError::Environment {
            field: field.into(),
            message: format!("{value_name} and {file_name} are ambiguous; set exactly one"),
        }),
        (Some(_), None) => {
            *target = Some(SecretRef::environment(value_name));
            mark_env(sources, field, value_name);
            Ok(())
        }
        (None, Some(path)) => {
            *target = Some(SecretRef::file(path));
            mark_env(sources, field, file_name);
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

fn apply_environment(
    config: &mut RootConfig,
    service: Service,
    environment: &BTreeMap<String, String>,
    sources: &mut BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) -> Result<(), ConfigError> {
    set_string(
        &mut config.deployment.profile,
        environment,
        "BLAKTAIL_DEPLOYMENT_PROFILE",
        "deployment.profile",
        sources,
    );
    set_string(
        &mut config.diagnostics.log_filter,
        environment,
        "RUST_LOG",
        "diagnostics.log_filter",
        sources,
    );
    set_usize(
        &mut config.diagnostics.support_log_lines,
        environment,
        "BLAKTAIL_SUPPORT_LOG_LINES",
        "diagnostics.support_log_lines",
        sources,
    )?;

    if matches!(service, Service::Coordinator | Service::All) {
        let coordinator = &mut config.coordinator;
        set_string(
            &mut coordinator.region,
            environment,
            "BLAKTAIL_REGION",
            "coordinator.region",
            sources,
        );
        set_string(
            &mut coordinator.bind,
            environment,
            "BLAKTAIL_BIND",
            "coordinator.bind",
            sources,
        );
        set_string(
            &mut coordinator.metrics_bind,
            environment,
            "BLAKTAIL_COORD_METRICS_BIND",
            "coordinator.metrics_bind",
            sources,
        );
        set_bool(
            &mut coordinator.allow_public_metrics,
            environment,
            "BLAKTAIL_COORD_ALLOW_PUBLIC_METRICS",
            "coordinator.allow_public_metrics",
            sources,
        )?;
        set_secret(
            &mut coordinator.diagnostics_token,
            environment,
            "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN",
            "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN_FILE",
            "coordinator.diagnostics_token",
            sources,
        )?;
        set_string(
            &mut coordinator.database_backend,
            environment,
            "BLAKTAIL_DATABASE_BACKEND",
            "coordinator.database_backend",
            sources,
        );
        let canonical_database = env(environment, "BLAKTAIL_DATABASE");
        let deprecated_database = env(environment, "BLAKTAIL_DB_PATH");
        match (canonical_database, deprecated_database) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Environment {
                    field: "coordinator.database".into(),
                    message: "BLAKTAIL_DATABASE and deprecated BLAKTAIL_DB_PATH are ambiguous; remove BLAKTAIL_DB_PATH".into(),
                })
            }
            (Some(path), None) => {
                coordinator.database = path.into();
                mark_env(sources, "coordinator.database", "BLAKTAIL_DATABASE");
            }
            (None, Some(path)) => {
                coordinator.database = path.into();
                mark_env(sources, "coordinator.database", "BLAKTAIL_DB_PATH");
                warnings.push(
                    "BLAKTAIL_DB_PATH is deprecated; use BLAKTAIL_DATABASE before schema v2"
                        .into(),
                );
            }
            (None, None) => {}
        }
        set_secret(
            &mut coordinator.database_url,
            environment,
            "BLAKTAIL_DATABASE_URL",
            "BLAKTAIL_DATABASE_URL_FILE",
            "coordinator.database_url",
            sources,
        )?;
        set_string(
            &mut coordinator.database_storage,
            environment,
            "BLAKTAIL_DATABASE_STORAGE",
            "coordinator.database_storage",
            sources,
        );
        set_bool(
            &mut coordinator.allow_unsafe_efs_sqlite,
            environment,
            "BLAKTAIL_ALLOW_UNSAFE_EFS_SQLITE",
            "coordinator.allow_unsafe_efs_sqlite",
            sources,
        )?;
        set_string(
            &mut coordinator.tls_mode,
            environment,
            "BLAKTAIL_TLS_MODE",
            "coordinator.tls_mode",
            sources,
        );
        set_path(
            &mut coordinator.tls_cert,
            environment,
            "BLAKTAIL_TLS_CERT",
            "coordinator.tls_cert",
            sources,
        );
        if let Some(path) = env(environment, "BLAKTAIL_TLS_KEY") {
            coordinator.tls_key = Some(SecretRef::file(path));
            mark_env(sources, "coordinator.tls_key", "BLAKTAIL_TLS_KEY");
        }
        set_secret(
            &mut coordinator.auth_hmac_secret,
            environment,
            "BLAKTAIL_AUTH_HMAC_SECRET",
            "BLAKTAIL_AUTH_HMAC_SECRET_FILE",
            "coordinator.auth_hmac_secret",
            sources,
        )?;
        set_secret(
            &mut coordinator.relay_auth_secret,
            environment,
            "BLAKTAIL_RELAY_AUTH_SECRET",
            "BLAKTAIL_RELAY_AUTH_SECRET_FILE",
            "coordinator.relay_auth_secret",
            sources,
        )?;
        set_list(
            &mut coordinator.relays,
            environment,
            "BLAKTAIL_RELAYS",
            "coordinator.relays",
            sources,
        );
        set_string(
            &mut coordinator.console_url,
            environment,
            "BLAKTAIL_CONSOLE_URL",
            "coordinator.console_url",
            sources,
        );
    }

    if matches!(service, Service::Relay | Service::All) {
        let relay = &mut config.relay;
        set_string(
            &mut relay.region,
            environment,
            "BLAKTAIL_REGION",
            "relay.region",
            sources,
        );
        set_string(
            &mut relay.bind,
            environment,
            "BLAKTAIL_RELAY_BIND",
            "relay.bind",
            sources,
        );
        set_string(
            &mut relay.metrics_bind,
            environment,
            "BLAKTAIL_RELAY_METRICS_BIND",
            "relay.metrics_bind",
            sources,
        );
        set_bool(
            &mut relay.allow_public_metrics,
            environment,
            "BLAKTAIL_RELAY_ALLOW_PUBLIC_METRICS",
            "relay.allow_public_metrics",
            sources,
        )?;
        set_secret(
            &mut relay.diagnostics_token,
            environment,
            "BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN",
            "BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN_FILE",
            "relay.diagnostics_token",
            sources,
        )?;
        set_secret(
            &mut relay.auth_secret,
            environment,
            "BLAKTAIL_RELAY_AUTH_SECRET",
            "BLAKTAIL_RELAY_AUTH_SECRET_FILE",
            "relay.auth_secret",
            sources,
        )?;
        set_u64(
            &mut relay.idle_seconds,
            environment,
            "BLAKTAIL_RELAY_IDLE_SECONDS",
            "relay.idle_seconds",
            sources,
        )?;
        set_u32(
            &mut relay.rate_per_second,
            environment,
            "BLAKTAIL_RELAY_RATE_PER_SECOND",
            "relay.rate_per_second",
            sources,
        )?;
        set_u32(
            &mut relay.rate_burst,
            environment,
            "BLAKTAIL_RELAY_RATE_BURST",
            "relay.rate_burst",
            sources,
        )?;
    }

    if matches!(service, Service::Agent | Service::All) {
        let agent = &mut config.agent;
        set_path(
            &mut agent.state_dir,
            environment,
            "BLAKTAIL_AGENT_STATE_DIR",
            "agent.state_dir",
            sources,
        );
        if let Some(value) = env(environment, "BLAKTAIL_AGENT_COORD_URL") {
            agent.coordinator_url = Some(value.into());
            mark_env(sources, "agent.coordinator_url", "BLAKTAIL_AGENT_COORD_URL");
        }
        if let Some(value) = env(environment, "BLAKTAIL_COORDINATOR_URL") {
            if env(environment, "BLAKTAIL_AGENT_COORD_URL").is_some() {
                return Err(ConfigError::Environment {
                    field: "agent.coordinator_url".into(),
                    message: "BLAKTAIL_AGENT_COORD_URL and deprecated BLAKTAIL_COORDINATOR_URL are ambiguous; remove BLAKTAIL_COORDINATOR_URL".into(),
                });
            }
            agent.coordinator_url = Some(value.into());
            mark_env(sources, "agent.coordinator_url", "BLAKTAIL_COORDINATOR_URL");
            warnings.push(
                "BLAKTAIL_COORDINATOR_URL is deprecated; use BLAKTAIL_AGENT_COORD_URL before schema v2"
                    .into(),
            );
        }
        set_string(
            &mut agent.interface,
            environment,
            "BLAKTAIL_AGENT_INTERFACE",
            "agent.interface",
            sources,
        );
        set_u64(
            &mut agent.poll_seconds,
            environment,
            "BLAKTAIL_AGENT_POLL_SECONDS",
            "agent.poll_seconds",
            sources,
        )?;
        set_list(
            &mut agent.advertised_routes,
            environment,
            "BLAKTAIL_AGENT_ADVERTISE_ROUTES",
            "agent.advertised_routes",
            sources,
        );
    }

    if matches!(service, Service::Console | Service::All) {
        let console = &mut config.console;
        set_string(
            &mut console.region,
            environment,
            "BLAKTAIL_REGION",
            "console.region",
            sources,
        );
        if let Some(value) = env(environment, "PORT") {
            console.port = value.parse::<u16>().map_err(|_| ConfigError::Environment {
                field: "console.port".into(),
                message: "PORT must be an integer from 1 to 65535".into(),
            })?;
            mark_env(sources, "console.port", "PORT");
        }
        set_secret(
            &mut console.database_url,
            environment,
            "DATABASE_URL",
            "DATABASE_URL_FILE",
            "console.database_url",
            sources,
        )?;
        set_string(
            &mut console.base_url,
            environment,
            "BETTER_AUTH_URL",
            "console.base_url",
            sources,
        );
        set_list(
            &mut console.trusted_origins,
            environment,
            "BETTER_AUTH_TRUSTED_ORIGINS",
            "console.trusted_origins",
            sources,
        );
        set_string(
            &mut console.coordinator_url,
            environment,
            "COORD_BASE_URL",
            "console.coordinator_url",
            sources,
        );
        if let Some(value) = env(environment, "NODE_EXTRA_CA_CERTS") {
            console.coordinator_ca_file = Some(value.into());
            mark_env(
                sources,
                "console.coordinator_ca_file",
                "NODE_EXTRA_CA_CERTS",
            );
        }
        set_secret(
            &mut console.auth_secret,
            environment,
            "BETTER_AUTH_SECRET",
            "BETTER_AUTH_SECRET_FILE",
            "console.auth_secret",
            sources,
        )?;
        set_secret(
            &mut console.coordinator_auth_secret,
            environment,
            "BLAKTAIL_AUTH_HMAC_SECRET",
            "BLAKTAIL_AUTH_HMAC_SECRET_FILE",
            "console.coordinator_auth_secret",
            sources,
        )?;
    }
    Ok(())
}

fn validate_diagnostics(config: &DiagnosticsConfig, violations: &mut Vec<Violation>) {
    if config.log_filter.trim().is_empty() {
        violation(violations, "diagnostics.log_filter", "must not be empty");
    } else if tracing_subscriber::EnvFilter::try_new(&config.log_filter).is_err() {
        violation(
            violations,
            "diagnostics.log_filter",
            "must be a valid tracing filter",
        );
    }
    if !(1..=500).contains(&config.support_log_lines) {
        violation(
            violations,
            "diagnostics.support_log_lines",
            "must be between 1 and 500",
        );
    }
}

fn validate_coordinator(loaded: &LoadedConfig, violations: &mut Vec<Violation>) {
    let config = &loaded.config.coordinator;
    validate_region(&config.region, "coordinator.region", violations);
    validate_bind(&config.bind, "coordinator.bind", false, false, violations);
    validate_bind(
        &config.metrics_bind,
        "coordinator.metrics_bind",
        true,
        config.allow_public_metrics,
        violations,
    );
    if config.allow_public_metrics || config.diagnostics_token.is_some() {
        validate_secret(
            loaded,
            config.diagnostics_token.as_ref(),
            "coordinator.diagnostics_token",
            32,
            violations,
        );
    }
    match config.database_backend.as_str() {
        "sqlite" => {
            if config.database.as_os_str().is_empty() {
                violation(violations, "coordinator.database", "must not be empty");
            }
            if config.database_url.is_some() {
                violation(
                    violations,
                    "coordinator.database_url",
                    "must not be set when database_backend is sqlite",
                );
            }
            match config.database_storage.as_str() {
                "local" => {
                    if config.allow_unsafe_efs_sqlite {
                        violation(
                            violations,
                            "coordinator.allow_unsafe_efs_sqlite",
                            "must be false when database_storage is local",
                        );
                    }
                }
                "efs" => {
                    if loaded.config.deployment.profile != "e2e" || !config.allow_unsafe_efs_sqlite
                    {
                        violation(
                            violations,
                            "coordinator.database_storage",
                            "SQLite on EFS is allowed only for the explicit e2e profile with allow_unsafe_efs_sqlite=true; use local durable storage or PostgreSQL",
                        );
                    }
                }
                _ => violation(
                    violations,
                    "coordinator.database_storage",
                    "must be local or efs when database_backend is sqlite",
                ),
            }
        }
        "postgres" => {
            validate_secret(
                loaded,
                config.database_url.as_ref(),
                "coordinator.database_url",
                12,
                violations,
            );
            if let Some(reference) = config.database_url.as_ref() {
                if let Ok(value) = loaded.secret(reference, "coordinator.database_url") {
                    match value.as_str("coordinator.database_url") {
                        Ok(url)
                            if url.starts_with("postgres://")
                                || url.starts_with("postgresql://") => {}
                        Ok(_) => violation(
                            violations,
                            "coordinator.database_url",
                            "must use a postgres:// or postgresql:// URL",
                        ),
                        Err(error) => {
                            violation(violations, "coordinator.database_url", error.to_string())
                        }
                    }
                }
            }
            if config.database_storage != "network" {
                violation(
                    violations,
                    "coordinator.database_storage",
                    "must be network when database_backend is postgres",
                );
            }
            if config.allow_unsafe_efs_sqlite {
                violation(
                    violations,
                    "coordinator.allow_unsafe_efs_sqlite",
                    "must be false when database_backend is postgres",
                );
            }
        }
        _ => violation(
            violations,
            "coordinator.database_backend",
            "must be sqlite or postgres",
        ),
    }
    if config.tls_mode != "files" {
        violation(
            violations,
            "coordinator.tls_mode",
            "must be files; plaintext and implicit TLS modes are not supported",
        );
    }
    if config.tls_cert.as_os_str().is_empty() {
        violation(
            violations,
            "coordinator.tls_cert",
            "certificate file is required when tls_mode=files",
        );
    } else if !config.tls_cert.is_absolute() {
        violation(
            violations,
            "coordinator.tls_cert",
            "certificate file path must be absolute",
        );
    } else {
        match fs::metadata(&config.tls_cert) {
            Ok(metadata) if !metadata.is_file() => violation(
                violations,
                "coordinator.tls_cert",
                "certificate path must be a regular file",
            ),
            Ok(_) => {}
            Err(error) => violation(
                violations,
                "coordinator.tls_cert",
                format!("certificate file could not be read: {error}"),
            ),
        }
    }
    validate_secret(
        loaded,
        config.tls_key.as_ref(),
        "coordinator.tls_key",
        1,
        violations,
    );
    validate_secret(
        loaded,
        config.auth_hmac_secret.as_ref(),
        "coordinator.auth_hmac_secret",
        32,
        violations,
    );
    if !config.relays.is_empty() {
        validate_secret(
            loaded,
            config.relay_auth_secret.as_ref(),
            "coordinator.relay_auth_secret",
            32,
            violations,
        );
    }
    for (index, relay) in config.relays.iter().enumerate() {
        validate_relay_endpoint(relay, &format!("coordinator.relays[{index}]"), violations);
    }
    validate_http_url(&config.console_url, "coordinator.console_url", violations);
}

fn validate_relay(loaded: &LoadedConfig, violations: &mut Vec<Violation>) {
    let config = &loaded.config.relay;
    validate_region(&config.region, "relay.region", violations);
    validate_bind(&config.bind, "relay.bind", false, false, violations);
    validate_bind(
        &config.metrics_bind,
        "relay.metrics_bind",
        true,
        config.allow_public_metrics,
        violations,
    );
    if config.allow_public_metrics || config.diagnostics_token.is_some() {
        validate_secret(
            loaded,
            config.diagnostics_token.as_ref(),
            "relay.diagnostics_token",
            32,
            violations,
        );
    }
    validate_secret(
        loaded,
        config.auth_secret.as_ref(),
        "relay.auth_secret",
        32,
        violations,
    );
    if !(10..=86_400).contains(&config.idle_seconds) {
        violation(
            violations,
            "relay.idle_seconds",
            "must be between 10 and 86400",
        );
    }
    if !(1..=100_000).contains(&config.rate_per_second) {
        violation(
            violations,
            "relay.rate_per_second",
            "must be between 1 and 100000",
        );
    }
    if config.rate_burst < config.rate_per_second || config.rate_burst > 1_000_000 {
        violation(
            violations,
            "relay.rate_burst",
            "must be at least rate_per_second and no more than 1000000",
        );
    }
}

fn validate_agent(loaded: &LoadedConfig, violations: &mut Vec<Violation>) {
    let config = &loaded.config.agent;
    if config.state_dir.as_os_str().is_empty() || !config.state_dir.is_absolute() {
        violation(violations, "agent.state_dir", "must be an absolute path");
    }
    if let Some(url) = &config.coordinator_url {
        validate_http_url(url, "agent.coordinator_url", violations);
    }
    if config.interface.trim().is_empty() || config.interface.len() > 15 {
        violation(
            violations,
            "agent.interface",
            "must contain 1 to 15 characters",
        );
    }
    if !(1..=3_600).contains(&config.poll_seconds) {
        violation(
            violations,
            "agent.poll_seconds",
            "must be between 1 and 3600",
        );
    }
    for (index, route) in config.advertised_routes.iter().enumerate() {
        validate_cidr(
            route,
            &format!("agent.advertised_routes[{index}]"),
            violations,
        );
    }
}

fn validate_console(loaded: &LoadedConfig, violations: &mut Vec<Violation>) {
    let config = &loaded.config.console;
    validate_region(&config.region, "console.region", violations);
    if config.port == 0 {
        violation(violations, "console.port", "must not be zero");
    }
    match config.database_url.as_ref() {
        Some(reference) => match loaded.secret(reference, "console.database_url") {
            Ok(value) => match value.as_str("console.database_url") {
                Ok(database_url) => match Url::parse(database_url) {
                    Ok(url) if matches!(url.scheme(), "postgres" | "postgresql") => {}
                    Ok(_) => violation(
                        violations,
                        "console.database_url",
                        "must use postgres:// or postgresql://",
                    ),
                    Err(_) => violation(
                        violations,
                        "console.database_url",
                        "must be a valid PostgreSQL URL",
                    ),
                },
                Err(_) => violation(
                    violations,
                    "console.database_url",
                    "secret must contain valid UTF-8",
                ),
            },
            Err(error) => violation(violations, "console.database_url", error.to_string()),
        },
        None => violation(
            violations,
            "console.database_url",
            "secret reference is required",
        ),
    }
    validate_origin(&config.base_url, "console.base_url", violations);
    validate_http_url(
        &config.coordinator_url,
        "console.coordinator_url",
        violations,
    );
    if let Some(path) = &config.coordinator_ca_file {
        if path.as_os_str().is_empty() || !path.is_absolute() {
            violation(
                violations,
                "console.coordinator_ca_file",
                "must be an absolute path",
            );
        } else {
            match fs::metadata(path) {
                Ok(metadata) if !metadata.is_file() => violation(
                    violations,
                    "console.coordinator_ca_file",
                    "CA path must be a regular file",
                ),
                Ok(_) => {}
                Err(error) => violation(
                    violations,
                    "console.coordinator_ca_file",
                    format!("CA file could not be read: {error}"),
                ),
            }
        }
    }
    if config.trusted_origins.is_empty() {
        violation(
            violations,
            "console.trusted_origins",
            "must contain at least the console base origin",
        );
    }
    let base_origin = origin(&config.base_url);
    let mut includes_base = false;
    for (index, value) in config.trusted_origins.iter().enumerate() {
        let field = format!("console.trusted_origins[{index}]");
        validate_origin(value, &field, violations);
        if origin(value).is_some() && origin(value) == base_origin {
            includes_base = true;
        }
    }
    if base_origin.is_some() && !includes_base {
        violation(
            violations,
            "console.trusted_origins",
            "must include console.base_url origin",
        );
    }
    validate_text_secret(
        loaded,
        config.auth_secret.as_ref(),
        "console.auth_secret",
        32,
        violations,
    );
    validate_text_secret(
        loaded,
        config.coordinator_auth_secret.as_ref(),
        "console.coordinator_auth_secret",
        32,
        violations,
    );
}

fn validate_secret(
    loaded: &LoadedConfig,
    reference: Option<&SecretRef>,
    field: &str,
    minimum: usize,
    violations: &mut Vec<Violation>,
) {
    let Some(reference) = reference else {
        violation(violations, field, "secret reference is required");
        return;
    };
    if let SecretRef::File { path, .. } = reference {
        if !path.is_absolute() {
            violation(violations, field, "secret file path must be absolute");
            return;
        }
    }
    match loaded.secret(reference, field) {
        Ok(value) if value.as_bytes().len() >= minimum => {}
        Ok(_) => violation(
            violations,
            field,
            format!("secret must be at least {minimum} bytes"),
        ),
        Err(error) => violation(violations, field, error.to_string()),
    }
}

fn validate_text_secret(
    loaded: &LoadedConfig,
    reference: Option<&SecretRef>,
    field: &str,
    minimum: usize,
    violations: &mut Vec<Violation>,
) {
    let Some(reference) = reference else {
        violation(violations, field, "secret reference is required");
        return;
    };
    if let SecretRef::File { path, .. } = reference {
        if !path.is_absolute() {
            violation(violations, field, "secret file path must be absolute");
            return;
        }
    }
    match loaded.secret(reference, field) {
        Ok(value) if value.as_bytes().len() < minimum => violation(
            violations,
            field,
            format!("secret must be at least {minimum} bytes"),
        ),
        Ok(value) if value.as_str(field).is_err() => {
            violation(violations, field, "secret must contain valid UTF-8")
        }
        Ok(_) => {}
        Err(error) => violation(violations, field, error.to_string()),
    }
}

pub fn is_australian_region(region: &str) -> bool {
    matches!(
        region.trim().to_ascii_lowercase().as_str(),
        "ap-southeast-2"
            | "australiaeast"
            | "australiasoutheast"
            | "australia-southeast1"
            | "australia-southeast2"
    )
}

fn validate_region(region: &str, field: &str, violations: &mut Vec<Violation>) {
    if !is_australian_region(region) {
        violation(
            violations,
            field,
            "must be an approved Australian cloud region",
        );
    }
}

fn validate_bind(
    value: &str,
    field: &str,
    private_by_default: bool,
    public_allowed: bool,
    violations: &mut Vec<Violation>,
) {
    match value.parse::<SocketAddr>() {
        Ok(address) if address.port() == 0 => violation(violations, field, "port must not be zero"),
        Ok(address) if private_by_default && !address.ip().is_loopback() && !public_allowed => {
            violation(
                violations,
                field,
                "must bind to loopback unless explicit public metrics exposure is enabled",
            )
        }
        Ok(_) => {}
        Err(_) => violation(violations, field, "must be an IP socket address"),
    }
}

fn validate_http_url(value: &str, field: &str, violations: &mut Vec<Violation>) {
    let url = match Url::parse(value) {
        Ok(url) => url,
        Err(_) => {
            violation(violations, field, "must be a valid HTTP(S) URL");
            return;
        }
    };
    if url.host().is_none() {
        violation(violations, field, "must include a host");
    }
    if url.port() == Some(0) {
        violation(violations, field, "port must not be zero");
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && url_host_is_loopback(&url)) {
        violation(
            violations,
            field,
            "must use HTTPS except for a loopback development URL",
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        violation(violations, field, "must not include credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        violation(violations, field, "must not include a query or fragment");
    }
}

fn validate_origin(value: &str, field: &str, violations: &mut Vec<Violation>) {
    let before = violations.len();
    validate_http_url(value, field, violations);
    if before != violations.len() {
        return;
    }
    let Ok(url) = Url::parse(value) else {
        return;
    };
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        violation(
            violations,
            field,
            "must be an origin without credentials, path, query, or fragment",
        );
    }
}

fn origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!("{}://{host}{port}", url.scheme()))
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Splits a `coordinator.relays` entry into its UDP endpoint and optional
/// declared region: `relay-a.example.org.au:3478#ap-southeast-2`. Untagged
/// entries inherit `coordinator.region`. An optional `;wss=<url>` suffix
/// (see [`relay_entry_wss`]) is ignored here.
pub fn split_relay_entry(entry: &str) -> (&str, Option<&str>) {
    let entry = relay_entry_parts(entry).0;
    match entry.split_once('#') {
        Some((endpoint, region)) => (endpoint.trim(), Some(region.trim())),
        None => (entry, None),
    }
}

/// The WebSocket-over-TLS fallback served by the same relay process, from
/// `relay-a.example.org.au:3478#ap-southeast-2;wss=wss://relay-a.example.org.au/v1/relay`.
pub fn relay_entry_wss(entry: &str) -> Option<&str> {
    relay_entry_parts(entry).1
}

fn relay_entry_parts(entry: &str) -> (&str, Option<&str>) {
    let entry = entry.trim();
    match entry.split_once(';') {
        Some((relay, option)) => (
            relay.trim(),
            option
                .trim()
                .strip_prefix("wss=")
                .map(str::trim)
                .filter(|url| !url.is_empty()),
        ),
        None => (entry, None),
    }
}

fn validate_relay_endpoint(entry: &str, field: &str, violations: &mut Vec<Violation>) {
    if let Some((_, option)) = entry.split_once(';') {
        let valid = relay_entry_wss(entry).is_some_and(|url| {
            Url::parse(url).is_ok_and(|url| {
                url.scheme() == "wss"
                    && url.host_str().is_some_and(|host| !host.is_empty())
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
            })
        });
        if !valid || !option.trim().starts_with("wss=") {
            violation(
                violations,
                field,
                "only a ;wss=wss://host/path fallback without credentials may follow the relay",
            );
        }
    }
    let (value, region) = split_relay_entry(entry);
    if let Some(region) = region {
        if !is_australian_region(region) {
            violation(
                violations,
                field,
                "declares a region that is not an approved Australian cloud region",
            );
        }
    }
    let candidate = format!("udp://{value}");
    match Url::parse(&candidate) {
        Ok(url)
            if url.host().is_some()
                && url.port().is_some_and(|port| port > 0)
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(url.path(), "" | "/")
                && url.query().is_none()
                && url.fragment().is_none() => {}
        _ => violation(
            violations,
            field,
            "must be a hostname or IP with a non-zero UDP port",
        ),
    }
}

fn validate_cidr(value: &str, field: &str, violations: &mut Vec<Violation>) {
    let Some((address, prefix)) = value.split_once('/') else {
        violation(violations, field, "must be an IPv4 or IPv6 CIDR");
        return;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        violation(violations, field, "must contain a valid IP address");
        return;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        violation(violations, field, "must contain a numeric prefix length");
        return;
    };
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        violation(
            violations,
            field,
            format!("prefix length must be at most {maximum}"),
        );
    }
}

fn violation(violations: &mut Vec<Violation>, field: &str, message: impl Into<String>) {
    violations.push(Violation {
        field: field.into(),
        message: message.into(),
    });
}

#[derive(Clone)]
pub struct ConfigHandle(Arc<RwLock<RootConfig>>);

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReloadPlan {
    NoChange,
    Safe { fields: Vec<String> },
    RestartRequired { fields: Vec<String> },
}

impl ConfigHandle {
    pub fn new(config: RootConfig) -> Self {
        Self(Arc::new(RwLock::new(config)))
    }

    pub fn snapshot(&self) -> RootConfig {
        self.0.read().expect("configuration lock poisoned").clone()
    }

    pub fn plan(&self, candidate: &RootConfig) -> ReloadPlan {
        reload_plan(&self.snapshot(), candidate)
    }

    pub fn plan_for_service(&self, candidate: &RootConfig, service: Service) -> ReloadPlan {
        reload_plan_for_service(&self.snapshot(), candidate, service)
    }

    pub fn commit_safe(&self, candidate: RootConfig) -> Result<ReloadPlan, ReloadPlan> {
        self.commit_safe_for_service(candidate, Service::All)
    }

    pub fn commit_safe_for_service(
        &self,
        candidate: RootConfig,
        service: Service,
    ) -> Result<ReloadPlan, ReloadPlan> {
        let mut current = self.0.write().expect("configuration lock poisoned");
        let plan = reload_plan_for_service(&current, &candidate, service);
        match &plan {
            ReloadPlan::NoChange => Ok(plan),
            ReloadPlan::Safe { .. } => {
                current.diagnostics = candidate.diagnostics;
                Ok(plan)
            }
            ReloadPlan::RestartRequired { .. } => Err(plan),
        }
    }
}

pub fn reload_plan(current: &RootConfig, candidate: &RootConfig) -> ReloadPlan {
    reload_plan_for_service(current, candidate, Service::All)
}

pub fn reload_plan_for_service(
    current: &RootConfig,
    candidate: &RootConfig,
    service: Service,
) -> ReloadPlan {
    let mut restart = Vec::new();
    macro_rules! restart_if_changed {
        ($path:literal, $current:expr, $candidate:expr) => {
            if $current != $candidate {
                restart.push($path.into());
            }
        };
    }
    restart_if_changed!(
        "schema_version",
        current.schema_version,
        candidate.schema_version
    );
    restart_if_changed!(
        "deployment.profile",
        current.deployment.profile,
        candidate.deployment.profile
    );
    if matches!(service, Service::Coordinator | Service::All) {
        restart_if_changed!(
            "coordinator.region",
            current.coordinator.region,
            candidate.coordinator.region
        );
        restart_if_changed!(
            "coordinator.bind",
            current.coordinator.bind,
            candidate.coordinator.bind
        );
        restart_if_changed!(
            "coordinator.metrics_bind",
            current.coordinator.metrics_bind,
            candidate.coordinator.metrics_bind
        );
        restart_if_changed!(
            "coordinator.allow_public_metrics",
            current.coordinator.allow_public_metrics,
            candidate.coordinator.allow_public_metrics
        );
        restart_if_changed!(
            "coordinator.diagnostics_token",
            current.coordinator.diagnostics_token,
            candidate.coordinator.diagnostics_token
        );
        restart_if_changed!(
            "coordinator.database_backend",
            current.coordinator.database_backend,
            candidate.coordinator.database_backend
        );
        restart_if_changed!(
            "coordinator.database",
            current.coordinator.database,
            candidate.coordinator.database
        );
        restart_if_changed!(
            "coordinator.database_url",
            current.coordinator.database_url,
            candidate.coordinator.database_url
        );
        restart_if_changed!(
            "coordinator.database_storage",
            current.coordinator.database_storage,
            candidate.coordinator.database_storage
        );
        restart_if_changed!(
            "coordinator.allow_unsafe_efs_sqlite",
            current.coordinator.allow_unsafe_efs_sqlite,
            candidate.coordinator.allow_unsafe_efs_sqlite
        );
        restart_if_changed!(
            "coordinator.tls_mode",
            current.coordinator.tls_mode,
            candidate.coordinator.tls_mode
        );
        restart_if_changed!(
            "coordinator.tls_cert",
            current.coordinator.tls_cert,
            candidate.coordinator.tls_cert
        );
        restart_if_changed!(
            "coordinator.tls_key",
            current.coordinator.tls_key,
            candidate.coordinator.tls_key
        );
        restart_if_changed!(
            "coordinator.auth_hmac_secret",
            current.coordinator.auth_hmac_secret,
            candidate.coordinator.auth_hmac_secret
        );
        restart_if_changed!(
            "coordinator.relay_auth_secret",
            current.coordinator.relay_auth_secret,
            candidate.coordinator.relay_auth_secret
        );
        restart_if_changed!(
            "coordinator.relays",
            current.coordinator.relays,
            candidate.coordinator.relays
        );
        restart_if_changed!(
            "coordinator.console_url",
            current.coordinator.console_url,
            candidate.coordinator.console_url
        );
    }
    if matches!(service, Service::Relay | Service::All) {
        restart_if_changed!("relay.region", current.relay.region, candidate.relay.region);
        restart_if_changed!("relay.bind", current.relay.bind, candidate.relay.bind);
        restart_if_changed!(
            "relay.metrics_bind",
            current.relay.metrics_bind,
            candidate.relay.metrics_bind
        );
        restart_if_changed!(
            "relay.allow_public_metrics",
            current.relay.allow_public_metrics,
            candidate.relay.allow_public_metrics
        );
        restart_if_changed!(
            "relay.diagnostics_token",
            current.relay.diagnostics_token,
            candidate.relay.diagnostics_token
        );
        restart_if_changed!(
            "relay.auth_secret",
            current.relay.auth_secret,
            candidate.relay.auth_secret
        );
        restart_if_changed!(
            "relay.idle_seconds",
            current.relay.idle_seconds,
            candidate.relay.idle_seconds
        );
        restart_if_changed!(
            "relay.rate_per_second",
            current.relay.rate_per_second,
            candidate.relay.rate_per_second
        );
        restart_if_changed!(
            "relay.rate_burst",
            current.relay.rate_burst,
            candidate.relay.rate_burst
        );
    }
    if matches!(service, Service::Agent | Service::All) {
        restart_if_changed!(
            "agent.state_dir",
            current.agent.state_dir,
            candidate.agent.state_dir
        );
        restart_if_changed!(
            "agent.coordinator_url",
            current.agent.coordinator_url,
            candidate.agent.coordinator_url
        );
        restart_if_changed!(
            "agent.interface",
            current.agent.interface,
            candidate.agent.interface
        );
        restart_if_changed!(
            "agent.poll_seconds",
            current.agent.poll_seconds,
            candidate.agent.poll_seconds
        );
        restart_if_changed!(
            "agent.advertised_routes",
            current.agent.advertised_routes,
            candidate.agent.advertised_routes
        );
    }
    if matches!(service, Service::Console | Service::All) {
        restart_if_changed!(
            "console.region",
            current.console.region,
            candidate.console.region
        );
        restart_if_changed!("console.port", current.console.port, candidate.console.port);
        restart_if_changed!(
            "console.database_url",
            current.console.database_url,
            candidate.console.database_url
        );
        restart_if_changed!(
            "console.base_url",
            current.console.base_url,
            candidate.console.base_url
        );
        restart_if_changed!(
            "console.trusted_origins",
            current.console.trusted_origins,
            candidate.console.trusted_origins
        );
        restart_if_changed!(
            "console.coordinator_url",
            current.console.coordinator_url,
            candidate.console.coordinator_url
        );
        restart_if_changed!(
            "console.coordinator_ca_file",
            current.console.coordinator_ca_file,
            candidate.console.coordinator_ca_file
        );
        restart_if_changed!(
            "console.auth_secret",
            current.console.auth_secret,
            candidate.console.auth_secret
        );
        restart_if_changed!(
            "console.coordinator_auth_secret",
            current.console.coordinator_auth_secret,
            candidate.console.coordinator_auth_secret
        );
    }
    if service == Service::Console {
        restart_if_changed!(
            "diagnostics.log_filter",
            current.diagnostics.log_filter,
            candidate.diagnostics.log_filter
        );
        restart_if_changed!(
            "diagnostics.support_log_lines",
            current.diagnostics.support_log_lines,
            candidate.diagnostics.support_log_lines
        );
    }
    if !restart.is_empty() {
        return ReloadPlan::RestartRequired { fields: restart };
    }
    let mut safe = Vec::new();
    if service != Service::Console
        && current.diagnostics.log_filter != candidate.diagnostics.log_filter
    {
        safe.push("diagnostics.log_filter".into());
    }
    if service != Service::Console
        && current.diagnostics.support_log_lines != candidate.diagnostics.support_log_lines
    {
        safe.push("diagnostics.support_log_lines".into());
    }
    if safe.is_empty() {
        ReloadPlan::NoChange
    } else {
        ReloadPlan::Safe { fields: safe }
    }
}

#[derive(Debug, Serialize)]
pub struct SupportPreview {
    pub service: Service,
    pub schema_version: u32,
    pub log_lines: usize,
    pub listeners: Vec<String>,
    pub confirmation_digest: String,
}

#[derive(Serialize)]
struct SupportBundle {
    format: &'static str,
    generated_by_version: &'static str,
    schema_version: u32,
    service: Service,
    readiness: BTreeMap<&'static str, &'static str>,
    listeners: Vec<String>,
    effective_config: serde_json::Value,
    recent_logs: Vec<String>,
}

pub fn support_preview(
    loaded: &LoadedConfig,
    service: Service,
    log_file: Option<&Path>,
) -> Result<(SupportPreview, Vec<u8>), ConfigError> {
    loaded.validate(service)?;
    let recent_logs = redacted_log_tail(log_file, loaded.config.diagnostics.support_log_lines)?;
    let listeners = configured_listeners(&loaded.config, service);
    let redacted = loaded.redacted_dump(service)?;
    let effective_config = serde_json::from_str(&redacted).expect("redacted dump is JSON");
    let mut readiness = BTreeMap::new();
    readiness.insert("configuration", "valid");
    readiness.insert("external_checks", "not-run-offline");
    let bundle = SupportBundle {
        format: "blaktail-support-v1",
        generated_by_version: env!("CARGO_PKG_VERSION"),
        schema_version: SCHEMA_VERSION,
        service,
        readiness,
        listeners: listeners.clone(),
        effective_config,
        recent_logs,
    };
    let bytes = serde_json::to_vec_pretty(&bundle).expect("support bundle is serializable");
    let digest = hex_digest(&bytes);
    Ok((
        SupportPreview {
            service,
            schema_version: SCHEMA_VERSION,
            log_lines: bundle.recent_logs.len(),
            listeners,
            confirmation_digest: digest,
        },
        bytes,
    ))
}

pub fn write_support_bundle(
    output: &Path,
    confirmation: &str,
    preview: &SupportPreview,
    bytes: &[u8],
) -> Result<(), ConfigError> {
    if confirmation != preview.confirmation_digest {
        return Err(ConfigError::SupportConfirmation);
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("blaktail-support.json"),
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|source| ConfigError::SupportOutput {
            path: temporary.clone(),
            source,
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(ConfigError::SupportOutput {
            path: temporary,
            source,
        });
    }
    fs::rename(&temporary, output).map_err(|source| ConfigError::SupportOutput {
        path: output.to_owned(),
        source,
    })?;
    Ok(())
}

fn configured_listeners(config: &RootConfig, service: Service) -> Vec<String> {
    let mut listeners = Vec::new();
    if matches!(service, Service::Coordinator | Service::All) {
        listeners.push(format!("https {}", config.coordinator.bind));
        listeners.push(format!("private-http {}", config.coordinator.metrics_bind));
    }
    if matches!(service, Service::Relay | Service::All) {
        listeners.push(format!("udp {}", config.relay.bind));
        listeners.push(format!("private-http {}", config.relay.metrics_bind));
    }
    listeners
}

fn redacted_log_tail(path: Option<&Path>, maximum: usize) -> Result<Vec<String>, ConfigError> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let metadata = fs::metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > 2 * 1024 * 1024 {
        return Err(ConfigError::Environment {
            field: "support-bundle.log-file".into(),
            message: "log input exceeds the 2 MiB safety limit".into(),
        });
    }
    let input = Zeroizing::new(
        fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?,
    );
    let lines = input.lines().rev().take(maximum).collect::<Vec<_>>();
    Ok(lines.into_iter().rev().map(redact_log_line).collect())
}

fn redact_log_line(line: &str) -> String {
    let mut redacted = line.chars().take(512).collect::<String>();
    let patterns = [
        (r"(?i)bearer\s+[a-z0-9._~+/=-]+", "Bearer <redacted>"),
        (
            r"(?i)(password|secret|token|cookie|authorization|join[_-]?key|private[_-]?key|database_url)(\s*[:=]\s*)[^\s,;]+",
            "$1$2<redacted>",
        ),
        (r"(?i)postgres(?:ql)?://[^\s,;]+", "<redacted-database-url>"),
        (
            r"(?i)([?&](?:code|device_code|join_key)=)[^&\s]+",
            "$1<redacted>",
        ),
        (
            r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            "<redacted-email>",
        ),
        (
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            "<redacted-id>",
        ),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted-ip>"),
        (
            r"(?i)(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}|(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}",
            "<redacted-ip>",
        ),
    ];
    for (pattern, replacement) in patterns {
        let regex = Regex::new(pattern).expect("redaction pattern is valid");
        redacted = regex.replace_all(&redacted, replacement).into_owned();
    }
    redacted
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub const ENVIRONMENT_OVERRIDES: &[(&str, &str, bool)] = &[
    ("BLAKTAIL_CONFIG", "configuration file path", false),
    ("BLAKTAIL_DEPLOYMENT_PROFILE", "deployment.profile", false),
    ("RUST_LOG", "diagnostics.log_filter", false),
    (
        "BLAKTAIL_SUPPORT_LOG_LINES",
        "diagnostics.support_log_lines",
        false,
    ),
    (
        "BLAKTAIL_REGION",
        "coordinator.region, relay.region, console.region",
        false,
    ),
    ("BLAKTAIL_BIND", "coordinator.bind", false),
    (
        "BLAKTAIL_COORD_METRICS_BIND",
        "coordinator.metrics_bind",
        false,
    ),
    (
        "BLAKTAIL_COORD_ALLOW_PUBLIC_METRICS",
        "coordinator.allow_public_metrics",
        false,
    ),
    (
        "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN",
        "coordinator.diagnostics_token",
        true,
    ),
    (
        "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN_FILE",
        "coordinator.diagnostics_token",
        true,
    ),
    (
        "BLAKTAIL_DATABASE_BACKEND",
        "coordinator.database_backend",
        false,
    ),
    ("BLAKTAIL_DATABASE", "coordinator.database", false),
    (
        "BLAKTAIL_DB_PATH",
        "coordinator.database (deprecated)",
        false,
    ),
    ("BLAKTAIL_DATABASE_URL", "coordinator.database_url", true),
    (
        "BLAKTAIL_DATABASE_URL_FILE",
        "coordinator.database_url",
        true,
    ),
    (
        "BLAKTAIL_DATABASE_STORAGE",
        "coordinator.database_storage",
        false,
    ),
    (
        "BLAKTAIL_ALLOW_UNSAFE_EFS_SQLITE",
        "coordinator.allow_unsafe_efs_sqlite",
        false,
    ),
    ("BLAKTAIL_TLS_MODE", "coordinator.tls_mode", false),
    ("BLAKTAIL_TLS_CERT", "coordinator.tls_cert", false),
    ("BLAKTAIL_TLS_KEY", "coordinator.tls_key", true),
    (
        "BLAKTAIL_TLS_CERT_PEM",
        "container TLS certificate adapter",
        false,
    ),
    ("BLAKTAIL_TLS_KEY_PEM", "container TLS key adapter", true),
    (
        "BLAKTAIL_AUTH_HMAC_SECRET",
        "coordinator/console shared assertion secret",
        true,
    ),
    (
        "BLAKTAIL_AUTH_HMAC_SECRET_FILE",
        "coordinator/console shared assertion secret",
        true,
    ),
    (
        "BLAKTAIL_RELAY_AUTH_SECRET",
        "coordinator/relay capability secret",
        true,
    ),
    (
        "BLAKTAIL_RELAY_AUTH_SECRET_FILE",
        "coordinator/relay capability secret",
        true,
    ),
    ("BLAKTAIL_RELAYS", "coordinator.relays", false),
    ("BLAKTAIL_CONSOLE_URL", "coordinator.console_url", false),
    ("BLAKTAIL_RELAY_BIND", "relay.bind", false),
    ("BLAKTAIL_RELAY_METRICS_BIND", "relay.metrics_bind", false),
    (
        "BLAKTAIL_RELAY_ALLOW_PUBLIC_METRICS",
        "relay.allow_public_metrics",
        false,
    ),
    (
        "BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN",
        "relay.diagnostics_token",
        true,
    ),
    (
        "BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN_FILE",
        "relay.diagnostics_token",
        true,
    ),
    ("BLAKTAIL_RELAY_IDLE_SECONDS", "relay.idle_seconds", false),
    (
        "BLAKTAIL_RELAY_RATE_PER_SECOND",
        "relay.rate_per_second",
        false,
    ),
    ("BLAKTAIL_RELAY_RATE_BURST", "relay.rate_burst", false),
    ("BLAKTAIL_AGENT_STATE_DIR", "agent.state_dir", false),
    ("BLAKTAIL_AGENT_COORD_URL", "agent.coordinator_url", false),
    (
        "BLAKTAIL_COORDINATOR_URL",
        "agent.coordinator_url (deprecated)",
        false,
    ),
    ("BLAKTAIL_AGENT_INTERFACE", "agent.interface", false),
    ("BLAKTAIL_AGENT_POLL_SECONDS", "agent.poll_seconds", false),
    (
        "BLAKTAIL_AGENT_ADVERTISE_ROUTES",
        "agent.advertised_routes",
        false,
    ),
    ("DATABASE_URL", "console.database_url", true),
    ("DATABASE_URL_FILE", "console.database_url", true),
    ("BETTER_AUTH_URL", "console.base_url", false),
    ("PORT", "console.port", false),
    (
        "BETTER_AUTH_TRUSTED_ORIGINS",
        "console.trusted_origins",
        false,
    ),
    ("COORD_BASE_URL", "console.coordinator_url", false),
    ("NODE_EXTRA_CA_CERTS", "console.coordinator_ca_file", false),
    ("BETTER_AUTH_SECRET", "console.auth_secret", true),
    ("BETTER_AUTH_SECRET_FILE", "console.auth_secret", true),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn valid_environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("BLAKTAIL_REGION".into(), "ap-southeast-2".into()),
            ("BLAKTAIL_TLS_CERT".into(), "/tmp/cert.pem".into()),
            ("BLAKTAIL_TLS_KEY".into(), "/tmp/key.pem".into()),
            (
                "BLAKTAIL_AUTH_HMAC_SECRET".into(),
                "coordinator-secret-at-least-32-bytes".into(),
            ),
            (
                "BLAKTAIL_RELAY_AUTH_SECRET".into(),
                "relay-secret-is-separate-and-32-bytes".into(),
            ),
            (
                "BLAKTAIL_CONSOLE_URL".into(),
                "https://console.example".into(),
            ),
            (
                "DATABASE_URL".into(),
                "postgres://db.example/blaktail".into(),
            ),
            ("BETTER_AUTH_URL".into(), "https://console.example".into()),
            (
                "BETTER_AUTH_TRUSTED_ORIGINS".into(),
                "https://console.example".into(),
            ),
            ("COORD_BASE_URL".into(), "https://coord.example".into()),
            (
                "BETTER_AUTH_SECRET".into(),
                "console-secret-is-at-least-32-bytes".into(),
            ),
        ])
    }

    #[test]
    fn unknown_fields_fail_with_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "schema_version=1\n[coordinator]\nunknown_listener=true\n",
        )
        .unwrap();
        let error = LoadedConfig::load_with_environment(
            Some(&path),
            Service::Coordinator,
            valid_environment(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("unknown field `unknown_listener`"));
    }

    #[test]
    fn parse_errors_never_echo_rejected_secret_literals() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let marker = "SHOULD-NOT-APPEAR-IN-ERROR-123456789";
        fs::write(
            &path,
            format!("schema_version=1\n[coordinator]\ntls_key={marker:?}\n"),
        )
        .unwrap();
        let error = LoadedConfig::load_with_environment(
            Some(&path),
            Service::Coordinator,
            valid_environment(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(!error.contains(marker));
        assert!(error.contains("secret references"));

        fs::write(
            &path,
            "schema_version=1\n[coordinator]\ntls_key='file:relative.key'\n",
        )
        .unwrap();
        let error = LoadedConfig::load_with_environment(
            Some(&path),
            Service::Coordinator,
            valid_environment(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("secret file path must be absolute"));

        fs::write(
            &path,
            format!("schema_version=1\n[console]\nport={marker:?}\n"),
        )
        .unwrap();
        let error =
            LoadedConfig::load_with_environment(Some(&path), Service::Console, valid_environment())
                .err()
                .unwrap()
                .to_string();
        assert!(!error.contains(marker));
        assert!(error.contains("console.port"));
        assert!(error.contains("invalid type or format"));
    }

    #[test]
    fn duplicate_deprecated_alias_is_rejected() {
        let mut environment = valid_environment();
        environment.insert("BLAKTAIL_DATABASE".into(), "/tmp/new.sqlite".into());
        environment.insert("BLAKTAIL_DB_PATH".into(), "/tmp/old.sqlite".into());
        let error = LoadedConfig::load_with_environment(None, Service::Coordinator, environment)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("ambiguous"));
        assert!(error.contains("BLAKTAIL_DB_PATH"));
    }

    #[test]
    fn invalid_urls_cidrs_regions_and_public_metrics_are_field_specific() {
        let mut environment = valid_environment();
        environment.insert("BLAKTAIL_REGION".into(), "us-east-1".into());
        environment.insert("RUST_LOG".into(), "[invalid".into());
        environment.insert(
            "BLAKTAIL_CONSOLE_URL".into(),
            "http://public.example".into(),
        );
        environment.insert("BLAKTAIL_COORD_METRICS_BIND".into(), "0.0.0.0:9701".into());
        environment.insert(
            "BLAKTAIL_AGENT_ADVERTISE_ROUTES".into(),
            "10.0.0.0/99".into(),
        );
        let loaded = LoadedConfig::load_with_environment(None, Service::All, environment).unwrap();
        let fields = loaded
            .violations(Service::All)
            .into_iter()
            .map(|violation| violation.field)
            .collect::<BTreeSet<_>>();
        assert!(fields.contains("coordinator.region"));
        assert!(fields.contains("diagnostics.log_filter"));
        assert!(fields.contains("relay.region"));
        assert!(fields.contains("console.region"));
        assert!(fields.contains("coordinator.console_url"));
        assert!(fields.contains("coordinator.metrics_bind"));
        assert!(fields.contains("agent.advertised_routes[0]"));
    }

    #[test]
    fn urls_and_relay_endpoints_reject_embedded_request_data() {
        let mut environment = valid_environment();
        environment.insert(
            "BLAKTAIL_AGENT_COORD_URL".into(),
            "https://operator:secret@coord.example/v1?token=secret".into(),
        );
        environment.insert(
            "BLAKTAIL_RELAYS".into(),
            "relay.example:3478/hidden?token=secret".into(),
        );
        environment.insert(
            "BETTER_AUTH_URL".into(),
            "https://console.example/auth".into(),
        );
        let loaded = LoadedConfig::load_with_environment(None, Service::All, environment).unwrap();
        let fields = loaded
            .violations(Service::All)
            .into_iter()
            .map(|violation| violation.field)
            .collect::<BTreeSet<_>>();
        assert!(fields.contains("agent.coordinator_url"));
        assert!(fields.contains("coordinator.relays[0]"));
        assert!(fields.contains("console.base_url"));
    }

    #[test]
    fn relay_entries_may_declare_only_australian_regions() {
        assert_eq!(
            split_relay_entry(" relay-a.example:3478#australiaeast "),
            ("relay-a.example:3478", Some("australiaeast"))
        );
        assert_eq!(
            split_relay_entry("relay-a.example:3478"),
            ("relay-a.example:3478", None)
        );
        let with_wss = "relay-a.example:3478#australiaeast;wss=wss://relay-a.example.au/v1/relay";
        assert_eq!(
            split_relay_entry(with_wss),
            ("relay-a.example:3478", Some("australiaeast"))
        );
        assert_eq!(
            relay_entry_wss(with_wss),
            Some("wss://relay-a.example.au/v1/relay")
        );
        assert_eq!(relay_entry_wss("relay-a.example:3478"), None);
        let mut environment = valid_environment();
        environment.insert(
            "BLAKTAIL_RELAYS".into(),
            format!(
                "{with_wss},relay-b.example:3478;wss=https://relay-b.example.au/,relay-c.example:3478;wss=wss://u:p@relay-c.example.au/,relay-d.example:3478;proxy=x"
            ),
        );
        let loaded = LoadedConfig::load_with_environment(None, Service::All, environment).unwrap();
        let fields = loaded
            .violations(Service::All)
            .into_iter()
            .map(|violation| violation.field)
            .collect::<BTreeSet<_>>();
        assert!(!fields.contains("coordinator.relays[0]"));
        assert!(fields.contains("coordinator.relays[1]"));
        assert!(fields.contains("coordinator.relays[2]"));
        assert!(fields.contains("coordinator.relays[3]"));
        let mut environment = valid_environment();
        environment.insert(
            "BLAKTAIL_RELAYS".into(),
            "relay-a.example:3478#ap-southeast-2,relay-b.example:3478,relay-c.example:3478#us-east-1"
                .into(),
        );
        let loaded = LoadedConfig::load_with_environment(None, Service::All, environment).unwrap();
        let fields = loaded
            .violations(Service::All)
            .into_iter()
            .map(|violation| violation.field)
            .collect::<BTreeSet<_>>();
        assert!(!fields.contains("coordinator.relays[0]"));
        assert!(!fields.contains("coordinator.relays[1]"));
        assert!(fields.contains("coordinator.relays[2]"));
    }

    #[test]
    fn unsafe_efs_and_contradictory_tls_fail() {
        let mut environment = valid_environment();
        environment.insert("BLAKTAIL_DATABASE_STORAGE".into(), "efs".into());
        environment.insert("BLAKTAIL_TLS_MODE".into(), "disabled".into());
        let loaded =
            LoadedConfig::load_with_environment(None, Service::Coordinator, environment).unwrap();
        let error = loaded
            .validate(Service::Coordinator)
            .unwrap_err()
            .to_string();
        assert!(error.contains("coordinator.database_storage"));
        assert!(error.contains("coordinator.tls_mode"));
    }

    #[test]
    fn postgres_coordinator_requires_a_redacted_postgres_secret() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("coord.pem");
        let private_key = directory.path().join("coord.key");
        fs::write(&certificate, "test certificate").unwrap();
        fs::write(&private_key, "test private key").unwrap();
        let mut environment = valid_environment();
        let database_url = "postgresql://coord:password@db.example/blaktail";
        environment.insert(
            "BLAKTAIL_TLS_CERT".into(),
            certificate.display().to_string(),
        );
        environment.insert("BLAKTAIL_TLS_KEY".into(), private_key.display().to_string());
        environment.insert("BLAKTAIL_DATABASE_BACKEND".into(), "postgres".into());
        environment.insert("BLAKTAIL_DATABASE_STORAGE".into(), "network".into());
        environment.insert("BLAKTAIL_DATABASE_URL".into(), database_url.into());
        let loaded =
            LoadedConfig::load_with_environment(None, Service::Coordinator, environment.clone())
                .unwrap();
        loaded.validate(Service::Coordinator).unwrap();
        let dump = loaded.redacted_dump(Service::Coordinator).unwrap();
        assert!(!dump.contains(database_url));
        assert!(dump.contains("<redacted:environment>"));

        environment.insert("BLAKTAIL_DATABASE_URL".into(), "sqlite:///tmp/wrong".into());
        let loaded =
            LoadedConfig::load_with_environment(None, Service::Coordinator, environment).unwrap();
        let error = loaded
            .validate(Service::Coordinator)
            .unwrap_err()
            .to_string();
        assert!(error.contains("coordinator.database_url"));
        assert!(!error.contains("sqlite:///tmp/wrong"));
    }

    #[test]
    fn redacted_dump_never_contains_generated_secrets() {
        for index in 0..100 {
            let marker = format!("UNIQUE-SECRET-{index:03}-{}", "x".repeat(40));
            let mut environment = valid_environment();
            environment.insert("BLAKTAIL_AUTH_HMAC_SECRET".into(), marker.clone());
            environment.insert("BETTER_AUTH_SECRET".into(), marker.clone());
            let loaded =
                LoadedConfig::load_with_environment(None, Service::All, environment).unwrap();
            let dump = loaded.redacted_dump(Service::All).unwrap();
            assert!(!dump.contains(&marker));
            assert!(!dump.contains("postgres://db.example/blaktail"));
            assert!(dump.contains("<redacted:environment>"));
        }
    }

    #[test]
    fn safe_reload_is_atomic_and_restart_fields_remain_unchanged() {
        let original = RootConfig::default();
        let handle = ConfigHandle::new(original.clone());
        let mut safe = original.clone();
        safe.diagnostics.log_filter = "warn,blaktail=debug".into();
        let reader = {
            let handle = handle.clone();
            thread::spawn(move || {
                for _ in 0..1_000 {
                    let value = handle.snapshot().diagnostics.log_filter;
                    assert!(value == "info" || value == "warn,blaktail=debug");
                }
            })
        };
        assert!(matches!(
            handle.commit_safe(safe),
            Ok(ReloadPlan::Safe { .. })
        ));
        reader.join().unwrap();

        let before = handle.snapshot();
        let mut restart = before.clone();
        restart.coordinator.bind = "127.0.0.1:8444".into();
        assert_eq!(
            handle.commit_safe(restart),
            Err(ReloadPlan::RestartRequired {
                fields: vec!["coordinator.bind".into()]
            })
        );
        assert_eq!(handle.snapshot(), before);

        let mut unrelated = before.clone();
        unrelated.relay.bind = "127.0.0.1:3479".into();
        assert_eq!(
            handle.plan_for_service(&unrelated, Service::Agent),
            ReloadPlan::NoChange
        );
        assert_eq!(
            handle
                .commit_safe_for_service(unrelated, Service::Agent)
                .unwrap(),
            ReloadPlan::NoChange
        );
        assert_eq!(handle.snapshot(), before);
    }

    #[test]
    fn in_place_secret_rotation_requires_restart_without_exposing_fingerprint() {
        let directory = tempfile::tempdir().unwrap();
        let secret_path = directory.path().join("relay-secret");
        let environment = BTreeMap::from([
            ("BLAKTAIL_REGION".into(), "ap-southeast-2".into()),
            (
                "BLAKTAIL_RELAY_AUTH_SECRET_FILE".into(),
                secret_path.display().to_string(),
            ),
        ]);
        let first_value = "first-relay-secret-value-at-least-32-bytes";
        fs::write(&secret_path, first_value).unwrap();
        let current =
            LoadedConfig::load_with_environment(None, Service::Relay, environment.clone()).unwrap();
        current.validate(Service::Relay).unwrap();

        let second_value = "second-relay-secret-value-at-least-32-bytes";
        fs::write(&secret_path, second_value).unwrap();
        let candidate =
            LoadedConfig::load_with_environment(None, Service::Relay, environment).unwrap();
        candidate.validate(Service::Relay).unwrap();
        assert_eq!(
            reload_plan_for_service(&current.config, &candidate.config, Service::Relay),
            ReloadPlan::RestartRequired {
                fields: vec!["relay.auth_secret".into()]
            }
        );
        let dump = candidate.redacted_dump(Service::Relay).unwrap();
        assert!(!dump.contains(first_value));
        assert!(!dump.contains(second_value));
        assert!(dump.contains("<redacted:file>"));
    }

    #[test]
    fn support_bundle_requires_preview_and_redacts_logs() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("service.log");
        fs::write(
            &log,
            "email=owner@example.com token=very-secret-value peer=203.0.113.8 ipv6=2001:db8::8 id=7d9d69ab-1bc5-4d73-9492-d3df8f06b834 database_url=postgres://owner:password@db.example/blaktail enroll=https://console.example/enroll?code=ABCD-EFGH private_key=base64-material\n",
        )
        .unwrap();
        let loaded =
            LoadedConfig::load_with_environment(None, Service::Agent, BTreeMap::new()).unwrap();
        loaded.validate(Service::Agent).unwrap();
        let (preview, bytes) = support_preview(&loaded, Service::Agent, Some(&log)).unwrap();
        let output = directory.path().join("support.json");
        assert!(matches!(
            write_support_bundle(&output, "wrong", &preview, &bytes),
            Err(ConfigError::SupportConfirmation)
        ));
        write_support_bundle(&output, &preview.confirmation_digest, &preview, &bytes).unwrap();
        let bundle = fs::read_to_string(output).unwrap();
        assert!(!bundle.contains("owner@example.com"));
        assert!(!bundle.contains("very-secret-value"));
        assert!(!bundle.contains("203.0.113.8"));
        assert!(!bundle.contains("2001:db8::8"));
        assert!(!bundle.contains("7d9d69ab-1bc5-4d73-9492-d3df8f06b834"));
        assert!(!bundle.contains("postgres://owner:password"));
        assert!(!bundle.contains("ABCD-EFGH"));
        assert!(!bundle.contains("base64-material"));
    }

    #[test]
    fn checked_in_schema_and_reference_cover_every_environment_override() {
        let schema = include_str!("../../config/schema-v1.json");
        let parsed: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(parsed["properties"]["schema_version"]["const"], 1);
        let defaults = serde_json::to_value(RootConfig::default()).unwrap();
        let root_fields = defaults
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let schema_root_fields = parsed["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(schema_root_fields, root_fields);
        let documentation = include_str!("../../docs/configuration.md");
        for section in [
            "deployment",
            "diagnostics",
            "coordinator",
            "relay",
            "agent",
            "console",
        ] {
            let runtime_fields = defaults[section]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let schema_fields = parsed["$defs"][section]["properties"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert_eq!(schema_fields, runtime_fields, "schema drift in {section}");
            for field in runtime_fields {
                let path = format!("{section}.{field}");
                assert!(
                    documentation.contains(&path),
                    "configuration reference is missing {path}"
                );
            }
        }
        for (name, _, _) in ENVIRONMENT_OVERRIDES {
            assert!(
                documentation.contains(name),
                "configuration reference is missing {name}"
            );
        }
    }
}
