//! Email, Slack and Microsoft Teams channels on the webhook outbox (draft 18).
//!
//! A channel is a `webhook_destinations` row with a `kind` other than
//! `webhook`, so subscriptions, retries, dead-letter and replay are the same
//! outbox. Chat webhook URLs are sealed in `target_sealed` and never returned;
//! SMTP relay credentials come from the operator's environment and are never
//! stored. Slack and Teams are offshore services: creating one needs an owner
//! and an explicit residency acknowledgement.
//!
//! Quiet hours and digests apply to these human channels only. Warning-level
//! (critical) events and test sends are always delivered at once.

use crate::permissions::{require, Permission};
use crate::webhooks::{
    open_signing_secret, revalidate_resolved_ips, seal_signing_secret, validate_destination_url,
    WebhookDestination,
};
use crate::{append_audit, console_session, hash, now, secret, ApiError, AppState, Session};
use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use chrono::{Datelike, NaiveDate, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, Tls, TlsParameters},
    },
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};
use tracing::warn;
use uuid::Uuid;

pub(crate) const DEFAULT_TIMEZONE: &str = "Australia/Sydney";
pub(crate) const TEST_EVENT: &str = "notification.test";
const MAX_RECIPIENTS: usize = 10;
const MAX_DIGEST_MINUTES: i64 = 24 * 60;
const MAX_DIGEST_ROWS: i64 = 50;
const MAX_DESTINATIONS: i64 = 8;
const MAX_ATTEMPTS: i64 = 8;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RENDERED_FIELDS: usize = 20;
const MAX_FIELD_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Channel kinds

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChannelKind {
    Webhook,
    Email,
    Slack,
    Teams,
}

impl ChannelKind {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "webhook" => Some(Self::Webhook),
            "email" => Some(Self::Email),
            "slack" => Some(Self::Slack),
            "teams" => Some(Self::Teams),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Email => "email",
            Self::Slack => "slack",
            Self::Teams => "teams",
        }
    }

    /// Slack and Teams process message content outside Australia.
    pub(crate) fn offshore(self) -> bool {
        matches!(self, Self::Slack | Self::Teams)
    }
}

/// Warning-level events are critical: quiet hours and digests never hold
/// them back. Test sends are delivered at once so an owner sees the result.
pub(crate) fn is_critical(event_type: &str) -> bool {
    event_type == TEST_EVENT
        || crate::notifications::find(event_type)
            .is_some_and(|kind| kind.severity == crate::notifications::Severity::Warning)
}

// ---------------------------------------------------------------------------
// Quiet hours

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuietHours {
    /// IANA zone, `Australia/Sydney` when omitted.
    #[serde(default = "default_timezone")]
    pub(crate) timezone: String,
    /// Local `HH:MM` when quiet hours begin.
    pub(crate) start: String,
    /// Local `HH:MM` when quiet hours end; before `start` wraps midnight.
    pub(crate) end: String,
}

fn default_timezone() -> String {
    DEFAULT_TIMEZONE.into()
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct QuietWindow {
    tz: Tz,
    start: u32,
    end: u32,
}

fn parse_hhmm(value: &str) -> Option<u32> {
    let (hours, minutes) = value.trim().split_once(':')?;
    if hours.len() != 2 || minutes.len() != 2 {
        return None;
    }
    let hours: u32 = hours.parse().ok()?;
    let minutes: u32 = minutes.parse().ok()?;
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

fn format_hhmm(minutes: u32) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

impl QuietWindow {
    pub(crate) fn parse(input: &QuietHours) -> Result<Self, ApiError> {
        let tz: Tz =
            input.timezone.trim().parse().map_err(|_| {
                ApiError::BadRequest("quiet hours timezone is not an IANA zone".into())
            })?;
        let start = parse_hhmm(&input.start)
            .ok_or_else(|| ApiError::BadRequest("quiet hours start must be HH:MM".into()))?;
        let end = parse_hhmm(&input.end)
            .ok_or_else(|| ApiError::BadRequest("quiet hours end must be HH:MM".into()))?;
        if start == end {
            return Err(ApiError::BadRequest(
                "quiet hours start and end must differ".into(),
            ));
        }
        Ok(Self { tz, start, end })
    }

    fn from_columns(tz: Option<String>, start: Option<i64>, end: Option<i64>) -> Option<Self> {
        let tz: Tz = tz?.parse().ok()?;
        let start = u32::try_from(start?).ok().filter(|value| *value < 1440)?;
        let end = u32::try_from(end?).ok().filter(|value| *value < 1440)?;
        (start != end).then_some(Self { tz, start, end })
    }

    fn view(self) -> QuietHours {
        QuietHours {
            timezone: self.tz.name().into(),
            start: format_hhmm(self.start),
            end: format_hhmm(self.end),
        }
    }

    fn local_minute(self, at: i64) -> Option<(NaiveDate, u32)> {
        let local = Utc.timestamp_opt(at, 0).single()?.with_timezone(&self.tz);
        Some((local.date_naive(), local.hour() * 60 + local.minute()))
    }

    fn contains_minute(self, minute: u32) -> bool {
        if self.start < self.end {
            (self.start..self.end).contains(&minute)
        } else {
            minute >= self.start || minute < self.end
        }
    }

    /// Whether `at` (Unix seconds) falls inside quiet hours, by local wall
    /// clock in the window's zone, so daylight saving moves with the clock.
    pub(crate) fn contains(self, at: i64) -> bool {
        self.local_minute(at)
            .is_some_and(|(_, minute)| self.contains_minute(minute))
    }

    /// The first instant at or after `at` when quiet hours are over. A local
    /// end time skipped by a daylight-saving jump resolves to the first valid
    /// local time after it.
    pub(crate) fn next_end(self, at: i64) -> i64 {
        let Some((date, minute)) = self.local_minute(at) else {
            return at;
        };
        if !self.contains_minute(minute) {
            return at;
        }
        let end_date = if minute >= self.end {
            date.succ_opt().unwrap_or(date)
        } else {
            date
        };
        let mut wall = end_date
            .and_hms_opt(self.end / 60, self.end % 60, 0)
            .unwrap_or_default();
        for _ in 0..8 {
            if let Some(instant) = self.tz.from_local_datetime(&wall).earliest() {
                return instant.timestamp().max(at);
            }
            wall += chrono::Duration::minutes(15);
        }
        at + 3600
    }
}

// ---------------------------------------------------------------------------
// SMTP relay (operator environment)

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SmtpTls {
    Starttls,
    Tls,
    None,
}

#[derive(Clone)]
pub(crate) struct SmtpConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: SmtpTls,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) from: Mailbox,
    pub(crate) ca_pem: Option<Vec<u8>>,
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("from", &self.from.to_string())
            .finish()
    }
}

impl SmtpConfig {
    /// Reads `BLAKTAIL_SMTP_*`. `Ok(None)` when no relay host is set.
    pub(crate) fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, String> {
        let get = |name: &str| {
            get(name)
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let Some(host) = get("BLAKTAIL_SMTP_HOST") else {
            return Ok(None);
        };
        let tls = match get("BLAKTAIL_SMTP_TLS").as_deref().unwrap_or("starttls") {
            "starttls" => SmtpTls::Starttls,
            "tls" => SmtpTls::Tls,
            "none" => SmtpTls::None,
            other => {
                return Err(format!(
                    "BLAKTAIL_SMTP_TLS {other:?} must be starttls, tls or none"
                ))
            }
        };
        let port = match get("BLAKTAIL_SMTP_PORT") {
            Some(value) => value
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or("BLAKTAIL_SMTP_PORT must be a port number")?,
            None => match tls {
                SmtpTls::Tls => 465,
                SmtpTls::Starttls => 587,
                SmtpTls::None => 25,
            },
        };
        let username = get("BLAKTAIL_SMTP_USERNAME");
        let password = match (
            get("BLAKTAIL_SMTP_PASSWORD"),
            get("BLAKTAIL_SMTP_PASSWORD_FILE"),
        ) {
            (Some(value), _) => Some(value),
            (None, Some(path)) => Some(
                std::fs::read_to_string(&path)
                    .map_err(|_| "BLAKTAIL_SMTP_PASSWORD_FILE could not be read".to_owned())?
                    .trim()
                    .to_owned(),
            ),
            (None, None) => None,
        };
        if username.is_some() != password.is_some() {
            return Err("set both BLAKTAIL_SMTP_USERNAME and a password, or neither".into());
        }
        if tls == SmtpTls::None && username.is_some() {
            return Err("SMTP credentials are never sent without TLS; use starttls or tls".into());
        }
        let from: Mailbox = get("BLAKTAIL_SMTP_FROM")
            .ok_or("BLAKTAIL_SMTP_FROM is required when BLAKTAIL_SMTP_HOST is set")?
            .parse()
            .map_err(|_| "BLAKTAIL_SMTP_FROM is not an email address".to_owned())?;
        let ca_pem = match get("BLAKTAIL_SMTP_CA_FILE") {
            Some(path) => Some(
                std::fs::read(&path)
                    .map_err(|_| "BLAKTAIL_SMTP_CA_FILE could not be read".to_owned())?,
            ),
            None => None,
        };
        Ok(Some(Self {
            host,
            port,
            tls,
            username,
            password,
            from,
            ca_pem,
        }))
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let tls = match self.tls {
            SmtpTls::None => Tls::None,
            mode => {
                let mut params = TlsParameters::builder(self.host.clone());
                if let Some(pem) = &self.ca_pem {
                    let cert = Certificate::from_pem(pem)
                        .map_err(|_| "SMTP CA certificate is invalid".to_owned())?;
                    params = params.add_root_certificate(cert);
                }
                let params = params
                    .build_rustls()
                    .map_err(|_| "SMTP TLS parameters are invalid".to_owned())?;
                if mode == SmtpTls::Tls {
                    Tls::Wrapper(params)
                } else {
                    Tls::Required(params)
                }
            }
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host)
            .port(self.port)
            .tls(tls)
            .timeout(Some(SEND_TIMEOUT));
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }
        Ok(builder.build())
    }
}

fn smtp_slot() -> &'static RwLock<Option<Arc<SmtpConfig>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<SmtpConfig>>>> = OnceLock::new();
    SLOT.get_or_init(|| {
        let loaded = match SmtpConfig::from_lookup(|name| std::env::var(name).ok()) {
            Ok(config) => config.map(Arc::new),
            Err(error) => {
                warn!(%error, "SMTP relay is misconfigured; email channels are disabled");
                None
            }
        };
        RwLock::new(loaded)
    })
}

pub(crate) fn smtp() -> Option<Arc<SmtpConfig>> {
    smtp_slot().read().ok()?.clone()
}

#[cfg(test)]
pub(crate) fn set_smtp_for_test(config: Option<SmtpConfig>) {
    *smtp_slot().write().unwrap() = config.map(Arc::new);
}

// ---------------------------------------------------------------------------
// Rendering

#[derive(Clone, Debug)]
pub(crate) struct Notice {
    pub(crate) event_type: String,
    pub(crate) event_id: String,
    pub(crate) created_at: i64,
    pub(crate) payload: serde_json::Value,
}

impl Notice {
    fn severity(&self) -> &'static str {
        if self.event_type == TEST_EVENT {
            return "test";
        }
        crate::notifications::find(&self.event_type)
            .map(|kind| kind.severity.as_str())
            .unwrap_or("info")
    }

    fn summary(&self) -> &'static str {
        if self.event_type == TEST_EVENT {
            return "Test notification. If you can read this, the channel works.";
        }
        crate::notifications::find(&self.event_type)
            .map(|kind| kind.summary)
            .unwrap_or("")
    }

    /// Flat `key: value` lines from the redacted payload, bounded in size.
    fn fields(&self) -> Vec<(String, String)> {
        let mut payload = self.payload.clone();
        crate::audit_log::redact(&mut payload);
        let mut out = Vec::new();
        flatten("", &payload, &mut out);
        out.truncate(MAX_RENDERED_FIELDS);
        out
    }
}

fn flatten(prefix: &str, value: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&key, nested, out);
            }
        }
        serde_json::Value::Null => {}
        serde_json::Value::String(text) => out.push((prefix.into(), clip(text))),
        other => out.push((prefix.into(), clip(&other.to_string()))),
    }
}

fn clip(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() > MAX_FIELD_CHARS {
        format!(
            "{}…",
            cleaned.chars().take(MAX_FIELD_CHARS).collect::<String>()
        )
    } else {
        cleaned
    }
}

fn one_line(text: &str) -> String {
    clip(text).trim().to_owned()
}

fn local_time(at: i64, tz: Tz) -> String {
    Utc.timestamp_opt(at, 0)
        .single()
        .map(|time| {
            let local = time.with_timezone(&tz);
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} {}",
                local.year(),
                local.month(),
                local.day(),
                local.hour(),
                local.minute(),
                local.format("%Z")
            )
        })
        .unwrap_or_default()
}

pub(crate) struct Rendered {
    pub(crate) subject: String,
    pub(crate) text: String,
}

/// Plain-text email. Only the catalogue summary and the redacted payload are
/// rendered: never a destination URL, signing secret or relay credential.
pub(crate) fn render_email(
    org_name: &str,
    notices: &[Notice],
    tz: Tz,
    console_url: &str,
) -> Rendered {
    let org = one_line(org_name);
    let subject = match notices {
        [single] => format!(
            "[BlakTail] {} {} - {}",
            single.severity(),
            single.event_type,
            org
        ),
        many => format!("[BlakTail] {} notifications - {}", many.len(), org),
    };
    let mut text = format!("Organisation: {org}\n\n");
    for notice in notices {
        text.push_str(&format!(
            "{} ({})\n{}\nWhen: {}\nEvent id: {}\n",
            notice.event_type,
            notice.severity(),
            notice.summary(),
            local_time(notice.created_at, tz),
            notice.event_id
        ));
        for (key, value) in notice.fields() {
            text.push_str(&format!("  {key}: {value}\n"));
        }
        text.push('\n');
    }
    text.push_str(&format!(
        "Review the audit log: {console_url}/audit\n\nAlerts are best effort and are not a safety control.\nChange or stop these emails in Settings, Notifications.\n"
    ));
    Rendered {
        subject: one_line(&subject),
        text,
    }
}

fn slack_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn notice_lines(notice: &Notice, tz: Tz) -> String {
    let mut lines = format!(
        "{}\nWhen: {}",
        notice.summary(),
        local_time(notice.created_at, tz)
    );
    for (key, value) in notice.fields() {
        lines.push_str(&format!("\n{key}: {value}"));
    }
    lines
}

/// Slack incoming-webhook body: `text` fallback plus Block Kit sections.
pub(crate) fn slack_payload(org_name: &str, notices: &[Notice], tz: Tz) -> serde_json::Value {
    let rendered = render_email(org_name, notices, tz, "");
    let mut blocks = vec![serde_json::json!({
        "type": "header",
        "text": {"type": "plain_text", "text": clip(&rendered.subject)},
    })];
    for notice in notices.iter().take(MAX_DIGEST_ROWS as usize) {
        blocks.push(serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": slack_escape(&format!(
                    "*{}* ({})\n{}",
                    notice.event_type,
                    notice.severity(),
                    notice_lines(notice, tz)
                )),
            },
        }));
    }
    blocks.truncate(49);
    blocks.push(serde_json::json!({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "BlakTail alerts are best effort, not a safety control."}],
    }));
    serde_json::json!({"text": slack_escape(&rendered.subject), "blocks": blocks})
}

/// Adaptive Card text renders a Markdown subset; event values (device and
/// organisation names, reasons) must not become links or formatting.
fn teams_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '\\' | '[' | ']' | '(' | ')' | '*' | '_' | '~' | '`') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Teams incoming-webhook / Workflows body carrying an Adaptive Card.
pub(crate) fn teams_payload(org_name: &str, notices: &[Notice], tz: Tz) -> serde_json::Value {
    let rendered = render_email(org_name, notices, tz, "");
    let mut body = vec![serde_json::json!({
        "type": "TextBlock",
        "size": "Medium",
        "weight": "Bolder",
        "wrap": true,
        "text": teams_escape(&rendered.subject),
    })];
    for notice in notices.iter().take(MAX_DIGEST_ROWS as usize) {
        body.push(serde_json::json!({
            "type": "TextBlock",
            "wrap": true,
            "weight": "Bolder",
            "text": format!("{} ({})", notice.event_type, notice.severity()),
        }));
        body.push(serde_json::json!({
            "type": "FactSet",
            "facts": std::iter::once(serde_json::json!({"title": "Summary", "value": teams_escape(notice.summary())}))
                .chain(std::iter::once(serde_json::json!({"title": "When", "value": local_time(notice.created_at, tz)})))
                .chain(notice.fields().into_iter().map(|(key, value)| serde_json::json!({"title": teams_escape(&key), "value": teams_escape(&value)})))
                .collect::<Vec<_>>(),
        }));
    }
    serde_json::json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            },
        }],
    })
}

// ---------------------------------------------------------------------------
// Sending

pub(crate) async fn send_email(
    config: &SmtpConfig,
    recipients: &[String],
    rendered: &Rendered,
) -> Result<(), String> {
    let mut builder = Message::builder()
        .from(config.from.clone())
        .subject(rendered.subject.clone())
        .header(ContentType::TEXT_PLAIN);
    for recipient in recipients {
        let address: Address = recipient
            .parse()
            .map_err(|_| "a stored recipient is not an email address".to_owned())?;
        builder = builder.to(Mailbox::new(None, address));
    }
    let message = builder
        .body(rendered.text.clone())
        .map_err(|_| "email could not be built".to_owned())?;
    config
        .transport()?
        .send(message)
        .await
        .map(|_| ())
        // Relay errors carry SMTP codes, not the configured credentials.
        .map_err(|error| format!("SMTP relay refused or failed: {error}"))
}

/// Slack and Teams hosts. Loopback is allowed only in tests (local mocks).
pub(crate) fn validate_chat_url(
    kind: ChannelKind,
    raw: &str,
    allow_private: bool,
) -> Result<url::Url, ApiError> {
    let url = validate_destination_url(raw, allow_private)?;
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let local_mock =
        allow_private && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback());
    let allowed = match kind {
        ChannelKind::Slack => host == "hooks.slack.com" && url.path().starts_with("/services/"),
        ChannelKind::Teams => {
            host.ends_with(".webhook.office.com")
                || host.ends_with(".logic.azure.com")
                || host.ends_with(".api.powerplatform.com")
        }
        _ => false,
    };
    if !allowed && !local_mock {
        return Err(ApiError::BadRequest(match kind {
            ChannelKind::Slack => "Slack URL must be an https://hooks.slack.com/services/ incoming webhook".into(),
            _ => "Teams URL must be a Teams incoming webhook or Workflows URL (webhook.office.com, logic.azure.com or api.powerplatform.com)".into(),
        }));
    }
    Ok(url)
}

/// Display form that never reveals the secret path or query.
fn redacted_url(url: &url::Url) -> String {
    format!("{}://{}/…", url.scheme(), url.host_str().unwrap_or(""))
}

async fn post_chat(
    kind: ChannelKind,
    raw_url: &str,
    body: &serde_json::Value,
) -> Result<(), String> {
    let parsed = validate_chat_url(kind, raw_url, cfg!(test)).map_err(|error| error.to_string())?;
    let pinned = revalidate_resolved_ips(&parsed)
        .await
        .map_err(|error| error.to_string())?;
    let mut builder = reqwest::Client::builder()
        .timeout(SEND_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let (Some(host), Some(addr)) = (parsed.host_str(), pinned) {
        builder = builder.resolve(host, addr);
    }
    let client = builder
        .build()
        .map_err(|_| "HTTP client could not be built".to_owned())?;
    let response = client
        .post(parsed)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        // The URL is the credential, so it must not reach last_error.
        .map_err(|error| format!("{} request failed: {}", kind.as_str(), error.without_url()))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("{} returned {}", kind.as_str(), status.as_u16()))
    }
}

// ---------------------------------------------------------------------------
// Delivery (called from the webhook delivery loop)

struct DueRow {
    id: String,
    destination_id: String,
    event_id: String,
    event_type: String,
    payload: String,
    attempts: i64,
    created_at: i64,
    kind: ChannelKind,
    target_sealed: Option<String>,
    recipients: Vec<String>,
    quiet: Option<QuietWindow>,
    digest_minutes: i64,
    org_name: String,
}

pub(crate) async fn deliver_due(state: &AppState) -> Result<(), ApiError> {
    let at = now();
    let rows = sqlx::query(
        "SELECT o.id,o.destination_id,o.event_id,o.event_type,o.payload_json,o.attempts,o.created_at,
                d.kind,d.target_sealed,d.recipients_json,d.quiet_timezone,d.quiet_start_minute,d.quiet_end_minute,d.digest_minutes,g.name
         FROM webhook_outbox o
         JOIN webhook_destinations d ON d.id=o.destination_id
         JOIN orgs g ON g.id=o.org_id
         WHERE o.delivered_at IS NULL AND o.dead_lettered_at IS NULL AND o.next_attempt_at<=$1
           AND d.enabled=1 AND d.kind<>'webhook'
         ORDER BY o.next_attempt_at,o.id
         LIMIT 16",
    )
    .bind(at)
    .fetch_all(&state.store.pool)
    .await?;
    let mut handled = HashSet::new();
    for row in rows {
        let due = DueRow {
            id: row.try_get(0)?,
            destination_id: row.try_get(1)?,
            event_id: row.try_get(2)?,
            event_type: row.try_get(3)?,
            payload: row.try_get(4)?,
            attempts: row.try_get(5)?,
            created_at: row.try_get(6)?,
            kind: ChannelKind::parse(&row.try_get::<String, _>(7)?).ok_or(ApiError::CorruptData)?,
            target_sealed: row.try_get(8)?,
            recipients: serde_json::from_str(&row.try_get::<String, _>(9)?).unwrap_or_default(),
            quiet: QuietWindow::from_columns(row.try_get(10)?, row.try_get(11)?, row.try_get(12)?),
            digest_minutes: row.try_get(13)?,
            org_name: row.try_get(14)?,
        };
        if !handled.insert(due.id.clone()) {
            continue;
        }
        let critical = is_critical(&due.event_type);
        if !critical {
            if let Some(quiet) = due.quiet.filter(|quiet| quiet.contains(at)) {
                postpone(state, &due.id, quiet.next_end(at)).await?;
                continue;
            }
        }
        let batch = if !critical && due.digest_minutes > 0 {
            let release = due.created_at + due.digest_minutes * 60;
            if release > at {
                postpone(state, &due.id, release).await?;
                continue;
            }
            let batch = digest_batch(state, &due, at).await?;
            handled.extend(batch.iter().map(|(id, ..)| id.clone()));
            batch
        } else {
            vec![(
                due.id.clone(),
                due.attempts,
                notice_from(&due.event_type, &due.event_id, &due.payload, due.created_at),
            )]
        };
        let notices: Vec<Notice> = batch.iter().map(|(_, _, notice)| notice.clone()).collect();
        let outcome = send(state, &due, &notices).await;
        for (id, attempts, _) in &batch {
            record_outcome(state, id, *attempts, outcome.as_ref().err()).await?;
        }
    }
    Ok(())
}

fn notice_from(event_type: &str, event_id: &str, payload: &str, created_at: i64) -> Notice {
    Notice {
        event_type: event_type.into(),
        event_id: event_id.into(),
        created_at,
        payload: serde_json::from_str(payload).unwrap_or(serde_json::Value::Null),
    }
}

async fn digest_batch(
    state: &AppState,
    due: &DueRow,
    at: i64,
) -> Result<Vec<(String, i64, Notice)>, ApiError> {
    let rows = sqlx::query(
        "SELECT id,event_id,event_type,payload_json,created_at,attempts FROM webhook_outbox
         WHERE destination_id=$1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND created_at<=$2
         ORDER BY created_at,id LIMIT $3",
    )
    .bind(&due.destination_id)
    .bind(at)
    .bind(MAX_DIGEST_ROWS)
    .fetch_all(&state.store.pool)
    .await?;
    let mut batch = Vec::new();
    for row in rows {
        let event_type: String = row.try_get(2)?;
        // Critical rows are sent on their own as soon as they are due.
        if is_critical(&event_type) {
            continue;
        }
        let event_id: String = row.try_get(1)?;
        let payload: String = row.try_get(3)?;
        let created_at: i64 = row.try_get(4)?;
        batch.push((
            row.try_get(0)?,
            row.try_get(5)?,
            notice_from(&event_type, &event_id, &payload, created_at),
        ));
    }
    if !batch.iter().any(|(id, ..)| *id == due.id) {
        batch.push((
            due.id.clone(),
            due.attempts,
            notice_from(&due.event_type, &due.event_id, &due.payload, due.created_at),
        ));
    }
    Ok(batch)
}

async fn send(state: &AppState, due: &DueRow, notices: &[Notice]) -> Result<(), String> {
    let tz = due
        .quiet
        .map(|quiet| quiet.tz)
        .unwrap_or(chrono_tz::Australia::Sydney);
    match due.kind {
        ChannelKind::Email => {
            let config = smtp().ok_or("email relay is not configured on this coordinator")?;
            let rendered = render_email(&due.org_name, notices, tz, &state.console_url);
            send_email(&config, &due.recipients, &rendered).await
        }
        ChannelKind::Slack | ChannelKind::Teams => {
            let sealed = due
                .target_sealed
                .as_deref()
                .ok_or("channel URL was removed")?;
            let url = open_signing_secret(&state.auth_hmac_secret, sealed)
                .map_err(|_| "channel URL could not be opened".to_owned())?;
            let body = if due.kind == ChannelKind::Slack {
                slack_payload(&due.org_name, notices, tz)
            } else {
                teams_payload(&due.org_name, notices, tz)
            };
            post_chat(due.kind, &url, &body).await
        }
        ChannelKind::Webhook => Err("webhooks are delivered by the webhook loop".into()),
    }
}

async fn postpone(state: &AppState, id: &str, until: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE webhook_outbox SET next_attempt_at=$1 WHERE id=$2")
        .bind(until)
        .bind(id)
        .execute(&state.store.pool)
        .await?;
    Ok(())
}

async fn record_outcome(
    state: &AppState,
    id: &str,
    attempts: i64,
    error: Option<&String>,
) -> Result<(), ApiError> {
    match error {
        None => {
            sqlx::query("UPDATE webhook_outbox SET delivered_at=$1,last_error=NULL WHERE id=$2")
                .bind(now())
                .bind(id)
                .execute(&state.store.pool)
                .await?;
        }
        Some(error) => {
            let next_attempts = attempts + 1;
            let dead = next_attempts >= MAX_ATTEMPTS;
            let backoff = 1_i64 << attempts.min(7);
            sqlx::query(
                "UPDATE webhook_outbox SET attempts=$1,next_attempt_at=$2,last_error=$3,dead_lettered_at=$4 WHERE id=$5",
            )
            .bind(next_attempts)
            .bind(now() + backoff)
            .bind(clip(error))
            .bind(if dead { Some(now()) } else { None })
            .bind(id)
            .execute(&state.store.pool)
            .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Console routes

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/orgs/:org_id/notification-channels/capabilities",
            get(capabilities_console),
        )
        .route(
            "/v1/orgs/:org_id/notification-channels",
            post(create_channel_console),
        )
        .route(
            "/v1/orgs/:org_id/notification-channels/:destination_id/schedule",
            put(schedule_console),
        )
        .route(
            "/v1/orgs/:org_id/notification-channels/:destination_id/test",
            post(test_console),
        )
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Capabilities {
    pub(crate) email_configured: bool,
    pub(crate) email_from: Option<String>,
    pub(crate) email_tls: Option<SmtpTls>,
    pub(crate) offshore_kinds: Vec<String>,
    pub(crate) default_timezone: String,
}

async fn capabilities_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Capabilities>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    let config = smtp();
    Ok(Json(Capabilities {
        email_configured: config.is_some(),
        email_from: config.as_ref().map(|config| config.from.email.to_string()),
        email_tls: config.as_ref().map(|config| config.tls),
        offshore_kinds: vec!["slack".into(), "teams".into()],
        default_timezone: DEFAULT_TIMEZONE.into(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateChannel {
    kind: String,
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    recipients: Option<Vec<String>>,
    #[serde(default)]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    quiet_hours: Option<QuietHours>,
    #[serde(default)]
    digest_minutes: Option<i64>,
    #[serde(default)]
    residency_acknowledged: bool,
}

fn validate_recipients(input: &[String]) -> Result<Vec<String>, ApiError> {
    if input.is_empty() || input.len() > MAX_RECIPIENTS {
        return Err(ApiError::BadRequest(format!(
            "email channels need 1-{MAX_RECIPIENTS} recipients"
        )));
    }
    let mut out = Vec::new();
    for raw in input {
        let value = raw.trim().to_ascii_lowercase();
        if value.parse::<Address>().is_err() || value.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(format!(
                "{value:?} is not an email address"
            )));
        }
        out.push(value);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn validate_digest(minutes: Option<i64>) -> Result<i64, ApiError> {
    let minutes = minutes.unwrap_or(0);
    if !(0..=MAX_DIGEST_MINUTES).contains(&minutes) || (1..5).contains(&minutes) {
        return Err(ApiError::BadRequest(
            "digest must be 0 (off) or 5-1440 minutes".into(),
        ));
    }
    Ok(minutes)
}

async fn create_channel_console(
    State(s): State<AppState>,
    UrlPath(org_id): UrlPath<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateChannel>,
) -> Result<(StatusCode, Json<WebhookDestination>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    create_channel(&s, org_id, &session, input).await
}

pub(crate) async fn create_channel(
    state: &AppState,
    org_id: Uuid,
    session: &Session,
    input: CreateChannel,
) -> Result<(StatusCode, Json<WebhookDestination>), ApiError> {
    require(session, Permission::ManageIntegrations)?;
    let kind = ChannelKind::parse(input.kind.trim())
        .filter(|kind| *kind != ChannelKind::Webhook)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "kind must be email, slack or teams; use /webhooks for HTTPS webhooks".into(),
            )
        })?;
    if kind.offshore() {
        // Sending alert content offshore is a residency decision for an owner.
        require(session, Permission::ManageSecurity)?;
        if !input.residency_acknowledged {
            return Err(ApiError::BadRequest(format!(
                "{} processes messages outside Australia; an owner must acknowledge this before alerts are sent there",
                if kind == ChannelKind::Slack { "Slack" } else { "Microsoft Teams" }
            )));
        }
    }
    let name = input.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::BadRequest(
            "channel name must be 1-64 characters".into(),
        ));
    }
    let event_types = crate::notifications::validate_event_types(
        input
            .event_types
            .as_deref()
            .unwrap_or(&[crate::notifications::ALL_EVENTS.to_owned()]),
    )?;
    let quiet = input
        .quiet_hours
        .as_ref()
        .map(QuietWindow::parse)
        .transpose()?;
    let digest_minutes = validate_digest(input.digest_minutes)?;
    let (display, target_sealed, recipients) = match kind {
        ChannelKind::Email => {
            if smtp().is_none() {
                return Err(ApiError::BadRequest(
                    "email is not configured on this coordinator; the operator must set BLAKTAIL_SMTP_HOST and BLAKTAIL_SMTP_FROM".into(),
                ));
            }
            if input.url.is_some() {
                return Err(ApiError::BadRequest(
                    "email channels take recipients, not a URL".into(),
                ));
            }
            let recipients = validate_recipients(input.recipients.as_deref().unwrap_or(&[]))?;
            (format!("mailto:{}", recipients.join(",")), None, recipients)
        }
        _ => {
            if input.recipients.is_some() {
                return Err(ApiError::BadRequest(
                    "chat channels take a URL, not recipients".into(),
                ));
            }
            let raw = input.url.as_deref().ok_or_else(|| {
                ApiError::BadRequest("an incoming webhook URL is required".into())
            })?;
            let url = validate_chat_url(kind, raw.trim(), cfg!(test))?;
            (
                redacted_url(&url),
                Some(seal_signing_secret(&state.auth_hmac_secret, url.as_str())?),
                Vec::new(),
            )
        }
    };
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_destinations WHERE org_id=$1 AND enabled=1",
    )
    .bind(org_id.to_string())
    .fetch_one(&state.store.pool)
    .await?;
    if count >= MAX_DESTINATIONS {
        return Err(ApiError::BadRequest(
            "organisations are limited to 8 destinations across webhooks and channels".into(),
        ));
    }
    let id = Uuid::new_v4();
    // Unused for chat and email, but the column is required and must never
    // hold a usable plaintext value.
    let signing_secret = secret("btw");
    let sealed_signing = seal_signing_secret(&state.auth_hmac_secret, &signing_secret)?;
    let created_at = now();
    let residency_at = kind.offshore().then_some(created_at);
    let mut tx = state.store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO webhook_destinations(id,org_id,name,url,signing_secret,secret_hash,secret_prefix,enabled,created_at,event_types_json,
            kind,target_sealed,recipients_json,quiet_timezone,quiet_start_minute,quiet_end_minute,digest_minutes,residency_ack_by,residency_ack_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
    )
    .bind(id.to_string())
    .bind(org_id.to_string())
    .bind(name)
    .bind(&display)
    .bind(&sealed_signing)
    .bind(hash(&signing_secret))
    .bind("")
    .bind(created_at)
    .bind(serde_json::to_string(&event_types).map_err(|_| ApiError::CorruptData)?)
    .bind(kind.as_str())
    .bind(target_sealed)
    .bind(serde_json::to_string(&recipients).map_err(|_| ApiError::CorruptData)?)
    .bind(quiet.map(|quiet| quiet.tz.name().to_owned()))
    .bind(quiet.map(|quiet| i64::from(quiet.start)))
    .bind(quiet.map(|quiet| i64::from(quiet.end)))
    .bind(digest_minutes)
    .bind(kind.offshore().then(|| session.user_id.clone()))
    .bind(residency_at)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if error.to_string().to_ascii_lowercase().contains("unique") {
            ApiError::Conflict("a destination with that name already exists".into())
        } else {
            ApiError::Database(error)
        }
    })?;
    append_audit(
        &mut tx,
        org_id,
        session,
        "notification_channel.created",
        "webhook",
        Some(&id.to_string()),
        &serde_json::json!({
            "kind": kind.as_str(),
            "name": name,
            "target": display,
            "event_types": event_types,
            "quiet_hours": quiet.map(QuietWindow::view),
            "digest_minutes": digest_minutes,
            "residency_acknowledged": kind.offshore(),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(WebhookDestination {
            id,
            name: name.to_owned(),
            url: display,
            secret_prefix: String::new(),
            enabled: true,
            created_at,
            event_types,
            secret: None,
            kind: kind.as_str().into(),
            recipients,
            quiet_hours: quiet.map(QuietWindow::view),
            digest_minutes,
            residency_acknowledged_at: residency_at,
        }),
    ))
}

/// Columns `quiet_timezone, quiet_start_minute, quiet_end_minute` as a view.
pub(crate) fn quiet_view(
    tz: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
) -> Option<QuietHours> {
    QuietWindow::from_columns(tz, start, end).map(QuietWindow::view)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScheduleInput {
    #[serde(default)]
    quiet_hours: Option<QuietHours>,
    #[serde(default)]
    digest_minutes: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScheduleView {
    pub(crate) destination_id: Uuid,
    pub(crate) quiet_hours: Option<QuietHours>,
    pub(crate) digest_minutes: i64,
}

async fn schedule_console(
    State(s): State<AppState>,
    UrlPath((org_id, destination_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<ScheduleInput>,
) -> Result<Json<ScheduleView>, ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    let quiet = input
        .quiet_hours
        .as_ref()
        .map(QuietWindow::parse)
        .transpose()?;
    let digest_minutes = validate_digest(input.digest_minutes)?;
    let mut tx = s.store.pool.begin().await?;
    let kind: String = sqlx::query_scalar(
        "SELECT kind FROM webhook_destinations WHERE id=$1 AND org_id=$2 AND enabled=1",
    )
    .bind(destination_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if kind == ChannelKind::Webhook.as_str() {
        return Err(ApiError::BadRequest(
            "quiet hours and digests apply to email, Slack and Teams channels".into(),
        ));
    }
    sqlx::query(
        "UPDATE webhook_destinations SET quiet_timezone=$1,quiet_start_minute=$2,quiet_end_minute=$3,digest_minutes=$4 WHERE id=$5 AND org_id=$6",
    )
    .bind(quiet.map(|quiet| quiet.tz.name().to_owned()))
    .bind(quiet.map(|quiet| i64::from(quiet.start)))
    .bind(quiet.map(|quiet| i64::from(quiet.end)))
    .bind(digest_minutes)
    .bind(destination_id.to_string())
    .bind(org_id.to_string())
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "notification_channel.schedule_updated",
        "webhook",
        Some(&destination_id.to_string()),
        &serde_json::json!({
            "quiet_hours": quiet.map(QuietWindow::view),
            "digest_minutes": digest_minutes,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(ScheduleView {
        destination_id,
        quiet_hours: quiet.map(QuietWindow::view),
        digest_minutes,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TestSend {
    pub(crate) delivery_id: Uuid,
}

async fn test_console(
    State(s): State<AppState>,
    UrlPath((org_id, destination_id)): UrlPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<TestSend>), ApiError> {
    let session = console_session(&s, &headers, org_id).await?;
    require(&session, Permission::ManageIntegrations)?;
    let mut tx = s.store.pool.begin().await?;
    let exists: Option<String> = sqlx::query_scalar(
        "SELECT id FROM webhook_destinations WHERE id=$1 AND org_id=$2 AND enabled=1",
    )
    .bind(destination_id.to_string())
    .bind(org_id.to_string())
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let delivery_id = Uuid::new_v4();
    let created_at = now();
    sqlx::query(
        "INSERT INTO webhook_outbox(id,org_id,destination_id,event_id,event_type,payload_json,created_at,next_attempt_at,attempts)
         VALUES($1,$2,$3,$4,$5,$6,$7,$7,0)",
    )
    .bind(delivery_id.to_string())
    .bind(org_id.to_string())
    .bind(destination_id.to_string())
    .bind(format!("{TEST_EVENT}:{delivery_id}"))
    .bind(TEST_EVENT)
    .bind(
        serde_json::json!({
            "message": "Test notification from BlakTail",
            "requested_by": session.name,
        })
        .to_string(),
    )
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    append_audit(
        &mut tx,
        org_id,
        &session,
        "notification_channel.test_sent",
        "webhook",
        Some(&destination_id.to_string()),
        &serde_json::json!({"delivery_id": delivery_id}),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(TestSend { delivery_id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(tz: Tz, y: i32, m: u32, d: u32, h: u32, min: u32) -> i64 {
        tz.with_ymd_and_hms(y, m, d, h, min, 0)
            .earliest()
            .unwrap()
            .timestamp()
    }

    fn window(tz: &str, start: &str, end: &str) -> QuietWindow {
        QuietWindow::parse(&QuietHours {
            timezone: tz.into(),
            start: start.into(),
            end: end.into(),
        })
        .unwrap()
    }

    #[test]
    fn quiet_hours_boundaries_wrap_midnight() {
        let sydney = chrono_tz::Australia::Sydney;
        let quiet = window("Australia/Sydney", "22:00", "07:00");
        assert!(!quiet.contains(at(sydney, 2026, 6, 10, 21, 59)));
        assert!(quiet.contains(at(sydney, 2026, 6, 10, 22, 0)));
        assert!(quiet.contains(at(sydney, 2026, 6, 11, 0, 30)));
        assert!(quiet.contains(at(sydney, 2026, 6, 11, 6, 59)));
        assert!(!quiet.contains(at(sydney, 2026, 6, 11, 7, 0)));
        assert_eq!(
            quiet.next_end(at(sydney, 2026, 6, 10, 23, 15)),
            at(sydney, 2026, 6, 11, 7, 0)
        );
        assert_eq!(
            quiet.next_end(at(sydney, 2026, 6, 11, 3, 0)),
            at(sydney, 2026, 6, 11, 7, 0)
        );
        let outside = at(sydney, 2026, 6, 11, 12, 0);
        assert_eq!(quiet.next_end(outside), outside);
        // A same-day window does not wrap.
        let lunch = window("Australia/Perth", "12:00", "13:00");
        let perth = chrono_tz::Australia::Perth;
        assert!(lunch.contains(at(perth, 2026, 1, 5, 12, 30)));
        assert!(!lunch.contains(at(perth, 2026, 1, 5, 13, 0)));
        assert!(!lunch.contains(at(perth, 2026, 1, 5, 23, 0)));
    }

    #[test]
    fn quiet_hours_follow_daylight_saving() {
        let sydney = chrono_tz::Australia::Sydney;
        let quiet = window("Australia/Sydney", "22:00", "07:00");
        // DST starts 4 October 2026 (02:00 -> 03:00): 07:00 local is 20:00 UTC
        // the day before, an hour earlier in UTC than under standard time.
        let night_before = at(sydney, 2026, 10, 3, 23, 0);
        let end = quiet.next_end(night_before);
        assert_eq!(end, at(sydney, 2026, 10, 4, 7, 0));
        assert_eq!(end - night_before, 7 * 3600);
        // DST ends 5 April 2026 (03:00 -> 02:00): the night is an hour longer.
        let autumn = at(sydney, 2026, 4, 4, 23, 0);
        assert_eq!(quiet.next_end(autumn) - autumn, 9 * 3600);
        // An end time inside the spring-forward gap resolves after the gap.
        let gap = window("Australia/Sydney", "01:00", "02:30");
        let inside = at(sydney, 2026, 10, 4, 1, 30);
        assert!(gap.contains(inside));
        assert_eq!(gap.next_end(inside), at(sydney, 2026, 10, 4, 3, 0));
        // Brisbane has no daylight saving: the same UTC instant is an hour
        // different on the wall clock from Sydney in summer.
        let brisbane = window("Australia/Brisbane", "22:00", "07:00");
        let instant = at(sydney, 2026, 12, 1, 22, 30);
        assert!(quiet.contains(instant));
        assert!(!brisbane.contains(instant));
    }

    #[test]
    fn quiet_hours_reject_bad_input() {
        for (tz, start, end) in [
            ("Mars/Olympus", "22:00", "07:00"),
            ("Australia/Sydney", "24:00", "07:00"),
            ("Australia/Sydney", "7:00", "08:00"),
            ("Australia/Sydney", "22:00", "22:00"),
        ] {
            assert!(QuietWindow::parse(&QuietHours {
                timezone: tz.into(),
                start: start.into(),
                end: end.into(),
            })
            .is_err());
        }
        assert!(validate_digest(Some(2)).is_err());
        assert!(validate_digest(Some(1441)).is_err());
        assert_eq!(validate_digest(None).unwrap(), 0);
        assert_eq!(validate_digest(Some(60)).unwrap(), 60);
    }

    #[test]
    fn warning_events_and_tests_are_critical() {
        assert!(is_critical("device.revoked"));
        assert!(is_critical(TEST_EVENT));
        assert!(!is_critical("device.renamed"));
        assert!(!is_critical("policy.published"));
    }

    #[test]
    fn smtp_config_reads_env_and_refuses_plaintext_credentials() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        assert!(SmtpConfig::from_lookup(env(&[])).unwrap().is_none());
        let config = SmtpConfig::from_lookup(env(&[
            ("BLAKTAIL_SMTP_HOST", "smtp.example.org.au"),
            ("BLAKTAIL_SMTP_USERNAME", "alerts"),
            ("BLAKTAIL_SMTP_PASSWORD", "relay-password-123"),
            ("BLAKTAIL_SMTP_FROM", "BlakTail <alerts@example.org.au>"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(config.port, 587);
        assert_eq!(config.tls, SmtpTls::Starttls);
        assert!(!format!("{config:?}").contains("relay-password-123"));
        assert!(SmtpConfig::from_lookup(env(&[
            ("BLAKTAIL_SMTP_HOST", "smtp.example.org.au"),
            ("BLAKTAIL_SMTP_TLS", "none"),
            ("BLAKTAIL_SMTP_USERNAME", "alerts"),
            ("BLAKTAIL_SMTP_PASSWORD", "relay-password-123"),
            ("BLAKTAIL_SMTP_FROM", "alerts@example.org.au"),
        ]))
        .is_err());
        assert!(
            SmtpConfig::from_lookup(env(&[("BLAKTAIL_SMTP_HOST", "smtp.example.org.au")])).is_err()
        );
        assert!(SmtpConfig::from_lookup(env(&[
            ("BLAKTAIL_SMTP_HOST", "smtp.example.org.au"),
            ("BLAKTAIL_SMTP_TLS", "ssl"),
            ("BLAKTAIL_SMTP_FROM", "alerts@example.org.au"),
        ]))
        .is_err());
    }

    fn notice(event_type: &str, payload: serde_json::Value) -> Notice {
        Notice {
            event_type: event_type.into(),
            event_id: "evt-1".into(),
            created_at: 1_790_000_000,
            payload,
        }
    }

    #[test]
    fn email_rendering_redacts_secrets() {
        let rendered = render_email(
            "Ranger Org\r\nBcc: attacker@example.com",
            &[notice(
                "device.revoked",
                serde_json::json!({
                    "device_id": "node-1",
                    "token": "btn_live-secret-value",
                    "details": {"signing_secret": "btw_abcdef", "note": "rotated"},
                }),
            )],
            chrono_tz::Australia::Sydney,
            "https://console.example.org.au",
        );
        assert!(rendered
            .subject
            .starts_with("[BlakTail] warning device.revoked - Ranger Org"));
        assert!(!rendered.subject.contains('\n') && !rendered.subject.contains('\r'));
        assert!(rendered.text.contains("device_id: node-1"));
        assert!(rendered.text.contains("details.note: rotated"));
        assert!(rendered.text.contains("AEST") || rendered.text.contains("AEDT"));
        for leaked in ["btn_live-secret-value", "btw_abcdef"] {
            assert!(!rendered.text.contains(leaked), "{leaked} leaked");
        }
        let digest = render_email(
            "Org",
            &[
                notice("device.renamed", serde_json::json!({})),
                notice("dns.published", serde_json::json!({})),
            ],
            chrono_tz::Australia::Sydney,
            "",
        );
        assert_eq!(digest.subject, "[BlakTail] 2 notifications - Org");
    }

    #[test]
    fn chat_payload_shapes() {
        let notices = [notice(
            "posture.failed",
            serde_json::json!({"device": "<b>x</b>"}),
        )];
        let slack = slack_payload("Org", &notices, chrono_tz::Australia::Sydney);
        assert!(slack["text"].as_str().unwrap().contains("posture.failed"));
        assert_eq!(slack["blocks"][0]["type"], "header");
        assert_eq!(slack["blocks"][1]["text"]["type"], "mrkdwn");
        assert!(slack["blocks"][1]["text"]["text"]
            .as_str()
            .unwrap()
            .contains("&lt;b&gt;"));
        let teams = teams_payload("Org", &notices, chrono_tz::Australia::Sydney);
        assert_eq!(teams["type"], "message");
        assert_eq!(
            teams["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(teams["attachments"][0]["content"]["type"], "AdaptiveCard");
        assert_eq!(
            teams["attachments"][0]["content"]["body"][2]["type"],
            "FactSet"
        );
    }

    #[test]
    fn teams_values_cannot_inject_markdown() {
        let notices = [notice(
            "posture.failed",
            serde_json::json!({"device": "[click](https://evil.example) *now* _x_ ~y~ `z` \\"}),
        )];
        let teams = teams_payload(
            "[Org](https://evil.example)",
            &notices,
            chrono_tz::Australia::Sydney,
        );
        let text = teams.to_string();
        assert!(!text.contains("[click](https"), "{text}");
        let body = &teams["attachments"][0]["content"]["body"];
        assert!(body[0]["text"]
            .as_str()
            .unwrap()
            .contains("\\[Org\\]\\(https://evil.example\\)"));
        let device = body[2]["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|fact| {
                fact["value"]
                    .as_str()
                    .filter(|value| value.contains("click"))
            })
            .unwrap();
        assert_eq!(
            device,
            "\\[click\\]\\(https://evil.example\\) \\*now\\* \\_x\\_ \\~y\\~ \\`z\\` \\\\"
        );
    }

    #[test]
    fn chat_urls_are_pinned_to_vendor_hosts() {
        assert!(validate_chat_url(
            ChannelKind::Slack,
            "https://hooks.slack.com/services/T1/B2/abc",
            false
        )
        .is_ok());
        assert!(validate_chat_url(
            ChannelKind::Slack,
            "https://hooks.slack.com.evil.example/services/x",
            false
        )
        .is_err());
        assert!(
            validate_chat_url(ChannelKind::Slack, "https://example.com/services/x", false).is_err()
        );
        assert!(validate_chat_url(
            ChannelKind::Slack,
            "http://hooks.slack.com/services/x",
            false
        )
        .is_err());
        assert!(validate_chat_url(
            ChannelKind::Teams,
            "https://contoso.webhook.office.com/webhookb2/abc",
            false
        )
        .is_ok());
        assert!(validate_chat_url(
            ChannelKind::Teams,
            "https://prod-01.australiasoutheast.logic.azure.com:443/workflows/abc",
            false
        )
        .is_ok());
        assert!(
            validate_chat_url(ChannelKind::Teams, "https://169.254.169.254/latest", true).is_err()
        );
        assert!(validate_chat_url(ChannelKind::Teams, "https://example.com/hook", false).is_err());
        let url = validate_chat_url(
            ChannelKind::Slack,
            "https://hooks.slack.com/services/T1/B2/abc",
            false,
        )
        .unwrap();
        assert_eq!(redacted_url(&url), "https://hooks.slack.com/…");
    }
}
