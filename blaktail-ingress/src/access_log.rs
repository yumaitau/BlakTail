//! Access logs on the ingress host's own storage, one JSON-lines file per
//! route per UTC day, pruned to each route's retention. Entries carry the
//! public name, client address, method, path (never the query string),
//! status and timing; never the target address or request bodies.

use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, sync::mpsc};

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub ts: u64,
    pub host: String,
    pub client: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    /// `proxied`, `rejected_host`, `rate_limited`, `too_large`,
    /// `connection_limit`, `login_required`, `upstream_error`, ...
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Clone)]
pub struct AccessLog {
    sender: Option<mpsc::Sender<Entry>>,
}

impl AccessLog {
    /// Starts the writer task. Entries are dropped (and counted in the
    /// process log) rather than blocking requests when the disk is slow.
    pub fn start(dir: PathBuf) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Entry>(4096);
        tokio::spawn(async move {
            while let Some(entry) = receiver.recv().await {
                if let Err(error) = append(&dir, &entry).await {
                    tracing::warn!(%error, "could not write access log entry");
                }
            }
        });
        Self {
            sender: Some(sender),
        }
    }

    pub fn disabled() -> Self {
        Self { sender: None }
    }

    pub fn record(&self, entry: Entry) {
        if let Some(sender) = &self.sender {
            if sender.try_send(entry).is_err() {
                tracing::warn!("access log queue full; entry dropped");
            }
        }
    }
}

fn safe_component(host: &str) -> Option<&str> {
    (!host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.starts_with('.'))
    .then_some(host)
}

async fn append(dir: &Path, entry: &Entry) -> std::io::Result<()> {
    // Unknown or hostile Host values share one bucket instead of making paths.
    let bucket = safe_component(&entry.host)
        .filter(|_| entry.outcome != "rejected_host")
        .unwrap_or("_rejected");
    let route_dir = dir.join(bucket);
    tokio::fs::create_dir_all(&route_dir).await?;
    let path = route_dir.join(format!("{}.jsonl", civil_date(entry.ts)));
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o640);
    let mut file = options.open(path).await?;
    let mut line = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
    line.push(b'\n');
    file.write_all(&line).await
}

/// Deletes day files older than each route's retention. Routes no longer
/// served (and the rejected bucket) keep `default_days`.
pub fn prune(dir: &Path, retention: &HashMap<String, u32>, default_days: u32, now: u64) -> usize {
    let mut removed = 0;
    let Ok(routes) = std::fs::read_dir(dir) else {
        return 0;
    };
    for route in routes.flatten() {
        let name = route.file_name().to_string_lossy().into_owned();
        let days = retention.get(&name).copied().unwrap_or(default_days).max(1);
        let oldest = civil_date(now.saturating_sub(u64::from(days) * 86_400));
        let Ok(files) = std::fs::read_dir(route.path()) else {
            continue;
        };
        for file in files.flatten() {
            let file_name = file.file_name().to_string_lossy().into_owned();
            if let Some(day) = file_name.strip_suffix(".jsonl") {
                // ISO dates sort lexically.
                if day.len() == 10
                    && day < oldest.as_str()
                    && std::fs::remove_file(file.path()).is_ok()
                {
                    removed += 1;
                }
            }
        }
    }
    removed
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp.
pub fn civil_date(ts: u64) -> String {
    let days = i64::try_from(ts / 86_400).unwrap_or(0);
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(1_790_985_600), "2026-10-03");
        assert_eq!(civil_date(951_782_400), "2000-02-29");
    }

    #[test]
    fn prune_keeps_each_routes_retention() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_790_985_600; // 2026-10-03
        for (route, day) in [
            ("a.example.org.au", "2026-09-01"),
            ("a.example.org.au", "2026-10-02"),
            ("b.example.org.au", "2026-09-01"),
            ("_rejected", "2026-09-20"),
        ] {
            std::fs::create_dir_all(dir.path().join(route)).unwrap();
            std::fs::write(dir.path().join(route).join(format!("{day}.jsonl")), "{}").unwrap();
        }
        let retention = HashMap::from([
            ("a.example.org.au".to_owned(), 7),
            ("b.example.org.au".to_owned(), 90),
        ]);
        assert_eq!(prune(dir.path(), &retention, 7, now), 2);
        assert!(dir
            .path()
            .join("a.example.org.au/2026-10-02.jsonl")
            .exists());
        assert!(!dir
            .path()
            .join("a.example.org.au/2026-09-01.jsonl")
            .exists());
        assert!(dir
            .path()
            .join("b.example.org.au/2026-09-01.jsonl")
            .exists());
        assert!(!dir.path().join("_rejected/2026-09-20.jsonl").exists());
    }

    #[tokio::test]
    async fn entries_never_create_paths_from_hostile_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let entry = Entry {
            ts: 1_790_985_600,
            host: "../../etc".into(),
            client: "203.0.113.1".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 404,
            duration_ms: 1,
            outcome: "rejected_host",
            user: None,
        };
        append(dir.path(), &entry).await.unwrap();
        assert!(dir.path().join("_rejected/2026-10-03.jsonl").exists());
    }
}
