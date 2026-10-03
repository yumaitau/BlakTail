//! BlakTail public ingress: an organisation-operated HTTPS reverse proxy
//! that runs on an onshore host next to an enrolled blaktaild, serves only
//! the public routes the coordinator delivers to that node, and reaches each
//! route's single target over the BlakTail overlay. See docs/public-ingress.md.

pub mod access_log;
pub mod acme;
pub mod coord;
pub mod headers;
pub mod limits;
pub mod oidc;
pub mod proxy;
pub mod routes;
pub mod server;
pub mod tls;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

/// Long-running background work: the config feed, certificate reloads and
/// ACME issuance, status reports and access-log pruning.
pub struct Runtime {
    pub coordinator: coord::Coordinator,
    pub routes: Arc<routes::RouteTable>,
    pub certs: Arc<tls::CertStore>,
    pub acme: Option<Arc<acme::Acme>>,
    pub log_dir: Option<std::path::PathBuf>,
    pub changed: Arc<Notify>,
    refused: Mutex<Vec<(Uuid, String)>>,
}

impl Runtime {
    pub fn new(
        coordinator: coord::Coordinator,
        routes: Arc<routes::RouteTable>,
        certs: Arc<tls::CertStore>,
        acme: Option<Arc<acme::Acme>>,
        log_dir: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            coordinator,
            routes,
            certs,
            acme,
            log_dir,
            changed: Arc::new(Notify::new()),
            refused: Mutex::new(Vec::new()),
        }
    }

    /// Follows the coordinator's long-poll. Disables propagate within one
    /// poll; if the coordinator cannot be reached the table goes stale and
    /// serves nothing after the stale bound (30 s).
    pub async fn config_loop(self: Arc<Self>) {
        let mut since = 0;
        let mut stale_after = Duration::from_secs(30);
        let mut last_error = String::new();
        loop {
            match self.coordinator.poll(since).await {
                coord::Poll::Changed(config) => {
                    stale_after = Duration::from_secs(config.stale_after_secs.min(30));
                    let outcome = self.routes.apply(&config);
                    since = config.revision;
                    tracing::info!(
                        revision = config.revision,
                        served = outcome.served.len(),
                        refused = outcome.refused.len(),
                        "public routes updated"
                    );
                    for (id, reason) in &outcome.refused {
                        tracing::warn!(route = %id, %reason, "route refused");
                    }
                    *self.refused.lock().await = outcome.refused;
                    last_error.clear();
                    self.changed.notify_one();
                }
                coord::Poll::Unchanged => self.routes.confirm(stale_after),
                coord::Poll::Refused(status) => {
                    self.routes.clear();
                    since = 0;
                    let error = format!("coordinator refused this node ({status}); check the device is active and blaktaild runs with --public-ingress");
                    if error != last_error {
                        tracing::error!("{error}");
                        last_error = error;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                coord::Poll::Failed(error) => {
                    if error != last_error {
                        tracing::warn!("{error}");
                        last_error = error;
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    fn route_modes(&self) -> Vec<(String, String)> {
        self.routes
            .all()
            .iter()
            .map(|r| {
                (
                    r.config.fqdn.to_ascii_lowercase(),
                    r.config.tls_mode.clone(),
                )
            })
            .collect()
    }

    /// Reloads certificates, runs ACME, prunes logs and reports status after
    /// every config change and every minute.
    pub async fn maintenance_loop(self: Arc<Self>) {
        let mut last_prune = None::<std::time::Instant>;
        loop {
            let modes = self.route_modes();
            self.certs.refresh(&modes);
            if let Some(acme) = &self.acme {
                let names: Vec<String> = modes
                    .iter()
                    .filter(|(_, mode)| mode == "acme_http01")
                    .map(|(fqdn, _)| fqdn.clone())
                    .collect();
                if !names.is_empty() {
                    acme.ensure(&names).await;
                    self.certs.refresh(&modes);
                }
            }
            if let Some(dir) = &self.log_dir {
                if last_prune
                    .is_none_or(|at: std::time::Instant| at.elapsed() > Duration::from_secs(3600))
                {
                    let retention: HashMap<String, u32> = self
                        .routes
                        .all()
                        .iter()
                        .map(|r| {
                            (
                                r.config.fqdn.to_ascii_lowercase(),
                                u32::try_from(r.config.log_retention_days).unwrap_or(30),
                            )
                        })
                        .collect();
                    let removed = access_log::prune(dir, &retention, 30, access_log::unix_now());
                    if removed > 0 {
                        tracing::info!(removed, "pruned access logs past retention");
                    }
                    last_prune = Some(std::time::Instant::now());
                }
            }
            if let Err(error) = self.coordinator.report(self.reports().await).await {
                tracing::debug!(%error, "status report not delivered");
            }
            let _ = tokio::time::timeout(Duration::from_secs(60), self.changed.notified()).await;
        }
    }

    async fn reports(&self) -> Vec<coord::RouteReport> {
        let mut reports: Vec<coord::RouteReport> = Vec::new();
        for route in self.routes.all() {
            let fqdn = route.config.fqdn.to_ascii_lowercase();
            let status = self.certs.status(&fqdn);
            let mut error = status.as_ref().and_then(|s| s.error.clone());
            if route.config.tls_mode == "acme_http01" {
                match &self.acme {
                    None => error = Some("ACME is not configured on this ingress".into()),
                    Some(acme) => {
                        if let Some(failure) = acme.failure(&fqdn).await {
                            error = Some(failure);
                        }
                    }
                }
            }
            reports.push(coord::RouteReport {
                route_id: route.config.id,
                certificate_not_after: status.as_ref().and_then(|s| s.not_after),
                certificate_source: status.map(|s| s.source.to_owned()),
                error,
            });
        }
        for (id, reason) in self.refused.lock().await.iter() {
            reports.push(coord::RouteReport {
                route_id: *id,
                certificate_not_after: None,
                certificate_source: None,
                error: Some(reason.clone()),
            });
        }
        reports
    }
}
