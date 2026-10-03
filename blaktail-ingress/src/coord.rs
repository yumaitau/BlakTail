//! Coordinator client. The ingress uses the identity of the co-located
//! blaktaild (`state.json`), re-read on every poll so renewed node tokens
//! are picked up. It never registers its own node or holds WireGuard keys.

use crate::routes::IngressConfig;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const LONG_POLL_WAIT_SECS: u64 = 20;

#[derive(Deserialize)]
struct NodeIdentity {
    node_id: Uuid,
    node_token: String,
    coord: String,
}

#[derive(Debug)]
pub enum Poll {
    Changed(IngressConfig),
    Unchanged,
    /// The coordinator refused this node (revoked, suspended, expired, or the
    /// `public-ingress` capability is not reported). Serve nothing.
    Refused(u16),
    Failed(String),
}

#[derive(Debug, Serialize)]
pub struct RouteReport {
    pub route_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_not_after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct Coordinator {
    http: reqwest::Client,
    state_dir: PathBuf,
}

impl Coordinator {
    pub fn new(state_dir: PathBuf, coord_ca: Option<&Path>) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = coord_ca {
            let pem =
                std::fs::read(path).map_err(|e| format!("cannot read coordinator CA: {e}"))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|_| "coordinator CA is not a PEM certificate".to_owned())?;
            builder = builder.add_root_certificate(certificate);
        }
        Ok(Self {
            http: builder.build().map_err(|e| e.to_string())?,
            state_dir,
        })
    }

    fn identity(&self) -> Result<NodeIdentity, String> {
        let bytes = std::fs::read(self.state_dir.join("state.json")).map_err(|e| {
            format!(
                "cannot read blaktaild state in {} ({e}); enrol with `blaktaild up --public-ingress` first",
                self.state_dir.display()
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|_| "blaktaild state is unreadable".into())
    }

    pub async fn poll(&self, since: i64) -> Poll {
        let identity = match self.identity() {
            Ok(identity) => identity,
            Err(error) => return Poll::Failed(error),
        };
        let url = format!(
            "{}/v1/nodes/{}/public-ingress/config?since={since}&wait={LONG_POLL_WAIT_SECS}",
            identity.coord.trim_end_matches('/'),
            identity.node_id
        );
        let response = match self
            .http
            .get(url)
            .bearer_auth(&identity.node_token)
            .timeout(Duration::from_secs(LONG_POLL_WAIT_SECS + 8))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return Poll::Failed(format!("coordinator unreachable: {error}")),
        };
        match response.status().as_u16() {
            200 => match response.json::<IngressConfig>().await {
                Ok(config) => Poll::Changed(config),
                Err(_) => Poll::Failed("coordinator sent an invalid config".into()),
            },
            204 => Poll::Unchanged,
            status @ (401 | 403) => Poll::Refused(status),
            status => Poll::Failed(format!("coordinator answered {status}")),
        }
    }

    pub async fn report(&self, routes: Vec<RouteReport>) -> Result<(), String> {
        let identity = self.identity()?;
        let url = format!(
            "{}/v1/nodes/{}/public-ingress/report",
            identity.coord.trim_end_matches('/'),
            identity.node_id
        );
        let response = self
            .http
            .post(url)
            .bearer_auth(&identity.node_token)
            .timeout(Duration::from_secs(15))
            .json(&serde_json::json!({ "routes": routes }))
            .send()
            .await
            .map_err(|e| format!("report failed: {e}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("report answered {}", response.status()))
        }
    }
}
