//! Optional ACME HTTP-01 issuance (instant-acme) for routes in
//! `acme_http01` mode. The account key, certificate keys and challenge
//! answers stay on this host. The operator chooses the ACME directory, so
//! BlakTail makes no residency claim about the certificate authority.

use crate::{proxy::ChallengeMap, tls};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const RENEW_BEFORE_SECS: i64 = 30 * 24 * 60 * 60;
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

pub struct Acme {
    pub directory: String,
    pub root: Option<PathBuf>,
    pub contact: Option<String>,
    pub dir: PathBuf,
    pub challenges: ChallengeMap,
    account: Mutex<Option<Account>>,
    failures: Mutex<HashMap<String, (Instant, String)>>,
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

impl Acme {
    pub fn new(
        directory: String,
        root: Option<PathBuf>,
        contact: Option<String>,
        dir: PathBuf,
        challenges: ChallengeMap,
    ) -> Self {
        Self {
            directory,
            root,
            contact,
            dir,
            challenges,
            account: Mutex::new(None),
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn builder(&self) -> Result<instant_acme::AccountBuilder, String> {
        match &self.root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        }
        .map_err(|e| format!("ACME client setup failed: {e}"))
    }

    async fn account(&self) -> Result<Account, String> {
        let mut cached = self.account.lock().await;
        if let Some(account) = cached.as_ref() {
            return Ok(account.clone());
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let path = self.dir.join("account.json");
        let account = match std::fs::read(&path) {
            Ok(bytes) => {
                let credentials: AccountCredentials = serde_json::from_slice(&bytes)
                    .map_err(|_| "stored ACME account is unreadable".to_owned())?;
                self.builder()?
                    .from_credentials(credentials)
                    .await
                    .map_err(|e| format!("ACME account restore failed: {e}"))?
            }
            Err(_) => {
                let contact = self.contact.as_ref().map(|c| format!("mailto:{c}"));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let (account, credentials) = self
                    .builder()?
                    .create(
                        &NewAccount {
                            contact: &contacts,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.directory.clone(),
                        None,
                    )
                    .await
                    .map_err(|e| format!("ACME account creation failed: {e}"))?;
                write_private(
                    &path,
                    &serde_json::to_vec(&credentials).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                account
            }
        };
        *cached = Some(account.clone());
        Ok(account)
    }

    /// The last issuance error for `fqdn`, while its backoff lasts.
    pub async fn failure(&self, fqdn: &str) -> Option<String> {
        self.failures
            .lock()
            .await
            .get(fqdn)
            .filter(|(at, _)| at.elapsed() < FAILURE_BACKOFF)
            .map(|(_, error)| error.clone())
    }

    /// Issues or renews certificates that are missing or within 30 days of
    /// expiry. Failures back off for an hour per name.
    pub async fn ensure(&self, names: &[String]) {
        for fqdn in names {
            let (cert, key) = tls::cert_paths(&self.dir, fqdn);
            let now = crate::access_log::unix_now() as i64;
            if let Ok((_, not_after)) = tls::load_pair(&cert, &key, fqdn) {
                if not_after - now > RENEW_BEFORE_SECS {
                    continue;
                }
            }
            if self.failure(fqdn).await.is_some() {
                continue;
            }
            match self.issue(fqdn).await {
                Ok(()) => {
                    self.failures.lock().await.remove(fqdn);
                    tracing::info!(host = %fqdn, "ACME certificate issued");
                }
                Err(error) => {
                    tracing::warn!(host = %fqdn, %error, "ACME issuance failed");
                    self.failures
                        .lock()
                        .await
                        .insert(fqdn.clone(), (Instant::now(), error));
                }
            }
        }
    }

    async fn issue(&self, fqdn: &str) -> Result<(), String> {
        let account = self.account().await?;
        let identifiers = [Identifier::Dns(fqdn.to_owned())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("ACME order failed: {e}"))?;
        let mut tokens = Vec::new();
        let result = async {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|e| format!("ACME authorisation failed: {e}"))?;
                match authorization.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    status => return Err(format!("ACME authorisation is {status:?}")),
                }
                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or("the ACME server offered no HTTP-01 challenge")?;
                let token = challenge.token.clone();
                self.challenges
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        token.clone(),
                        (
                            fqdn.to_owned(),
                            challenge.key_authorization().as_str().to_owned(),
                        ),
                    );
                tokens.push(token);
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| format!("ACME challenge failed: {e}"))?;
            }
            let status = order
                .poll_ready(&RetryPolicy::default())
                .await
                .map_err(|e| format!("ACME validation failed: {e}"))?;
            if status != OrderStatus::Ready {
                return Err(format!("ACME order ended {status:?}"));
            }
            let key_pem = order
                .finalize()
                .await
                .map_err(|e| format!("ACME finalise failed: {e}"))?;
            let chain_pem = order
                .poll_certificate(&RetryPolicy::default())
                .await
                .map_err(|e| format!("ACME certificate download failed: {e}"))?;
            Ok::<_, String>((key_pem, chain_pem))
        }
        .await;
        {
            let mut challenges = self.challenges.write().unwrap_or_else(|e| e.into_inner());
            for token in &tokens {
                challenges.remove(token);
            }
        }
        let (key_pem, chain_pem) = result?;
        let (cert_path, key_path) = tls::cert_paths(&self.dir, fqdn);
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // Key first: the store reloads only when both files changed and load.
        write_private(&key_path, key_pem.as_bytes()).map_err(|e| e.to_string())?;
        write_private(&cert_path, chain_pem.as_bytes()).map_err(|e| e.to_string())?;
        Ok(())
    }
}
