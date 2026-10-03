//! TLS termination. Certificates are chosen by SNI and only for names that
//! are currently live routes, so an unknown, disabled or missing name fails
//! the handshake. Keys come from operator files or the ACME store on this
//! host; the coordinator never sees them. Files are re-read when they change,
//! so a rotated certificate is picked up without dropping connections.

use crate::routes::RouteTable;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::SystemTime,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertStatus {
    pub not_after: Option<i64>,
    pub source: &'static str,
    pub error: Option<String>,
}

struct Loaded {
    key: Arc<CertifiedKey>,
    modified: (SystemTime, SystemTime),
    not_after: i64,
}

pub struct CertStore {
    operator_dir: PathBuf,
    acme_dir: PathBuf,
    loaded: RwLock<HashMap<String, Loaded>>,
    status: RwLock<HashMap<String, CertStatus>>,
}

/// `<dir>/<fqdn>/fullchain.pem` and `<dir>/<fqdn>/privkey.pem`, the layout
/// certbot and most ACME clients write.
pub fn cert_paths(dir: &Path, fqdn: &str) -> (PathBuf, PathBuf) {
    let base = dir.join(fqdn);
    (base.join("fullchain.pem"), base.join("privkey.pem"))
}

impl CertStore {
    pub fn new(operator_dir: PathBuf, acme_dir: PathBuf) -> Self {
        Self {
            operator_dir,
            acme_dir,
            loaded: RwLock::default(),
            status: RwLock::default(),
        }
    }

    pub fn acme_dir(&self) -> &Path {
        &self.acme_dir
    }

    /// Re-reads certificates for every route whose files changed; drops
    /// names no longer routed.
    pub fn refresh(&self, routes: &[(String, String)]) {
        let mut loaded = self.loaded.write().unwrap_or_else(|e| e.into_inner());
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        loaded.retain(|name, _| routes.iter().any(|(fqdn, _)| fqdn == name));
        status.retain(|name, _| routes.iter().any(|(fqdn, _)| fqdn == name));
        for (fqdn, mode) in routes {
            let (source, dir) = if mode == "acme_http01" {
                ("acme_http01", &self.acme_dir)
            } else {
                ("operator_files", &self.operator_dir)
            };
            let (cert_path, key_path) = cert_paths(dir, fqdn);
            let modified = match (
                std::fs::metadata(&cert_path).and_then(|m| m.modified()),
                std::fs::metadata(&key_path).and_then(|m| m.modified()),
            ) {
                (Ok(cert), Ok(key)) => (cert, key),
                _ => {
                    loaded.remove(fqdn);
                    status.insert(
                        fqdn.clone(),
                        CertStatus {
                            not_after: None,
                            source,
                            error: Some(if source == "acme_http01" {
                                "waiting for an ACME certificate".into()
                            } else {
                                format!("no certificate at {}", cert_path.display())
                            }),
                        },
                    );
                    continue;
                }
            };
            if loaded.get(fqdn).is_some_and(|l| l.modified == modified) {
                continue;
            }
            match load_pair(&cert_path, &key_path, fqdn) {
                Ok((key, not_after)) => {
                    warn_if_key_exposed(&key_path);
                    loaded.insert(
                        fqdn.clone(),
                        Loaded {
                            key,
                            modified,
                            not_after,
                        },
                    );
                    status.insert(
                        fqdn.clone(),
                        CertStatus {
                            not_after: Some(not_after),
                            source,
                            error: None,
                        },
                    );
                }
                Err(error) => {
                    // Keep serving the previous good pair during a botched
                    // rotation, but report the problem.
                    let previous = loaded.get(fqdn).map(|l| l.not_after);
                    status.insert(
                        fqdn.clone(),
                        CertStatus {
                            not_after: previous,
                            source,
                            error: Some(error),
                        },
                    );
                }
            }
        }
    }

    pub fn status(&self, fqdn: &str) -> Option<CertStatus> {
        self.status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(fqdn)
            .cloned()
    }

    pub fn not_after(&self, fqdn: &str) -> Option<i64> {
        self.loaded
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(fqdn)
            .map(|l| l.not_after)
    }

    fn get(&self, fqdn: &str) -> Option<Arc<CertifiedKey>> {
        self.loaded
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(fqdn)
            .map(|l| l.key.clone())
    }
}

fn warn_if_key_exposed(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(path = %path.display(), "TLS private key is readable by group or others; chmod 600 it");
            }
        }
    }
}

/// Loads and checks a certificate chain and key: the leaf must name `fqdn`
/// and be within its validity period.
pub fn load_pair(cert: &Path, key: &Path, fqdn: &str) -> Result<(Arc<CertifiedKey>, i64), String> {
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).map_err(|e| format!("cannot read certificate: {e}"))?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|e| format!("certificate file is not PEM: {e}"))?;
    let leaf = chain
        .first()
        .ok_or_else(|| "certificate file has no certificate".to_owned())?;
    let private: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(key).map_err(|e| format!("cannot read private key: {e}"))?,
        ))
        .map_err(|e| format!("private key file is not PEM: {e}"))?
        .ok_or_else(|| "private key file has no key".to_owned())?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| "certificate is not valid X.509".to_owned())?;
    let not_after = parsed.validity().not_after.timestamp();
    let now = crate::access_log::unix_now() as i64;
    if not_after <= now {
        return Err("certificate has expired".into());
    }
    if parsed.validity().not_before.timestamp() > now + 300 {
        return Err("certificate is not valid yet".into());
    }
    let names: Vec<String> = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        Some(dns.to_ascii_lowercase())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if !names.iter().any(|name| name_matches(name, fqdn)) {
        return Err(format!("certificate does not name {fqdn}"));
    }
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private)
        .map_err(|_| "unsupported private key type".to_owned())?;
    let certified = CertifiedKey::new(chain, signing);
    certified
        .keys_match()
        .map_err(|_| "private key does not match the certificate".to_owned())?;
    Ok((Arc::new(certified), not_after))
}

fn name_matches(pattern: &str, fqdn: &str) -> bool {
    if pattern == fqdn {
        return true;
    }
    // A wildcard covers exactly one label.
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        fqdn.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
    })
}

/// Picks a certificate by SNI, only for names that are live routes now.
pub struct Resolver {
    pub certs: Arc<CertStore>,
    pub routes: Arc<RouteTable>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        self.routes.get(&name)?;
        self.certs.get(&name)
    }
}

pub fn server_config(resolver: Resolver) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    /// Writes a self-signed pair for `names` under `<dir>/<names[0]>/`.
    pub fn write_cert(dir: &Path, names: &[&str]) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(
            names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap()
        .self_signed(&key)
        .unwrap();
        let base = dir.join(names[0]);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(base.join("privkey.pem"), key.serialize_pem()).unwrap();
        cert.pem()
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::write_cert, *};

    #[test]
    fn wildcard_covers_one_label() {
        assert!(name_matches("*.example.org.au", "app.example.org.au"));
        assert!(!name_matches("*.example.org.au", "a.b.example.org.au"));
        assert!(!name_matches("*.example.org.au", "example.org.au"));
    }

    #[test]
    fn pairs_must_name_the_route() {
        let dir = tempfile::tempdir().unwrap();
        write_cert(dir.path(), &["other.example.org.au"]);
        let (cert, key) = cert_paths(dir.path(), "other.example.org.au");
        assert!(load_pair(&cert, &key, "app.example.org.au")
            .unwrap_err()
            .contains("does not name"));
        assert!(load_pair(&cert, &key, "other.example.org.au").is_ok());
    }

    #[test]
    fn refresh_reports_missing_and_rotated_certificates() {
        let operator = tempfile::tempdir().unwrap();
        let acme = tempfile::tempdir().unwrap();
        let store = CertStore::new(operator.path().into(), acme.path().into());
        let routes = vec![
            ("app.example.org.au".to_owned(), "operator_files".to_owned()),
            ("auto.example.org.au".to_owned(), "acme_http01".to_owned()),
        ];
        store.refresh(&routes);
        assert!(store.status("app.example.org.au").unwrap().error.is_some());
        assert!(store
            .status("auto.example.org.au")
            .unwrap()
            .error
            .unwrap()
            .contains("ACME"));
        write_cert(operator.path(), &["app.example.org.au"]);
        store.refresh(&routes);
        let first = store.get("app.example.org.au").unwrap();
        assert!(store.status("app.example.org.au").unwrap().error.is_none());
        // Rotation: a new pair replaces the old one on the next refresh.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_cert(operator.path(), &["app.example.org.au"]);
        store.refresh(&routes);
        let second = store.get("app.example.org.au").unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        // A broken rotation keeps the last good pair and reports the error.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let (cert, _) = cert_paths(operator.path(), "app.example.org.au");
        std::fs::write(cert, "not a certificate").unwrap();
        store.refresh(&routes);
        assert!(Arc::ptr_eq(
            &second,
            &store.get("app.example.org.au").unwrap()
        ));
        assert!(store.status("app.example.org.au").unwrap().error.is_some());
    }
}
