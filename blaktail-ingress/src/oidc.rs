//! Optional identity gate: OpenID Connect authorisation-code flow with PKCE
//! against the organisation's own issuer, then a short-lived HMAC-signed,
//! host-bound session cookie. The ingress holds the OIDC client secret and
//! the cookie key; neither leaves this host.

use crate::headers::{FLOW_COOKIE, SESSION_COOKIE};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use hyper::header::{HeaderMap, COOKIE};
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub const CALLBACK_PATH: &str = "/.blaktail-ingress/callback";
pub const LOGOUT_PATH: &str = "/.blaktail-ingress/logout";
const SESSION_SECS: u64 = 8 * 60 * 60;
const FLOW_SECS: u64 = 10 * 60;
const METADATA_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub struct Oidc {
    config: OidcConfig,
    http: reqwest::Client,
    key: Vec<u8>,
    discovery: Mutex<Option<(Discovery, Instant)>>,
    jwks: Mutex<Option<(JwkSet, Instant)>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionClaims {
    h: String,
    e: String,
    x: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct FlowClaims {
    h: String,
    state: String,
    nonce: String,
    verifier: String,
    back: String,
    x: u64,
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    nonce: Option<String>,
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn trim_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// Only same-site relative paths may be returned to after login.
pub fn safe_return_path(path: &str) -> String {
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.starts_with("/.blaktail-ingress/")
        && !path.chars().any(|c| c.is_control());
    if ok {
        path.to_owned()
    } else {
        "/".to_owned()
    }
}

pub fn email_allowed(email: &str, domains: &[String]) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && (domains.is_empty() || domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

impl Oidc {
    pub fn new(config: OidcConfig, key: Vec<u8>) -> Result<Self, String> {
        let issuer = url::Url::parse(&config.issuer).map_err(|_| "OIDC issuer is not a URL")?;
        let loopback = issuer
            .host_str()
            .is_some_and(|h| h == "127.0.0.1" || h == "localhost" || h == "[::1]");
        if issuer.scheme() != "https" && !loopback {
            return Err("OIDC issuer must use https".into());
        }
        if key.len() < 32 {
            return Err("cookie key must be at least 32 bytes".into());
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            http,
            key,
            discovery: Mutex::new(None),
            jwks: Mutex::new(None),
        })
    }

    fn sign<T: Serialize>(&self, purpose: &str, claims: &T) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap_or_default());
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key");
        mac.update(purpose.as_bytes());
        mac.update(b"|");
        mac.update(payload.as_bytes());
        format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    fn verify<T: DeserializeOwned>(&self, purpose: &str, value: &str) -> Option<T> {
        let (payload, signature) = value.split_once('.')?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).ok()?;
        mac.update(purpose.as_bytes());
        mac.update(b"|");
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature).ok()?;
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
    }

    /// The signed-in email for this host, if the session cookie is valid and
    /// still allowed by the route.
    pub fn session_user(
        &self,
        headers: &HeaderMap,
        host: &str,
        domains: &[String],
    ) -> Option<String> {
        let claims: SessionClaims = self.verify("session", cookie(headers, SESSION_COOKIE)?)?;
        (claims.h == host
            && claims.x > crate::access_log::unix_now()
            && email_allowed(&claims.e, domains))
        .then_some(claims.e)
    }

    pub fn session_cookie(&self, host: &str, email: &str, now: u64) -> String {
        let value = self.sign(
            "session",
            &SessionClaims {
                h: host.into(),
                e: email.into(),
                x: now + SESSION_SECS,
            },
        );
        format!("{SESSION_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECS}")
    }

    pub fn clear_cookie() -> String {
        format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
    }

    async fn discovery(&self) -> Result<Discovery, String> {
        let mut cached = self.discovery.lock().await;
        if let Some((discovery, at)) = cached.as_ref() {
            if at.elapsed() < METADATA_TTL {
                return Ok(discovery.clone());
            }
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            trim_issuer(&self.config.issuer)
        );
        let discovery: Discovery = self
            .http
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| "identity provider discovery failed".to_owned())?
            .json()
            .await
            .map_err(|_| "identity provider discovery was not valid JSON".to_owned())?;
        if trim_issuer(&discovery.issuer) != trim_issuer(&self.config.issuer) {
            return Err("identity provider reported a different issuer".into());
        }
        *cached = Some((discovery.clone(), Instant::now()));
        Ok(discovery)
    }

    async fn jwks(&self, discovery: &Discovery, refresh: bool) -> Result<JwkSet, String> {
        let mut cached = self.jwks.lock().await;
        if let Some((set, at)) = cached.as_ref() {
            if !refresh && at.elapsed() < METADATA_TTL {
                return Ok(set.clone());
            }
        }
        let set: JwkSet = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| "could not fetch identity provider keys".to_owned())?
            .json()
            .await
            .map_err(|_| "identity provider keys were not valid".to_owned())?;
        *cached = Some((set.clone(), Instant::now()));
        Ok(set)
    }

    /// Where to send a browser to sign in, plus the flow cookie binding the
    /// callback to this browser.
    pub async fn login(&self, host: &str, back: &str) -> Result<(String, String), String> {
        let discovery = self.discovery().await?;
        let verifier = random_token();
        let flow = FlowClaims {
            h: host.into(),
            state: random_token(),
            nonce: random_token(),
            verifier: verifier.clone(),
            back: safe_return_path(back),
            x: crate::access_log::unix_now() + FLOW_SECS,
        };
        let mut url = url::Url::parse(&discovery.authorization_endpoint)
            .map_err(|_| "identity provider authorisation endpoint is invalid".to_owned())?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &format!("https://{host}{CALLBACK_PATH}"))
            .append_pair("scope", "openid email")
            .append_pair("state", &flow.state)
            .append_pair("nonce", &flow.nonce)
            .append_pair(
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            )
            .append_pair("code_challenge_method", "S256");
        let cookie = format!(
            "{FLOW_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={FLOW_SECS}",
            self.sign("flow", &flow)
        );
        Ok((url.into(), cookie))
    }

    /// Completes sign-in: checks state, exchanges the code, verifies the ID
    /// token and the route's domain rule. Returns (session cookie, return path).
    pub async fn callback(
        &self,
        host: &str,
        query: &str,
        headers: &HeaderMap,
        domains: &[String],
    ) -> Result<(String, String), String> {
        let flow: FlowClaims = cookie(headers, FLOW_COOKIE)
            .and_then(|value| self.verify("flow", value))
            .ok_or("sign-in session expired; try again")?;
        let now = crate::access_log::unix_now();
        if flow.h != host || flow.x <= now {
            return Err("sign-in session expired; try again".into());
        }
        let params: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();
        if params.get("state") != Some(&flow.state) {
            return Err("sign-in state did not match".into());
        }
        let code = params.get("code").ok_or("sign-in was not completed")?;
        let discovery = self.discovery().await?;
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let tokens: TokenResponse = self
            .http
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", &format!("https://{host}{CALLBACK_PATH}")),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("code_verifier", &flow.verifier),
            ])
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|_| "identity provider refused the sign-in code".to_owned())?
            .json()
            .await
            .map_err(|_| "identity provider token response was invalid".to_owned())?;
        let claims = self.verify_id_token(&discovery, &tokens.id_token).await?;
        if claims.nonce.as_deref() != Some(flow.nonce.as_str()) {
            return Err("sign-in nonce did not match".into());
        }
        if claims.email_verified == Some(false) {
            return Err("your email address is not verified with the identity provider".into());
        }
        let email = claims
            .email
            .map(|e| e.trim().to_ascii_lowercase())
            .ok_or("the identity provider did not share an email address")?;
        if !email_allowed(&email, domains) {
            return Err("your account is not allowed to use this service".into());
        }
        Ok((self.session_cookie(host, &email, now), flow.back))
    }

    async fn verify_id_token(
        &self,
        discovery: &Discovery,
        token: &str,
    ) -> Result<IdClaims, String> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| "ID token is malformed".to_owned())?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::EdDSA
        ) {
            return Err("ID token uses an unsupported algorithm".into());
        }
        let mut set = self.jwks(discovery, false).await?;
        let find = |set: &JwkSet| match &header.kid {
            Some(kid) => set.find(kid).cloned(),
            None if set.keys.len() == 1 => set.keys.first().cloned(),
            None => None,
        };
        let jwk = match find(&set) {
            Some(jwk) => jwk,
            None => {
                set = self.jwks(discovery, true).await?;
                find(&set).ok_or("ID token key is unknown")?
            }
        };
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| "ID token key is invalid".to_owned())?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[trim_issuer(&discovery.issuer), discovery.issuer.as_str()]);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 60;
        jsonwebtoken::decode::<IdClaims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|_| "ID token failed verification".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc() -> Oidc {
        Oidc::new(
            OidcConfig {
                issuer: "https://login.example.org.au".into(),
                client_id: "ingress".into(),
                client_secret: "secret".into(),
            },
            vec![7; 32],
        )
        .unwrap()
    }

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, cookie.parse().unwrap());
        headers
    }

    #[test]
    fn session_cookies_are_bound_to_host_expiry_and_key() {
        let gate = oidc();
        let now = crate::access_log::unix_now();
        let set = gate.session_cookie("app.example.org.au", "kim@example.org.au", now);
        let value = set.split(';').next().unwrap();
        let headers = headers_with(value);
        assert_eq!(
            gate.session_user(&headers, "app.example.org.au", &[])
                .as_deref(),
            Some("kim@example.org.au")
        );
        assert!(gate
            .session_user(&headers, "other.example.org.au", &[])
            .is_none());
        assert!(gate
            .session_user(&headers, "app.example.org.au", &["other.org".into()])
            .is_none());
        let expired = gate.session_cookie(
            "app.example.org.au",
            "kim@example.org.au",
            now - SESSION_SECS - 1,
        );
        assert!(gate
            .session_user(
                &headers_with(expired.split(';').next().unwrap()),
                "app.example.org.au",
                &[]
            )
            .is_none());
        let mut other = oidc();
        other.key = vec![8; 32];
        assert!(other
            .session_user(&headers, "app.example.org.au", &[])
            .is_none());
        // A flow cookie cannot stand in for a session cookie.
        let forged = value.replace(SESSION_COOKIE, "x");
        assert!(gate
            .session_user(&headers_with(&forged), "app.example.org.au", &[])
            .is_none());
        assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Lax"));
    }

    #[test]
    fn return_paths_stay_on_site() {
        assert_eq!(safe_return_path("/docs?a=1"), "/docs?a=1");
        for bad in [
            "//evil.example",
            "https://evil.example",
            "/\\evil",
            "/.blaktail-ingress/callback",
            "",
        ] {
            assert_eq!(safe_return_path(bad), "/");
        }
    }

    #[test]
    fn email_domain_rules() {
        assert!(email_allowed("kim@example.org.au", &[]));
        assert!(email_allowed(
            "kim@Example.org.au",
            &["example.org.au".into()]
        ));
        assert!(!email_allowed(
            "kim@evil.example",
            &["example.org.au".into()]
        ));
        assert!(!email_allowed(
            "kim@sub.example.org.au",
            &["example.org.au".into()]
        ));
        assert!(!email_allowed("@example.org.au", &[]));
        assert!(!email_allowed("nobody", &[]));
    }

    #[test]
    fn plain_http_issuers_are_refused() {
        assert!(Oidc::new(
            OidcConfig {
                issuer: "http://login.example.org.au".into(),
                client_id: "a".into(),
                client_secret: "b".into(),
            },
            vec![1; 32],
        )
        .is_err());
    }
}
