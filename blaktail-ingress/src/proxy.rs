//! The reverse proxy. Each request is matched to a live route by the TLS
//! server name and the request host, which must agree; it is then forwarded
//! over HTTP/1.1 to the route's single published target and nowhere else.
//! Absolute-form URIs and Host tricks cannot change where it connects, and
//! redirects from the target are handed back to the client, never followed.

use crate::{
    access_log::{AccessLog, Entry},
    headers,
    oidc::{self, Oidc},
    routes::{LiveRoute, RouteTable},
};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, LengthLimitError, Limited};
use hyper::{
    body::Incoming,
    header::{self, HeaderValue},
    Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// ACME HTTP-01 responses: token -> (host, key authorisation).
pub type ChallengeMap = Arc<RwLock<HashMap<String, (String, String)>>>;

pub struct Proxy {
    pub routes: Arc<RouteTable>,
    pub log: AccessLog,
    pub oidc: Option<Arc<Oidc>>,
    pub challenges: ChallengeMap,
}

fn text(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn redirect(status: StatusCode, location: &str) -> Response<Body> {
    let mut response = text(status, "");
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// Lower-cased host without a trailing dot; the port, if any, must match.
fn host_of(value: &str, port: u16) -> Option<String> {
    let authority: hyper::http::uri::Authority = value.parse().ok()?;
    if authority.port_u16().is_some_and(|p| p != port) {
        return None;
    }
    Some(authority.host().trim_end_matches('.').to_ascii_lowercase())
}

/// The single host a request names. Absolute-form authority and every Host
/// header must agree; anything ambiguous is refused.
fn request_host(req: &Request<Incoming>, port: u16) -> Result<String, StatusCode> {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let header_host = match (hosts.next(), hosts.next()) {
        (Some(value), None) => Some(
            value
                .to_str()
                .ok()
                .and_then(|v| host_of(v, port))
                .ok_or(StatusCode::BAD_REQUEST)?,
        ),
        (None, _) => None,
        (Some(_), Some(_)) => return Err(StatusCode::BAD_REQUEST),
    };
    let uri_host = match req.uri().authority() {
        Some(authority) => {
            Some(host_of(authority.as_str(), port).ok_or(StatusCode::MISDIRECTED_REQUEST)?)
        }
        None => None,
    };
    match (uri_host, header_host) {
        (Some(a), Some(b)) if a != b => Err(StatusCode::MISDIRECTED_REQUEST),
        (Some(host), _) | (None, Some(host)) => Ok(host),
        (None, None) => Err(StatusCode::BAD_REQUEST),
    }
}

fn is_length_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<LengthLimitError>() {
            return true;
        }
        current = error.source();
    }
    false
}

struct Outcome {
    response: Response<Body>,
    outcome: &'static str,
    user: Option<String>,
}

impl Outcome {
    fn of(response: Response<Body>, outcome: &'static str) -> Self {
        Self {
            response,
            outcome,
            user: None,
        }
    }
}

impl Proxy {
    /// Handles one request on the HTTPS listener. `sni` is the TLS server
    /// name the client connected with.
    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        client: SocketAddr,
        sni: Option<String>,
    ) -> Response<Body> {
        let started = Instant::now();
        let method = req.method().to_string();
        let path = req.uri().path().chars().take(512).collect::<String>();
        let host = request_host(&req, 443);
        let logged_host = host.clone().unwrap_or_default();
        let outcome = match host {
            Err(status) => Outcome::of(
                text(status, "This request does not name a published host.\n"),
                "rejected_host",
            ),
            Ok(host) if sni.as_deref() != Some(host.as_str()) => Outcome::of(
                text(
                    StatusCode::MISDIRECTED_REQUEST,
                    "This connection is not for that host.\n",
                ),
                "rejected_host",
            ),
            Ok(host) => match self.routes.get(&host) {
                None if !self.routes.is_fresh() => Outcome::of(
                    text(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable.\n"),
                    "stale_config",
                ),
                None => Outcome::of(text(StatusCode::NOT_FOUND, "Not found.\n"), "rejected_host"),
                Some(route) => self.forward(req, client, route).await,
            },
        };
        self.log.record(Entry {
            ts: crate::access_log::unix_now(),
            host: logged_host,
            client: client.ip().to_string(),
            method,
            path,
            status: outcome.response.status().as_u16(),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome: outcome.outcome,
            user: outcome.user,
        });
        outcome.response
    }

    async fn forward(
        &self,
        mut req: Request<Incoming>,
        client: SocketAddr,
        route: Arc<LiveRoute>,
    ) -> Outcome {
        if req.method() == Method::CONNECT || !req.uri().path().starts_with('/') {
            return Outcome::of(
                text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.\n"),
                "bad_request",
            );
        }
        if !route.source_allowed(client.ip()) {
            return Outcome::of(
                text(StatusCode::FORBIDDEN, "Not available from your network.\n"),
                "source_denied",
            );
        }
        if !route
            .limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allow(client.ip())
        {
            let mut response = text(StatusCode::TOO_MANY_REQUESTS, "Too many requests.\n");
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("10"));
            return Outcome::of(response, "rate_limited");
        }
        let declared = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|len| len > route.max_body()) {
            return Outcome::of(
                text(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large.\n"),
                "too_large",
            );
        }
        let Ok(permit) = route.connections.clone().try_acquire_owned() else {
            return Outcome::of(
                text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service busy; try again shortly.\n",
                ),
                "connection_limit",
            );
        };
        let fqdn = route.config.fqdn.clone();
        let mut user = None;
        if route.oidc() {
            let Some(gate) = self.oidc.clone() else {
                return Outcome::of(
                    text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Sign-in is not configured on this ingress.\n",
                    ),
                    "auth_unavailable",
                );
            };
            let domains = &route.config.allowed_email_domains;
            match req.uri().path() {
                oidc::CALLBACK_PATH => {
                    let query = req.uri().query().unwrap_or_default().to_owned();
                    return match gate.callback(&fqdn, &query, req.headers(), domains).await {
                        Ok((cookie, back)) => {
                            let mut response = redirect(StatusCode::SEE_OTHER, &back);
                            if let Ok(value) = HeaderValue::from_str(&cookie) {
                                response.headers_mut().append(header::SET_COOKIE, value);
                            }
                            Outcome::of(response, "login_completed")
                        }
                        Err(reason) => {
                            tracing::info!(host = %fqdn, %reason, "sign-in refused");
                            Outcome::of(
                                text(
                                    StatusCode::FORBIDDEN,
                                    "Sign-in failed or is not allowed for this service.\n",
                                ),
                                "login_refused",
                            )
                        }
                    };
                }
                oidc::LOGOUT_PATH => {
                    let mut response = redirect(StatusCode::SEE_OTHER, "/");
                    if let Ok(value) = HeaderValue::from_str(&Oidc::clear_cookie()) {
                        response.headers_mut().append(header::SET_COOKIE, value);
                    }
                    return Outcome::of(response, "logout");
                }
                _ => {}
            }
            match gate.session_user(req.headers(), &fqdn, domains) {
                Some(email) => user = Some(email),
                None if matches!(*req.method(), Method::GET | Method::HEAD)
                    && !headers::is_websocket(req.headers()) =>
                {
                    let back = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str().to_owned())
                        .unwrap_or_else(|| "/".into());
                    return match gate.login(&fqdn, &back).await {
                        Ok((location, cookie)) => {
                            let mut response = redirect(StatusCode::FOUND, &location);
                            if let Ok(value) = HeaderValue::from_str(&cookie) {
                                response.headers_mut().append(header::SET_COOKIE, value);
                            }
                            Outcome::of(response, "login_required")
                        }
                        Err(reason) => {
                            tracing::warn!(host = %fqdn, %reason, "identity provider unavailable");
                            Outcome::of(
                                text(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Sign-in is unavailable right now.\n",
                                ),
                                "auth_unavailable",
                            )
                        }
                    };
                }
                None => {
                    return Outcome::of(
                        text(StatusCode::UNAUTHORIZED, "Sign in to use this service.\n"),
                        "login_required",
                    )
                }
            }
        }

        let websocket = req.method() == Method::GET && headers::is_websocket(req.headers());
        let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());
        let upstream_headers = headers::upstream_request_headers(
            req.headers(),
            &fqdn,
            client.ip(),
            websocket,
            user.as_deref(),
        );
        let method = req.method().clone();
        let body = Limited::new(
            req.into_body(),
            usize::try_from(route.max_body()).unwrap_or(usize::MAX),
        )
        .boxed();
        let mut upstream = Request::new(body);
        *upstream.method_mut() = method;
        *upstream.uri_mut() = path_and_query
            .parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("/"));
        *upstream.version_mut() = Version::HTTP_11;
        *upstream.headers_mut() = upstream_headers;

        let stream =
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(route.target)).await {
                Ok(Ok(stream)) => stream,
                _ => {
                    return Outcome {
                        response: text(
                            StatusCode::BAD_GATEWAY,
                            "The service is not reachable right now.\n",
                        ),
                        outcome: "upstream_unreachable",
                        user,
                    }
                }
            };
        let _ = stream.set_nodelay(true);
        let (mut sender, connection) = match hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(stream))
            .await
        {
            Ok(pair) => pair,
            Err(_) => {
                return Outcome {
                    response: text(
                        StatusCode::BAD_GATEWAY,
                        "The service is not reachable right now.\n",
                    ),
                    outcome: "upstream_unreachable",
                    user,
                }
            }
        };
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        let mut response =
            match tokio::time::timeout(RESPONSE_TIMEOUT, sender.send_request(upstream)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) if is_length_limit(&error) => {
                    return Outcome {
                        response: text(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large.\n"),
                        outcome: "too_large",
                        user,
                    }
                }
                Ok(Err(_)) => {
                    return Outcome {
                        response: text(
                            StatusCode::BAD_GATEWAY,
                            "The service returned an invalid response.\n",
                        ),
                        outcome: "upstream_error",
                        user,
                    }
                }
                Err(_) => {
                    return Outcome {
                        response: text(
                            StatusCode::GATEWAY_TIMEOUT,
                            "The service took too long to respond.\n",
                        ),
                        outcome: "upstream_timeout",
                        user,
                    }
                }
            };
        let upgraded = response.status() == StatusCode::SWITCHING_PROTOCOLS;
        let sanitized = headers::client_response_headers(
            response.headers(),
            &fqdn,
            route.target,
            upgraded && websocket,
        );
        if upgraded {
            let Some(client_upgrade) = client_upgrade else {
                return Outcome {
                    response: text(
                        StatusCode::BAD_GATEWAY,
                        "The service returned an invalid response.\n",
                    ),
                    outcome: "upstream_error",
                    user,
                };
            };
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            let routes = self.routes.clone();
            tokio::spawn(tunnel(
                client_upgrade,
                upstream_upgrade,
                route,
                routes,
                permit,
            ));
            let mut reply = Response::new(Empty::new().map_err(|never| match never {}).boxed());
            *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            *reply.headers_mut() = sanitized;
            return Outcome {
                response: reply,
                outcome: "proxied_upgrade",
                user,
            };
        }
        let status = response.status();
        // The permit lives as long as the response body is streaming.
        let body = response
            .into_body()
            .map_err(|e| -> BoxError { Box::new(e) })
            .map_frame(move |frame| {
                let _held = &permit;
                frame
            })
            .boxed();
        let mut reply = Response::new(body);
        *reply.status_mut() = status;
        *reply.headers_mut() = sanitized;
        Outcome {
            response: reply,
            outcome: "proxied",
            user,
        }
    }

    /// Port 80: ACME HTTP-01 answers for routes being issued, and a redirect
    /// to HTTPS for live routes. Nothing is proxied in plain HTTP.
    pub async fn handle_plain(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        let Ok(host) = request_host(&req, 80) else {
            return text(StatusCode::BAD_REQUEST, "Bad request.\n");
        };
        if let Some(token) = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        {
            let answer = self
                .challenges
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(token)
                .filter(|(for_host, _)| *for_host == host)
                .map(|(_, key_authorization)| key_authorization.clone());
            return match answer {
                Some(answer) => {
                    let mut response = Response::new(
                        Full::new(Bytes::from(answer))
                            .map_err(|never| match never {})
                            .boxed(),
                    );
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    );
                    response
                }
                None => text(StatusCode::NOT_FOUND, "Not found.\n"),
            };
        }
        if self.routes.get(&host).is_none() {
            return text(StatusCode::NOT_FOUND, "Not found.\n");
        }
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .filter(|p| p.starts_with('/'))
            .unwrap_or("/");
        redirect(
            StatusCode::PERMANENT_REDIRECT,
            &format!("https://{host}{path}"),
        )
    }
}

/// Copies an upgraded (WebSocket) connection until either side closes, the
/// route is withdrawn, or the route table goes stale.
async fn tunnel(
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    route: Arc<LiveRoute>,
    routes: Arc<RouteTable>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _permit = permit;
    let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream) else {
        return;
    };
    let mut client = TokioIo::new(client);
    let mut upstream = TokioIo::new(upstream);
    let mut revoked = route.revoked();
    let still_live = {
        let route = route.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let current = routes.get(&route.config.fqdn);
                if !current.is_some_and(|c| Arc::ptr_eq(&c, &route)) {
                    return;
                }
            }
        }
    };
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
        _ = revoked.wait_for(|revoked| *revoked) => {}
        _ = still_live => {}
    }
}
