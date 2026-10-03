//! Listeners: HTTPS (TLS by SNI, HTTP/1.1 with upgrades) and plain HTTP
//! (ACME challenges and redirects only), with global connection and
//! handshake/header timeouts so slow clients cannot pin resources.

use crate::proxy::Proxy;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

fn http1() -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(64 * 1024)
        .keep_alive(true);
    builder
}

pub async fn serve_https(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    proxy: Arc<Proxy>,
    max_connections: usize,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let Ok((stream, client)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let acceptor = acceptor.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok(tls)) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
            else {
                return;
            };
            let sni = tls.get_ref().1.server_name().map(str::to_ascii_lowercase);
            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                let sni = sni.clone();
                async move { Ok::<_, Infallible>(proxy.handle(req, client, sni).await) }
            });
            let _ = http1()
                .serve_connection(TokioIo::new(tls), service)
                .with_upgrades()
                .await;
        });
    }
}

pub async fn serve_plain(listener: TcpListener, proxy: Arc<Proxy>, max_connections: usize) {
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { Ok::<_, Infallible>(proxy.handle_plain(req).await) }
            });
            let _ = http1()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
