use hyper::server::conn::Http;
use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::net::TcpStream;

use crate::common::net::{relay, relay_with_atomic_counter};
use crate::common::new_error;
use crate::config::{Router, COUNTER_MAP};
use crate::debug_log;
use crate::proxy::{Address, ChainStreamBuilder};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Body, Method, Request, Response};
use log::info;

pub async fn serve_http_conn(
    io: TcpStream,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,
    enable_api_server: bool,
    in_counter_up: Option<&'static AtomicU64>,
    in_counter_down: Option<&'static AtomicU64>,
) -> io::Result<()> {
    let mut http_conn = Http::new();
    http_conn
        .http1_preserve_header_case(true)
        .http1_preserve_header_case(true);
    let conn = http_conn
        .serve_connection(
            io,
            service_fn(|req| {
                let inner_map = inner_map.clone();
                let router = router.clone();
                async move {
                    proxy(
                        req,
                        inner_map,
                        router,
                        enable_api_server,
                        in_counter_up,
                        in_counter_down,
                    )
                    .await
                }
            }),
        )
        .with_upgrades();
    if let Err(e) = conn.await {
        return Err(new_error(e));
    }
    Ok(())
}

async fn proxy(
    req: Request<Body>,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,

    enable_api_server: bool,
    in_counter_up: Option<&'static AtomicU64>,
    in_counter_down: Option<&'static AtomicU64>,
) -> Result<Response<Body>, hyper::Error> {
    debug_log!("http proxy server req: {:?}", req);

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                let inner_map = inner_map;
                let router = router;
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(
                            upgraded,
                            addr,
                            inner_map,
                            router,
                            enable_api_server,
                            in_counter_up,
                            in_counter_down,
                        )
                        .await
                        {
                            log::error!("http tunnel error: {}", e);
                        };
                    }
                    Err(e) => log::error!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            log::error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        // todo: support other method
        let mut resp = Response::new(Body::from("only support CONNECT"));
        *resp.status_mut() = http::StatusCode::BAD_REQUEST;
        Ok(resp)
    }
}

fn host_addr(uri: &http::Uri) -> Option<Address> {
    uri.authority()
        .and_then(|auth| Address::from_str(auth.as_str()).map(Some).unwrap_or(None))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    addr: Address,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,
    enable_api_server: bool,
    in_counter_up: Option<&'static AtomicU64>,
    in_counter_down: Option<&'static AtomicU64>,
) -> std::io::Result<()> {
    // Connect to remote server
    let ob = router.match_addr(&addr);
    let stream_builder = inner_map.get(ob).unwrap();
    info!("routing {} to outbound:{}", addr, ob);
    if stream_builder.is_blackhole() {
        return Ok(());
    }
    let server = stream_builder.build_tcp(addr).await?;
    if enable_api_server {
        let out_down = format!("outbound>>>{}>>>traffic>>>downlink", ob);
        let out_up = format!("outbound>>>{}>>>traffic>>>uplink", ob);
        let out_down = COUNTER_MAP.get().unwrap().get(out_down.as_str()).unwrap();
        let out_up = COUNTER_MAP.get().unwrap().get(out_up.as_str()).unwrap();
        relay_with_atomic_counter(
            upgraded,
            server,
            in_counter_up.unwrap(),
            in_counter_down.unwrap(),
            out_up,
            out_down,
        )
        .await?;
    } else {
        relay(upgraded, server).await?;
    }
    Ok(())
}
