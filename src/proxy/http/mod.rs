use hyper::server::conn::Http;
use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;

use crate::common::net::relay;
use crate::common::new_error;
use crate::config::Router;
use crate::proxy::{Address, ChainStreamBuilder};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Body, Method, Request, Response};
use log::info;

pub async fn serve_http_conn(
    io: TcpStream,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,
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
                async move { proxy(req, inner_map, router).await }
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
) -> Result<Response<Body>, hyper::Error> {
    println!("http proxy server req: {:?}", req);

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                let inner_map = inner_map;
                let router = router;
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr, inner_map, router).await {
                            log::error!("server io error: {}", e);
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
    uri.authority().and_then(|auth| {
        Address::from_str(auth.as_str())
            .map(|e| Some(e))
            .unwrap_or(None)
    })
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    addr: Address,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,
) -> std::io::Result<()> {
    // Connect to remote server
    let stream_builder;
    {
        let ob = router.match_addr(&addr);
        info!("routing {} to outbound:{}", addr, ob);
        stream_builder = inner_map.get(ob).unwrap();
    }
    let server = stream_builder.build_tcp(addr).await?;
    relay(upgraded, server).await?;
    Ok(())
}
