use http::uri::Scheme;
use http::Uri;
use hyper::client::connect::{Connected, Connection};

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::str::FromStr;

use std::sync::Arc;
use std::task::Poll;

use crate::config::{Router};

use crate::proxy::{Address, BoxProxyStream, ChainStreamBuilder};

#[derive(Clone)]
pub struct Connector {
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    router: Arc<Router>,
}

impl Connector {
    pub fn new(inner_map: Arc<HashMap<String, ChainStreamBuilder>>, router: Arc<Router>) -> Self {
        Self { inner_map, router }
    }
}

impl tower::Service<Uri> for Connector {
    type Response = BoxProxyStream;

    type Error = io::Error;

    type Future = Pin<Box<dyn Future<Output = io::Result<BoxProxyStream>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls_scheme = uri
            .scheme()
            .map(|s| s == &Scheme::HTTPS || s.as_str() == "wss")
            .unwrap_or(false);

        let addr = uri.authority().map(|x| x.as_str()).unwrap_or("");
        let addr = Address::from_str(
            addr.get(addr.find('@').map_or(0, |x| x + 1)..)
                .unwrap_or(""),
        );
        let inner_map = self.inner_map.clone();
        let router = self.router.clone();
        let f = async move {
            match addr {
                Ok(addr) => {
                    if is_tls_scheme {
                        let err =
                            Error::new(ErrorKind::Other, "HTTP inbound target URI is tls and the client is not using CONNECT method.");
                        log::error!("HTTP inbound target URI is tls and the client is not using CONNECT method. URI is: {}", uri);
                        return Err(err);
                    }
                    let ob = router.match_addr(&addr);
                    let stream_builder = inner_map.get(ob).unwrap();
                    log::info!("routing {} to outbound:{}", addr, ob);
                    if stream_builder.is_blackhole() {
                        let err =
                            Error::new(ErrorKind::Other, "HTTP inbound target URI is in blackhole");
                        return Err(err);
                    }
                    let server = stream_builder.build_tcp(addr).await?;
                    Ok(server)
                }
                Err(_) => {
                    log::error!(
                        "HTTP inbound target URI must be a valid address, but found: {}",
                        uri
                    );
                    let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                    Err(err)
                }
            }
        };
        Box::pin(f)
    }
}

// To proxy tls scheme, the client must use CONNECT method. So here we are always using HTTP1.1.
impl Connection for BoxProxyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
