use crate::api::ApiServer;
use crate::common::net::{relay, relay_with_atomic_counter};
use crate::config::{DokodemoDoor, Inbounds, Router};
use crate::proxy::dokodemo_door::build_dokodemo_door_listener;
use crate::proxy::http::serve_http_conn;
use crate::proxy::socks::socks5::{Socks5Stream, Socks5UdpDatagram};
use crate::proxy::socks::SOCKS_VERSION;
use crate::proxy::{Address, ChainStreamBuilder};
use actix_server::Server;
use actix_service::fn_service;
use log::info;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::net::TcpStream;

pub static COUNTER_MAP: OnceCell<HashMap<String, AtomicU64>> = OnceCell::new();

pub struct ConfigServerBuilder {
    backlog: u32,
    inbounds: Vec<Inbounds>,
    dokodemo: Vec<DokodemoDoor>,
    router: Arc<Router>,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    enable_api_server: bool,
    api_server_addr: Address,
}

impl ConfigServerBuilder {
    pub(super) fn new(
        backlog: u32,
        inbounds: Vec<Inbounds>,
        dokodemo: Vec<DokodemoDoor>,
        router: Arc<Router>,
        inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
        enable_api_server: bool,
        api_server_addr: Address,
    ) -> Self {
        Self {
            backlog,
            inbounds,
            dokodemo,
            router,
            inner_map,
            enable_api_server,
            api_server_addr,
        }
    }
    pub fn run(mut self) -> io::Result<()> {
        let router = (&self.router).clone();
        let enable_api_server = self.enable_api_server;
        if enable_api_server {
            COUNTER_MAP.get_or_init(|| {
                let mut map = HashMap::new();
                for k in self.inner_map.keys() {
                    map.insert(
                        format!("outbound>>>{}>>>traffic>>>uplink", k),
                        AtomicU64::new(0),
                    );
                    map.insert(
                        format!("outbound>>>{}>>>traffic>>>downlink", k),
                        AtomicU64::new(0),
                    );
                }
                for k in self.inbounds.iter() {
                    map.insert(
                        format!("inbound>>>{}>>>traffic>>>uplink", k.tag),
                        AtomicU64::new(0),
                    );
                    map.insert(
                        format!("inbound>>>{}>>>traffic>>>downlink", k.tag),
                        AtomicU64::new(0),
                    );
                }
                map.insert(
                    "inbound>>>dokodemo>>>traffic>>>uplink".to_string(),
                    AtomicU64::new(0),
                );
                map.insert(
                    "inbound>>>dokodemo>>>traffic>>>downlink".to_string(),
                    AtomicU64::new(0),
                );
                map
            });
        }
        let inner_map = (&self.inner_map).clone();
        {
            actix_rt::System::new().block_on(async move {
                if enable_api_server {
                    log::info!("api server listening on: {}", self.api_server_addr);
                    tokio::spawn(async move {
                        let api_server = ApiServer::new_server();
                        tonic::transport::Server::builder()
                            .add_service(api_server)
                            .serve(self.api_server_addr.get_sock_addr())
                            .await?;
                        Ok::<(), tonic::transport::Error>(())
                    });
                }
                let mut server = Server::build();
                server = server.backlog(self.backlog);
                info!("backlog is:{}", self.backlog);
                for door in self.dokodemo.iter_mut() {
                    let inner_map = inner_map.clone();
                    let router = router.clone();
                    let target_addr = door.target_addr.take();
                    let std_listener = build_dokodemo_door_listener(door, self.backlog)?;
                    server = server.listen("dokodemo", std_listener, move || {
                        let target_addr = target_addr.clone();
                        let inner_map = inner_map.clone();
                        let router = router.clone();
                        fn_service(move |io: TcpStream| {
                            let target_addr = target_addr.clone();
                            let inner_map = inner_map.clone();
                            let router = router.clone();
                            async move {
                                let dokodemo_door_addr = io.local_addr()?;
                                if let Some(addr) = target_addr {
                                    let out_stream = addr.connect_tcp().await?;
                                    return relay(io, out_stream).await;
                                }
                                let ob = router.match_socket_addr(&dokodemo_door_addr);
                                info!(
                                    "routing dokodemo addr {} to outbound:{}",
                                    dokodemo_door_addr, ob
                                );
                                let stream_builder = inner_map.get(ob).unwrap();
                                let out_stream =
                                    stream_builder.build_tcp(dokodemo_door_addr.into()).await?;
                                if enable_api_server {
                                    let in_down = COUNTER_MAP
                                        .get()
                                        .unwrap()
                                        .get("inbound>>>dokodemo>>>traffic>>>downlink");
                                    let in_up = COUNTER_MAP
                                        .get()
                                        .unwrap()
                                        .get("inbound>>>dokodemo>>>traffic>>>uplink");
                                    let out_down =
                                        format!("outbound>>>{}>>>traffic>>>downlink", ob);
                                    let out_up = format!("outbound>>>{}>>>traffic>>>uplink", ob);
                                    let out_down =
                                        COUNTER_MAP.get().unwrap().get(out_down.as_str()).unwrap();
                                    let out_up =
                                        COUNTER_MAP.get().unwrap().get(out_up.as_str()).unwrap();
                                    return relay_with_atomic_counter(
                                        io,
                                        out_stream,
                                        in_up.unwrap(),
                                        in_down.unwrap(),
                                        out_up,
                                        out_down,
                                    )
                                    .await;
                                } else {
                                    return relay(io, out_stream).await;
                                }
                            }
                        })
                    })?;
                }
                for inbound in self.inbounds.into_iter() {
                    let inner_map_1 = inner_map.clone();
                    let router_1 = router.clone();
                    let enable_udp = inbound.enable_udp;
                    let mut in_down = None;
                    let mut in_up = None;
                    if enable_api_server {
                        let down = format!("inbound>>>{}>>>traffic>>>downlink", inbound.tag);
                        let up = format!("inbound>>>{}>>>traffic>>>uplink", inbound.tag);
                        in_down = Some(COUNTER_MAP.get().unwrap().get(down.as_str()).unwrap());
                        in_up = Some(COUNTER_MAP.get().unwrap().get(up.as_str()).unwrap());
                    }

                    server = server.bind("in", inbound.addr.to_string(), move || {
                        let inner_map = inner_map_1.clone();
                        let router = router_1.clone();
                        fn_service(move |io: TcpStream| {
                            let inner_map = inner_map.clone();
                            let router = router.clone();
                            async move {
                                let mut header = [0u8; 1];
                                io.peek(&mut header).await?;
                                if header[0] != SOCKS_VERSION {
                                    return serve_http_conn(
                                        io,
                                        inner_map,
                                        router,
                                        enable_api_server,
                                        in_up,
                                        in_down,
                                    )
                                    .await;
                                }
                                let peer_ip = io.peer_addr()?.ip();
                                let addr = if enable_udp {
                                    Some(SocketAddr::new(peer_ip, 0))
                                } else {
                                    None
                                };
                                let stream = Socks5Stream::new(io);
                                let mut udp_socket = None;
                                let x = stream.init(addr, &mut udp_socket).await?;
                                if let Some(udp_socket) = udp_socket {
                                    Socks5UdpDatagram::run(udp_socket, router, inner_map, x.0)
                                        .await?;
                                    return Ok(());
                                }
                                let ob = router.match_addr(&x.1);
                                info!("routing {} to outbound:{}", x.1, ob);
                                let stream_builder = inner_map.get(ob).unwrap();
                                let out_stream = stream_builder.build_tcp(x.1).await?;
                                if enable_api_server {
                                    let out_down =
                                        format!("outbound>>>{}>>>traffic>>>downlink", ob);
                                    let out_up = format!("outbound>>>{}>>>traffic>>>uplink", ob);
                                    let out_down =
                                        COUNTER_MAP.get().unwrap().get(out_down.as_str()).unwrap();
                                    let out_up =
                                        COUNTER_MAP.get().unwrap().get(out_up.as_str()).unwrap();
                                    return relay_with_atomic_counter(
                                        x.0,
                                        out_stream,
                                        in_up.unwrap(),
                                        in_down.unwrap(),
                                        out_up,
                                        out_down,
                                    )
                                    .await;
                                } else {
                                    return relay(x.0, out_stream).await;
                                }
                            }
                        })
                    })?;
                }
                server.run().await
            })
        }
    }
}
