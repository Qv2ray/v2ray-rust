mod deserialize;
mod geoip;
mod geosite;
mod ip_trie;
mod route;
mod to_chainable_builder;

pub use route::Router;
pub use to_chainable_builder::ToChainableStreamBuilder;

use crate::common::net::relay;
use crate::common::new_error;
use crate::config::deserialize::{
    default_backlog, default_http2_method, default_true, default_v2ray_geoip_path,
    default_v2ray_geosite_path, from_str_to_address, from_str_to_cipher_kind,
    from_str_to_http_method, from_str_to_option_address, from_str_to_path,
    from_str_to_security_num, from_str_to_sni, from_str_to_uuid, from_str_to_ws_uri, EarlyDataUri,
};
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::shadowsocks::context::{BloomContext, SharedBloomContext};

use crate::proxy::socks::socks5::{Socks5Stream, Socks5UdpDatagram};

use crate::proxy::{Address, ChainStreamBuilder, ProtocolType};
use actix_server::Server;
use actix_service::fn_service;

use serde::Deserialize;

use std::net::SocketAddr;

use crate::config::route::RouterBuilder;

use domain_matcher::MatchType;
use log::info;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::proxy::dokodemo_door::build_dokodemo_door_listener;
use crate::proxy::http::serve_http_conn;
use crate::proxy::socks::SOCKS_VERSION;
use uuid::Uuid;
static SS_LOCAL_SHARED_CONTEXT: once_cell::sync::Lazy<SharedBloomContext> =
    once_cell::sync::Lazy::new(|| Arc::new(BloomContext::new(true)));

#[derive(Deserialize, Clone)]
struct VmessConfig {
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
    #[serde(deserialize_with = "from_str_to_uuid")]
    uuid: Uuid,
    #[serde(
        rename(deserialize = "method"),
        deserialize_with = "from_str_to_security_num"
    )]
    security_num: u8,
    tag: String,
}

#[derive(Deserialize, Clone)]
struct TrojanConfig {
    password: String,
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
    tag: String,
}

#[derive(Deserialize, Clone)]
struct TlsConfig {
    #[serde(deserialize_with = "from_str_to_sni")]
    sni: String,
    cert_file: Option<String>,
    key_file: Option<String>,
    #[serde(default = "default_true")]
    verify_hostname: bool,
    #[serde(default = "default_true")]
    verify_sni: bool,
    tag: String,
}

#[derive(Deserialize, Clone)]
struct WebsocketConfig {
    #[serde(deserialize_with = "from_str_to_ws_uri")]
    uri: EarlyDataUri,
    #[serde(default)]
    early_data_header_name: String,
    #[serde(default)]
    max_early_data: usize,
    #[serde(default)]
    headers: Vec<(String, String)>,
    tag: String,
}

#[derive(Deserialize, Clone)]
struct ShadowsocksConfig {
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
    password: String,
    #[serde(deserialize_with = "from_str_to_cipher_kind")]
    method: CipherKind,
    tag: String,
}

#[derive(Deserialize, Clone)]
struct BlackHoleConfig {
    tag: String,
}

#[derive(Deserialize, Clone)]
struct DirectConfig {
    tag: String,
}

#[derive(Deserialize)]
struct Outbounds {
    chain: Vec<String>,
    tag: String,
}

#[derive(Deserialize)]
struct Inbounds {
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
    #[serde(default)]
    enable_udp: bool,
}

#[derive(Deserialize)]
struct GeoSiteRules {
    tag: String,
    #[serde(default = "default_v2ray_geosite_path")]
    file_path: PathBuf,
    rules: Vec<String>,
    #[serde(default)]
    use_mph: bool,
}

#[derive(Deserialize)]
struct GeoIpRules {
    tag: String,
    #[serde(default = "default_v2ray_geoip_path")]
    file_path: PathBuf,
    rules: HashSet<String>,
}

#[derive(Deserialize)]
struct IpRoutingRules {
    tag: String,
    cidr_rules: Vec<String>,
}

#[derive(Deserialize)]
struct DomainRoutingRules {
    tag: String,
    #[serde(default)]
    full_rules: Vec<String>,
    #[serde(default)]
    domain_rules: Vec<String>,
    #[serde(default)]
    regex_rules: Vec<String>,
    #[serde(default)]
    substr_rules: Vec<String>,
    #[serde(default)]
    use_mph: bool,
}

#[derive(Deserialize)]
pub(crate) struct DokodemoDoor {
    #[allow(dead_code)]
    #[serde(default)]
    pub tproxy: bool,
    #[serde(deserialize_with = "from_str_to_address")]
    pub addr: Address,
    #[serde(default, deserialize_with = "from_str_to_option_address")]
    pub target_addr: Option<Address>,
}

#[derive(Deserialize, Clone)]
struct Http2Config {
    tag: String,
    hosts: Vec<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(
        default = "default_http2_method",
        deserialize_with = "from_str_to_http_method"
    )]
    method: http::Method,
    #[serde(deserialize_with = "from_str_to_path")]
    path: http::uri::PathAndQuery,
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_backlog")]
    backlog: u32,
    #[serde(default)]
    ss: Vec<ShadowsocksConfig>,
    #[serde(default)]
    tls: Vec<TlsConfig>,
    #[serde(default)]
    vmess: Vec<VmessConfig>,
    #[serde(default)]
    ws: Vec<WebsocketConfig>,
    #[serde(default)]
    trojan: Vec<TrojanConfig>,
    #[serde(default)]
    direct: Vec<DirectConfig>,
    #[serde(default)]
    blackhole: Vec<BlackHoleConfig>,
    #[serde(default)]
    dokodemo: Vec<DokodemoDoor>,
    #[serde(default)]
    domain_routing_rules: Vec<DomainRoutingRules>,
    #[serde(default)]
    ip_routing_rules: Vec<IpRoutingRules>,
    #[serde(default)]
    h2: Vec<Http2Config>,
    #[serde(default)]
    geosite_rules: Vec<GeoSiteRules>,
    #[serde(default)]
    geoip_rules: Vec<GeoIpRules>,
    #[serde(default)]
    default_outbound: String,

    outbounds: Vec<Outbounds>,
    inbounds: Vec<Inbounds>,
}

impl std::ops::Index<(ProtocolType, usize)> for Config {
    type Output = dyn ToChainableStreamBuilder;

    fn index(&self, index: (ProtocolType, usize)) -> &Self::Output {
        match index.0 {
            ProtocolType::SS => &self.ss[index.1],
            ProtocolType::TLS => &self.tls[index.1],
            ProtocolType::VMESS => &self.vmess[index.1],
            ProtocolType::WS => &self.ws[index.1],
            ProtocolType::TROJAN => &self.trojan[index.1],
            ProtocolType::DIRECT => &self.direct[index.1],
            ProtocolType::H2 => &self.h2[index.1],
            ProtocolType::BLACKHOLE => &self.blackhole[index.1],
        }
    }
}

macro_rules! insert_config_map {
    ($name:expr,$map:tt) => {{
        for (idx, s) in $name.iter().enumerate() {
            $map.insert(s.tag.as_str(), (s.get_protocol_type(), idx));
        }
    }};
}

impl Config {
    pub fn read_from_file(filename: String) -> io::Result<Config> {
        let mut file = File::open(filename)?;
        let mut config_string = String::new();
        file.read_to_string(&mut config_string)?;
        let config = toml::from_str(&config_string)?;
        Ok(config)
    }
    fn build_inner_map<'a>(&'a self) -> io::Result<HashMap<String, ChainStreamBuilder>> {
        // tag->(protocol idx, idx of protocol vec)
        let mut config_map: HashMap<&'a str, (ProtocolType, usize)> = HashMap::new();
        insert_config_map!(self.ss, config_map);
        insert_config_map!(self.tls, config_map);
        insert_config_map!(self.vmess, config_map);
        insert_config_map!(self.ws, config_map);
        insert_config_map!(self.trojan, config_map);
        insert_config_map!(self.direct, config_map);
        insert_config_map!(self.h2, config_map);
        insert_config_map!(self.blackhole, config_map);
        let mut inner_map = HashMap::new();
        for out in self.outbounds.iter() {
            let mut addrs = Vec::new();
            let mut builder = ChainStreamBuilder::new();
            for tag in out.chain.iter() {
                if let Some((p, idx)) = config_map.get(tag.as_str()) {
                    if let Some(tmp_addr) = self[(*p, *idx)].get_addr() {
                        if builder.remote_addr_is_none() {
                            builder.push_remote_addr(tmp_addr);
                            continue;
                        }
                        addrs.push(tmp_addr);
                    }
                } else {
                    return Err(new_error(format!(
                        "config parse failed, can't find chain tag `{}` in outbound `{}`",
                        tag, out.tag
                    )));
                }
            }
            let mut addr_iter = addrs.into_iter();
            out.chain.iter().for_each(|t| {
                if let Some((p, idx)) = config_map.get(t.as_str()) {
                    match *p {
                        ProtocolType::TROJAN | ProtocolType::SS | ProtocolType::VMESS => {
                            let next_addr = addr_iter.next();
                            if next_addr.is_none() {
                                builder.push_last_builder(self[(*p, *idx)].clone_box());
                            } else {
                                builder
                                    .push(self[(*p, *idx)].to_chainable_stream_builder(next_addr));
                            }
                        }
                        _ => {
                            builder.push(self[(*p, *idx)].to_chainable_stream_builder(None));
                        }
                    }
                }
            });
            builder.build_inner_markers();
            inner_map.insert(out.tag.clone(), builder);
        }
        Ok(inner_map)
    }

    pub fn build_server(mut self) -> io::Result<ConfigServerBuilder> {
        let inner_map = self.build_inner_map()?;
        if !inner_map.contains_key(&self.default_outbound) {
            return Err(new_error(
                "missing default outbound tag or default outbound tag is not in outbounds",
            ));
        }
        let default_outbound_tag = self.default_outbound.as_str();
        let router = build_router(
            std::mem::take(&mut self.domain_routing_rules),
            std::mem::take(&mut self.ip_routing_rules),
            std::mem::take(&mut self.geosite_rules),
            std::mem::take(&mut self.geoip_rules),
            default_outbound_tag.to_string(),
        )?;
        Ok(ConfigServerBuilder {
            backlog: self.backlog,
            inbounds: std::mem::take(&mut self.inbounds),
            dokodemo: std::mem::take(&mut self.dokodemo),
            router: Arc::new(router),
            inner_map: Arc::new(inner_map),
        })
    }
}

pub struct ConfigServerBuilder {
    backlog: u32,
    inbounds: Vec<Inbounds>,
    dokodemo: Vec<DokodemoDoor>,
    router: Arc<Router>,
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
}

impl ConfigServerBuilder {
    pub fn run(mut self) -> io::Result<()> {
        let router = (&self.router).clone();
        let inner_map = (&self.inner_map).clone();
        {
            actix_rt::System::new().block_on(async move {
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
                                let stream_builder;
                                {
                                    let ob = router.match_socket_addr(&dokodemo_door_addr);
                                    info!(
                                        "routing dokodemo addr {} to outbound:{}",
                                        dokodemo_door_addr, ob
                                    );
                                    stream_builder = inner_map.get(ob).unwrap();
                                }
                                let out_stream =
                                    stream_builder.build_tcp(dokodemo_door_addr.into()).await?;
                                return relay(io, out_stream).await;
                            }
                        })
                    })?;
                }
                for inbound in self.inbounds.into_iter() {
                    let inner_map_1 = inner_map.clone();
                    let router_1 = router.clone();
                    let enable_udp = inbound.enable_udp;

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
                                    return serve_http_conn(io, inner_map, router).await;
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
                                let stream_builder;
                                {
                                    let ob = router.match_addr(&x.1);
                                    info!("routing {} to outbound:{}", x.1, ob);
                                    stream_builder = inner_map.get(ob).unwrap();
                                }
                                let out_stream = stream_builder.build_tcp(x.1).await?;
                                return relay(x.0, out_stream).await;
                            }
                        })
                    })?;
                }
                server.run().await
            })
        }
    }
}

fn build_router(
    vec_domain_routing_rules: Vec<DomainRoutingRules>,
    vec_ip_routing_rules: Vec<IpRoutingRules>,
    vec_geosite_rules: Vec<GeoSiteRules>,
    vec_geoip_rules: Vec<GeoIpRules>,
    default_outbound_tag: String,
) -> io::Result<Router> {
    let mut builder = RouterBuilder::new();
    for domain_routing_rules in vec_domain_routing_rules {
        let use_mph = domain_routing_rules.use_mph;
        for full in domain_routing_rules.full_rules {
            builder.add_domain_rules(
                full.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::Full(true),
                use_mph,
            );
        }
        for domain in domain_routing_rules.domain_rules {
            builder.add_domain_rules(
                domain.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::Domain(true),
                use_mph,
            );
        }
        for substr in domain_routing_rules.substr_rules {
            builder.add_domain_rules(
                substr.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::SubStr(true),
                use_mph,
            );
        }
        builder.add_regex_rules(
            domain_routing_rules.tag.as_str(),
            domain_routing_rules.regex_rules,
        );
    }
    for cidr_rules in vec_ip_routing_rules {
        builder.add_cidr_rules(cidr_rules.tag.as_str(), &cidr_rules.cidr_rules);
    }
    for geosite_rule in vec_geosite_rules {
        let mut geosite_tag_map = HashMap::new();
        for rule in geosite_rule.rules {
            geosite_tag_map.insert(rule.to_uppercase(), geosite_rule.tag.as_str());
        }
        builder.read_geosite_file(
            geosite_rule.file_path,
            geosite_tag_map,
            geosite_rule.use_mph,
        )?;
    }
    for geoip_rule in vec_geoip_rules {
        builder.read_geoip_file(
            geoip_rule.file_path,
            geoip_rule.tag.as_str(),
            geoip_rule.rules,
        )?;
    }
    builder.build(default_outbound_tag)
}
