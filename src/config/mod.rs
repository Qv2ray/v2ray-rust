mod deserialize;
mod geoip;
mod geosite;
mod ip_trie;
mod route;
mod server_builder;
mod to_chainable_builder;
mod utils;

pub use route::Router;
pub use server_builder::{ConfigServerBuilder, COUNTER_MAP};
pub use to_chainable_builder::ToChainableStreamBuilder;

use crate::common::new_error;
use crate::config::deserialize::{
    default_backlog, default_grpc_path, default_http2_method, default_random_string,
    default_relay_buffer_size, default_true, default_v2ray_geoip_path, default_v2ray_geosite_path,
    from_str_to_address, from_str_to_cipher_kind, from_str_to_grpc_path, from_str_to_http_method,
    from_str_to_option_address, from_str_to_path, from_str_to_security_num, from_str_to_sni,
    from_str_to_uuid, from_str_to_ws_uri, EarlyDataUri,
};
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::shadowsocks::context::{BloomContext, SharedBloomContext};

use crate::proxy::{Address, ChainStreamBuilder, ProtocolType};

use serde::Deserialize;

use crate::config::route::build_router;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

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
    headers: BTreeMap<String, String>,
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
    #[serde(default = "default_random_string")]
    tag: String,
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
    headers: HashMap<String, String>,
    #[serde(
        default = "default_http2_method",
        deserialize_with = "from_str_to_http_method"
    )]
    method: http::Method,
    #[serde(deserialize_with = "from_str_to_path")]
    path: http::uri::PathAndQuery,
}

#[derive(Deserialize, Clone)]
struct SimpleObfsConfig {
    tag: String,
    #[serde(deserialize_with = "from_str_to_address")]
    host: Address,
}

#[derive(Deserialize, Clone)]
struct GrpcConfig {
    tag: String,
    host: String,
    #[serde(
        rename(deserialize = "service_name"),
        deserialize_with = "from_str_to_grpc_path",
        default = "default_grpc_path"
    )]
    path: http::uri::PathAndQuery,
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    enable_api_server: bool,
    #[serde(default = "default_relay_buffer_size")]
    relay_buffer_size: usize,
    #[serde(deserialize_with = "from_str_to_address", default)]
    api_server_addr: Address,

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
    simpleobfs: Vec<SimpleObfsConfig>,
    #[serde(default)]
    dokodemo: Vec<DokodemoDoor>,
    #[serde(default)]
    domain_routing_rules: Vec<DomainRoutingRules>,
    #[serde(default)]
    ip_routing_rules: Vec<IpRoutingRules>,
    #[serde(default)]
    h2: Vec<Http2Config>,
    #[serde(default)]
    grpc: Vec<GrpcConfig>,
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
            ProtocolType::Tls => &self.tls[index.1],
            ProtocolType::Vmess => &self.vmess[index.1],
            ProtocolType::WS => &self.ws[index.1],
            ProtocolType::Trojan => &self.trojan[index.1],
            ProtocolType::Direct => &self.direct[index.1],
            ProtocolType::H2 => &self.h2[index.1],
            ProtocolType::Grpc => &self.grpc[index.1],
            ProtocolType::Blackhole => &self.blackhole[index.1],
            ProtocolType::SimpleObfs => &self.simpleobfs[index.1],
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
        insert_config_map!(self.grpc, config_map);
        insert_config_map!(self.blackhole, config_map);
        insert_config_map!(self.simpleobfs, config_map);
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
                        ProtocolType::Trojan | ProtocolType::SS | ProtocolType::Vmess => {
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
        if self.default_outbound.is_empty() {
            if let Some(name) = self.outbounds.first() {
                self.default_outbound = name.tag.clone();
            }
        }
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
        Ok(ConfigServerBuilder::new(
            self.backlog,
            self.relay_buffer_size,
            std::mem::take(&mut self.inbounds),
            std::mem::take(&mut self.dokodemo),
            Arc::new(router),
            Arc::new(inner_map),
            self.enable_api_server,
            self.api_server_addr,
        ))
    }
}
