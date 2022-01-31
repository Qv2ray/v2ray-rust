use crate::common::net::copy_with_capacity_and_counter;
use crate::common::{new_error, LW_BUFFER_SIZE};
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::shadowsocks::context::{BloomContext, SharedBloomContext};
use crate::proxy::shadowsocks::ShadowsocksBuilder;
use crate::proxy::socks::socks5::Socks5Stream;
use crate::proxy::tls::tls::TlsStreamBuilder;
use crate::proxy::trojan::TrojanStreamBuilder;
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::vmess::VmessBuilder;
use crate::proxy::websocket::BinaryWsStreamBuilder;
use crate::proxy::{Address, AddressError, ChainStreamBuilder, ChainableStreamBuilder};
use actix_server::Server;
use actix_service::fn_service;
use lazy_static::lazy_static;
use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use webpki::DnsNameRef;

use crate::proxy::direct::DirectStreamBuilder;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::Uri;
use uuid::Uuid;
lazy_static! {
    static ref SS_LOCAL_SHARED_CONTEXT: SharedBloomContext = Arc::new(BloomContext::new(true));
}

pub trait ToChainableStreamBuilder: Sync + Send {
    fn to_chainable_stream_builder(&self, addr: Option<Address>)
        -> Box<dyn ChainableStreamBuilder>;
    fn tag(&self) -> &str;
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder>;
}
impl Clone for Box<dyn ToChainableStreamBuilder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Deserialize, Clone)]
pub struct VmessConfig {
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

impl ToChainableStreamBuilder for VmessConfig {
    fn to_chainable_stream_builder(
        &self,
        addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(VmessBuilder {
            vmess_option: VmessOption {
                uuid: self.uuid.clone(),
                alter_id: 0,
                addr: addr.unwrap(),
                security_num: self.security_num,
                is_udp: false,
            },
        })
    }

    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

fn from_str_to_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let addr: &str = Deserialize::deserialize(deserializer)?;
    addr.parse()
        .map_err(|e: AddressError| D::Error::custom(e.as_str()))
}

fn from_str_to_security_num<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let security_num: u8;
    let security: &str = Deserialize::deserialize(deserializer)?;
    if security == "aes-128-gcm" {
        security_num = 0x03;
    } else if security == "chacha20-poly1305" {
        security_num = 0x04;
    } else if security == "none" {
        security_num = 0x05;
    } else if security == "auto" {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            security_num = 0x03;
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            security_num = 0x04;
        }
    } else {
        let msg = format!("unknown security type {}", security);
        return Err(D::Error::custom(msg.as_str()));
    };
    Ok(security_num)
}

fn from_str_to_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let uuid_str: &str = Deserialize::deserialize(deserializer)?;
    Uuid::parse_str(uuid_str).map_err(D::Error::custom)
}

fn from_str_to_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let uri: &str = Deserialize::deserialize(deserializer)?;
    uri.parse().map_err(D::Error::custom)
}

fn from_str_to_sni<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let sni: &str = Deserialize::deserialize(deserializer)?;
    let dns_name = DnsNameRef::try_from_ascii_str(sni).map_err(D::Error::custom)?;
    let res = std::str::from_utf8(dns_name.as_ref()).map_err(D::Error::custom)?;
    Ok(res.to_owned())
}

#[derive(Deserialize, Clone)]
pub struct TrojanConfig {
    password: String,
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
    tag: String,
}

impl ToChainableStreamBuilder for TrojanConfig {
    fn to_chainable_stream_builder(
        &self,
        addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(TrojanStreamBuilder::new(
            addr.unwrap(),
            self.password.as_bytes(),
            false,
        ))
    }
    fn tag(&self) -> &str {
        self.tag.as_str()
    }
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

#[derive(Deserialize, Clone)]
pub struct TlsConfig {
    #[serde(deserialize_with = "from_str_to_sni")]
    sni: String,
    cert_file: Option<String>,
    key_file: Option<String>,
    tag: String,
}

impl ToChainableStreamBuilder for TlsConfig {
    fn to_chainable_stream_builder(
        &self,
        _addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(TlsStreamBuilder::new_from_config(
            self.sni.clone(),
            &self.cert_file,
            &self.key_file,
        ))
    }
    fn tag(&self) -> &str {
        self.tag.as_str()
    }
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

#[derive(Deserialize, Clone)]
pub struct WebsocketConfig {
    #[serde(deserialize_with = "from_str_to_uri")]
    uri: Uri,
    #[serde(default)]
    headers: Vec<(String, String)>,
    tag: String,
}

impl ToChainableStreamBuilder for WebsocketConfig {
    fn to_chainable_stream_builder(
        &self,
        _addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(BinaryWsStreamBuilder::new_from_config(
            self.uri.clone(),
            None,
            self.headers.clone(),
        ))
    }
    fn tag(&self) -> &str {
        self.tag.as_str()
    }
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
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
struct DirectConfig {
    tag: String,
}
impl ToChainableStreamBuilder for DirectConfig {
    fn to_chainable_stream_builder(
        &self,
        _addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(DirectStreamBuilder)
    }

    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

impl ToChainableStreamBuilder for ShadowsocksConfig {
    fn to_chainable_stream_builder(
        &self,
        addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(ShadowsocksBuilder::new_from_config(
            addr.unwrap(),
            self.password.as_str(),
            self.method,
            SS_LOCAL_SHARED_CONTEXT.clone(),
        ))
    }
    fn tag(&self) -> &str {
        self.tag.as_str()
    }
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

fn from_str_to_cipher_kind<'de, D>(deserializer: D) -> Result<CipherKind, D::Error>
where
    D: Deserializer<'de>,
{
    let method: &str = Deserialize::deserialize(deserializer)?;
    let method = match method {
        "none" => CipherKind::None,
        "aes-128-gcm" => CipherKind::Aes128Gcm,
        "aes-256-gcm" => CipherKind::Aes256Gcm,
        "chacha20-poly1305" => CipherKind::ChaCha20Poly1305,
        _ => return Err(D::Error::custom("wrong ss encryption method")),
    };
    Ok(method)
}
#[derive(Deserialize)]
pub struct Outbounds {
    chain: Vec<String>,
    tag: String,
}

#[derive(Deserialize)]
pub struct Inbounds {
    #[serde(deserialize_with = "from_str_to_address")]
    addr: Address,
}

#[derive(Deserialize)]
pub struct Config {
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
    outbounds: Vec<Outbounds>,
    inbounds: Vec<Inbounds>,
}

macro_rules! insert_config_map {
    ($name:expr,$protocol_idx:tt,$map:tt) => {{
        for (idx, s) in $name.iter().enumerate() {
            $map.insert(s.tag.clone(), ($protocol_idx, idx));
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
    fn build_inner_map(&self) -> io::Result<HashMap<String, ChainStreamBuilder>> {
        // tag->(protocol idx, idx of protocol vec)
        let mut config_map: HashMap<String, (u8, usize)> = HashMap::new();
        insert_config_map!(self.ss, 0u8, config_map);
        insert_config_map!(self.tls, 1u8, config_map);
        insert_config_map!(self.vmess, 2u8, config_map);
        insert_config_map!(self.ws, 3u8, config_map);
        insert_config_map!(self.trojan, 4u8, config_map);
        insert_config_map!(self.direct, 5u8, config_map);
        let mut inner_map = HashMap::new();
        for out in self.outbounds.iter() {
            let mut addrs = Vec::new();
            let mut builder = ChainStreamBuilder::new();
            for tag in out.chain.iter() {
                let protocol = config_map.get(tag);
                if protocol.is_none() {
                    return Err(new_error(format!(
                        "config parse failed, can't find tag: {}",
                        tag
                    )));
                }
                let protocol = protocol.unwrap();
                match protocol.0 {
                    0 => {
                        let tmp_addr = self.ss[protocol.1].addr.clone();
                        if builder.remote_addr_is_none() {
                            builder.push_remote_addr(tmp_addr);
                            continue;
                        }
                        addrs.push(tmp_addr);
                    }
                    2 => {
                        let tmp_addr = self.vmess[protocol.1].addr.clone();
                        if builder.remote_addr_is_none() {
                            builder.push_remote_addr(tmp_addr);
                            continue;
                        }
                        addrs.push(tmp_addr);
                    }
                    4 => {
                        let tmp_addr = self.trojan[protocol.1].addr.clone();
                        if builder.remote_addr_is_none() {
                            builder.push_remote_addr(tmp_addr);
                            continue;
                        }
                        addrs.push(tmp_addr);
                    }
                    _ => {}
                }
            }
            let mut addr_iter = addrs.into_iter();
            for tag in out.chain.iter() {
                let protocol = config_map.get(tag).unwrap();
                match protocol.0 {
                    0 => {
                        let next_addr = addr_iter.next();
                        if next_addr.is_none() {
                            builder.push_last_builder(Box::new(self.ss[protocol.1].clone()));
                            continue;
                        }
                        builder.push(self.ss[protocol.1].to_chainable_stream_builder(next_addr));
                    }
                    1 => {
                        builder.push(self.tls[protocol.1].to_chainable_stream_builder(None));
                    }
                    2 => {
                        let next_addr = addr_iter.next();
                        if next_addr.is_none() {
                            builder.push_last_builder(Box::new(self.vmess[protocol.1].clone()));
                            continue;
                        }
                        builder.push(self.vmess[protocol.1].to_chainable_stream_builder(next_addr));
                    }
                    3 => {
                        builder.push(self.ws[protocol.1].to_chainable_stream_builder(None));
                    }
                    4 => {
                        let next_addr = addr_iter.next();
                        if next_addr.is_none() {
                            builder.push_last_builder(Box::new(self.trojan[protocol.1].clone()));
                            continue;
                        }
                        builder
                            .push(self.trojan[protocol.1].to_chainable_stream_builder(next_addr));
                    }
                    5 => {
                        builder.push(self.direct[protocol.1].to_chainable_stream_builder(None));
                    }
                    _ => {
                        unreachable!()
                    }
                }
            }
            inner_map.insert(out.tag.clone(), builder);
        }
        Ok(inner_map)
    }

    pub fn build_server(self) -> io::Result<()> {
        let inner_map = self.build_inner_map()?;
        let inner_map = Arc::new(inner_map);
        {
            actix_rt::System::new().block_on(async move {
                let mut server = Server::build();
                for inbound in self.inbounds.into_iter() {
                    let inner_map = inner_map.clone();
                    server = server.bind("in", inbound.addr.to_string(), move || {
                        let inner_map = inner_map.clone();
                        fn_service(move |io: TcpStream| {
                            let inner_map = inner_map.clone();
                            async move {
                                let stream = Socks5Stream::new(io);
                                let x = stream.init(None).await?;
                                let stream_builder;
                                {
                                    // todo: route according tag
                                    stream_builder = inner_map.get("out").unwrap();
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

async fn relay<T1, T2>(inbound_stream: T1, outbound_stream: T2) -> io::Result<()>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);
    let mut down = 0u64;
    let mut up = 0u64;
    tokio::select! {
            _ = copy_with_capacity_and_counter(&mut outbound_r,&mut inbound_w,&mut down,LW_BUFFER_SIZE*2)=>{
            }
            _ = copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w,&mut up,LW_BUFFER_SIZE*2)=>{
            }
    }
    println!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}
