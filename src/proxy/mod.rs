use crate::config::ToChainableStreamBuilder;
use crate::deref_udp_read;
use crate::deref_udp_write;

use async_trait::async_trait;

use std::net::{IpAddr, SocketAddr};
use std::num::ParseIntError;
use std::pin::Pin;

use std::io;
use std::task::{Context, Poll};
use std::vec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

mod address;
pub mod direct;
pub mod dokodemo_door;
pub mod shadowsocks;
pub mod socks;
pub mod tls;
pub mod trojan;
mod udp;
pub mod vmess;
pub mod websocket;
pub use address::{Address, AddressError};

#[allow(dead_code)]
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[allow(dead_code)]
pub fn show_utf8_lossy(bs: &[u8]) -> String {
    String::from_utf8_lossy(bs).into_owned()
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_log {
    ($( $args:expr ),*) => { {use log::debug;debug!( $( $args ),* ); }}
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_log {
    ($( $args:expr ),*) => {};
}

pub enum ProtocolType {
    SS,
    TLS,
    VMESS,
    WS,
    TROJAN,
    DIRECT,
}

#[async_trait]
pub trait ChainableStreamBuilder: Sync + Send {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream>;
    async fn build_udp(&self, io: BoxProxyUdpStream) -> io::Result<BoxProxyUdpStream>;
    fn into_box(self) -> Box<dyn ChainableStreamBuilder>;
    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder>;
    fn protocol_type(&self) -> ProtocolType;
}

impl Clone for Box<dyn ChainableStreamBuilder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
pub trait UdpRead {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<Address>>;
}

pub trait UdpWrite {
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Address,
    ) -> Poll<io::Result<usize>>;
}

pub trait ProxyUdpStream: AsyncRead + AsyncWrite + Send + Unpin + UdpRead + UdpWrite {
    fn is_tokio_socket(&self) -> bool;
}

impl<T: ?Sized + UdpRead + Unpin> UdpRead for Box<T> {
    deref_udp_read!();
}
impl<T: ?Sized + UdpWrite + Unpin> UdpWrite for Box<T> {
    deref_udp_write!();
}
impl<T: ?Sized + UdpRead + Unpin> UdpRead for &mut T {
    deref_udp_read!();
}
impl<T: ?Sized + UdpWrite + Unpin> UdpWrite for &mut T {
    deref_udp_write!();
}

impl<T: ?Sized + ProxyUdpStream> ProxyUdpStream for Box<T> {
    fn is_tokio_socket(&self) -> bool {
        (**self).is_tokio_socket()
    }
}

impl UdpRead for TcpStream {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        unimplemented!()
    }
}

impl UdpWrite for TcpStream {
    fn poll_send_to(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _target: &Address,
    ) -> Poll<io::Result<usize>> {
        unimplemented!()
    }
}

impl ProxyUdpStream for TcpStream {
    fn is_tokio_socket(&self) -> bool {
        true
    }
}

pub trait ProxySteam: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxySteam for T {}

pub type BoxProxyStream = Box<dyn ProxySteam>;
pub type BoxProxyUdpStream = Box<dyn ProxyUdpStream>;

#[derive(Clone)]
pub struct ChainStreamBuilder {
    builders: Vec<Box<dyn ChainableStreamBuilder>>,
    remote_addr: Option<Address>,
    last_builder: Option<Box<dyn ToChainableStreamBuilder>>,
    is_uot: bool,
    is_full_cone: bool,
}

impl ChainStreamBuilder {
    pub fn new() -> ChainStreamBuilder {
        ChainStreamBuilder {
            builders: vec![],
            remote_addr: None,
            last_builder: None,
            is_uot: false,
            is_full_cone: true,
        }
    }

    pub fn remote_addr_is_none(&self) -> bool {
        self.remote_addr.is_none()
    }

    pub fn push_remote_addr(&mut self, addr: Address) {
        self.remote_addr = Some(addr);
    }

    pub fn push_last_builder(&mut self, builder: Box<dyn ToChainableStreamBuilder>) {
        self.check_builder_protocol_type(builder.protocol_type());
        self.last_builder = Some(builder);
    }

    fn check_builder_protocol_type(&mut self, ty: ProtocolType) {
        match ty {
            ProtocolType::VMESS => {
                self.is_uot = true;
                self.is_full_cone = false;
            }
            ProtocolType::TROJAN => {
                self.is_uot = true;
            }
            _ => {}
        }
    }

    pub fn push(&mut self, builder: Box<dyn ChainableStreamBuilder>) {
        self.check_builder_protocol_type(builder.protocol_type());
        self.builders.push(builder);
    }

    pub async fn build_tcp(&self, proxy_addr: Address) -> io::Result<BoxProxyStream> {
        return if let Some(remote_addr) = &self.remote_addr {
            let outer_stream = remote_addr.connect_tcp().await?;
            let mut outer_stream: Box<dyn ProxySteam> = Box::new(outer_stream);
            for b in self.builders.iter() {
                outer_stream = b.build_tcp(outer_stream).await?;
            }
            if let Some(b) = &self.last_builder {
                outer_stream = b
                    .to_chainable_stream_builder(Some(proxy_addr))
                    .build_tcp(outer_stream)
                    .await?;
            }
            Ok(outer_stream)
        } else {
            let outer_stream = proxy_addr.connect_tcp().await?;
            let mut outer_stream: Box<dyn ProxySteam> = Box::new(outer_stream);
            for b in self.builders.iter() {
                outer_stream = b.build_tcp(outer_stream).await?;
            }
            if let Some(b) = &self.last_builder {
                outer_stream = b
                    .to_chainable_stream_builder(Some(proxy_addr))
                    .build_tcp(outer_stream)
                    .await?;
            }
            Ok(outer_stream)
        };
    }

    // todo: chain check
    // if chain is uot, then before uot builder all builder must build tcp inside
    pub async fn build_udp(
        &self,
        proxy_addr: Address,
        udp_bind_ip: IpAddr,
    ) -> io::Result<BoxProxyUdpStream> {
        let mut outer_stream: BoxProxyUdpStream;
        if let Some(remote_addr) = &self.remote_addr {
            if self.is_uot {
                outer_stream = Box::new(remote_addr.connect_tcp().await?);
            } else {
                let socket = UdpSocket::bind(SocketAddr::new(udp_bind_ip, 0)).await?;
                outer_stream = Box::new(remote_addr.connect_udp(socket).await?);
            }
        } else {
            if self.is_uot {
                outer_stream = Box::new(proxy_addr.connect_tcp().await?);
            } else {
                let socket = UdpSocket::bind(SocketAddr::new(udp_bind_ip, 0)).await?;
                outer_stream = Box::new(proxy_addr.connect_udp(socket).await?);
            }
        }
        for b in self.builders.iter() {
            outer_stream = b.build_udp(outer_stream).await?;
        }
        if let Some(b) = &self.last_builder {
            outer_stream = b
                .to_chainable_stream_builder(Some(proxy_addr))
                .build_udp(outer_stream)
                .await?;
        }
        Ok(outer_stream)
    }
}
