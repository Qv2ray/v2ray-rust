use crate::config::ToChainableStreamBuilder;
use crate::deref_udp_read;
use crate::deref_udp_write;

use async_trait::async_trait;

use std::net::{IpAddr, SocketAddr};
use std::num::ParseIntError;
use std::pin::Pin;

use bitvec::vec::BitVec;
use std::io;
use std::task::{Context, Poll};
use std::vec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

mod address;
pub mod blackhole;
pub mod direct;
pub mod dokodemo_door;
pub mod grpc;
pub mod h2;
pub mod http;
pub mod shadowsocks;
pub mod simpleobfs;
pub mod socks;
pub mod tls;
pub mod trojan;
mod udp;
mod utils;
pub mod vmess;
pub mod websocket;

use crate::common::new_error;
use crate::proxy::utils::ChainStreamBuilderProtocolTypeIter;
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

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ProtocolType {
    SS,
    Tls,
    Vmess,
    Grpc,
    WS,
    Trojan,
    Direct,
    H2,
    Blackhole,
    SimpleObfs,
}

impl ProtocolType {
    pub fn is_uot(&self) -> bool {
        matches!(self, ProtocolType::Vmess | ProtocolType::Trojan)
    }
}

#[async_trait]
pub trait ChainableStreamBuilder: Sync + Send {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream>;
    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream>;
    fn into_box(self) -> Box<dyn ChainableStreamBuilder>;
    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder>;
    fn protocol_type(&self) -> ProtocolType;
    fn get_addr(&self) -> Option<Address> {
        None
    }
}

impl Clone for Box<dyn ChainableStreamBuilder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
pub trait UdpRead {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        unimplemented!()
    }
}

pub trait UdpWrite {
    fn poll_send_to(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _target: &Address,
    ) -> Poll<io::Result<usize>> {
        unimplemented!()
    }
}

pub trait ProxyUdpStream: AsyncRead + AsyncWrite + Send + Unpin + UdpRead + UdpWrite {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + UdpRead + UdpWrite> ProxyUdpStream for T {}

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

impl UdpRead for TcpStream {}

impl UdpWrite for TcpStream {}

pub trait ProxySteam: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxySteam for T {}

pub type BoxProxyStream = Box<dyn ProxySteam>;
pub type BoxProxyUdpStream = Box<dyn ProxyUdpStream>;

#[derive(Clone)]
pub struct ChainStreamBuilder {
    builders: Vec<Box<dyn ChainableStreamBuilder>>,
    remote_addr: Option<Address>,
    last_udp_addr: Option<Address>,
    build_udp_marker: BitVec,
    last_builder: Option<Box<dyn ToChainableStreamBuilder>>,
    #[allow(dead_code)]
    is_full_cone: bool,
    is_black_hole: bool,
}

impl ChainStreamBuilder {
    pub fn new() -> ChainStreamBuilder {
        ChainStreamBuilder {
            builders: vec![],
            remote_addr: None,
            last_udp_addr: None,
            build_udp_marker: Default::default(),
            last_builder: None,
            is_full_cone: true,
            is_black_hole: false,
        }
    }

    pub fn build_inner_markers(&mut self) {
        let mut iter = ChainStreamBuilderProtocolTypeIter::new(&self.builders, &self.last_builder);
        self.is_black_hole = iter.any(|x| x == ProtocolType::Blackhole);

        let iter = ChainStreamBuilderProtocolTypeIter::new(&self.builders, &self.last_builder);
        build_udp_marker_impl(&mut self.build_udp_marker, iter);
        let mut iter = ChainStreamBuilderProtocolTypeIter::new(&self.builders, &self.last_builder);
        if let Some(idx) = iter.position(|a| a.is_uot()) {
            if idx == 0 {
                // last builder is uot
            } else {
                // the builders first uot protocol from right to left;
                self.last_udp_addr = self.builders[self.builders.len() - idx].get_addr();
            }
        } else {
            self.last_udp_addr = self.remote_addr.clone();
        }
    }

    pub fn is_blackhole(&self) -> bool {
        self.is_black_hole
    }

    pub fn remote_addr_is_none(&self) -> bool {
        self.remote_addr.is_none()
    }

    pub fn push_remote_addr(&mut self, addr: Address) {
        self.remote_addr = Some(addr);
    }

    pub fn push_last_builder(&mut self, builder: Box<dyn ToChainableStreamBuilder>) {
        self.last_builder = Some(builder);
    }

    pub fn push(&mut self, builder: Box<dyn ChainableStreamBuilder>) {
        self.builders.push(builder);
    }

    pub async fn build_tcp(&self, proxy_addr: Address) -> io::Result<BoxProxyStream> {
        if self.is_black_hole {
            return Err(new_error("block connection"));
        }
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

    /// if builder in proxy chain is UoT, then before uot builder all builder must build tcp inside
    pub async fn build_udp(
        &self,
        proxy_addr: Address,
        udp_bind_ip: IpAddr,
    ) -> io::Result<BoxProxyUdpStream> {
        if self.is_black_hole {
            return Err(new_error("block connection"));
        }
        let mut outer_stream: BoxProxyUdpStream;
        // debug_log!("build udp marker len:{}", self.build_udp_marker.len());
        debug_log!("build udp marker:{}", self.build_udp_marker);
        // debug_log!("self.builders len:{}", self.builders.len());
        if let Some(remote_addr) = &self.remote_addr {
            debug_log!("remote_addr:{},proxy_addr:{}", remote_addr, proxy_addr);
            if self.build_udp_marker[0] {
                outer_stream = Box::new(remote_addr.connect_tcp().await?);
            } else {
                let socket = UdpSocket::bind(SocketAddr::new(udp_bind_ip, 0)).await?;
                outer_stream = Box::new(remote_addr.connect_udp(socket).await?);
            }
        } else if self.build_udp_marker[0] {
            outer_stream = Box::new(proxy_addr.connect_tcp().await?);
        } else {
            let socket = UdpSocket::bind(SocketAddr::new(udp_bind_ip, 0)).await?;
            outer_stream = Box::new(proxy_addr.connect_udp(socket).await?);
        }
        for (b, build_tcp_inside) in self.builders.iter().zip(self.build_udp_marker.iter()) {
            outer_stream = b.build_udp(outer_stream, *build_tcp_inside).await?;
        }
        if let Some(b) = &self.last_builder {
            if b.get_protocol_type().is_uot() {
                outer_stream = b
                    .to_chainable_stream_builder(Some(proxy_addr))
                    .build_udp(outer_stream, *self.build_udp_marker.last().unwrap())
                    .await?;
            } else {
                outer_stream = b
                    .to_chainable_stream_builder(self.last_udp_addr.clone())
                    .build_udp(outer_stream, *self.build_udp_marker.last().unwrap())
                    .await?;
            }
        }
        Ok(outer_stream)
    }
}
fn build_udp_marker_impl<T>(bit_vec: &mut BitVec, iter: T)
where
    T: Iterator<Item = ProtocolType>,
{
    let mut is_uot = false;
    for ty in iter {
        if ty.is_uot() && !is_uot {
            bit_vec.push(false);
            is_uot = true;
        } else {
            bit_vec.push(is_uot);
        }
    }
    bit_vec.reverse();
}

#[cfg(test)]
mod tests {
    use crate::proxy::ProtocolType::{Trojan, Vmess, SS, WS};
    use crate::proxy::{build_udp_marker_impl, ProtocolType};
    use bitvec::vec::BitVec;

    fn from_protocol_type_to_udp_marker_bit_vec<T>(t: T) -> BitVec
    where
        T: Iterator<Item = ProtocolType>,
    {
        let mut b = BitVec::new();
        build_udp_marker_impl(&mut b, t);
        b
    }

    fn test_eq_bit_vec(l: BitVec, r: Vec<bool>) -> bool {
        println!("bit vec:{},expected:{:?}", l, r);
        if l.len() != r.len() {
            return false;
        }
        for (l, r) in l.iter().zip(r.iter()) {
            if *l != *r {
                return false;
            }
        }
        true
    }

    #[test]
    fn test() {
        // ws vmess ss: T F F
        // ws vmess ss ss: T F F F
        // trojan ws vmess : T T F
        let type1 = vec![WS, Vmess, SS];
        let b1 = vec![true, false, false];
        assert!(test_eq_bit_vec(
            from_protocol_type_to_udp_marker_bit_vec(type1.into_iter().rev()),
            b1
        ));
        let type2 = vec![WS, Vmess, SS, SS];
        let b2 = vec![true, false, false, false];
        assert!(test_eq_bit_vec(
            from_protocol_type_to_udp_marker_bit_vec(type2.into_iter().rev()),
            b2,
        ));
        let type3 = vec![Trojan, WS, Vmess];
        let b3 = vec![true, true, false];
        assert!(test_eq_bit_vec(
            from_protocol_type_to_udp_marker_bit_vec(type3.into_iter().rev()),
            b3
        ));
    }
}
