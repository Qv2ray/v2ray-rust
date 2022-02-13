use crate::common::sha224;
use crate::proxy::trojan::trojan::RequestHeader;
use crate::proxy::{
    Address, BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType,
};
use async_trait::async_trait;
use std::io;

mod trojan;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone)]
pub struct TrojanStreamBuilder {
    password: [u8; 56],
    addr: Address,
}

impl TrojanStreamBuilder {
    pub fn new(addr: Address, password: &[u8], _is_udp: bool) -> TrojanStreamBuilder {
        let x = sha224(password);
        let mut p = [0u8; 56];
        for (i, t) in x.iter().enumerate() {
            p[i * 2] = HEX_CHARS_LOWER[(t >> 4) as usize];
            p[i * 2 + 1] = HEX_CHARS_LOWER[(t & 0x0f) as usize];
        }
        TrojanStreamBuilder { password: p, addr }
    }
}

#[async_trait]
impl ChainableStreamBuilder for TrojanStreamBuilder {
    async fn build_tcp(&self, mut io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        let header = RequestHeader::TcpConnect(self.password, self.addr.clone());
        header.write_to(&mut io).await.map(|_| io)
    }

    async fn build_udp(&self, mut io: BoxProxyUdpStream) -> io::Result<BoxProxyUdpStream> {
        let header = RequestHeader::UdpAssociate(self.password);
        header.write_to(&mut io).await.map(|_| io)
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::TROJAN
    }
}
