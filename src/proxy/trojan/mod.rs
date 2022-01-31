use crate::common::sha224;
use crate::proxy::trojan::trojan::RequestHeader;
use crate::proxy::{Address, BoxProxyStream, ChainableStreamBuilder};
use async_trait::async_trait;

mod trojan;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone)]
pub struct TrojanStreamBuilder(RequestHeader);

impl TrojanStreamBuilder {
    pub fn new(addr: Address, password: &[u8], is_udp: bool) -> TrojanStreamBuilder {
        let x = sha224(password);
        let mut p = [0u8; 56];
        for (i, t) in x.iter().enumerate() {
            p[i * 2] = HEX_CHARS_LOWER[(t >> 4) as usize];
            p[i * 2 + 1] = HEX_CHARS_LOWER[(t & 0x0f) as usize];
        }
        if is_udp {
            todo!()
        } else {
            TrojanStreamBuilder(RequestHeader::TcpConnect(p, addr))
        }
    }
}

#[async_trait]
impl ChainableStreamBuilder for TrojanStreamBuilder {
    async fn build_tcp(&self, mut io: BoxProxyStream) -> std::io::Result<BoxProxyStream> {
        let res = self.0.write_to(&mut io).await;
        match res {
            Ok(_) => Ok(io),
            Err(e) => Err(e),
        }
    }

    async fn build_udp(&self, _io: BoxProxyStream) -> std::io::Result<BoxProxyStream> {
        todo!()
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }
}
