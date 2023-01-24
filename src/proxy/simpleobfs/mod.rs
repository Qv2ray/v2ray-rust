mod http;
use self::http::HttpObfs;
use crate::proxy::BoxProxyUdpStream;
use crate::proxy::ChainableStreamBuilder;
use crate::proxy::ProtocolType;
use crate::proxy::{Address, BoxProxyStream};
use async_trait::async_trait;
use std::io;

#[derive(Clone)]
pub struct SimpleObfsStreamBuilder {
    host: Address,
}

impl SimpleObfsStreamBuilder {
    pub fn new(host: Address) -> SimpleObfsStreamBuilder {
        SimpleObfsStreamBuilder { host }
    }
}

#[async_trait]
impl ChainableStreamBuilder for SimpleObfsStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        Ok(Box::new(HttpObfs::new(self.host.clone(), io)))
    }

    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream> {
        if build_tcp_inside {
            return Ok(Box::new(HttpObfs::new(self.host.clone(), io)));
        }
        Ok(io)
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::SimpleObfs
    }
}
