use crate::proxy::BoxProxyStream;
use crate::proxy::ChainableStreamBuilder;
use async_trait::async_trait;
use std::io;

#[derive(Clone)]
pub struct DirectStreamBuilder;

#[async_trait]
impl ChainableStreamBuilder for DirectStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        Ok(io)
    }

    async fn build_udp(&self, _io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        unimplemented!()
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }
}
