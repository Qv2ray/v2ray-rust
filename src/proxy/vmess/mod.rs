use crate::proxy::vmess::vmess::VmessStream;
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::{BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType};
use async_trait::async_trait;
use std::io;

mod aead;
mod aead_header;
mod kdf;
pub mod vmess;
pub mod vmess_option;

#[derive(Clone)]
pub struct VmessBuilder {
    pub(crate) vmess_option: VmessOption,
}

#[async_trait]
impl ChainableStreamBuilder for VmessBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> std::io::Result<BoxProxyStream> {
        let opt = self.vmess_option.clone();
        Ok(Box::new(VmessStream::new(opt, io)))
    }

    async fn build_udp(&self, io: BoxProxyUdpStream) -> io::Result<BoxProxyUdpStream> {
        let mut opt = self.vmess_option.clone();
        opt.is_udp = true;
        Ok(Box::new(VmessStream::new(opt, io)))
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::VMESS
    }
}
