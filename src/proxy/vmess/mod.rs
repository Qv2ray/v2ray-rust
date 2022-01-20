use crate::proxy::{Address, BoxProxyStream, ChainableStreamBuilder};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use crate::proxy::vmess::vmess::VmessStream;
use crate::proxy::vmess::vmess_option::VmessOption;

mod aead;
mod aead_header;
mod kdf;
pub mod vmess;
pub mod vmess_option;

#[derive(Clone)]
pub struct VmessBuilder {
    vmess_option: VmessOption,
}

impl VmessBuilder {
    pub fn new(
        uuid: String,
        security: String,
        alter_id: u16,
        addr: Address,
        is_udp: bool,
    ) -> anyhow::Result<VmessBuilder> {
        Ok(VmessBuilder {
            vmess_option: VmessOption::new(&uuid, alter_id, &security, addr, is_udp)?,
        })
    }
}

#[async_trait]
impl ChainableStreamBuilder for VmessBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> std::io::Result<BoxProxyStream> {
        let opt = self.vmess_option.clone();
        Ok(Box::new(VmessStream::new(opt, io)))
    }

    async fn build_udp(&self, _io: BoxProxyStream) -> std::io::Result<BoxProxyStream> {
        unimplemented!()
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }
}
