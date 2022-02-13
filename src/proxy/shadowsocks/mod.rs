use crate::common::openssl_bytes_to_key;
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::shadowsocks::context::SharedBloomContext;
use crate::proxy::shadowsocks::crypto_io::CryptoStream;
use crate::proxy::{
    Address, BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType,
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::io;

mod aead;
pub mod aead_helper;
pub mod context;
pub mod crypto_io;
mod udp_crypto_io;

fn ss_hkdf_sha1(iv_or_salt: &[u8], key: &[u8]) -> [u8; 64] {
    use hkdf::Hkdf;
    use sha1::Sha1;
    let ikm = key;
    let mut okm = [0u8; 64];
    let hk = Hkdf::<Sha1>::new(Some(iv_or_salt), ikm);
    hk.expand(b"ss-subkey", &mut okm)
        .expect("ss hkdf sha1 failed");
    okm
}

#[derive(Clone)]
pub struct ShadowsocksBuilder {
    addr: Address,
    method: CipherKind,
    context: SharedBloomContext,
    key: Bytes,
}

impl ShadowsocksBuilder {
    pub fn new_from_config(
        addr: Address,
        password: &str,
        method: CipherKind,
        context: SharedBloomContext,
    ) -> ShadowsocksBuilder {
        let mut key = BytesMut::with_capacity(method.key_len());
        unsafe {
            key.set_len(key.capacity());
        }
        openssl_bytes_to_key(password.as_bytes(), key.as_mut());
        ShadowsocksBuilder {
            addr,
            method,
            context,
            key: key.freeze(),
        }
    }
}

#[async_trait]
impl ChainableStreamBuilder for ShadowsocksBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        let mut stream = Box::new(CryptoStream::new(
            self.context.clone(),
            io,
            self.key.clone(),
            self.method,
        ));
        let res = self.addr.write_to_stream(&mut stream).await;
        match res {
            Ok(_) => Ok(stream),
            Err(e) => Err(e),
        }
    }

    async fn build_udp(&self, _io: BoxProxyUdpStream) -> io::Result<BoxProxyUdpStream> {
        todo!()
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::SS
    }
}
