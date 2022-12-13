use crate::common::new_error;
use crate::debug_log;
use crate::proxy::{
    BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType, ProxyUdpStream,
    UdpRead, UdpWrite,
};
use async_trait::async_trait;

use boring::ssl::{SslConnector, SslSignatureAlgorithm};
use boring::ssl::{SslMethod, SslVersion};
use foreign_types_shared::ForeignTypeRef;
use std::io;

use tokio_boring::{connect, SslStream};

#[cfg(target_os = "macos")]
use super::macos as platform;
#[cfg(all(unix, not(target_os = "macos")))]
use super::unix as platform;
#[cfg(windows)]
use super::windows as platform;

#[derive(Clone)]
pub struct TlsStreamBuilder {
    connector: SslConnector,
    sni: String,
    verify_hostname: bool,
    verify_sni: bool,
}

impl TlsStreamBuilder {
    pub fn new_from_config(
        sni: String,
        cert_file: &Option<String>,
        verify_hostname: bool,
        verify_sni: bool,
    ) -> Self {
        let mut configuration = SslConnector::builder(SslMethod::tls()).unwrap();
        {
            log::debug!("start add system cert");
            let certs = platform::load_native_certs().unwrap();
            log::debug!("certs len:{}", certs.len());
            let mut count = 0;
            for cert in certs.into_iter() {
                let err = configuration.cert_store_mut().add_cert(cert);
                if err.is_ok() {
                    count += 1;
                }
                log::debug!("add system cert:{}", count);
            }
            log::debug!("add cert done");
        }
        if let Some(cert_file) = cert_file {
            debug_log!("load custom ca file");
            configuration.set_ca_file(cert_file).unwrap();
        }
        configuration
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .unwrap();
        configuration
            .set_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES")
            .unwrap();
        configuration
            .set_verify_algorithm_prefs(&[
                SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                SslSignatureAlgorithm::RSA_PKCS1_SHA256,
                SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                SslSignatureAlgorithm::RSA_PKCS1_SHA384,
                SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
                SslSignatureAlgorithm::RSA_PKCS1_SHA512,
            ])
            .unwrap();
        configuration
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        configuration.enable_signed_cert_timestamps();
        configuration.enable_ocsp_stapling();
        configuration.set_grease_enabled(true);
        unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                configuration.as_ptr(),
                boring_sys::TLSEXT_cert_compression_brotli as u16,
                None,
                Some(decompress_ssl_cert),
            );
        }
        Self {
            connector: configuration.build(),
            sni,
            verify_hostname,
            verify_sni,
        }
    }
}

impl<S: ProxyUdpStream> UdpRead for SslStream<S> {}

impl<S: ProxyUdpStream> UdpWrite for SslStream<S> {}

macro_rules! build_tcp_impl {
    ($name:tt,$io:tt) => {
        let mut configuration = $name.connector.configure().unwrap();
        configuration.set_use_server_name_indication($name.verify_sni);
        configuration.set_verify_hostname($name.verify_hostname);
        unsafe {
            boring_sys::SSL_add_application_settings(
                configuration.as_ptr(),
                b"h2".as_ptr(),
                2,
                b"\x00\x03".as_ptr(),
                2,
            );
        }
        let stream = connect(configuration, $name.sni.as_str(), $io).await;
        return match stream {
            Ok(stream) => Ok(Box::new(stream)),
            Err(e) => {
                let res = e.to_string();
                debug_log!("tls connect failed:{}", res);
                Err(new_error(res))
            }
        };
    };
}

#[async_trait]
impl ChainableStreamBuilder for TlsStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        build_tcp_impl!(self, io);
    }

    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream> {
        if build_tcp_inside {
            build_tcp_impl!(self, io);
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
        ProtocolType::Tls
    }
}

extern "C" fn decompress_ssl_cert(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    mut uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> libc::c_int {
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let x: *mut *mut u8 = &mut buf;
        let allocated_buffer = boring_sys::CRYPTO_BUFFER_alloc(x, uncompressed_len);
        if buf.is_null() {
            return 0;
        }
        let uncompressed_len_ptr: *mut usize = &mut uncompressed_len;
        if brotli::ffi::decompressor::CBrotliDecoderDecompress(
            in_len,
            in_,
            uncompressed_len_ptr,
            buf,
        ) as i32
            == 1
        {
            *out = allocated_buffer;
            1
        } else {
            boring_sys::CRYPTO_BUFFER_free(allocated_buffer);
            0
        }
    }
}

#[cfg(all(target_os = "linux", test))]
mod tests {
    use crate::proxy::tls::tls_stream::TlsStreamBuilder;
    use crate::proxy::ChainableStreamBuilder;
    use std::net::ToSocketAddrs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_tls() {
        let b = "client.tlsfingerprint.io:8443";
        let addr = b.to_socket_addrs().unwrap().next().unwrap();
        let stream = TcpStream::connect(&addr).await.unwrap();
        println!("local:{}", stream.local_addr().unwrap());
        let b = TlsStreamBuilder::new_from_config(
            "client.tlsfingerprint.io".to_string(),
            &None,
            true,
            true,
        );
        let mut stream = b.build_tcp(Box::new(stream)).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: client.tlsfingerprint.io\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        stream.read_buf(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        let response = response.trim_end();
        println!("from google response:{}", response);
    }
}
