use crate::common::new_error;
use crate::debug_log;
use crate::proxy::{
    BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType, ProxyUdpStream,
    UdpRead, UdpWrite,
};
use async_trait::async_trait;

use boring::ssl::SslMethod;
use boring::ssl::{SslConnector, SslFiletype};
use std::io;

use tokio_boring::{connect, SslStream};

#[derive(Clone)]
pub struct TlsStreamBuilder {
    connector: SslConnector,
    sni: String,
}

impl TlsStreamBuilder {
    pub fn new_from_config(
        sni: String,
        cert_file: &Option<String>,
        key_file: &Option<String>,
    ) -> Self {
        let mut configuration = SslConnector::builder(SslMethod::tls()).unwrap();
        if let Some(cert_file) = cert_file {
            configuration
                .set_certificate_file(cert_file, SslFiletype::PEM)
                .unwrap();
        }
        if let Some(key_file) = key_file {
            configuration
                .set_private_key_file(key_file, SslFiletype::PEM)
                .unwrap();
        }
        configuration
            .set_alpn_protos(b"\x06spdy/1\x08http/1.1")
            .unwrap();
        Self {
            connector: configuration.build(),
            sni,
        }
    }
}

impl<S: ProxyUdpStream> UdpRead for SslStream<S> {}

impl<S: ProxyUdpStream> UdpWrite for SslStream<S> {}

impl<S: ProxyUdpStream> ProxyUdpStream for tokio_boring::SslStream<S> {
    fn is_tokio_socket(&self) -> bool {
        false
    }
}

#[async_trait]
impl ChainableStreamBuilder for TlsStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        let configuration = self.connector.configure().unwrap();
        let stream = connect(configuration, self.sni.as_str(), io).await;
        match stream {
            Ok(stream) => Ok(Box::new(stream)),
            Err(e) => {
                let res = e.to_string();
                debug_log!("tls connect failed:{}", res);
                Err(new_error(res))
            }
        }
    }

    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream> {
        if build_tcp_inside {
            let configuration = self.connector.configure().unwrap();
            let stream = connect(configuration, self.sni.as_str(), io).await;
            return match stream {
                Ok(stream) => Ok(Box::new(stream)),
                Err(e) => {
                    let res = e.to_string();
                    debug_log!("tls connect failed:{}", res);
                    Err(new_error(res))
                }
            };
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
        ProtocolType::TLS
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::tls::tls::TlsStreamBuilder;
    use crate::proxy::ChainableStreamBuilder;
    use boring::ssl::SslConnector;
    use boring::ssl::SslMethod;
    use std::io;
    use std::net::ToSocketAddrs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use webpki::DnsNameRef;
    fn new(sni: &str) -> io::Result<TlsStreamBuilder> {
        let dns_name = DnsNameRef::try_from_ascii_str(sni)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
        let dns_name = std::str::from_utf8(dns_name.as_ref()).unwrap();
        let mut configuration = SslConnector::builder(SslMethod::tls()).unwrap();
        configuration
            .set_alpn_protos(b"\x06spdy/1\x08http/1.1")
            .unwrap();
        Ok(TlsStreamBuilder {
            connector: configuration.build(),
            sni: dns_name.to_string(),
        })
    }

    #[tokio::test]
    async fn test_tls() {
        let b = "ja3er.com:443";
        let addr = b.to_socket_addrs().unwrap().next().unwrap();
        let stream = TcpStream::connect(&addr).await.unwrap();
        let b = new("ja3er.com").unwrap();
        let mut stream = b.build_tcp(Box::new(stream)).await.unwrap();
        stream.write_all(b"GET /json HTTP/1.1\r\nHost: ja3er.com\r\nAccept: */*\r\nUser-Agent: curl/7.81.0\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        stream.read_buf(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        let response = response.trim_end();
        println!("from ja3er response:{}", response);
    }
}
