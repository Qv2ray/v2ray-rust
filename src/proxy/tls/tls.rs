use crate::common::new_error;
use crate::debug_log;
use crate::proxy::{BoxProxyStream, ChainableStreamBuilder};
use async_trait::async_trait;
use boring::ssl::ConnectConfiguration;
use boring::ssl::SslConnector;
use boring::ssl::SslMethod;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_boring::{connect, SslStream};
use webpki::DnsNameRef;

#[derive(Clone)]
pub struct TlsStreamBuilder {
    sni: String,
}

impl TlsStreamBuilder {
    pub fn new(sni: &str) -> io::Result<Self> {
        Ok(Self {
            sni: sni.to_string(),
        })
    }
}

#[async_trait]
impl ChainableStreamBuilder for TlsStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        let dns_name = DnsNameRef::try_from_ascii_str(&self.sni)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
        let dns_name = std::str::from_utf8(dns_name.as_ref()).unwrap();
        println!("dnsname:{}", dns_name);
        let mut configuration = SslConnector::builder(SslMethod::tls()).unwrap();
        configuration
            .set_alpn_protos(b"\x06spdy/1\x08http/1.1")
            .unwrap();
        let configuration = configuration.build().configure().unwrap();
        let stream = connect(configuration, dns_name, io).await;
        match stream {
            Ok(stream) => Ok(Box::new(stream)),
            Err(e) => {
                let res = e.to_string();
                debug_log!("tls connect failed:{}", res);
                Err(new_error(res))
            }
        }
    }

    async fn build_udp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        unimplemented!()
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::tls::tls::TlsStreamBuilder;
    use crate::proxy::ChainableStreamBuilder;
    use std::net::ToSocketAddrs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_tls() {
        let b = "ja3er.com:443";
        let addr = b.to_socket_addrs().unwrap().next().unwrap();
        let stream = TcpStream::connect(&addr).await.unwrap();
        let b = TlsStreamBuilder::new("ja3er.com").unwrap();
        let mut stream = b.build_tcp(Box::new(stream)).await.unwrap();
        stream.write_all(b"GET /json HTTP/1.1\r\nHost: ja3er.com\r\nAccept: */*\r\nUser-Agent: curl/7.81.0\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        stream.read_buf(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        let response = response.trim_end();
        println!("from ja3er response:{}", response);
    }
}
