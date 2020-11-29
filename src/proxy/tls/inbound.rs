use crate::proxy::{AcceptSteam, Acceptor};
use async_rustls::server::TlsStream;
use async_rustls::TlsAcceptor;
use async_trait::async_trait;
use smol::io;
use smol::net::{AsyncToSocketAddrs, Shutdown, SocketAddr, TcpListener, TcpStream};

pub struct TlsInbound {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
}

impl TlsInbound {
    // todo add tls config
}

#[async_trait]
impl AcceptSteam for TlsStream<TcpStream> {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let (stream, _) = self.get_ref();
        stream.shutdown(how)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let (stream, _) = self.get_ref();
        stream.local_addr()
    }
}

#[async_trait]
impl Acceptor for TlsInbound {
    type S = TlsStream<TcpStream>;

    #[inline]
    async fn accept(&self) -> io::Result<(Self::S, SocketAddr)> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        let stream = self.tls_acceptor.accept(stream).await?;
        Ok((stream, addr))
    }
}
