use crate::proxy::socks5::server_client::ServerClient;
use crate::proxy::Acceptor;
use async_trait::async_trait;
use smol::net::{AsyncToSocketAddrs, SocketAddr, TcpListener, TcpStream, UdpSocket};
use smol::{io, Async};

pub struct Socks5Inbound<T: Acceptor> {
    listener: T,
    udp_socket: Option<UdpSocket>,
}

impl<T: Acceptor> Socks5Inbound<T> {
    pub async fn bind_udp(
        acceptor: T,
        udp_bind_addr: Option<SocketAddr>,
    ) -> io::Result<Socks5Inbound<T>> {
        Ok(Socks5Inbound {
            listener: acceptor,
            udp_socket: match udp_bind_addr {
                None => None,
                Some(addr) => Some(UdpSocket::bind(addr).await?),
            },
        })
    }
}

impl Socks5Inbound<TcpListener> {
    pub async fn bind(
        tcp_bind_addr: SocketAddr,
        udp_bind_addr: Option<SocketAddr>,
    ) -> io::Result<Socks5Inbound<TcpListener>> {
        Ok(Socks5Inbound {
            listener: TcpListener::bind(tcp_bind_addr).await?,
            udp_socket: match udp_bind_addr {
                None => None,
                Some(addr) => Some(UdpSocket::bind(addr).await?),
            },
        })
    }
}

#[async_trait]
impl<T: Acceptor> Acceptor for Socks5Inbound<T> {
    type S = T::S;

    #[inline]
    async fn accept(&self) -> io::Result<(Self::S, SocketAddr)> {
        let (mut stream, addr) = self.listener.accept().await?;
        if let Some(udp_socket) = &self.udp_socket {
            ServerClient::no_auth_new()
                .init(&mut stream, Some(udp_socket.local_addr().unwrap()))
                .await?;
        } else {
            ServerClient::no_auth_new().init(&mut stream, None).await?;
        }
        Ok((stream, addr))
    }
}
