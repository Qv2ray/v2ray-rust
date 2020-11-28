use crate::proxy::socks5::server_client::ServerClient;
use smol::net::TcpListener;
use smol::{io, Async};

pub struct Socks5Inbound {
    listener: TcpListener,
}

impl Socks5Inbound {
    async fn accept(&self) -> io::Result<()> {
        let (mut stream, addr) = self.listener.accept().await?;
        ServerClient::no_auth_new().init(&mut stream).await?;
        Ok(())
    }
}
