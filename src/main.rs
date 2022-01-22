use crate::dev::{test_direct, test_relay_vmess, test_relay_ws_vmess};
use actix_server::Server;
use actix_service::fn_service;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

mod common;
mod dev;
mod proxy;

fn main() -> io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
    actix_rt::System::new().block_on(async move {
        {
            Server::build()
                //.workers(2)
                .bind("socks", "127.0.0.1:1087", || {
                    fn_service(|io: TcpStream| {
                        use proxy::socks::socks5::Socks5Stream;
                        async move {
                            let stream = Socks5Stream::new(io);
                            if let Ok(x) = stream.init(None).await {
                                let res = test_direct(x).await;
                                if res.is_err() {
                                    return res;
                                }
                            }
                            Ok(())
                        }
                    })
                })?
                .bind("socks", "127.0.0.1:9080", || {
                    fn_service(|io: TcpStream| {
                        use proxy::socks::socks5::Socks5Stream;
                        async move {
                            let stream = Socks5Stream::new(io);
                            if let Ok(x) = stream.init(None).await {
                                let res = test_relay_vmess(x).await;
                                if res.is_err() {
                                    return res;
                                }
                            }
                            Ok(())
                        }
                    })
                })?
                //.bind("api","127.0.0.1:9999",||{
                //})
                .run()
                .await
        }
    })
}
