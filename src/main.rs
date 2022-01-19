use std::io;

mod common;
mod proxy;

use crate::common::net::copy_with_capacity_and_counter;

use crate::common::LW_BUFFER_SIZE;
use crate::proxy::shadowsocks::context::Context;
use crate::proxy::shadowsocks::crypto_io::CryptoStream;
use crate::proxy::socks::Address;
use actix_server::Server;
use actix_service::fn_service;
use bytes::BytesMut;

use shadowsocks_crypto::v1::{openssl_bytes_to_key, CipherKind};

use crate::proxy::vmess::vmess::VmessStream;
use crate::proxy::vmess::vmess_option::VmessOption;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub(crate) async fn test_relay_shadowsocks<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, addr) = t;
    let mut key = BytesMut::with_capacity(CipherKind::CHACHA20_POLY1305.key_len());
    unsafe {
        key.set_len(key.capacity());
    }
    openssl_bytes_to_key("123456".as_bytes(), key.as_mut());
    let outbound_stream = TcpStream::connect("127.0.0.1:9000").await?;
    let mut outbound_stream = CryptoStream::<TcpStream>::new(
        Arc::new(Context::new(true)),
        outbound_stream,
        key.freeze(),
        CipherKind::CHACHA20_POLY1305,
    );
    addr.write_to_stream(&mut outbound_stream).await?;
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);
    let mut down = 0u64;
    let mut up = 0u64;
    let res = tokio::try_join!(
        copy_with_capacity_and_counter(&mut outbound_r, &mut inbound_w, &mut down, LW_BUFFER_SIZE),
        copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w, &mut up, LW_BUFFER_SIZE)
    );
    match res {
        Ok((_, _)) => {}
        Err(e) => {
            println!("processing failed; error = {}", e);
        }
    }
    println!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}

pub(crate) async fn test_relay_vmess<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, addr) = t;
    println!("addr:{}", addr);
    let outbound_stream = TcpStream::connect("127.0.0.1:10002").await?;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
    let security = "auto".to_string();
    let option = VmessOption::new(&uuid, 0, &security, addr, false).unwrap();
    let outbound_stream = VmessStream::<TcpStream>::new(option, outbound_stream);
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);
    let mut down = 0u64;
    let mut up = 0u64;
    let res = tokio::try_join!(
        copy_with_capacity_and_counter(&mut outbound_r, &mut inbound_w, &mut down, LW_BUFFER_SIZE),
        copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w, &mut up, LW_BUFFER_SIZE)
    );
    match res {
        Ok((_, _)) => {}
        Err(e) => {
            println!("processing failed; error = {}", e);
        }
    }
    println!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}

pub(crate) async fn test_relay_ws_vmess<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, addr) = t;
    println!("addr:{}", addr);
    let outbound_stream = TcpStream::connect("127.0.0.1:10002").await?;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
    let security = "auto".to_string();
    let option = VmessOption::new(&uuid, 0, &security, addr, false).unwrap();
    let outbound_stream = VmessStream::<TcpStream>::new(option, outbound_stream);
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);
    let mut down = 0u64;
    let mut up = 0u64;
    let res = tokio::try_join!(
        copy_with_capacity_and_counter(&mut outbound_r, &mut inbound_w, &mut down, LW_BUFFER_SIZE),
        copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w, &mut up, LW_BUFFER_SIZE)
    );
    match res {
        Ok((_, _)) => {}
        Err(e) => {
            println!("processing failed; error = {}", e);
        }
    }
    println!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}
fn main() -> io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
    actix_rt::System::new().block_on(async move {
        {
            Server::build()
                .workers(1)
                .bind("socks", "127.0.0.1:8080", || {
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
