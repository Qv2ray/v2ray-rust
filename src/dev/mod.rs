use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use crate::common::openssl_bytes_to_key;
use crate::proxy::{Address, ChainableStreamBuilder, ChainStreamBuilder, ProxySteam};
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::shadowsocks::context::BloomContext;
use crate::proxy::shadowsocks::crypto_io::CryptoStream;
use crate::proxy::shadowsocks::ShadowsocksBuilder;
use crate::proxy::vmess::vmess::VmessStream;
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::vmess::VmessBuilder;
use crate::proxy::websocket::BinaryWsStreamBuilder;
use crate::common::net::copy_with_capacity_and_counter;
use crate::common::LW_BUFFER_SIZE;
use crate::proxy::tls::tls::TlsStreamBuilder;

#[allow(dead_code)]
pub(crate) async fn test_relay_shadowsocks<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, addr) = t;
    let mut key = BytesMut::with_capacity(CipherKind::ChaCha20Poly1305.key_len());
    unsafe {
        key.set_len(key.capacity());
    }
    openssl_bytes_to_key("123456".as_bytes(), key.as_mut());
    let outbound_stream = TcpStream::connect("127.0.0.1:9000").await?;
    let outbound_stream: Box<dyn ProxySteam> = Box::new(outbound_stream);
    let mut outbound_stream = CryptoStream::<Box<dyn ProxySteam>>::new(
        Arc::new(BloomContext::new(true)),
        outbound_stream,
        key.clone().freeze(),
        CipherKind::ChaCha20Poly1305,
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

#[allow(dead_code)]
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

#[allow(dead_code)]
pub(crate) async fn test_relay_ws_vmess<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, addr) = t;
    println!("addr:{}", addr);
    let outbound_stream = TcpStream::connect("127.0.0.1:10002").await?;
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
    let security = "auto".to_string();
    let option = VmessOption::new(&uuid, 0, &security, addr, false).unwrap();
    let ws_stream_builder = BinaryWsStreamBuilder::new("ws://127.0.0.1:10002/", None,vec![]).unwrap();
    let outbound_stream = ws_stream_builder
        .build_tcp(Box::new(outbound_stream))
        .await?;
    let outbound_stream = VmessStream::new(option, outbound_stream);
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

#[allow(dead_code)]
pub(crate) async fn test_chain_vmess_ss<T: AsyncWrite + AsyncRead + Unpin>(
    t: (T, Address),
) -> io::Result<()> {
    let (inbound_stream, proxy_addr) = t;
    println!("addr:{}", proxy_addr);

    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
    let security = "auto".to_string();
    let vmess_addr = Address::SocketAddress(SocketAddr::new("127.0.0.1".parse().unwrap(), 9000));
    let vmess = VmessBuilder::new(uuid, security, 0, vmess_addr, false).unwrap();
    let f = |addr: Address| {
        ShadowsocksBuilder::new(
            addr,
            "123456",
            "chacha20-ietf-poly1305",
            Arc::new(BloomContext::new(true)),
        )
            .unwrap()
            .into_box()
    };
    let mut outbound_stream = ChainStreamBuilder::new()
        .chain(vmess.into_box())
        .build_tcp("127.0.0.1:10002", proxy_addr, f)
        .await?;
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
