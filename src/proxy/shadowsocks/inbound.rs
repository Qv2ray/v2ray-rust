use crate::proxy::socks5::inbound::Socks5Inbound;
use crate::proxy::Acceptor;
use bytes::{Bytes, BytesMut};

pub struct ShadowsocksInbound<T: Acceptor> {
    socks5_inbound: Socks5Inbound<T>,
    password: Bytes,
    method: String,
}
