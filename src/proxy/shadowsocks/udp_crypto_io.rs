//! Adapted from shadowsocks-rust source code
//! Crypto protocol for ShadowSocks UDP
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```
use byte_string::ByteStr;
use std::io::{self, Cursor, Error, ErrorKind};

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::debug_log;
use crate::proxy::shadowsocks::aead_helper::{AeadCipher, CipherKind};
use crate::proxy::shadowsocks::context::BloomContext;
use crate::proxy::shadowsocks::context::SharedBloomContext;
use crate::proxy::{Address, ProxyUdpStream, UdpRead, UdpWrite};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::ready;
use gentian::gentian;
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method {
        CipherKind::None => {
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        // aead
        _ => encrypt_payload_aead(context, method, key, addr, payload, dst),
    }
}

fn encrypt_payload_aead(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let salt_len = method.salt_len();
    let addr_len = addr.serialized_len();

    // Packet = IV + ADDRESS + PAYLOAD + TAG
    dst.reserve(salt_len + addr_len + payload.len() + method.tag_len());

    // Generate IV
    dst.resize(salt_len, 0);
    let salt = &mut dst[..salt_len];

    if salt_len > 0 {
        context.generate_nonce(salt, false);
        trace!("UDP packet generated aead salt {:?}", ByteStr::new(salt));
    }

    let mut cipher = AeadCipher::new(method, key, salt);

    addr.write_to_buf(dst);
    dst.put_slice(payload);

    unsafe {
        dst.advance_mut(method.tag_len());
    }

    let m = &mut dst[salt_len..];
    cipher.encrypt(m);
}

/// Decrypt payload from ShadowSocks UDP encrypted packet
pub fn decrypt_payload(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    match method {
        CipherKind::None => {
            let mut cur = Cursor::new(payload);
            match Address::read_from_cursor(&mut cur) {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address))
                }
                Err(..) => {
                    let err =
                        io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
                    Err(err)
                }
            }
        }
        // aead
        _ => decrypt_payload_aead(method, key, payload),
    }
}

fn decrypt_payload_aead(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    let plen = payload.len();
    let salt_len = method.salt_len();
    if plen < salt_len {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short for salt");
        return Err(err);
    }

    let (salt, data) = payload.split_at_mut(salt_len);
    // context.check_nonce_replay(salt)?;

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let tag_len = method.tag_len();
    let mut cipher = AeadCipher::new(method, key, salt);

    if data.len() < tag_len {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "udp packet too short for tag",
        ));
    }

    if !cipher.decrypt(data) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    // Truncate TAG
    let data_len = data.len() - tag_len;
    let data = &mut data[..data_len];

    let (dn, addr) = parse_packet(data)?;

    let data_length = data_len - dn;
    let data_start_idx = salt_len + dn;
    let data_end_idx = data_start_idx + data_length;

    payload.copy_within(data_start_idx..data_end_idx, 0);

    Ok((data_length, addr))
}

fn parse_packet(buf: &[u8]) -> io::Result<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_from_cursor(&mut cur) {
        Ok(address) => {
            let pos = cur.position() as usize;
            Ok((pos, address))
        }
        Err(..) => {
            let err = io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
            Err(err)
        }
    }
}

pub struct ShadowSocksUdpStream<T> {
    stream: T,
    addr: Address,
    context: SharedBloomContext,
    write_buffer: BytesMut,
    method: CipherKind,
    key: Bytes,
    state: u32,
    write_res: Poll<io::Result<usize>>, // for state machine generator
}

impl<T> ShadowSocksUdpStream<T> {
    pub fn new(
        io: T,
        addr: Address,
        context: SharedBloomContext,
        method: CipherKind,
        key: Bytes,
    ) -> Self {
        debug_log!("build ss udp stream, addr is:{}", addr);
        Self {
            stream: io,
            addr,
            context,
            write_buffer: Default::default(),
            method,
            key,
            state: 0,
            write_res: Poll::Pending,
        }
    }
}

impl<T: UdpRead + Unpin> ShadowSocksUdpStream<T> {
    fn priv_poll_recv_from(
        this: &mut ShadowSocksUdpStream<T>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let r = Pin::new(&mut this.stream);
        let _ = ready!(r.poll_recv_from(cx, dst))?;
        let (n, addr) = decrypt_payload(this.method, &this.key, dst.filled_mut())?;
        dst.set_filled(n);
        debug_log!("recv from addr:{}, len:{}", addr, dst.filled().len());
        Ok(addr).into()
    }
}
impl<T: UdpRead + Unpin> UdpRead for ShadowSocksUdpStream<T> {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let this = self.get_mut();
        Self::priv_poll_recv_from(this, cx, buf)
    }
}

impl<T: UdpWrite + Unpin> UdpWrite for ShadowSocksUdpStream<T> {
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Address,
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.priv_poll_write(cx, buf, target)
    }
}

impl<T: ProxyUdpStream> AsyncRead for ShadowSocksUdpStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl<T: ProxyUdpStream> AsyncWrite for ShadowSocksUdpStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unimplemented!();
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unimplemented!();
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unimplemented!();
    }
}

impl<T: ProxyUdpStream> ProxyUdpStream for ShadowSocksUdpStream<T> {
    fn is_tokio_socket(&self) -> bool {
        false
    }
}

impl<T: UdpWrite + Unpin> ShadowSocksUdpStream<T> {
    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn priv_poll_write(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        addr: &Address,
    ) -> Poll<io::Result<usize>> {
        loop {
            encrypt_payload(
                &self.context,
                self.method,
                &self.key,
                addr,
                data,
                &mut self.write_buffer,
            );
            debug_log!(
                "encrypted buffer len:{},data len:{},tar addr:{}",
                self.write_buffer.len(),
                data.len(),
                addr
            );
            debug_log!("poll sendto {}, before addr:{}", self.addr, addr);
            self.write_res = co_await(Pin::new(&mut self.stream).poll_send_to(
                cx,
                &self.write_buffer,
                &self.addr,
            ));
            self.write_buffer.clear();
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }
}
