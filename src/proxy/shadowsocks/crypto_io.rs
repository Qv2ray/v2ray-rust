//! IO facilities for TCP relay

use std::{
    io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};

use super::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
use crate::common::net::poll_read_buf;
use crate::proxy::shadowsocks::context::SharedBloomContext;

use futures_util::ready;
use std::io::{Error, ErrorKind};

use crate::common::random_iv_or_salt;
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::{ProxyUdpStream, UdpRead, UdpWrite};
use crate::{impl_async_read, impl_async_useful_traits, impl_async_write, impl_flush_shutdown};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum DecryptedReader {
    None,
    Aead(AeadDecryptedReader),
}

enum EncryptedWriter {
    None,
    Aead(AeadEncryptedWriter),
}

/// Steps for initializing a DecryptedReader
enum ReadStatus {
    /// Waiting for initializing vector (or nonce for AEAD ciphers)
    ///
    /// (context, Buffer, already_read_bytes, method, key)
    WaitIv(SharedBloomContext, BytesMut, CipherKind, Bytes),

    /// Connection is established, DecryptedReader is initialized
    Established,
}

/// A bidirectional stream for communicating with ShadowSocks' server
pub struct CryptoStream<S> {
    stream: S,
    dec: Option<DecryptedReader>,
    enc: EncryptedWriter,
    read_status: ReadStatus,
}

impl<S: Unpin> Unpin for CryptoStream<S> {}

impl<S> CryptoStream<S> {
    /// Create a new CryptoStream with the underlying stream connection
    pub fn new(
        context: SharedBloomContext,
        stream: S,
        enc_key: Bytes,
        method: CipherKind,
    ) -> CryptoStream<S> {
        let key = enc_key;

        if method == CipherKind::None {
            return CryptoStream::<S>::new_none(stream);
        }

        let prev_len = method.salt_len();

        let iv = match method {
            CipherKind::None => Vec::new(),
            _ => {
                let local_salt = loop {
                    let mut salt = vec![0u8; prev_len];
                    if prev_len > 0 {
                        random_iv_or_salt(&mut salt);
                    }

                    if context.check_nonce_and_set(&salt) {
                        // Salt exist, generate another one
                        continue;
                    }
                    break salt;
                };
                //trace!("generated AEAD cipher salt {:?}", ByteStr::new(&local_salt));
                local_salt
            }
        };

        let enc = match method {
            CipherKind::None => EncryptedWriter::None,
            _ => EncryptedWriter::Aead(AeadEncryptedWriter::new(method, &key, &iv)),
        };

        CryptoStream {
            stream,
            dec: None,
            enc,
            read_status: ReadStatus::WaitIv(
                context,
                BytesMut::with_capacity(prev_len),
                method,
                key,
            ),
        }
    }

    fn new_none(stream: S) -> CryptoStream<S> {
        CryptoStream {
            stream,
            dec: Some(DecryptedReader::None),
            enc: EncryptedWriter::None,
            read_status: ReadStatus::Established,
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref ctx, ref mut buf, method, ref key) = self.read_status {
            while buf.len() != buf.capacity() {
                let n = ready!(poll_read_buf(&mut self.stream, cx, buf))?;
                // read iv fail
                if n == 0 {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                }
            }
            let nonce = buf.as_ref();
            // Got iv/salt, check if it is repeated
            if ctx.check_nonce_and_set(nonce) {
                let err = Error::new(ErrorKind::Other, "detected repeated iv/salt");
                return Poll::Ready(Err(err));
            }
            let dec = match method {
                CipherKind::None => DecryptedReader::None,
                _ => {
                    //trace!("got AEAD cipher salt {:?}", ByteStr::new(nonce));
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, key, nonce))
                }
            };
            self.dec = Some(dec);
            self.read_status = ReadStatus::Established;
        }

        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_read_handshake(ctx))?;

        match *this.dec.as_mut().unwrap() {
            DecryptedReader::None => Pin::new(&mut this.stream).poll_read(ctx, buf),
            DecryptedReader::Aead(ref mut r) => r.poll_read_decrypted(ctx, &mut this.stream, buf),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.enc {
            EncryptedWriter::None => Pin::new(&mut this.stream).poll_write(ctx, buf),
            EncryptedWriter::Aead(ref mut w) => w.poll_write_encrypted(ctx, &mut this.stream, buf),
        }
    }

    impl_flush_shutdown!();
}
impl_async_useful_traits!(CryptoStream);

impl<S: ProxyUdpStream> UdpRead for CryptoStream<S> {}

impl<S: ProxyUdpStream> UdpWrite for CryptoStream<S> {}

impl<S: ProxyUdpStream> ProxyUdpStream for CryptoStream<S> {
    fn is_tokio_socket(&self) -> bool {
        false
    }
}
