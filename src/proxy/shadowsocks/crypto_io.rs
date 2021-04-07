//! IO facilities for TCP relay

use std::{
    io,
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
};

use bytes::{buf::Limit, Buf, BufMut, Bytes, BytesMut};

use shadowsocks_crypto::v1::{random_iv_or_salt, CipherCategory, CipherKind};

use super::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
use crate::common::poll_read_buf;
use crate::proxy::shadowsocks::context::SharedContext;
use byte_string::ByteStr;
use futures_util::ready;
use std::io::{Error, ErrorKind, IoSlice};
use std::mem::MaybeUninit;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

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
    WaitIv(SharedContext, BytesMut, CipherKind, Bytes),

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
        context: SharedContext,
        stream: S,
        enc_key: Bytes,
        method: CipherKind,
    ) -> CryptoStream<S> {
        let category = method.category();
        let key = enc_key;

        if category == CipherCategory::None {
            return CryptoStream::<S>::new_none(stream);
        }

        let prev_len = match category {
            CipherCategory::Aead => method.salt_len(),
            _ => 0,
        };

        let iv = match category {
            CipherCategory::Aead => {
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
            _ => Vec::new(),
        };

        let enc = match category {
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(method, &key, &iv))
            }
            _ => EncryptedWriter::None,
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

    /// Return a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Consume the CryptoStream and return the internal stream instance
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncReadExt + Unpin,
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
                use std::io::{Error, ErrorKind};
                //debug!("detected repeated iv/salt {:?}", ByteStr::new(nonce));
                let err = Error::new(ErrorKind::Other, "detected repeated iv/salt");
                return Poll::Ready(Err(err));
            }
            let dec = match method.category() {
                CipherCategory::Aead => {
                    //trace!("got AEAD cipher salt {:?}", ByteStr::new(nonce));
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, key, nonce))
                }
                _ => DecryptedReader::None,
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

    fn priv_poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.stream), ctx)
    }

    fn priv_poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), ctx)
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Split connection into reader and writer
    ///
    /// The two halfs share the same `CryptoStream<S>`
    pub fn split(self) -> (ReadHalf<CryptoStream<S>>, WriteHalf<CryptoStream<S>>) {
        tokio::io::split(self)
    }
}

impl<S> AsyncRead for CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.priv_poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for CryptoStream<S>
where
    S: AsyncWrite + AsyncWriteExt + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.priv_poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.priv_poll_shutdown(cx)
    }
}
