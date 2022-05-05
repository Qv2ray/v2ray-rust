use std::{
    cmp,
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use bytes::{Buf, BufMut, BytesMut};

use crate::common::{net::PollUtil, LW_BUFFER_SIZE};
use futures_util::ready;
use gentian::gentian;

use crate::impl_read_utils;
use crate::proxy::shadowsocks::aead_helper::{AeadCipher, CipherKind};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    buffer: BytesMut,
    cipher: AeadCipher,
    tag_size: usize,
    state: u32,
    data_length: usize,
    minimal_data_to_put: usize,
    read_res: Poll<io::Result<()>>,
    read_zero: bool,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> DecryptedReader {
        DecryptedReader {
            buffer: BytesMut::with_capacity(LW_BUFFER_SIZE * 2),
            cipher: AeadCipher::new(method, key, iv_or_salt),
            tag_size: method.tag_len(),
            state: 0,
            data_length: 0,
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            read_zero: false,
        }
    }

    impl_read_utils!();
    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            self.read_res = co_await(self.read_at_least(r, ctx, self.tag_size + 2));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.data_length = DecryptedReader::decrypt_length(
                &mut self.cipher,
                &mut self.buffer.as_mut()[0..self.tag_size + 2],
            )? + self.tag_size;
            self.buffer.advance(self.tag_size + 2);
            self.read_reserve(self.data_length);
            self.read_res = co_await(self.read_at_least(r, ctx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            if !self
                .cipher
                .decrypt(&mut self.buffer.as_mut()[0..self.data_length])
            {
                return Poll::Ready(Err(io::Error::new(ErrorKind::Other, "invalid aead tag")));
            }
            self.data_length -= self.tag_size;
            while self.calc_data_to_put(dst) != 0 {
                dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
                self.data_length -= self.minimal_data_to_put;
                self.buffer.advance(self.minimal_data_to_put);
                co_yield(Poll::Ready(Ok(())));
            }
            self.buffer.advance(self.tag_size);
        }
    }

    fn decrypt_length(cipher: &mut AeadCipher, m: &mut [u8]) -> io::Result<usize> {
        let plen = {
            if !cipher.decrypt(m) {
                return Err(io::Error::new(ErrorKind::Other, "invalid tag-in"));
            }

            u16::from_be_bytes([m[0], m[1]]) as usize
        };
        if plen > MAX_PACKET_SIZE {
            let err = io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "buffer size too large ({:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero",
                    plen
                ),
            );
            return Err(err);
        }
        Ok(plen)
    }
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: AeadCipher,
    tag_size: usize,
    state: u32, // for state machine generator use
    buf: BytesMut,
    pos: usize,
    data_len: usize,
    write_res: Poll<io::Result<usize>>,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buf = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        buf.put(iv_or_salt);

        EncryptedWriter {
            cipher: AeadCipher::new(method, key, iv_or_salt),
            tag_size: method.tag_len(),
            state: 0,
            buf,
            pos: 0,
            data_len: 0,
            write_res: Poll::Pending,
        }
    }

    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        w: &mut W,
        mut data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            // we already put nonce
            let minimal_data_to_write = cmp::min(MAX_PACKET_SIZE, data.len());
            self.buf
                .reserve(minimal_data_to_write + 2 + self.tag_size * 2);
            data = &data[..minimal_data_to_write];
            self.encrypted_buffer(data);
            self.write_res = co_await(self.write_data(w, ctx));
            self.buf.clear();
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }

    #[inline]
    fn write_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buf.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buf[self.pos..]))?;
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(self.data_len))
    }

    fn encrypted_buffer(&mut self, data: &[u8]) {
        self.data_len = data.len();
        // 1. encrypt length
        let mbuf = &mut self.buf.chunk_mut()[..2 + self.tag_size];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buf.put_u16(self.data_len as u16);
        self.cipher.encrypt(mbuf);
        unsafe { self.buf.advance_mut(self.tag_size) };
        //2. encrypt data
        let mbuf = &mut self.buf.chunk_mut()[..self.data_len + self.tag_size];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buf.put_slice(data);
        self.cipher.encrypt(mbuf);
        unsafe {
            self.buf.advance_mut(self.tag_size);
        }
        self.pos = 0;
    }
}
