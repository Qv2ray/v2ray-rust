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

use crate::common::{poll_read_buf, PollUtil, HW_BUFFER_SIZE, LW_BUFFER_SIZE};
use futures_util::ready;
use generator::state_machine_generator;
use shadowsocks_crypto::v1::{Cipher, CipherKind};
use std::io::Write;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Debug)]
enum DecryptReadStep {
    Init,
    Length,
    Data(usize),
    Eof,
}
/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    buffer: BytesMut,
    cipher: Cipher,
    tag_size: usize,
    state: u32,
    data_length: usize,
    minimal_data_to_put: usize,
    read_res: Poll<io::Result<()>>,
    n: usize,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> DecryptedReader {
        DecryptedReader {
            buffer: BytesMut::with_capacity(LW_BUFFER_SIZE * 2),
            cipher: Cipher::new(method, key, nonce),
            tag_size: method.tag_len(),
            state: 0,
            data_length: 0,
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            n: 0,
        }
    }

    #[inline]
    fn calc_data_to_put(&mut self, dst: &mut ReadBuf<'_>) -> usize {
        self.minimal_data_to_put = cmp::min(self.data_length, dst.remaining());
        self.minimal_data_to_put
    }

    #[inline]
    fn read_until<R>(
        &mut self,
        r: &mut R,
        ctx: &mut Context<'_>,
        length: usize,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        self.n = 0;
        while self.buffer.len() < length {
            self.n += ready!(poll_read_buf(r, ctx, &mut self.buffer))?;
            if self.n == 0 {
                return Err(ErrorKind::UnexpectedEof.into()).into();
            }
        }
        Poll::Ready(Ok(()))
    }

    #[state_machine_generator(state, Err(ErrorKind::UnexpectedEof.into()).into())]
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
            loop {
                self.read_res = (self.read_until(r, ctx, self.tag_size + 2));
                if self.read_res.is_pending() {
                    co_yield(Poll::Pending);
                    continue;
                }
                if self.read_res.is_error() {
                    return std::mem::replace(&mut self.read_res, Poll::Pending);
                }
                break;
            }
            self.data_length = DecryptedReader::decrypt_length(
                &mut self.cipher,
                &mut self.buffer.as_mut()[0..self.tag_size + 2],
            )? + self.tag_size;
            self.buffer.advance(self.tag_size + 2);
            self.buffer.reserve(self.data_length);
            loop {
                self.read_res = (self.read_until(r, ctx, self.data_length));
                if self.read_res.is_pending() {
                    co_yield(Poll::Pending);
                    continue;
                }
                if self.read_res.is_error() {
                    return std::mem::replace(&mut self.read_res, Poll::Pending);
                }
                break;
            }
            if !self
                .cipher
                .decrypt_packet(&mut self.buffer.as_mut()[0..self.data_length])
            {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in")));
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

    fn decrypt_length(cipher: &mut Cipher, m: &mut [u8]) -> io::Result<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
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

enum EncryptWriteStep {
    Nothing,
    Writing,
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: Cipher,
    tag_size: usize,
    state: u32,
    steps: EncryptWriteStep,
    buf: BytesMut,
    pos: usize,
    data_len: usize,
    write_res: Poll<io::Result<usize>>,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buf = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        buf.put(nonce);

        EncryptedWriter {
            cipher: Cipher::new(method, key, nonce),
            tag_size: method.tag_len(),
            state: 0,
            steps: EncryptWriteStep::Nothing,
            buf,
            pos: 0,
            data_len: 0,
            write_res: Poll::Pending,
        }
    }

    #[state_machine_generator(state, Err(ErrorKind::UnexpectedEof.into()).into())]
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
            loop {
                self.write_res = self.write_data(w, ctx);
                if self.write_res.is_ready() {
                    break;
                }
                co_yield(Poll::Pending);
            }
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
                    io::ErrorKind::WriteZero,
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
        self.cipher.encrypt_packet(mbuf);
        unsafe { self.buf.advance_mut(self.tag_size) };
        //2. encrypt data
        let mbuf = &mut self.buf.chunk_mut()[..self.data_len + self.tag_size];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buf.put_slice(data);
        self.cipher.encrypt_packet(mbuf);
        unsafe {
            self.buf.advance_mut(self.tag_size);
        }
        self.pos = 0;
    }
}
