use crate::common::aead_helper::AeadCipherHelper;
use crate::common::net::PollUtil;
use crate::common::LW_BUFFER_SIZE;
use crate::proxy::vmess::vmess_stream::{CHUNK_SIZE, MAX_SIZE};
use crate::{debug_log, impl_read_utils};
use aes_gcm::Aes128Gcm;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures_util::ready;
use gentian::gentian;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, io, slice};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct VmessAeadWriter {
    security: VmessSecurity,
    buffer: BytesMut,
    nonce: [u8; 32],
    pos: usize,
    iv: BytesMut,
    count: u16,
    data_len: usize,
    state: u32, // for state machine generator use
    write_res: Poll<io::Result<usize>>,
}
pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        16
    }
}

impl VmessAeadWriter {
    pub fn new(iv: &[u8], security: VmessSecurity) -> VmessAeadWriter {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        VmessAeadWriter {
            security,
            buffer,
            nonce: [0u8; 32],
            pos: 0,
            iv,
            count: 0,
            data_len: 0,
            state: 0,
            write_res: Poll::Pending,
        }
    }

    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        w: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            if data.len() == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut minimal_data_to_write =
                cmp::min(CHUNK_SIZE - self.security.overhead_len(), data.len());
            let data = &data[..minimal_data_to_write];
            debug_log!("vmess: before encrypted data len:{}", data.len());
            self.encrypted_buffer(data);
            self.write_res = co_await(self.write_data(w, ctx));
            self.buffer.clear();
            debug_log!(
                "vmess: write data done,last writen len:{}",
                self.write_res.get_poll_res()
            );
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }

    fn encrypted_buffer(&mut self, data: &[u8]) {
        self.data_len = data.len();
        debug_log!("raw data len:{}", self.data_len);
        // 1. length is not encrypted
        self.buffer
            .reserve(self.data_len + 2 + self.security.tag_len());
        self.buffer
            .put_u16((self.data_len + self.security.tag_len()) as u16);
        debug_log!("encrypted buffer len1:{}", self.buffer.len());
        // 2. construct encrypted data buf
        let mbuf = &mut self.buffer.chunk_mut()[..self.data_len + self.security.tag_len()];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buffer.put_slice(data);
        debug_log!("encrypted buffer len2:{}", self.buffer.len());

        // 3. construct nonce
        self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
        self.nonce[2..12].copy_from_slice(&self.iv[2..12]);
        // 4. encrypted data, reserved aead tag
        let aad = [0u8; 0];
        let nonce_len = self.security.nonce_len();
        match &mut self.security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };
            }
        }
        debug_log!("encrypted buffer len3:{}", self.buffer.len());
        self.count += 1;
        self.pos = 0
    }

    #[inline]
    fn write_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buffer.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buffer[self.pos..]))?;
            debug_log!("cur write len:{}", n);
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
}

pub struct VmessAeadReader {
    security: VmessSecurity,
    pub buffer: BytesMut, // pub for replace buffer
    state: u32,           // for state machine generator use
    read_res: Poll<io::Result<()>>,
    nonce: [u8; 32],
    iv: BytesMut,
    data_length: usize,
    count: u16,
    minimal_data_to_put: usize,
    read_zero: bool,
}

impl VmessAeadReader {
    pub fn new(iv: &[u8], security: VmessSecurity) -> VmessAeadReader {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::new();
        VmessAeadReader {
            security,
            buffer,
            state: 0,
            read_res: Poll::Pending,
            nonce: [0u8; 32],
            iv,
            data_length: 0,
            count: 0,
            minimal_data_to_put: 0,
            read_zero: false,
        }
    }

    impl_read_utils!();
    fn decrypted_data(&mut self) -> bool {
        let aad = [0u8; 0];
        let nonce_len = self.security.nonce_len();
        let res: bool;
        match &mut self.security {
            VmessSecurity::Aes128Gcm(cipher) => {
                res = cipher.decrypt_inplace_with_slice(
                    &self.nonce[..nonce_len],
                    &aad,
                    &mut self.buffer[..self.data_length],
                );
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                res = cipher.decrypt_inplace_with_slice(
                    &self.nonce[..nonce_len],
                    &aad,
                    &mut self.buffer[..self.data_length],
                );
            }
        }
        res
    }

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
            // 1. read length
            debug_log!(
                "try read aead length, counter:{},buffer_len:{}",
                self.count,
                self.buffer.len()
            );
            self.read_res = co_await(self.read_at_least(r, ctx, 2));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.data_length = self.buffer.get_u16() as usize;
            if self.data_length > MAX_SIZE {
                let err = io::Error::new(ErrorKind::InvalidData, "buffer size too large!");
                return Poll::Ready(Err(err));
            }
            self.read_reserve(self.data_length);
            // 2. read data
            self.read_res = co_await(self.read_at_least(r, ctx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            // 3. construct nonce
            self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
            self.nonce[2..12].copy_from_slice(&self.iv[2..12]);

            // 4. decrypted data, includes aead tag
            if !self.decrypted_data() {
                debug_log!("read decrypted failed");
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid aead tag",
                )));
            }
            self.count += 1;

            debug_log!(
                "data_length(include aead tag): {},buffer_len:{}",
                self.data_length,
                self.buffer.len()
            );
            self.data_length -= 16; //remove tag
                                    // 5. put data
            while self.calc_data_to_put(dst) != 0 {
                dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
                self.data_length -= self.minimal_data_to_put;
                self.buffer.advance(self.minimal_data_to_put);
                debug_log!("buffer len:{}", self.buffer.len());
                debug_log!("put data len:{}", self.minimal_data_to_put);
                co_yield(Poll::Ready(Ok(())));
            }
            self.buffer.advance(16);
        }
    }
}
