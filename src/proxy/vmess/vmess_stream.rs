use aes_gcm::Aes128Gcm;
use std::hash::Hasher;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::aead_helper::AeadCipherHelper;
use crate::common::fnv1a::Fnv1aHasher;
use crate::common::net::PollUtil;
use crate::common::{random_iv_or_salt, sha256};
use crate::proxy::vmess::aead::{VmessAeadReader, VmessAeadWriter, VmessSecurity};
use crate::proxy::vmess::aead_header::{seal_vmess_aead_header, VmessHeaderReader};
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::{Address, ProxyUdpStream, UdpRead, UdpWrite};
use crate::{
    debug_log, impl_async_read, impl_async_useful_traits, impl_async_write, impl_flush_shutdown,
    md5,
};
use gentian::gentian;
use rand::random;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub const MAX_SIZE: usize = 17 * 1024;
pub const CHUNK_SIZE: usize = 1 << 14;
pub const VERSION: u8 = 1;
pub const OPT_CHUNK_STREAM: u8 = 1;
pub const COMMAND_UDP: u8 = 0x02;
pub const COMMAND_TCP: u8 = 0x01;
pub const AES_128_GCM_SECURITY_NUM: u8 = 0x03;
pub const CHACHA20POLY1305_SECURITY_NUM: u8 = 0x04;
#[allow(dead_code)]
pub const NONE_SECURITY_NUM: u8 = 0x05;

pub struct VmessStream<S> {
    stream: S,
    option: VmessOption,
    reader: VmessAeadReader,
    writer: VmessAeadWriter,
    salt: [u8; 64],
    respv: u8,
    header_reader: Box<VmessHeaderReader>,
    header_buffer: BytesMut,
    header_pos: usize,
    state_1: u32,                              // for state machine generator
    state_2: u32,                              // for state machine generator
    header_write_res: Poll<io::Result<usize>>, // for state machine generator
    header_read_res: Poll<io::Result<()>>,     // for state machine generator
}

impl<S> VmessStream<S> {
    fn construct_header_data(&mut self) {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put(self.req_body_iv());
        buf.put(self.req_body_key());
        debug_log!("req body key:{:02X?}", &self.req_body_key());
        buf.put_u8(self.respv);
        buf.put_u8(OPT_CHUNK_STREAM);
        let x = random::<u8>() % 16;
        buf.put_u8((x << 4) | self.option.security_num);
        buf.put_u8(0);
        buf.put_u8(if self.option.is_udp {
            debug_log!("vmess command udp detected");
            COMMAND_UDP
        } else {
            COMMAND_TCP
        });
        self.option.addr.write_to_buf_vmess(&mut buf);
        if x > 0 {
            let mut padding = [0u8; 16];
            random_iv_or_salt(&mut padding);
            buf.put(&padding[0..x as usize]);
        }
        let mut hasher = Fnv1aHasher::default();
        hasher.write(&buf);
        buf.put_u32(hasher.finish() as u32);
        let cmd_key = md5!(
            self.option.uuid.as_bytes(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        );
        self.header_buffer = seal_vmess_aead_header(&cmd_key, &buf)
    }

    #[inline]
    pub fn req_body_iv(&self) -> &[u8] {
        &self.salt[0..16]
    }

    #[inline]
    pub fn req_body_key(&self) -> &[u8] {
        &self.salt[16..32]
    }
    // #[inline]
    // pub fn resp_body_key(&self) -> &[u8] {
    //     &self.salt[32..48]
    // }
    // #[inline]
    // pub fn resp_body_iv(&self) -> &[u8] {
    //     &self.salt[48..]
    // }
    pub fn new(vmess_option: VmessOption, stream: S) -> VmessStream<S> {
        let mut salt = [0u8; 64];
        random_iv_or_salt(&mut salt);
        let respv = salt[32];
        let reader_cipher: VmessSecurity;
        let writer_cipher: VmessSecurity;
        let reader: VmessAeadReader;
        let writer: VmessAeadWriter;
        let resp_body_key = sha256(&salt[16..32]);
        let resp_body_iv = sha256(&salt[0..16]);
        salt[32..48].copy_from_slice(&resp_body_key[..16]);
        salt[48..64].copy_from_slice(&resp_body_iv[..16]);
        let req_body_iv = &salt[0..16];
        let req_body_key = &salt[16..32];
        debug_log!("req body key:{:02X?}", &req_body_key[..16]);
        let resp_body_key = &salt[32..48];
        debug_log!("resp body key:{:02X?}", &resp_body_key[..16]);
        let resp_body_iv = &salt[48..];
        match vmess_option.security_num {
            AES_128_GCM_SECURITY_NUM => {
                writer_cipher = VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(req_body_key));
                writer = VmessAeadWriter::new(req_body_iv, writer_cipher);
                reader_cipher = VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(resp_body_key));
                reader = VmessAeadReader::new(resp_body_iv, reader_cipher);
            }
            CHACHA20POLY1305_SECURITY_NUM => {
                let mut key = [0u8; 32];
                let tmp = md5!(req_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(&key[16..]);
                key[16..32].copy_from_slice(&tmp);
                writer_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                writer = VmessAeadWriter::new(req_body_iv, writer_cipher);

                let tmp = md5!(resp_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(&key[16..]);
                key[16..32].copy_from_slice(&tmp);
                reader_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                reader = VmessAeadReader::new(resp_body_iv, reader_cipher);
            }
            _ => {
                unimplemented!();
            }
        }
        let mut v = VmessStream {
            stream,
            option: vmess_option,
            reader,
            writer,
            salt,
            respv,
            header_reader: Box::new(VmessHeaderReader::new(
                &resp_body_key[..16],
                &resp_body_iv[..16],
                respv,
            )),
            header_buffer: BytesMut::new(),
            header_pos: 0,
            state_1: 0,
            state_2: 0,
            header_write_res: Poll::Pending,
            header_read_res: Poll::Pending,
        };
        v.construct_header_data();
        v
    }
}

impl<S> VmessStream<S>
where
    S: AsyncReadExt + Unpin,
{
    #[gentian]
    #[gentian_attr(state=this.state_1,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn poll_read_header(
        this: &mut VmessStream<S>,
        ctx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // wait resp
            while !(*this.header_reader).received_resp() {
                this.header_read_res =
                    (*this.header_reader).poll_read_decrypted(ctx, &mut this.stream);
                if this.header_read_res.is_error() {
                    return std::mem::replace(&mut this.header_read_res, Poll::Pending);
                } else if this.header_read_res.is_ready() {
                    break;
                }
                co_yield(Poll::Pending);
            }
            // steal buffer
            this.reader.buffer = this.header_reader.get_buffer();
            // streaming
            loop {
                co_yield(this.reader.poll_read_decrypted(ctx, &mut this.stream, dst));
            }
        }
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Self::poll_read_header(this, ctx, buf)
    }
}

impl<S> VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    #[gentian]
    #[gentian_attr(state=this.state_2,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn poll_write_header(
        this: &mut VmessStream<S>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            // 1. write header req
            debug_log!("vmess try write aead header");
            while this.header_pos < this.header_buffer.len() {
                this.header_write_res = Pin::new(&mut this.stream)
                    .poll_write(ctx, &this.header_buffer[this.header_pos..]);
                this.header_pos += this.header_write_res.get_poll_res();
                if this.header_write_res.is_error() {
                    debug_log!("vmess try write aead header error");
                    return std::mem::replace(&mut this.header_write_res, Poll::Pending);
                }
                if this.header_pos < this.header_buffer.len() {
                    debug_log!(
                        "vmess header pos:{},header buffer len:{}",
                        this.header_pos,
                        this.header_buffer.len()
                    );
                    co_yield(Poll::Pending);
                }
            }
            debug_log!("vmess try write aead header done");
            // 2. ready to write data
            loop {
                co_yield(this.writer.poll_write_encrypted(ctx, &mut this.stream, buf));
            }
        }
    }

    impl_flush_shutdown!();

    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Self::poll_write_header(this, ctx, buf)
    }
}

impl_async_useful_traits!(VmessStream);

impl<S: AsyncWrite + AsyncRead + Send + Unpin> UdpRead for VmessStream<S> {
    /// Vmess can't implement full-cone nat.
    /// So we just return the first address in handshake packet.
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let addr = self.option.addr.clone();
        self.priv_poll_read(cx, buf).map_ok(|_| addr)
    }
}

impl<S: AsyncWrite + AsyncRead + Send + Unpin> UdpWrite for VmessStream<S> {
    /// Vmess can't implement full-cone nat.
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        #[allow(unused_variables)] target: &Address,
    ) -> Poll<io::Result<usize>> {
        #[cfg(feature = "strict-vmess-udp")]
        {
            use crate::common::new_error;
            if self.option.addr != *target {
                return Err(new_error(
                    "Vmess can't change target udp address different from first packet. Try using a full-cone protocol instead.",
                ))
                    .into();
            }
        }
        self.priv_poll_write(cx, buf)
    }
}

impl<S: AsyncWrite + AsyncRead + Send + Unpin> ProxyUdpStream for VmessStream<S> {
    fn is_tokio_socket(&self) -> bool {
        false
    }
}
