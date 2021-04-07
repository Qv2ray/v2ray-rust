use crate::proxy::shadowsocks::context::Context as SSContext;
use crate::proxy::shadowsocks::crypto_io::CryptoStream;
use crate::proxy::socks::Address;
use bytes::{BufMut, BytesMut};
use futures_util::ready;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub mod copy_with_capacity;

pub(crate) async fn relay<T: AsyncWrite + AsyncRead + Unpin>(t: (T, Address)) -> io::Result<()> {
    use copy_with_capacity::copy_with_capacity_and_counter;
    let (inbound_stream, addr) = t;
    let outbound_stream = TcpStream::connect(addr.to_string()).await?;
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);
    let mut down = 0u64;
    let mut up = 0u64;
    tokio::select! {
            _ = copy_with_capacity_and_counter(&mut outbound_r,&mut inbound_w,&mut down,LW_BUFFER_SIZE)=>{
            }
            _ = copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w,&mut up,LW_BUFFER_SIZE)=>{
            }
    }
    println!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}

pub const LW_BUFFER_SIZE: usize = 4096;
pub const HW_BUFFER_SIZE: usize = 32_768;

pub fn read_available<T>(
    cx: &mut Context<'_>,
    io: &mut T,
    buf: &mut BytesMut,
) -> Result<Option<bool>, io::Error>
where
    T: AsyncReadExt + Unpin,
{
    let mut read_some = false;

    loop {
        // If buf is full return but do not disconnect since
        // there is more reading to be done
        if buf.len() >= HW_BUFFER_SIZE {
            return Ok(Some(false));
        }

        let remaining = buf.capacity() - buf.len();
        if remaining < LW_BUFFER_SIZE {
            buf.reserve(HW_BUFFER_SIZE - remaining);
        }

        match read(cx, io, buf) {
            Poll::Pending => {
                return if read_some { Ok(Some(false)) } else { Ok(None) };
            }
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    return Ok(Some(true));
                } else {
                    read_some = true;
                }
            }
            Poll::Ready(Err(e)) => {
                return if e.kind() == io::ErrorKind::WouldBlock {
                    if read_some {
                        Ok(Some(false))
                    } else {
                        Ok(None)
                    }
                } else if e.kind() == io::ErrorKind::ConnectionReset && read_some {
                    Ok(Some(true))
                } else {
                    Err(e)
                }
            }
        }
    }
}

pub fn read<T>(
    cx: &mut Context<'_>,
    io: &mut T,
    buf: &mut BytesMut,
) -> Poll<Result<usize, io::Error>>
where
    T: AsyncReadExt + Unpin,
{
    unsafe {
        let mut read_buf = io.read_buf(buf);
        Pin::new_unchecked(&mut read_buf).poll(cx)
    }
}

pub fn poll_read_buf<T>(
    io: &mut T,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
) -> Poll<io::Result<usize>>
where
    T: AsyncRead + Unpin,
{
    if !buf.has_remaining_mut() {
        return Poll::Ready(Ok(0));
    }
    let n = {
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
        let mut buf = ReadBuf::uninit(dst);
        let ptr = buf.filled().as_ptr();
        ready!(Pin::new(io).poll_read(cx, &mut buf)?);

        // Ensure the pointer does not change from under us
        assert_eq!(ptr, buf.filled().as_ptr());
        buf.filled().len()
    };

    // Safety: This is guaranteed to be the number of initialized (and read)
    // bytes due to the invariants provided by `ReadBuf::filled`.
    unsafe {
        buf.advance_mut(n);
    }
    return Poll::Ready(Ok(n));
}

pub trait PollUtil {
    fn drop_poll_result(self) -> Poll<io::Result<()>>;
    fn is_pending_or_error(&self) -> bool;
    fn is_error(&self) -> bool;
}

impl<T> PollUtil for Poll<io::Result<T>> {
    fn drop_poll_result(self) -> Poll<io::Result<()>> {
        match self {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_pending_or_error(&self) -> bool {
        match self {
            Poll::Ready(Err(_)) => true,
            Poll::Ready(Ok(_)) => false,
            Poll::Pending => true,
        }
    }

    fn is_error(&self) -> bool {
        match self {
            Poll::Ready(Err(_)) => true,
            Poll::Ready(Ok(_)) => false,
            Poll::Pending => false,
        }
    }
}
