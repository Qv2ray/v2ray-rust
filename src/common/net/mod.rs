use std::io;
use std::mem::MaybeUninit;

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures_util::ready;

use tokio::io::{AsyncRead, ReadBuf};

pub use copy_with_capacity::copy_with_capacity_and_counter;

pub mod copy_with_capacity;

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
    Poll::Ready(Ok(n))
}

pub trait PollUtil {
    type T;
    fn drop_poll_result(self) -> Poll<io::Result<()>>;
    fn is_pending_or_error(&self) -> bool;
    fn is_error(&self) -> bool;
    fn get_poll_res(&self) -> Self::T;
}

impl<T: Default + Copy> PollUtil for Poll<io::Result<T>> {
    type T = T;
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

    fn get_poll_res(&self) -> Self::T {
        match self {
            Poll::Ready(Err(_)) => Self::T::default(),
            Poll::Ready(Ok(t)) => *t,
            Poll::Pending => Self::T::default(),
        }
    }
}
