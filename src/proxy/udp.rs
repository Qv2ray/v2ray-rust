use crate::common::new_error;

use crate::proxy::{Address, ProxyUdpStream, UdpRead, UdpWrite};
use bytes::{BufMut, BytesMut};
use futures_util::ready;
use std::cell::UnsafeCell;
use std::future::Future;
use std::io::Error;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Release};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{lookup_host, UdpSocket};

/// a fake connected udp socket which implemented AsyncRead and AsyncWrite
pub struct ConnectedUdpSocket(UdpSocket, SocketAddr);

impl ConnectedUdpSocket {
    pub async fn connect<A: tokio::net::ToSocketAddrs>(
        socket: UdpSocket,
        addr: A,
    ) -> io::Result<ConnectedUdpSocket> {
        let mut addrs = lookup_host(addr).await?;
        if let Some(addr) = addrs.next() {
            return Ok(ConnectedUdpSocket { 0: socket, 1: addr });
        }
        Err(new_error("no valid addr after lookup_host"))
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::udp::{split_ext, ConnectedUdpSocket};
    use crate::proxy::Address;
    use bytes::BytesMut;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_udp() -> io::Result<()> {
        let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ip2 = IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5));
        let ip3 = IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114));
        let s = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
        println!("binding udp to {}", s.local_addr()?);
        let s = ConnectedUdpSocket::connect(s, SocketAddr::new(ip2, 53)).await?;
        let (mut r, mut w) = split_ext(s);
        let dns_req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        let dns = Address::SocketAddress(SocketAddr::new(ip2, 53));
        w.send_to(dns_req, &dns).await.unwrap();
        let mut buf = BytesMut::with_capacity(1024);
        let (n1, addr) = r.recv_from(&mut buf).await?;
        println!("read size:{},addr:{}", n1, addr);
        // Since this is a connected udp socket, send to another addr is ignored.
        let dns = Address::SocketAddress(SocketAddr::new(ip3, 53));
        w.send_to(dns_req, &dns).await.unwrap();
        let (n2, addr) = r.recv_from(&mut buf).await?;
        assert_eq!(addr.get_sock_addr().ip(), ip2);
        println!("read size:{},addr:{}", n2, addr);
        println!("buf now len:{}", buf.len());
        assert_eq!(n1 + n2, buf.len());
        Ok(())
    }
}

impl AsyncRead for ConnectedUdpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.0.poll_recv_from(cx, buf).map_ok(|_| ())
    }
}

impl AsyncWrite for ConnectedUdpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.get_mut();
        this.0.poll_send_to(cx, buf, this.1)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Ok(()).into()
    }
}

//
impl UdpRead for ConnectedUdpSocket {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let this = self.get_mut();
        this.0
            .poll_recv_from(cx, buf)
            .map_ok(Address::SocketAddress)
    }
}

impl UdpWrite for ConnectedUdpSocket {
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _target: &Address,
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.0.poll_send_to(cx, buf, this.1)
    }
}

impl ProxyUdpStream for ConnectedUdpSocket {
    fn is_tokio_socket(&self) -> bool {
        true
    }
}

pub struct UdpReadHalf<'a, 'b, T> {
    reader: &'a mut T,
    buf: &'b mut BytesMut,
    addr: Address,
}

impl<'a, 'b, T> UdpReadHalf<'a, 'b, T> {
    fn new(reader: &'a mut T, buf: &'b mut BytesMut) -> Self {
        Self {
            reader,
            buf,
            addr: Address::new_dummy_address(),
        }
    }
}

impl<'a, 'b, T: UdpRead + Unpin> Future for UdpReadHalf<'a, 'b, T> {
    type Output = io::Result<(usize, Address)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let r = Pin::new(&mut *this.reader);
        let n = {
            let dst = this.buf.chunk_mut();
            let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
            let mut buf = ReadBuf::uninit(dst);
            let ptr = buf.filled().as_ptr();
            this.addr = ready!(r.poll_recv_from(cx, &mut buf)?);

            // Ensure the pointer does not change from under us
            assert_eq!(ptr, buf.filled().as_ptr());
            buf.filled().len()
        };
        unsafe {
            this.buf.advance_mut(n);
        }
        Ok((n, std::mem::take(&mut this.addr))).into()
    }
}

pub struct UdpWriteHalf<'a, 'b, T> {
    writer: &'a mut T,
    target_addr: &'b Address,
    buf: &'b [u8],
}

impl<'a, 'b, T> UdpWriteHalf<'a, 'b, T> {
    fn new(writer: &'a mut T, target_addr: &'b Address, buf: &'b [u8]) -> Self {
        Self {
            writer,
            target_addr,
            buf,
        }
    }
}

impl<'a, 'b, T: UdpWrite + Unpin> Future for UdpWriteHalf<'a, 'b, T> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let w = Pin::new(&mut *this.writer);
        w.poll_send_to(cx, this.buf, this.target_addr)
    }
}

/// The readable half of a value returned from [`split`](split()).
pub struct ReadHalfExt<T> {
    inner: Arc<Inner<T>>,
}

/// The writable half of a value returned from [`split`](split()).
pub struct WriteHalfExt<T> {
    inner: Arc<Inner<T>>,
}

/// Splits a single value implementing `AsyncRead + AsyncWrite` into separate
/// `AsyncRead` and `AsyncWrite` handles.
///
/// To restore this read/write object from its `ReadHalf` and
/// `WriteHalf` use [`unsplit`](ReadHalf::unsplit()).
pub fn split_ext<T>(stream: T) -> (ReadHalfExt<T>, WriteHalfExt<T>)
where
    T: ProxyUdpStream,
{
    let inner = Arc::new(Inner {
        locked: AtomicBool::new(false),
        stream: UnsafeCell::new(stream),
    });

    let rd = ReadHalfExt {
        inner: inner.clone(),
    };

    let wr = WriteHalfExt { inner };

    (rd, wr)
}

struct Inner<T> {
    locked: AtomicBool,
    stream: UnsafeCell<T>,
}

struct Guard<'a, T> {
    inner: &'a Inner<T>,
}

#[allow(dead_code)]
impl<T> ReadHalfExt<T> {
    /// Checks if this `ReadHalf` and some `WriteHalf` were split from the same
    /// stream.
    pub fn is_pair_of(&self, other: &WriteHalfExt<T>) -> bool {
        other.is_pair_of(self)
    }

    /// Reunites with a previously split `WriteHalf`.
    ///
    /// # Panics
    ///
    /// If this `ReadHalf` and the given `WriteHalf` do not originate from the
    /// same `split` operation this method will panic.
    /// This can be checked ahead of time by comparing the stream ID
    /// of the two halves.
    pub fn unsplit(self, wr: WriteHalfExt<T>) -> T {
        if self.is_pair_of(&wr) {
            drop(wr);

            let inner = Arc::try_unwrap(self.inner)
                .ok()
                .expect("`Arc::try_unwrap` failed");

            inner.stream.into_inner()
        } else {
            panic!("Unrelated `split::Write` passed to `split::Read::unsplit`.")
        }
    }
}

#[allow(dead_code)]
impl<T> WriteHalfExt<T> {
    /// Checks if this `WriteHalf` and some `ReadHalf` were split from the same
    /// stream.
    pub fn is_pair_of(&self, other: &ReadHalfExt<T>) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<T: UdpRead> ReadHalfExt<T> {
    pub fn recv_from<'b>(&mut self, buf: &'b mut BytesMut) -> UdpReadHalf<'_, 'b, Self> {
        UdpReadHalf::new(self, buf)
    }
}

impl<T: UdpRead> UdpRead for ReadHalfExt<T> {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_recv_from(cx, buf)
    }
}

impl<T: AsyncRead> AsyncRead for ReadHalfExt<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_read(cx, buf)
    }
}

impl<T: UdpWrite> WriteHalfExt<T> {
    pub fn send_to<'b>(&mut self, buf: &'b [u8], addr: &'b Address) -> UdpWriteHalf<'_, 'b, Self> {
        UdpWriteHalf::new(self, addr, buf)
    }
}

impl<T: UdpWrite> UdpWrite for WriteHalfExt<T> {
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Address,
    ) -> Poll<io::Result<usize>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_send_to(cx, buf, target)
    }
}

impl<T: AsyncWrite> AsyncWrite for WriteHalfExt<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut inner = ready!(self.inner.poll_lock(cx));
        inner.stream_pin().poll_shutdown(cx)
    }
}

impl<T> Inner<T> {
    fn poll_lock(&self, cx: &mut Context<'_>) -> Poll<Guard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Acquire, Acquire)
            .is_ok()
        {
            Poll::Ready(Guard { inner: self })
        } else {
            // Spin... but investigate a better strategy

            std::thread::yield_now();
            cx.waker().wake_by_ref();

            Poll::Pending
        }
    }
}

impl<T> Guard<'_, T> {
    fn stream_pin(&mut self) -> Pin<&mut T> {
        // safety: the stream is pinned in `Arc` and the `Guard` ensures mutual
        // exclusion.
        unsafe { Pin::new_unchecked(&mut *self.inner.stream.get()) }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.inner.locked.store(false, Release);
    }
}

unsafe impl<T: Send> Send for ReadHalfExt<T> {}
unsafe impl<T: Send> Send for WriteHalfExt<T> {}
unsafe impl<T: Sync> Sync for ReadHalfExt<T> {}
unsafe impl<T: Sync> Sync for WriteHalfExt<T> {}

impl<T: fmt::Debug> fmt::Debug for ReadHalfExt<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("split::ReadHalfExt").finish()
    }
}

impl<T: fmt::Debug> fmt::Debug for WriteHalfExt<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("split::WriteHalfExt").finish()
    }
}
