use crate::proxy::{Address, ProxyUdpStream};
use futures_util::ready;
use std::future::Future;
use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct CopyUdpWithCapacity<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    read_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: &'a mut u64,
    buf: Box<[u8]>,
    addr: Address,
}

#[derive(Debug)]
struct CopyWithCapacity<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    read_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: &'a mut u64,
    buf: Box<[u8]>,
}

pub async fn copy_with_capacity_and_counter<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    counter: &'a mut u64,
    buf_capacity: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    CopyWithCapacity {
        reader,
        read_done: false,
        writer,
        amt: counter,
        pos: 0,
        cap: 0,
        buf: vec![0; buf_capacity].into_boxed_slice(),
    }
    .await
}

pub async fn copy_udp_with_capacity_and_counter<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    counter: &'a mut u64,
    buf_capacity: usize,
) -> io::Result<u64>
where
    R: ProxyUdpStream + ?Sized,
    W: ProxyUdpStream + ?Sized,
{
    CopyUdpWithCapacity {
        reader,
        read_done: false,
        writer,
        amt: counter,
        pos: 0,
        cap: 0,
        buf: vec![0; buf_capacity].into_boxed_slice(),
        // dummy addr
        addr: Address::new_dummy_address(),
    }
    .await
}

impl<R, W> Future for CopyWithCapacity<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    *self.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                let me = &mut *self;
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(*self.amt));
            }
        }
    }
}

impl<R, W> Future for CopyUdpWithCapacity<'_, R, W>
where
    R: ProxyUdpStream + ?Sized,
    W: ProxyUdpStream + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                me.addr = ready!(Pin::new(&mut *me.reader).poll_recv_from(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(Pin::new(&mut *me.writer).poll_send_to(
                    cx,
                    &me.buf[me.pos..me.cap],
                    &me.addr
                ))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    *self.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                return Poll::Ready(Ok(*self.amt));
            }
        }
    }
}
