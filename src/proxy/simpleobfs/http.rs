use crate::common::random_iv_or_salt;
use crate::proxy::{Address, ProxyUdpStream, UdpRead, UdpWrite};
use crate::{impl_async_read, impl_async_useful_traits, impl_async_write, impl_flush_shutdown};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use futures_util::ready;
use gentian::gentian;
use hyper::Request;
use rand::{thread_rng, Rng};
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct HttpObfs<S> {
    stream: S,
    host: Address,
    buffer: Vec<u8>,
    pos: usize,
    write_res: Poll<io::Result<usize>>,
    write_state: u32, // for state machine generator
    read_state: u32,  // for state machine generator
}

impl<S: Unpin> Unpin for HttpObfs<S> {}

impl<S> HttpObfs<S> {
    pub fn new(host: Address, stream: S) -> HttpObfs<S> {
        HttpObfs {
            stream,
            host,
            buffer: vec![],
            pos: 0,
            write_res: Poll::Pending,
            write_state: 0,
            read_state: 0,
        }
    }
}

impl<S> HttpObfs<S>
where
    S: AsyncRead + Unpin,
{
    #[gentian]
    #[gentian_attr(state=self.read_state,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn priv_poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            co_await(Pin::new(&mut self.stream).poll_read(ctx, buf));
            if (buf
                .filled()
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map_or(false, |s| {
                    let len = buf.filled().len();
                    buf.filled_mut().copy_within(s + 4..len, 0);
                    buf.set_filled(len - s - 4);
                    true
                }))
            {
                co_yield(Poll::Ready(Ok(())));
                break;
            } else {
                buf.set_filled(0);
            }
        }
        loop {
            co_yield(Pin::new(&mut self.stream).poll_read(ctx, buf));
        }
    }
}

impl<S> HttpObfs<S>
where
    S: AsyncWrite + Unpin,
{
    #[gentian]
    #[gentian_attr(state=self.write_state,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn priv_poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut rng = thread_rng();
        let mut encoded_buf = String::new();
        let mut salt = [0u8; 16];
        random_iv_or_salt(&mut salt);
        URL_SAFE.encode_string(salt, &mut encoded_buf);
        let req = Request::builder()
            .uri(format!("http://{}", self.host))
            .header(
                "User-Agent",
                format!("curl/7.{}.{}", rng.gen_range(0..50), rng.gen_range(0..10)),
            )
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", encoded_buf)
            .header("Content-Length", format!("{}", buf.len()))
            .header("Host", format!("{}", self.host))
            .body(())
            .unwrap();
        let (parts, _body) = req.into_parts();
        self.buffer
            .extend_from_slice(parts.method.as_str().as_bytes());
        self.buffer.extend_from_slice(b" ");
        self.buffer.extend_from_slice(parts.uri.path().as_bytes());
        self.buffer.extend_from_slice(b" ");
        self.buffer.extend_from_slice(b"HTTP/1.1");
        self.buffer.extend_from_slice(b"\r\n");
        for (k, v) in &parts.headers {
            self.buffer.extend_from_slice(k.to_string().as_bytes());
            self.buffer.extend_from_slice(b": ");
            self.buffer.extend_from_slice(v.as_bytes());
            self.buffer.extend_from_slice(b"\r\n");
        }
        self.buffer.extend_from_slice(b"\r\n");
        self.buffer.extend_from_slice(buf);
        self.write_res = co_await(self.write_buffer_data(ctx));
        co_yield(Poll::Ready(Ok(buf.len())));
        loop {
            self.write_res = co_await(Pin::new(&mut self.stream).poll_write(ctx, buf));
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }

    #[inline]
    fn write_buffer_data(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pos < self.buffer.len() {
            let n = ready!(Pin::new(&mut self.stream).poll_write(ctx, &self.buffer[self.pos..]))?;
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(0))
    }

    impl_flush_shutdown!();
}

impl_async_useful_traits!(HttpObfs);

impl<S: ProxyUdpStream> UdpRead for HttpObfs<S> {}

impl<S: ProxyUdpStream> UdpWrite for HttpObfs<S> {}
