use crate::common::{new_error, LW_BUFFER_SIZE};
use crate::proxy::{
    BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType, UdpRead, UdpWrite,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use log::error;
use rand::random;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub struct Http2StreamBuilder {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl Http2StreamBuilder {
    pub fn new(
        hosts: Vec<String>,
        headers: HashMap<String, String>,
        method: http::Method,
        path: http::uri::PathAndQuery,
    ) -> Self {
        Self {
            hosts,
            headers,
            method,
            path,
        }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let uri_idx = random::<usize>() % self.hosts.len();
        let uri: Uri = {
            Uri::builder()
                .scheme("https")
                .authority(self.hosts[uri_idx].as_str())
                .path_and_query(self.path.as_str())
                .build()
                .map_err(new_error)?
        };
        let mut request = Request::builder()
            //.method("GET")
            .uri(uri)
            .method(self.method.clone())
            .version(Version::HTTP_2);
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k.as_str(), v.as_str());
            }
        }
        Ok(request.body(()).unwrap())
    }
}

macro_rules! http2_build_tcp_impl {
    ($s:tt,$io:tt) => {
        let (mut client, h2) = h2::client::handshake($io).await.map_err(new_error)?;
        let req = $s.req()?;
        let (resp, send_stream) = client.send_request(req, false).map_err(new_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("http2 got err:{:?}", e);
            }
        });
        let recv_stream = resp.await.map_err(new_error)?.into_body();
        return Ok(Box::new(Http2Stream::new(recv_stream, send_stream)))
    };
}

#[async_trait]
impl ChainableStreamBuilder for Http2StreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        http2_build_tcp_impl!(self, io);
    }

    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream> {
        if build_tcp_inside {
            http2_build_tcp_impl!(self, io);
        } else {
            Ok(io)
        }
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::H2
    }
}

// Adapted from https://github.com/zephyrchien/midori/blob/master/src/transport/h2/stream.rs
pub struct Http2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
}

impl Http2Stream {
    #[inline]
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(LW_BUFFER_SIZE * 4),
        }
    }
}

impl AsyncRead for Http2Stream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.buffer.len());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        };
        Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_read]);
                // copy the left payload into buffer
                if data.len() > to_read {
                    self.buffer.extend_from_slice(&data[to_read..]);
                };
                // increase recv window
                self.recv
                    .flow_control()
                    .release_capacity(to_read)
                    .map_or_else(
                        |e| Err(Error::new(ErrorKind::ConnectionReset, e)),
                        |_| Ok(()),
                    )
            }
            // no more data frames
            // maybe trailer
            // or cancelled
            _ => Ok(()),
        })
    }
}

impl AsyncWrite for Http2Stream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.send.reserve_capacity(buf.len());
        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => self
                .send
                .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                .map_or_else(
                    |e| Err(Error::new(ErrorKind::BrokenPipe, e)),
                    |_| Ok(to_write),
                ),
            // is_send_streaming returns false
            // which indicates the state is
            // neither open nor half_close_remote
            _ => Err(Error::new(ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.reserve_capacity(0);
        Poll::Ready(ready!(self.send.poll_capacity(cx)).map_or(
            Err(Error::new(ErrorKind::BrokenPipe, "broken pipe")),
            |_| {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_or_else(|e| Err(Error::new(ErrorKind::BrokenPipe, e)), |_| Ok(()))
            },
        ))
    }
}

impl UdpRead for Http2Stream {}
impl UdpWrite for Http2Stream {}
