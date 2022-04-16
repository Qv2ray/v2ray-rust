mod ws_early_data;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite};

use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::{client_async_with_config, tungstenite::Message, WebSocketStream};

use crate::common::new_error;
use crate::debug_log;
use crate::proxy::websocket::ws_early_data::BinaryWsStreamWithEarlyData;
use crate::proxy::{
    BoxProxyStream, BoxProxyUdpStream, ChainableStreamBuilder, ProtocolType, ProxySteam,
    ProxyUdpStream, UdpRead, UdpWrite,
};
use futures_util::ready;
use futures_util::sink::Sink;
use futures_util::Stream;
use std::collections::BTreeMap;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_tungstenite::tungstenite::http::{Request, StatusCode, Uri};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub struct BinaryWsStream<T: ProxySteam> {
    inner: WebSocketStream<T>,
    read_buffer: Option<Bytes>,
}

impl<T: ProxySteam> AsyncRead for BinaryWsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(read_buffer) = &mut self.read_buffer {
                if read_buffer.len() <= buf.remaining() {
                    buf.put_slice(read_buffer);
                    self.read_buffer = None;
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&read_buffer[..len]);
                    read_buffer.advance(len);
                }
                return Poll::Ready(Ok(()));
            }
            let message = ready!(Pin::new(&mut self.inner).poll_next(cx));
            if message.is_none() {
                return Poll::Ready(Err(new_error("websocket stream drained")));
            }
            let message = message.unwrap().map_err(new_error)?;
            // binary only
            match message {
                Message::Binary(binary) => {
                    if binary.len() < buf.remaining() {
                        buf.put_slice(&binary);
                        return Poll::Ready(Ok(()));
                    } else {
                        self.read_buffer = Some(Bytes::from(binary));
                        continue;
                    }
                }
                Message::Close(_) => {
                    return Poll::Ready(Ok(()));
                }
                _ => {
                    return Poll::Ready(Err(new_error(format!(
                        "invalid message type {:?}",
                        message
                    ))))
                }
            }
        }
    }
}

impl<T: ProxySteam> AsyncWrite for BinaryWsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        let message = Message::Binary(buf.into());
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = Pin::new(&mut self.inner);
        inner
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        debug_log!("shut down");
        ready!(Pin::new(&mut self.inner).poll_ready(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        let message = Message::Close(None);
        let _ = Pin::new(&mut self.inner).start_send(message);

        let inner = Pin::new(&mut self.inner);
        inner
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("close {:?}", e)))
    }
}

impl<T: ProxyUdpStream> UdpRead for BinaryWsStream<T> {}

impl<T: ProxyUdpStream> UdpWrite for BinaryWsStream<T> {}

impl<T: ProxySteam> BinaryWsStream<T> {
    pub fn new(inner: WebSocketStream<T>) -> Self {
        Self {
            inner,
            read_buffer: None,
        }
    }
}

#[derive(Clone)]
pub struct BinaryWsStreamBuilder {
    uri: Uri,
    headers: BTreeMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
}

impl BinaryWsStreamBuilder {
    pub fn new_from_config(
        uri: Uri,
        max_early_data: usize,
        early_data_header_name: String,
        ws_config: Option<WebSocketConfig>,
        headers: BTreeMap<String, String>,
    ) -> BinaryWsStreamBuilder {
        BinaryWsStreamBuilder {
            uri,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
        }
    }

    fn req(&self) -> Request<()> {
        let authority = self.uri.authority().unwrap().as_str();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);
        let mut request = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(self.uri.clone());
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k.as_str(), v.as_str());
            }
        }
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "s");
        }
        request.body(()).unwrap()
    }
}

#[async_trait]
impl ChainableStreamBuilder for BinaryWsStreamBuilder {
    async fn build_tcp(&self, io: BoxProxyStream) -> io::Result<BoxProxyStream> {
        let req = self.req();
        if self.max_early_data > 0 {
            debug_log!("build tcp ws-0-rtt");
            return Ok(Box::new(BinaryWsStreamWithEarlyData::new(
                io,
                req,
                self.ws_config,
                self.early_data_header_name.clone(),
                self.max_early_data,
            )));
        }
        let (stream, resp) = client_async_with_config(req, io, self.ws_config)
            .await
            .map_err(new_error)?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(new_error(format!("bad status: {}", resp.status())));
        }
        debug_log!("build ws stream success");
        Ok(Box::new(BinaryWsStream::new(stream)))
    }

    async fn build_udp(
        &self,
        io: BoxProxyUdpStream,
        build_tcp_inside: bool,
    ) -> io::Result<BoxProxyUdpStream> {
        if build_tcp_inside {
            let req = self.req();
            if self.max_early_data > 0 {
                debug_log!("build tcp ws-0-rtt");
                let io = Box::new(BinaryWsStreamWithEarlyData::new(
                    Box::new(io),
                    req,
                    self.ws_config,
                    self.early_data_header_name.clone(),
                    self.max_early_data,
                ));
                return Ok(io);
            }
            let (stream, resp) = client_async_with_config(req, io, self.ws_config)
                .await
                .map_err(new_error)?;
            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(new_error(format!("bad status: {}", resp.status())));
            }
            debug_log!("build ws stream success");
            return Ok(Box::new(BinaryWsStream::new(stream)));
        }
        Ok(io)
    }

    fn into_box(self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn ChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::WS
    }
}
