use crate::common::new_error;
use crate::debug_log;
use crate::proxy::websocket::BinaryWsStream;
use crate::proxy::{BoxProxyStream, UdpRead, UdpWrite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::ready;
use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::{cmp, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::client_async_with_config;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub(super) struct BinaryWsStreamWithEarlyData {
    stream: Option<BoxProxyStream>,
    req: Option<Request<()>>,
    ws_stream_future: Option<Pin<Box<dyn Future<Output = io::Result<BoxProxyStream>> + Send>>>,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    is_write_early_data: bool,
}

impl BinaryWsStreamWithEarlyData {
    pub fn new(
        io: BoxProxyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> BinaryWsStreamWithEarlyData {
        Self {
            stream: Some(io),
            req: Some(req),
            ws_stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            is_write_early_data: false,
        }
    }

    fn build_stream_impl(
        io: BoxProxyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxProxyStream>> + Send>> {
        async fn run(
            io: BoxProxyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> io::Result<BoxProxyStream> {
            let (stream, resp) = client_async_with_config(req, io, config)
                .await
                .map_err(new_error)?;
            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(new_error(format!("bad status: {}", resp.status())));
            }
            debug_log!("build ws stream success");
            let ret: BoxProxyStream = Box::new(BinaryWsStream::new(stream));
            Ok(ret)
        }

        Box::pin(run(io, req, config))
    }
}

impl AsyncRead for BinaryWsStreamWithEarlyData {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        debug_log!("ws-0-rtt poll r");
        if !self.is_write_early_data {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let this = self.get_mut();
        match &mut this.stream {
            None => {
                unreachable!()
            }
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BinaryWsStreamWithEarlyData {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        debug_log!("ws-0-rtt poll w");
        if !self.is_write_early_data {
            loop {
                if let Some(f) = &mut self.as_mut().ws_stream_future {
                    let stream = ready!(Pin::new(f).poll(cx))?;
                    self.as_mut().stream = Some(stream);
                    self.as_mut().is_write_early_data = true;
                    if let Some(w) = self.as_mut().early_waker.take() {
                        w.wake();
                    }
                    if let Some(w) = self.as_mut().flush_waker.take() {
                        w.wake();
                    }
                    return Poll::Ready(Ok(self.as_mut().early_data_len));
                } else {
                    let mut req = self.as_mut().req.take().unwrap();
                    if let Some(v) = req
                        .headers_mut()
                        .get_mut(&self.as_mut().early_data_header_name)
                    {
                        debug_log!("ws-0-rtt early data buf len:{}", buf.len());
                        self.as_mut().early_data_len =
                            cmp::min(self.as_mut().early_data_len, buf.len());
                        let header_value =
                            URL_SAFE_NO_PAD.encode(&buf[..self.as_mut().early_data_len]);
                        *v = HeaderValue::from_bytes(header_value.as_bytes())
                            .expect("base64 encode error");
                        debug_log!("header base64 str:{}", header_value);
                        debug_log!(
                            "max_e_d:{}->{}",
                            self.as_mut().early_data_header_name,
                            v.len()
                        );
                    }
                    let io = self.as_mut().stream.take().unwrap();
                    let config = self.as_mut().ws_config.take();
                    self.as_mut().ws_stream_future = Some(
                        BinaryWsStreamWithEarlyData::build_stream_impl(io, req, config),
                    );
                }
            }
        }
        return match &mut self.as_mut().stream {
            None => {
                unreachable!()
            }
            Some(s) => Pin::new(s).poll_write(cx, buf),
        };
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        debug_log!("ws-0-rtt poll f");
        if !self.is_write_early_data {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let this = self.get_mut();
        match &mut this.stream {
            None => {
                unreachable!()
            }
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        debug_log!("ws-0-rtt poll s");
        if !self.is_write_early_data {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let this = self.get_mut();
        match &mut this.stream {
            None => {
                unreachable!()
            }
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl UdpRead for BinaryWsStreamWithEarlyData {}
impl UdpWrite for BinaryWsStreamWithEarlyData {}
