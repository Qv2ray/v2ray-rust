
use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use tokio_tungstenite::{
    client_async,client_async_with_config,
    tungstenite::http::{StatusCode, Uri},
};

use futures_util::sink::Sink;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use futures_util::ready;
use futures_util::Stream;
use crate::common::new_error;


pub struct BinaryWsStream<T: AsyncRead + AsyncWrite + Unpin> {
    inner: WebSocketStream<T>,
    read_buffer: Option<Bytes>,
}

impl<T: AsyncRead + AsyncWrite + Unpin > AsyncRead for BinaryWsStream<T> {
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
            let message = message.unwrap().map_err(|e| new_error(e))?;
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
                    return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
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

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for BinaryWsStream<T> {
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
        ready!(Pin::new(&mut self.inner).poll_ready(cx))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        let message = Message::Close(None);
        let _ = Pin::new(&mut self.inner).start_send(message);

        let inner = Pin::new(&mut self.inner);
        inner
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> BinaryWsStream<T> {
    pub fn new(inner: WebSocketStream<T>) -> Self {
        return Self {
            inner,
            read_buffer: None,
        };
    }
}
