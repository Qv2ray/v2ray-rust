#[macro_export]
macro_rules! md5 {
    ($($x:expr),*) => {{
        use md5::{Md5, Digest};
        let mut digest = Md5::new();
        $(digest.update($x);)*
        let res:[u8;16]=digest.finalize().into();
        res
    }}
}

#[macro_export]
macro_rules! impl_async_write {
    ($name:tt) => {
        impl<S> AsyncWrite for $name<S>
        where
            S: AsyncWrite + Unpin,
        {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, Error>> {
                self.priv_poll_write(cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
                self.priv_poll_flush(cx)
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Error>> {
                self.priv_poll_shutdown(cx)
            }
        }
    };
}
#[macro_export]
macro_rules! impl_async_read {
    ($name:tt) => {
        impl<S> AsyncRead for $name<S>
        where
            S: AsyncRead + Unpin,
        {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.priv_poll_read(cx, buf)
            }
        }
    };
}

// #[macro_export]
// macro_rules! impl_split_stream {
//     ($name:tt) => {
//         impl<S> $name<S>
//         where
//             S: AsyncRead + AsyncWrite + Unpin,
//         {
//             pub fn split(self) -> (ReadHalf<$name<S>>, WriteHalf<$name<S>>) {
//                 tokio::io::split(self)
//             }
//         }
//     };
// }

#[macro_export]
macro_rules! impl_async_useful_traits {
    ($name:tt) => {
        //impl_split_stream!($name);
        impl_async_read!($name);
        impl_async_write!($name);
    };
}

#[macro_export]
macro_rules! impl_flush_shutdown {
    () => {
        fn priv_poll_flush(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.stream), ctx)
        }

        fn priv_poll_shutdown(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), ctx)
        }
    };
}

/// # impl_read_utils
/// impl_read_utils include read_at_least and calc_data_to_put function.
/// ## struct must have members named as follows:
/// * minimal_data_to_put: usize ( for calc_data_to_put ).
/// * data_length: usize ( for calc_data_to_put ).
/// * buffer: BytesMut ( for read_at_least).
/// * read_zero : bool ( for read_at_least).
#[macro_export]
macro_rules! impl_read_utils {
    () => {
        #[allow(dead_code)]
        #[inline]
        fn read_reserve(&mut self, required_data_size: usize) {
            if self.buffer.capacity() < required_data_size {
                self.buffer.reserve(required_data_size);
            }
        }

        #[inline]
        fn read_at_least<R>(
            &mut self,
            r: &mut R,
            ctx: &mut Context<'_>,
            length: usize,
        ) -> Poll<io::Result<()>>
        where
            R: AsyncRead + Unpin,
        {
            use crate::common::net::poll_read_buf;
            while self.buffer.len() < length {
                let n = ready!(poll_read_buf(r, ctx, &mut self.buffer))?;
                if n == 0 {
                    self.read_zero = true;
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                }
            }
            Poll::Ready(Ok(()))
        }

        #[allow(dead_code)]
        #[inline]
        fn calc_data_to_put(&mut self, dst: &mut ReadBuf<'_>) -> usize {
            self.minimal_data_to_put = cmp::min(self.data_length, dst.remaining());
            self.minimal_data_to_put
        }
    };
}

#[macro_export]
macro_rules! deref_udp_read {
    () => {
        fn poll_recv_from(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<Address>> {
            Pin::new(&mut **self).poll_recv_from(cx, buf)
        }
    };
}

#[macro_export]
macro_rules! deref_udp_write {
    () => {
        fn poll_send_to(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: &Address,
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut **self).poll_send_to(cx, buf, target)
        }
    };
}
