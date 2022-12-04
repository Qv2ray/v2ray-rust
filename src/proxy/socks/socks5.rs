use crate::common::{new_error, HW_BUFFER_SIZE, LW_BUFFER_SIZE};
use crate::config::Router;
use crate::proxy::socks::{auth_methods, response_code, socks_command, SOCKS_VERSION};
use crate::proxy::ChainStreamBuilder;
use actix_rt::task::JoinHandle;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::SinkExt;
use futures_util::StreamExt;
use log::debug;

use std::collections::HashMap;

use std::io;
use std::io::Error;

use std::net::{IpAddr, SocketAddr};

use std::sync::Arc;

use crate::debug_log;
use crate::proxy::udp::split_ext;
use crate::proxy::Address;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use tokio_util::codec::{Decoder, Encoder};
use tokio_util::udp::UdpFramed;

pub struct Socks5Stream<S> {
    stream: S,
    read_buf: BytesMut,
    authed_users: HashMap<Bytes, Bytes>,
    local_addr: Address,
}

impl<S: AsyncReadExt + Unpin + AsyncWriteExt> Socks5Stream<S> {
    pub fn new(stream: S, local_addr: SocketAddr) -> Socks5Stream<S> {
        Socks5Stream {
            stream,
            read_buf: BytesMut::with_capacity(LW_BUFFER_SIZE),
            authed_users: HashMap::new(),
            local_addr: Address::SocketAddress(local_addr),
        }
    }
    pub async fn init(
        mut self,
        udp_addr: Option<SocketAddr>,
        udp_socket: &mut Option<UdpSocket>,
    ) -> io::Result<(S, Address)> {
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).await?;
        if header[0] != SOCKS_VERSION {
            self.stream.shutdown().await?;
            return Err(Error::new(
                io::ErrorKind::Other,
                format!("socks version {:#x} is not supported", header[0]),
            ));
        } else {
            self.read_buf.reserve(header[1] as usize);
            let mut len = 0usize;
            while len < header[1] as usize {
                len += self.stream.read_buf(&mut self.read_buf).await?;
            }
            let mut response = [SOCKS_VERSION, auth_methods::NO_AUTH];
            let methods = self.read_buf.as_mut();
            if methods.contains(&auth_methods::USER_PASS) {
                response[1] = auth_methods::USER_PASS;
                self.stream.write_all(&response).await?;
                let mut header = [0u8; 2];
                self.stream.read_exact(&mut header).await?;
                self.read_buf.clear();
                self.read_buf.reserve(header[1] as usize);
                unsafe {
                    self.read_buf.advance_mut(header[1] as usize);
                }
                self.stream.read_exact(self.read_buf.as_mut()).await?;
                let mut password_len = [0u8];
                self.stream.read_exact(&mut password_len).await?;
                self.read_buf.reserve(password_len[0] as usize);
                unsafe {
                    self.read_buf.advance_mut(password_len[0] as usize);
                }
                let (_, password) = self.read_buf.split_at_mut(header[1] as usize);
                self.stream.read_exact(password).await?;
                let (username, password) = self.read_buf.split_at(self.read_buf.len());
                if username.is_empty() && password.is_empty() {
                    // nattypetester use empty username and password
                    let response = [1, response_code::SUCCESS];
                    self.stream.write_all(&response).await?;
                } else {
                    let username = Bytes::copy_from_slice(username);
                    match self.authed_users.get(&username) {
                        Some(saved_pass) if saved_pass == password => {
                            let response = [1, response_code::SUCCESS];
                            self.stream.write_all(&response).await?;
                        }
                        _ => {
                            let response = [1, response_code::FAILURE];
                            self.stream.write_all(&response).await?;
                            self.stream.shutdown().await?;
                            return Err(Error::new(
                                io::ErrorKind::Other,
                                "socks5 client auth failure",
                            ));
                        }
                    }
                }
            } else if methods.contains(&auth_methods::NO_AUTH) {
                response[1] = auth_methods::NO_AUTH;
                self.stream.write_all(&response).await?;
            } else {
                response[1] = auth_methods::NO_METHODS;
                self.stream.write_all(&response).await?;
                self.stream.shutdown().await?;
                return Err(Error::new(
                    io::ErrorKind::Other,
                    "socks5 client auth failure",
                ));
            }
        }
        let mut buf = [0u8; 3];
        self.stream.read_exact(&mut buf).await?;
        if buf[0] != SOCKS_VERSION {
            return Err(Error::new(
                io::ErrorKind::Other,
                format!("socks version {:#x} is not supported", buf[0]),
            ));
        }
        let address: Address = Address::read_from_stream(&mut self.stream).await?;
        //cmd
        match buf[1] {
            socks_command::CONNECT => {
                self.read_buf.clear();
                self.read_buf.reserve(self.local_addr.serialized_len() + 3);
                self.read_buf
                    .put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                self.local_addr.write_to_buf(&mut self.read_buf);
                self.stream.write_all(&self.read_buf).await?;
                Ok((self.stream, address))
            }
            socks_command::UDP_ASSOSIATE if udp_addr.is_some() => {
                let socket = UdpSocket::bind((udp_addr.unwrap().ip(), 0)).await?;
                let udp_addr = socket.local_addr()?;
                debug_log!("udp assoc on addr:{}", udp_addr);
                *udp_socket = Some(socket);
                let addr = Address::SocketAddress(udp_addr);
                self.read_buf.clear();
                self.read_buf.reserve(address.serialized_len() + 3);
                self.read_buf
                    .put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                addr.write_to_buf(&mut self.read_buf);
                self.stream.write_all(&self.read_buf).await?;
                Ok((self.stream, addr))
            }
            _ => {
                self.read_buf.clear();
                self.read_buf.reserve(address.serialized_len() + 3);
                self.read_buf.put_slice(&[
                    SOCKS_VERSION,
                    response_code::COMMAND_NOT_SUPPORTED,
                    0x00,
                ]);
                address.write_to_buf(&mut self.read_buf);
                self.stream.write_all(&self.read_buf).await?;
                return Err(Error::new(
                    io::ErrorKind::Other,
                    format!("socks command {:#x} is not supported", buf[1]),
                ));
            }
        }
    }
}

type OutBoundPacketSender = tokio::sync::watch::Sender<(Address, BytesMut)>; // outbound packet sender
struct NatMap(
    HashMap<
        String, // outbound tag
        (
            JoinHandle<io::Result<()>>, // outbound udp read handle
            JoinHandle<io::Result<()>>, // outbound udp write handle
            OutBoundPacketSender,       // outbound packet sender
        ),
    >,
);

impl NatMap {
    fn new() -> NatMap {
        Self(Default::default())
    }

    fn get_mut_sender(&mut self, outbound_tag: &str) -> Option<&mut OutBoundPacketSender> {
        self.0.get_mut(outbound_tag).map(|e| &mut e.2)
    }

    fn insert(
        &mut self,
        outbound_tag: &str,
        recv_handle: JoinHandle<io::Result<()>>,
        send_handle: JoinHandle<io::Result<()>>,
        sender: OutBoundPacketSender,
    ) {
        self.0
            .insert(outbound_tag.to_string(), (recv_handle, send_handle, sender));
    }
}

impl Drop for NatMap {
    fn drop(&mut self) {
        debug_log!("shutting down udp outbound r/w handle");
        for (_, v) in self.0.iter_mut() {
            v.0.abort();
            v.1.abort();
        }
    }
}

/// Socks5UdpDataGram
/// This class support the following nat type.
///
/// todo: symmetric nat
/// * First, we need put addr in nat map. Map(curr_remote_addr, current_addr)
/// * Second, use this map to filter package source when a package need to write (i.e. poll_recv_write).
/// * Note: A package not in this map must not call poll_recv_write
///         to a valid current_addr and this can't be ensure by this trait.
///         We can't figure out which source if a host in map (i.e. atyp 0x03).
///
/// full-cone nat
/// * UoT: we can identify remote send to which current_addr simply.
/// * UoU: we should create a new UdpSocket with current_addr when communicate with current_remote_addr.
pub struct Socks5UdpDatagram;

impl Socks5UdpDatagram {
    pub async fn run(
        socket: UdpSocket,
        router: Arc<Router>,
        inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
        mut stream: TcpStream,
    ) -> io::Result<()> {
        let peer_ip = if socket.local_addr()?.ip().is_ipv4() {
            IpAddr::from([0u8; 4])
        } else {
            IpAddr::from([0u8; 16])
        };
        let mut nat = NatMap::new();
        let (local_addr_sender, local_addr_receiver) = tokio::sync::oneshot::channel();
        let framed_udp = UdpFramed::new(socket, Socks5UdpCodec);
        let (mut w, mut r) = framed_udp.split();
        let (tx_remote_packet, mut rx_remote_packet) = tokio::sync::mpsc::channel(32);
        let local_recv_handle = actix_rt::spawn(async move {
            let tx_remote_packet = tx_remote_packet;
            let mut set_local_addr = false;
            let mut local_addr_sender = Some(local_addr_sender);
            while let Some(res) = r.next().await {
                let ((target_addr, buf), local_addr) = res?;
                if !set_local_addr {
                    // todo: check local addr
                    let _ = std::mem::take(&mut local_addr_sender)
                        .unwrap()
                        .send(local_addr);
                    set_local_addr = true;
                }
                let ob = router.match_addr(&target_addr);
                log::info!("routing {} to outbound:{}", &target_addr, ob);
                if let Some(tx) = nat.get_mut_sender(ob) {
                    let _ = tx.send((target_addr, buf));
                } else {
                    let stream_builder = inner_map.get(ob).unwrap();
                    let out_stream = stream_builder
                        .build_udp(target_addr.clone(), peer_ip)
                        .await?;
                    let (mut out_stream_r, mut out_stream_w) = split_ext(out_stream);
                    let (tx, mut rx) = tokio::sync::watch::channel((target_addr, buf));
                    let tx_remote_packet = tx_remote_packet.clone();
                    let read_handle = actix_rt::spawn(async move {
                        // todo: set a reasonable buffer size
                        let mut buf = BytesMut::with_capacity(HW_BUFFER_SIZE);
                        loop {
                            #[allow(unused_variables)]
                            let (n, addr) = out_stream_r.recv_from(&mut buf).await?;
                            debug_log!("read from remote addr:{}, recv len:{}", addr, n);
                            let _ = tx_remote_packet.send((buf.clone(), addr)).await;
                            buf.clear();
                        }
                    });
                    let write_handle = actix_rt::spawn(async move {
                        {
                            let (t, b) = &*rx.borrow();
                            debug_log!("write packet to remote:{},len:{}", t, b.len());
                            out_stream_w.send_to(b, t).await?;
                        }
                        loop {
                            if rx.changed().await.is_ok() {
                                let (t, b) = &*rx.borrow();
                                debug_log!("write packet to remote:{},len:{}", t, b.len());
                                out_stream_w.send_to(b, t).await?;
                            }
                        }
                    });
                    nat.insert(ob, read_handle, write_handle, tx);
                }
            }
            Ok::<(), Error>(())
        });
        let local_send_handle = actix_rt::spawn(async move {
            let local_addr = local_addr_receiver
                .await
                .map_err(|_| new_error("recv local addr error."))?;
            while let Some((buf, from_addr)) = rx_remote_packet.recv().await {
                debug_log!(
                    "write udp packet to local addr:{},buf len:{},from_addr:{}",
                    local_addr,
                    buf.len(),
                    from_addr
                );
                // improve: a buffer pool?
                w.feed(((buf.freeze(), from_addr), local_addr)).await?;
                w.flush().await?;
            }
            Ok::<(), Error>(())
        });
        let mut buf = [0u8; 0x10];
        let _ = stream.read(&mut buf).await;
        debug!("shutting down udp session...");
        local_send_handle.abort();
        local_recv_handle.abort();
        Ok(())
    }
}

/// UDP ASSOCIATE request header
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
pub struct Socks5UdpCodec;

impl Encoder<(Bytes, Address)> for Socks5UdpCodec {
    type Error = Error;

    fn encode(&mut self, item: (Bytes, Address), dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(3 + item.1.serialized_len() + item.0.len());
        dst.put_slice(&[0u8, 0u8, 0u8]);
        item.1.write_to_buf(dst);
        dst.put_slice(&*item.0);
        Ok(())
    }
}

impl Decoder for Socks5UdpCodec {
    type Item = (Address, BytesMut);
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 3 {
            return Ok(None);
        }
        if src[2] != 0 {
            return Err(new_error("socks5 frag packet is not supported!"));
        }
        src.advance(3);
        let dst_addr = Address::read_from_buf(src)?;
        src.advance(dst_addr.serialized_len());
        let dst_packet = std::mem::take(src);
        Ok(Some((dst_addr, dst_packet)))
    }
}
