use crate::common::LW_BUFFER_SIZE;
use crate::proxy::socks::{auth_methods, response_code, socks_command, Address, SOCKS_VERSION};
use bytes::{BufMut, BytesMut};

use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Socks5Stream<S> {
    stream: S,
    read_buf: BytesMut,
    authed_users: HashMap<Vec<u8>, Vec<u8>>,
}

impl<S: AsyncReadExt + Unpin + AsyncWriteExt> Socks5Stream<S> {
    pub fn new(stream: S) -> Socks5Stream<S> {
        Socks5Stream {
            stream,
            read_buf: BytesMut::with_capacity(LW_BUFFER_SIZE),
            authed_users: HashMap::new(),
        }
    }
    pub async fn init(mut self, udp_addr: Option<SocketAddr>) -> io::Result<(S, Address)> {
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).await?;
        if header[0] != SOCKS_VERSION {
            self.stream.shutdown().await?;
            return Err(Error::new(
                std::io::ErrorKind::Other,
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
                match self.authed_users.get(&username.to_vec()) {
                    Some(saved_pass) if saved_pass == &password => {
                        let response = [1, response_code::SUCCESS];
                        self.stream.write_all(&response).await?;
                    }
                    _ => {
                        let response = [1, response_code::FAILURE];
                        self.stream.write_all(&response).await?;
                        self.stream.shutdown().await?;
                        return Err(Error::new(
                            std::io::ErrorKind::Other,
                            "socks5 client auth failure",
                        ));
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
                    std::io::ErrorKind::Other,
                    "socks5 client auth failure",
                ));
            }
        }
        let mut buf = [0u8; 3];
        self.stream.read_exact(&mut buf).await?;
        if buf[0] != SOCKS_VERSION {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!("socks version {:#x} is not supported", buf[0]),
            ));
        }
        let address: Address = Address::read_from_stream(&mut self.stream).await?;
        //cmd
        match buf[1] {
            socks_command::CONNECT => {
                self.read_buf.clear();
                self.read_buf.reserve(address.serialized_len() + 3);
                self.read_buf
                    .put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                address.write_to_buf(&mut self.read_buf);
                self.stream.write_all(&self.read_buf).await?;
                return Ok((self.stream, address));
            }
            socks_command::UDP_ASSOSIATE if udp_addr.is_some() => {
                //todo use server udp socket
                let addr = Address::SocketAddress(udp_addr.unwrap());
                self.read_buf.clear();
                self.read_buf.reserve(address.serialized_len() + 3);
                self.read_buf
                    .put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                addr.write_to_buf(&mut self.read_buf);
                self.stream.write_all(&self.read_buf).await?;
                return Ok((self.stream, addr));
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
                    std::io::ErrorKind::Other,
                    format!("socks command {:#x} is not supported", buf[1]),
                ));
            }
        }
    }
}
