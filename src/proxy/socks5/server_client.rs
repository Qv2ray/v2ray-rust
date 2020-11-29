use crate::proxy::socks5::auth_methods;
use crate::proxy::socks5::response_code;
use crate::proxy::socks5::socks_command;
use crate::proxy::socks5::SOCKS_VERSION;
use crate::proxy::{AcceptSteam, Address};
use bytes::{BufMut, BytesMut};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::Shutdown;
use smol::net::{SocketAddr, TcpStream, UdpSocket};
use smol::{io, Async};
use std::collections::HashMap;
use std::io::Error;

pub struct ServerClient {
    authed_users: HashMap<BytesMut, BytesMut>,
}

impl ServerClient {
    #[inline]
    pub fn no_auth_new() -> ServerClient {
        ServerClient {
            authed_users: HashMap::new(),
        }
    }

    pub async fn init(
        &self,
        stream: &mut impl AcceptSteam,
        udp_addr: Option<SocketAddr>,
    ) -> io::Result<()> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != SOCKS_VERSION {
            stream.shutdown(Shutdown::Both)?;
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!("socks version {:#x} is not supported", header[0]),
            ));
        } else {
            let mut methods = BytesMut::with_capacity(header[1] as usize);
            stream.read_exact(&mut methods).await?;
            let mut response = [SOCKS_VERSION, auth_methods::NO_AUTH];
            if methods.contains(&auth_methods::USER_PASS) {
                response[1] = auth_methods::USER_PASS;
                stream.write_all(&response).await?;
                let mut header = [0u8; 2];
                stream.read_exact(&mut header).await?;
                let mut username = BytesMut::with_capacity(header[1] as usize);
                stream.read_exact(&mut username).await?;
                let mut password_len = [0u8];
                stream.read_exact(&mut password_len).await?;
                let mut password = BytesMut::with_capacity(password_len[0] as usize);
                match self.authed_users.get(&username) {
                    Some(saved_pass) if saved_pass == &password => {
                        let response = [1, response_code::SUCCESS];
                        stream.write_all(&response).await?;
                    }
                    _ => {
                        let response = [1, response_code::FAILURE];
                        stream.write_all(&response).await?;
                        stream.shutdown(Shutdown::Both)?;
                        return Err(Error::new(
                            std::io::ErrorKind::Other,
                            "socks5 client auth failure",
                        ));
                    }
                }
            } else if methods.contains(&auth_methods::NO_AUTH) {
                response[1] = auth_methods::NO_AUTH;
                stream.write_all(&response).await?;
            } else {
                response[1] = auth_methods::NO_METHODS;
                stream.write_all(&response).await?;
                stream.shutdown(Shutdown::Both)?;
                return Err(Error::new(
                    std::io::ErrorKind::Other,
                    "socks5 client auth failure",
                ));
            }
        }
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await?;
        if buf[0] != SOCKS_VERSION {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!("socks version {:#x} is not supported", buf[0]),
            ));
        }
        let address: Address = Address::read_from_stream(stream).await?;
        //cmd
        match buf[1] {
            socks_command::CONNECT => {
                let mut buf = BytesMut::with_capacity(address.serialized_len() + 3);
                buf.put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                address.write_to_buf(&mut buf);
                stream.write_all(&buf).await?;
            }
            socks_command::UDP_ASSOSIATE if udp_addr.is_some() => {
                //todo use server udp socket
                let addr = Address::SocketAddress(udp_addr.unwrap());
                let mut buf = BytesMut::with_capacity(addr.serialized_len() + 3);
                buf.put_slice(&[SOCKS_VERSION, response_code::SUCCESS, 0x00]);
                addr.write_to_buf(&mut buf);
                stream.write_all(&buf).await?;
            }
            _ => {
                let mut buf = BytesMut::with_capacity(address.serialized_len() + 3);
                buf.put_slice(&[SOCKS_VERSION, response_code::COMMAND_NOT_SUPPORTED, 0x00]);
                address.write_to_buf(&mut buf);
                stream.write_all(&buf).await?;
                return Err(Error::new(
                    std::io::ErrorKind::Other,
                    format!("socks command {:#x} is not supported", buf[1]),
                ));
            }
        }
        Ok(())
    }
}
