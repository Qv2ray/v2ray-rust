use crate::common::new_error;
use crate::proxy::udp::ConnectedUdpSocket;
use bytes::{Buf, BufMut, BytesMut};
use std::fmt::{Debug, Formatter};
use std::io::Error;
use std::io::{Cursor, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::str::FromStr;
use std::{fmt, io, vec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address and port
    DomainNameAddress(String, u16),
}

/// Parse `Address` error
#[derive(Debug)]
pub struct AddressError {
    message: String,
}

impl AddressError {
    pub fn as_str(&self) -> &str {
        self.message.as_str()
    }
}

impl From<AddressError> for io::Error {
    fn from(e: AddressError) -> Self {
        io::Error::new(ErrorKind::Other, format!("address error: {}", e.message))
    }
}
impl Default for Address {
    fn default() -> Self {
        Address::new_dummy_address()
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(Address::SocketAddress(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => match port.parse::<u16>() {
                        Ok(port) => Ok(Address::DomainNameAddress(dn.to_owned(), port)),
                        Err(..) => Err(AddressError {
                            message: s.to_owned(),
                        }),
                    },
                    (Some(dn), None) => {
                        // Assume it is 80 (http's default port)
                        Ok(Address::DomainNameAddress(dn.to_owned(), 80))
                    }
                    _ => Err(AddressError {
                        message: s.to_owned(),
                    }),
                }
            }
        }
    }
}
impl Address {
    pub const ADDR_TYPE_IPV4: u8 = 1;
    pub const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
    pub const ADDR_TYPE_IPV6: u8 = 4;
    #[inline]
    pub fn new_dummy_address() -> Address {
        Address::SocketAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }

    #[inline]
    pub fn is_socket_addr(&self) -> bool {
        match self {
            Address::SocketAddress(_) => true,
            Address::DomainNameAddress(_, _) => false,
        }
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
        }
    }

    pub async fn read_from_stream<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            Self::ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
                let mut cursor = Cursor::new(buf);

                let v4addr = Ipv4Addr::new(
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                );
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }
            Self::ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;

                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                );
                let port = cursor.get_u16();

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            Self::ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let mut addr_buf = [0u8; 255 + 2];
                stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                stream.read_exact(&mut addr_buf[..length + 2]).await?;

                let domain_buf = &addr_buf[..length];
                let addr = match String::from_utf8(domain_buf.to_vec()) {
                    Ok(addr) => addr,
                    Err(..) => {
                        return Err(Error::new(io::ErrorKind::Other, "invalid address encoding"))
                    }
                };
                let mut port_buf = &addr_buf[length..length + 2];
                let port = port_buf.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(Error::new(
                    io::ErrorKind::Other,
                    format!("not supported address type {:#x}", addr_type),
                ))
            }
        }
    }

    #[inline]
    pub fn read_from_cursor<A: AsRef<[u8]>>(cur: &mut Cursor<A>) -> io::Result<Self> {
        if cur.remaining() < 1 + 1 {
            return Err(new_error("invalid address buffer"));
        }
        let addr_type = cur.get_u8();
        match addr_type {
            Self::ADDR_TYPE_IPV4 => {
                if cur.remaining() < 4 + 2 {
                    return Err(new_error("IPv4 address too short"));
                }
                let addr = Ipv4Addr::new(cur.get_u8(), cur.get_u8(), cur.get_u8(), cur.get_u8());
                let port = cur.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    addr, port,
                ))))
            }
            Self::ADDR_TYPE_DOMAIN_NAME => {
                let domain_len = cur.get_u8() as usize;
                if cur.remaining() < domain_len {
                    return Err(new_error("Domain name too short"));
                }
                let mut domain_name = vec![0u8; domain_len];
                cur.copy_to_slice(&mut domain_name);
                let port = cur.get_u16();
                let domain_name = String::from_utf8(domain_name).map_err(|e| {
                    new_error(format!("invalid utf8 domain name {}", e.to_string()))
                })?;
                Ok(Address::DomainNameAddress(domain_name, port))
            }
            Self::ADDR_TYPE_IPV6 => {
                if cur.remaining() < 8 * 2 + 2 {
                    return Err(new_error("IPv4 address too short"));
                }
                let addr = Ipv6Addr::new(
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                    cur.get_u16(),
                );
                let port = cur.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    addr, port, 0, 0,
                ))))
            }
            _ => Err(new_error(format!("unknown address type {}", addr_type))),
        }
    }

    pub fn read_from_buf(buf: &[u8]) -> io::Result<Self> {
        let mut cur = Cursor::new(buf);
        Address::read_from_cursor(&mut cur)
    }

    #[inline]
    pub async fn write_to_stream<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        writer.write(&buf).await?;
        Ok(())
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV6);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
                buf.put_u16(addr.port());
            }
            Self::DomainNameAddress(domain_name, port) => {
                buf.put_u8(Self::ADDR_TYPE_DOMAIN_NAME);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(&domain_name.as_bytes()[..]);
                buf.put_u16(*port);
            }
        }
    }
    pub fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x03);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
            }
            Self::DomainNameAddress(domain_name, port) => {
                buf.put_u16(*port);
                buf.put_u8(0x02);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(&domain_name.as_bytes()[..]);
            }
        }
    }

    pub fn get_sock_addr(&self) -> SocketAddr {
        match self {
            Address::SocketAddress(e) => *e,
            Address::DomainNameAddress(_, _) => {
                panic!("domain can't get sock addr");
            }
        }
    }

    pub async fn connect_tcp(&self) -> io::Result<TcpStream> {
        return match self {
            Address::SocketAddress(addr) => TcpStream::connect(addr).await,
            Address::DomainNameAddress(host, port) => {
                TcpStream::connect((host.as_str(), *port)).await
            }
        };
    }

    pub async fn connect_udp(&self, socket: UdpSocket) -> io::Result<ConnectedUdpSocket> {
        return match self {
            Address::SocketAddress(addr) => ConnectedUdpSocket::connect(socket, addr).await,
            Address::DomainNameAddress(host, port) => {
                ConnectedUdpSocket::connect(socket, (host.as_str(), *port)).await
            }
        };
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match self.clone() {
            Address::SocketAddress(addr) => Ok(vec![addr].into_iter()),
            Address::DomainNameAddress(addr, port) => (&addr[..], port).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Address {
        addr.clone()
    }
}
