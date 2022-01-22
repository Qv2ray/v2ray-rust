use crate::common::new_error;
use crate::proxy::Address;
use bytes::BufMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const HASH_STR_LEN: usize = 56;

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
#[derive(Clone)]
pub enum RequestHeader {
    TcpConnect([u8; HASH_STR_LEN], Address),
    UdpAssociate([u8; HASH_STR_LEN]),
}

impl RequestHeader {
    pub async fn read_from<R>(
        stream: &mut R,
        valid_hash: &[u8],
        first_packet: &mut Vec<u8>,
    ) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut hash_buf = [0u8; HASH_STR_LEN];
        let len = stream.read(&mut hash_buf).await?;
        if len != HASH_STR_LEN {
            first_packet.extend_from_slice(&hash_buf[..len]);
            return Err(new_error("first packet too short"));
        }

        if valid_hash != hash_buf {
            first_packet.extend_from_slice(&hash_buf);
            return Err(new_error(format!(
                "invalid password hash: {}",
                String::from_utf8_lossy(&hash_buf)
            )));
        }

        let mut crlf_buf = [0u8; 2];
        let mut cmd_buf = [0u8; 1];

        stream.read_exact(&mut crlf_buf).await?;
        stream.read_exact(&mut cmd_buf).await?;
        let addr = Address::read_from_stream(stream).await?;
        stream.read_exact(&mut crlf_buf).await?;

        match cmd_buf[0] {
            CMD_TCP_CONNECT => Ok(Self::TcpConnect(hash_buf, addr)),
            CMD_UDP_ASSOCIATE => Ok(Self::UdpAssociate(hash_buf)),
            _ => Err(new_error("invalid command")),
        }
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let udp_dummy_addr = Address::new_dummy_address();
        let (hash, addr, cmd) = match self {
            RequestHeader::TcpConnect(hash, addr) => (hash, addr, CMD_TCP_CONNECT),
            RequestHeader::UdpAssociate(hash) => (hash, &udp_dummy_addr, CMD_UDP_ASSOCIATE),
        };

        let header_len = HASH_STR_LEN + 2 + 1 + addr.serialized_len() + 2;
        let mut buf = Vec::with_capacity(header_len);

        let cursor = &mut buf;
        let crlf = b"\r\n";
        cursor.put_slice(hash);
        cursor.put_slice(crlf);
        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);
        cursor.put_slice(crlf);

        w.write(&buf).await?;
        Ok(())
    }
}
