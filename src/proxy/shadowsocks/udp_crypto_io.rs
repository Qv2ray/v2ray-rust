//! Adapted from shadowsocks-rust source code
//! Crypto protocol for ShadowSocks UDP
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```
use byte_string::ByteStr;
use std::io::{self, Cursor, ErrorKind};

use crate::proxy::shadowsocks::aead_helper::{AeadCipher, CipherKind};
use crate::proxy::shadowsocks::context::BloomContext;
use crate::proxy::Address;
use bytes::{BufMut, BytesMut};
use log::trace;

/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method {
        CipherKind::None => {
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        // aead
        _ => encrypt_payload_aead(context, method, key, addr, payload, dst),
    }
}

fn encrypt_payload_aead(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let salt_len = method.salt_len();
    let addr_len = addr.serialized_len();

    // Packet = IV + ADDRESS + PAYLOAD + TAG
    dst.reserve(salt_len + addr_len + payload.len() + method.tag_len());

    // Generate IV
    dst.resize(salt_len, 0);
    let salt = &mut dst[..salt_len];

    if salt_len > 0 {
        context.generate_nonce(salt, false);
        trace!("UDP packet generated aead salt {:?}", ByteStr::new(salt));
    }

    let mut cipher = AeadCipher::new(method, key, salt);

    addr.write_to_buf(dst);
    dst.put_slice(payload);

    unsafe {
        dst.advance_mut(method.tag_len());
    }

    let m = &mut dst[salt_len..];
    cipher.encrypt(m);
}

/// Decrypt payload from ShadowSocks UDP encrypted packet
pub fn decrypt_payload(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    match method {
        CipherKind::None => {
            let mut cur = Cursor::new(payload);
            match Address::read_from_cursor(&mut cur) {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address))
                }
                Err(..) => {
                    let err =
                        io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
                    Err(err)
                }
            }
        }
        // aead
        _ => decrypt_payload_aead(method, key, payload),
    }
}

fn decrypt_payload_aead(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    let plen = payload.len();
    let salt_len = method.salt_len();
    if plen < salt_len {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short for salt");
        return Err(err);
    }

    let (salt, data) = payload.split_at_mut(salt_len);
    // context.check_nonce_replay(salt)?;

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let tag_len = method.tag_len();
    let mut cipher = AeadCipher::new(method, key, salt);

    if data.len() < tag_len {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "udp packet too short for tag",
        ));
    }

    if !cipher.decrypt(data) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    // Truncate TAG
    let data_len = data.len() - tag_len;
    let data = &mut data[..data_len];

    let (dn, addr) = parse_packet(data)?;

    let data_length = data_len - dn;
    let data_start_idx = salt_len + dn;
    let data_end_idx = data_start_idx + data_length;

    payload.copy_within(data_start_idx..data_end_idx, 0);

    Ok((data_length, addr))
}

fn parse_packet(buf: &[u8]) -> io::Result<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_from_cursor(&mut cur) {
        Ok(address) => {
            let pos = cur.position() as usize;
            Ok((pos, address))
        }
        Err(..) => {
            let err = io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
            Err(err)
        }
    }
}
