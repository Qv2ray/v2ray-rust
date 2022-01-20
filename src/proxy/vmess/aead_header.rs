use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;
use std::slice::from_raw_parts_mut;

use crate::{debug_log, impl_read_utils};

use crate::common::aead_helper::AeadCipherHelper;
use crate::common::net::PollUtil;
use crate::common::{random_iv_or_salt, BlockCipherHelper, AES_128_GCM_TAG_LEN, LW_BUFFER_SIZE};
use crate::proxy::vmess::kdf::{
    vmess_kdf_1_one_shot, vmess_kdf_3_one_shot, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use aes::Aes128;
use aes_gcm::Aes128Gcm;
use futures_util::ready;
use generator::state_machine_generator;
use std::io::ErrorKind;
use std::task::{Context, Poll};
use std::{cmp, io};
use tokio::io::{AsyncRead, ReadBuf};

fn create_auth_id(cmd_key: &[u8], time: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_slice(time);
    let mut random_bytes = [0u8; 4];
    random_iv_or_salt(&mut random_bytes);
    buf.put_slice(&random_bytes);
    let zero = crc32fast::hash(&*buf);
    buf.put_u32(zero);
    let key = vmess_kdf_1_one_shot(cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let block = Aes128::new_with_slice(&key[0..16]);
    block.encrypt_with_slice(&mut buf);
    buf
}

pub fn seal_vmess_aead_header(cmd_key: &[u8], data: &[u8]) -> BytesMut {
    #[cfg(not(test))]
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_be_bytes();
    #[cfg(test)]
    let time = {
        let mut b = BytesMut::new();
        b.put_u64(99);
        b
    };
    let mut generated_auth_id = create_auth_id(cmd_key, &time);
    let id_len = generated_auth_id.len();
    let mut connection_nonce = [0u8; 8];
    random_iv_or_salt(&mut connection_nonce);

    // reserve (header_length + nonce + data + 2*tag) bytes
    // total_len = 16 +
    generated_auth_id.reserve(2 + connection_nonce.len() + data.len() + 2 * AES_128_GCM_TAG_LEN);
    {
        let payload_header_length_aeadkey = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &*generated_auth_id,
            &connection_nonce,
        );
        let payload_header_length_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &generated_auth_id,
            &connection_nonce,
        );
        let nonce = &payload_header_length_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_length_aeadkey[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..2 + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_u16(data.len() as u16);
        cipher.encrypt_inplace_with_slice(&nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };
    }
    generated_auth_id.put_slice(&connection_nonce);
    {
        let payload_header_aead_key = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let payload_header_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let nonce = &payload_header_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_aead_key[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..data.len() + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_slice(data);
        cipher.encrypt_inplace_with_slice(&nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };
    }
    generated_auth_id
}

pub struct VmessHeaderReader {
    buffer: BytesMut,
    n: usize,
    state: u32, // for state machine generator use
    resp_header_len_enc: Aes128Gcm,
    header_len_iv: [u8; 12],
    resp_header_payload_enc: Aes128Gcm,
    header_payload_iv: [u8; 12],
    respv: u8,
    data_length: usize,
    minimal_data_to_put: usize,
    read_res: Poll<io::Result<()>>,
    received_resp: bool,
    read_zero: bool,
}

impl VmessHeaderReader {
    pub fn new(resp_body_key: &[u8], resp_body_iv: &[u8], respv: u8) -> VmessHeaderReader {
        let header_key =
            vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
        let header_iv = vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV);
        let payload_key =
            vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY);
        let payload_iv =
            vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV);
        let resp_header_len_enc = Aes128Gcm::new_with_slice(&header_key[..16]);
        let resp_header_payload_enc = Aes128Gcm::new_with_slice(&payload_key[..16]);
        let buffer = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        VmessHeaderReader {
            buffer,
            n: 0,
            state: 0,
            resp_header_len_enc,
            header_len_iv: <[u8; 12]>::try_from(&header_iv[..12]).unwrap(),
            resp_header_payload_enc,
            header_payload_iv: <[u8; 12]>::try_from(&payload_iv[..12]).unwrap(),
            respv,
            data_length: 0,
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            received_resp: false,
            read_zero: false,
        }
    }

    pub fn get_buffer(&mut self) -> BytesMut {
        std::mem::take(&mut self.buffer)
    }

    impl_read_utils!();
    #[state_machine_generator]
    #[fsa_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            // 1. read length
            loop {
                debug_log!("vmess: try aead header read length");
                self.read_res = (self.read_at_least(r, ctx, 18));
                if self.read_res.is_pending() {
                    debug_log!("vmess: aead header reading");
                    co_yield(Poll::Pending);
                    continue;
                }
                if self.read_res.is_error() {
                    if self.read_zero {
                        return Poll::Ready(Ok(()));
                    }
                    debug_log!("vmess: aead header read length error");
                    return std::mem::replace(&mut self.read_res, Poll::Pending);
                }
                break;
            }
            let aad = [0u8; 0];
            debug_log!("vmess: try aead header decrypt len");
            if !self.resp_header_len_enc.decrypt_inplace_with_slice(
                &self.header_len_iv,
                &aad,
                &mut self.buffer[..18],
            ) {
                debug_log!("vmess: aead header decrypt failed");
                let err =
                    io::Error::new(ErrorKind::InvalidData, "decrypted resp header len failed!");
                return Poll::Ready(Err(err));
            }
            self.data_length = self.buffer.get_u16() as usize;
            self.buffer.advance(16);
            // 2. read data
            debug_log!(
                "vmess: try aead header read data, buffer len:{}",
                self.buffer.len()
            );
            loop {
                self.read_res = (self.read_at_least(r, ctx, self.data_length + 16));
                if self.read_res.is_pending() {
                    debug_log!("vmess: aead header data reading");
                    co_yield(Poll::Pending);
                    continue;
                }
                if self.read_res.is_error() {
                    if self.read_zero {
                        return Poll::Ready(Ok(()));
                    }
                    debug_log!("vmess: aead header read data error");
                    return std::mem::replace(&mut self.read_res, Poll::Pending);
                }
                break;
            }
            debug_log!("vmess: try aead header decrypt data");
            let aad = [0u8; 0];
            if !self.resp_header_payload_enc.decrypt_inplace_with_slice(
                &self.header_payload_iv,
                &aad,
                &mut self.buffer[..self.data_length + 16],
            ) {
                debug_log!("vmess: aead header data decrypt failed");
                let err = io::Error::new(
                    ErrorKind::InvalidData,
                    "decrypted resp header payload failed!",
                );
                return Poll::Ready(Err(err));
            }
            // tag(16) + vmess command(at least 4)
            if self.buffer.len() < 20 {
                debug_log!("vmess: buffer length error");
                let err = io::Error::new(ErrorKind::InvalidData, "unexpected buffer length!");
                return Poll::Ready(Err(err));
            }
            if self.buffer[0] != self.respv {
                debug_log!("vmess: respv error");
                let err = io::Error::new(ErrorKind::InvalidData, "unexpected response header!");
                return Poll::Ready(Err(err));
            }
            if self.buffer[2] != 0 {
                debug_log!("vmess: dynamic port error");
                let err =
                    io::Error::new(ErrorKind::InvalidData, "dynamic port is not supported now!");
                return Poll::Ready(Err(err));
            }
            self.buffer.advance(self.data_length + 16);
            self.data_length = self.buffer.len();
            self.received_resp = true;
            debug_log!("aead header read done");
            return Poll::Ready(Ok(()));
        }
    }

    pub fn received_resp(&self) -> bool {
        self.received_resp
    }
}

#[cfg(test)]
mod vmess_tests {
    use crate::common::sha256;
    use crate::proxy::decode_hex;
    use crate::proxy::vmess::aead_header::{create_auth_id, seal_vmess_aead_header};
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_create_auth_id() {
        let id = b"1234567890123456";
        let mut time = BytesMut::default();
        time.put_u64(99);
        let x = create_auth_id(id, &time); // without random bytes
        let expected = decode_hex("4ec6a618d72597e0a492ac59b5db162f").unwrap();
        assert_eq!(&expected, &x)
    }

    #[test]
    fn test_seal_vmess_aead_header() {
        let id = b"1234567890123456";
        let x = seal_vmess_aead_header(id, b"vmess");
        println!("header :{:02X}", x);
        let expected = decode_hex("4ec6a618d72597e0a492ac59b5db162faee11503a83b4b6f7785d2fd1d3dd51aabe400000000000000001eb64334545d67f30c2d8fc100bfa5132f1a583c5b").unwrap();
        println!("len:{}", x.len());
        assert_eq!(&expected, &x)
    }

    #[test]
    fn dummy() {
        let id = b"1234567890123456";
        let res = sha256(id);
        println!("sha256:{:02X?}", &res[..32]);
    }
}
