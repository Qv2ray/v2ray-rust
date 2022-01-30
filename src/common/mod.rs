use crate::debug_log;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use generic_array::GenericArray;
use sha2::Digest;
use sha2::{Sha224, Sha256};
use std::io;

pub mod aead_helper;
pub mod fnv1a;
pub mod macro_def;
pub mod net;

pub const LW_BUFFER_SIZE: usize = 4096;
pub const HW_BUFFER_SIZE: usize = 32_768;
pub const AES_128_GCM_TAG_LEN: usize = 16;
pub fn new_error<T: ToString>(message: T) -> io::Error {
    debug_log!("new error message:{}", message.to_string());
    return io::Error::new(
        std::io::ErrorKind::Other,
        format!("protocol: {}", message.to_string()),
    );
}

pub trait BlockCipherHelper {
    fn new_with_slice(key: &[u8]) -> Self;
    fn encrypt_with_slice(&self, block: &mut [u8]);
    fn decrypt_with_slice(&self, block: &mut [u8]);
}

impl BlockCipherHelper for Aes128 {
    #[inline]
    fn new_with_slice(key: &[u8]) -> Self {
        let key = GenericArray::from_slice(&key);
        Aes128::new(&key)
    }

    #[inline]
    fn encrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.encrypt_block(key)
    }

    #[inline]
    fn decrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.decrypt_block(key)
    }
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&b);
    hasher.finalize().into()
}

#[inline]
pub fn sha224(b: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(&b);
    hasher.finalize().into()
}

#[cfg(not(test))]
pub fn random_iv_or_salt(iv_or_salt: &mut [u8]) {
    // Gen IV or Gen Salt by KEY-LEN
    if iv_or_salt.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, iv_or_salt);
        let is_zeros = iv_or_salt.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}

#[cfg(test)]
pub fn random_iv_or_salt(_iv_or_salt: &mut [u8]) {}

pub fn openssl_bytes_to_key(password: &[u8], key: &mut [u8]) {
    use md5::Md5;
    let key_len = key.len();

    let mut last_digest: Option<[u8; 16]> = None;

    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }
        m.update(password);
        let digest = m.finalize();
        let amt = std::cmp::min(key_len - offset, 16);
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);
        offset += 16;
        last_digest = Some(digest.into());
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{openssl_bytes_to_key, BlockCipherHelper};
    use crate::md5;
    use aes::Aes128;

    #[test]
    fn bytes_to_key() {
        let mut key1 = [0u8; 32];
        openssl_bytes_to_key("123456".as_bytes(), key1.as_mut());
        let res=b"\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>e\xb4\xad'\x0b;\x98\t\x8d%j\xb3/[\x8f\xba";
        assert_eq!(res, &key1);
    }

    #[test]
    fn test_md5() {
        // just check code compiling
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(b"hello world");
        let res1: [u8; 16] = hasher.finalize().into();
        let res2 = md5!(b"hello world");
        assert_eq!(res1, res2);
    }

    #[test]
    fn test_aes_128() {
        // just check code compiling
        let k = [0u8; 16];
        let c = Aes128::new_with_slice(&k);
        let mut x = [0u8; 16];
        c.encrypt_with_slice(&mut x[..]);
        println!("{:02X?}", x);
    }
}
