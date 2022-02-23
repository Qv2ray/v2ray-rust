use crate::common::aead_helper::{AeadCipherHelper, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use crate::proxy::shadowsocks::ss_hkdf_sha1;

#[derive(Clone, Copy, PartialEq)]
pub enum CipherKind {
    None,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    fn new(&self, sub_key: &[u8]) -> CipherInner {
        match self {
            CipherKind::None => {
                unreachable!()
            }
            CipherKind::Aes128Gcm => CipherInner::Aes128Gcm(Aes128Gcm::new_with_slice(sub_key)),
            CipherKind::Aes256Gcm => CipherInner::Aes256Gcm(Aes256Gcm::new_with_slice(sub_key)),
            CipherKind::ChaCha20Poly1305 => {
                CipherInner::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(sub_key))
            }
        }
    }
    #[inline]
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }
    #[inline]
    pub fn nonce_len(&self) -> usize {
        match self {
            CipherKind::None => 0,
            CipherKind::Aes128Gcm => 12,
            CipherKind::Aes256Gcm => 12,
            CipherKind::ChaCha20Poly1305 => 12,
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            CipherKind::None => 0,
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
            CipherKind::ChaCha20Poly1305 => 32,
        }
    }
    pub fn tag_len(&self) -> usize {
        16
    }
}

enum CipherInner {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CipherInner {
    pub fn encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        match self {
            CipherInner::Aes128Gcm(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
            CipherInner::Aes256Gcm(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
            CipherInner::ChaCha20Poly1305(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
        }
    }
    pub fn decrypt_slice(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match self {
            CipherInner::Aes128Gcm(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
            CipherInner::Aes256Gcm(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
            CipherInner::ChaCha20Poly1305(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
        }
    }
}

pub struct AeadCipher {
    cipher: CipherInner,
    nonce: [u8; 24],
    nlen: usize,
}

impl AeadCipher {
    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> AeadCipher {
        let sub_key = ss_hkdf_sha1(iv_or_salt, key);
        let cipher = kind.new(&sub_key[..key.len()]);
        AeadCipher {
            cipher,
            nonce: [0u8; 24],
            nlen: kind.nonce_len(),
        }
    }
    pub fn encrypt(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = &self.nonce[..self.nlen];
        self.cipher
            .encrypt_slice(nonce, plaintext_in_ciphertext_out);
        self.increase_nonce();
    }

    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self
            .cipher
            .decrypt_slice(nonce, ciphertext_in_plaintext_out);
        self.increase_nonce();
        ret
    }

    #[inline]
    fn increase_nonce(&mut self) {
        let mut c = self.nonce[0] as u16 + 1;
        self.nonce[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < self.nlen {
            c += self.nonce[n] as u16;
            self.nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }
}
