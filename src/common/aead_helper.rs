use aes::cipher::generic_array::typenum::Unsigned;
use aes_gcm::{aead::Tag, AeadInPlace, KeyInit};
pub use aes_gcm::{Aes128Gcm, Aes256Gcm};
pub use chacha20poly1305::ChaCha20Poly1305;

pub trait AeadCipherHelper: AeadInPlace {
    fn new_with_slice(key: &[u8]) -> Self;
    fn encrypt_inplace_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        let x = self
            .encrypt_in_place_detached(nonce.into(), aad, msg)
            .expect("encryption failure!");
        tag.copy_from_slice(&x);
    }
    fn decrypt_inplace_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> bool {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        self.decrypt_in_place_detached(nonce.into(), aad, msg, Tag::<Self>::from_slice(tag))
            .is_ok()
    }
}

impl AeadCipherHelper for Aes128Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        Aes128Gcm::new(key.into())
    }
}

impl AeadCipherHelper for Aes256Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        Aes256Gcm::new(key.into())
    }
}

impl AeadCipherHelper for ChaCha20Poly1305 {
    fn new_with_slice(key: &[u8]) -> Self {
        ChaCha20Poly1305::new(key.into())
    }
}
