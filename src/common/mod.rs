use std::io;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use generic_array::GenericArray;
use sha2::{Sha224, Sha256};
use sha2::Digest;

pub mod fnv1a;
pub mod macro_def;
pub mod net;
pub mod aead_helper;

pub const LW_BUFFER_SIZE: usize = 4096;
pub const HW_BUFFER_SIZE: usize = 32_768;
pub const AES_128_GCM_TAG_LEN:usize=16;
pub fn new_error<T: ToString>(message: T) -> io::Error {
    return io::Error::new(
        std::io::ErrorKind::Other,
        format!("protocol: {}", message.to_string()),
    );
}

pub trait BlockCipherHelper{
    fn new_with_slice(key:&[u8])->Self;
    fn encrypt_with_slice(&self,block:&mut [u8]);
    fn decrypt_with_slice(&self,block:&mut [u8]);
}

impl BlockCipherHelper for Aes128{
    #[inline]
    fn new_with_slice(key: &[u8]) -> Self {
        let key = GenericArray::from_slice(&key);
        Aes128::new(&key)
    }

    #[inline]
    fn encrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice( block);
        self.encrypt_block(key)
    }

    #[inline]
    fn decrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice( block);
        self.decrypt_block(key)
    }
}

pub fn sha256(b:&[u8])->[u8;32]{
    let mut hasher = Sha256::new();
    hasher.update(&b);
    hasher.finalize().into()
}

pub fn sha224(b:&[u8])->[u8;28]{
    let mut hasher = Sha224::new();
    hasher.update(&b);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests{
    use aes::Aes128;
    use crate::common::BlockCipherHelper;
    use crate::md5;

    #[test]
    fn test_md5(){
        // just check code compiling
        use md5::{Md5, Digest};
        let mut hasher = Md5::new();
        hasher.update(b"hello world");
        let res1:[u8;16] = hasher.finalize().into();
        let res2=md5!(b"hello world");
        assert_eq!(res1,res2);
    }

    #[test]
    fn test_aes_128(){
        // just check code compiling
        let k = [0u8;16];
        let c = Aes128::new_with_slice(&k);
        let mut x = [0u8;16];
        c.encrypt_with_slice(&mut x[..]);
        println!("{:02X?}",x);
    }

}