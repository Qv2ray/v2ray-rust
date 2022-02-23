use std::hash::Hasher;

pub struct Fnv1aHasher(u32);

impl Default for Fnv1aHasher {
    #[inline]
    fn default() -> Fnv1aHasher {
        Fnv1aHasher(0x811c9dc5u32)
    }
}

impl Hasher for Fnv1aHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0 as u64
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let Fnv1aHasher(mut hash) = *self;

        for byte in bytes.iter() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }

        *self = Fnv1aHasher(hash);
    }
}
