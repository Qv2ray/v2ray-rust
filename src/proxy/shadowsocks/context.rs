use bloomfilter::Bloom;
use spin::Mutex as SpinMutex;

use crate::common::random_iv_or_salt;
use std::sync::Arc;

// A bloom filter borrowed from shadowsocks-libev's `ppbloom`
//
// It contains 2 bloom filters and each one holds 1/2 entries.
// Use them as a ring buffer.
struct PingPongBloom {
    blooms: [Bloom<[u8]>; 2],
    bloom_count: [usize; 2],
    item_count: usize,
    current: usize,
}

impl PingPongBloom {
    // Entries for server's bloom filter
    //
    // Borrowed from shadowsocks-libev's default value
    const BF_NUM_ENTRIES_FOR_SERVER: usize = 1_000_000;

    // Entries for client's bloom filter
    //
    // Borrowed from shadowsocks-libev's default value
    const BF_NUM_ENTRIES_FOR_CLIENT: usize = 10_000;

    // Error rate for server's bloom filter
    //
    // Borrowed from shadowsocks-libev's default value
    const BF_ERROR_RATE_FOR_SERVER: f64 = 1e-6;

    // Error rate for client's bloom filter
    //
    // Borrowed from shadowsocks-libev's default value
    const BF_ERROR_RATE_FOR_CLIENT: f64 = 1e-15;

    fn new(is_local: bool) -> PingPongBloom {
        let (mut item_count, fp_p) = if is_local {
            (
                Self::BF_NUM_ENTRIES_FOR_CLIENT,
                Self::BF_ERROR_RATE_FOR_CLIENT,
            )
        } else {
            (
                Self::BF_NUM_ENTRIES_FOR_SERVER,
                Self::BF_ERROR_RATE_FOR_SERVER,
            )
        };

        item_count /= 2;

        PingPongBloom {
            blooms: [
                Bloom::new_for_fp_rate(item_count, fp_p),
                Bloom::new_for_fp_rate(item_count, fp_p),
            ],
            bloom_count: [0, 0],
            item_count,
            current: 0,
        }
    }

    // Check if data in `buf` exist.
    //
    // Set into the current bloom filter if not exist.
    //
    // Return `true` if data exist in bloom filter.
    fn check_and_set(&mut self, buf: &[u8]) -> bool {
        for bloom in &self.blooms {
            if bloom.check(buf) {
                return true;
            }
        }

        if self.bloom_count[self.current] >= self.item_count {
            // Current bloom filter is full,
            // Create a new one and use that one as current.

            self.current = (self.current + 1) % 2;

            self.bloom_count[self.current] = 0;
            self.blooms[self.current].clear();
        }

        // Cannot be optimized by `check_and_set`
        // Because we have to check every filters in `blooms` before `set`
        self.blooms[self.current].set(buf);
        self.bloom_count[self.current] += 1;

        false
    }
}

/// Shared basic configuration for the whole server
pub struct BloomContext {
    // Check for duplicated IV/Nonce, for prevent replay attack
    // https://github.com/shadowsocks/shadowsocks-org/issues/44
    nonce_ppbloom: SpinMutex<PingPongBloom>,
}

/// Unique context thw whole server
pub type SharedBloomContext = Arc<BloomContext>;

impl BloomContext {
    /// Create a non-shared Context
    pub fn new(is_local: bool) -> BloomContext {
        BloomContext {
            nonce_ppbloom: SpinMutex::new(PingPongBloom::new(is_local)),
        }
    }

    /// Check if nonce exist or not
    ///
    /// If not, set into the current bloom filter
    pub fn check_nonce_and_set(&self, nonce: &[u8]) -> bool {
        // Plain cipher doesn't have a nonce
        // Always treated as non-duplicated
        if nonce.is_empty() {
            return false;
        }

        let mut ppbloom = self.nonce_ppbloom.lock();
        ppbloom.check_and_set(nonce)
    }

    /// Generate nonce (IV or SALT)
    pub fn generate_nonce(&self, nonce: &mut [u8], unique: bool) {
        if nonce.is_empty() {
            return;
        }

        loop {
            random_iv_or_salt(nonce);

            // Salt already exists, generate a new one.
            if unique && self.check_nonce_and_set(nonce) {
                continue;
            }

            break;
        }
    }
}
