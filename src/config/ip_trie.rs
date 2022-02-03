fn normalize6(ip: u128, prefix: u8) -> u128 {
    ip >> (128 - prefix) << (128 - prefix)
}
fn normalize(ip: u32, prefix: u8) -> u32 {
    ip >> (32 - prefix) << (32 - prefix)
}

trait TrieNode {
    fn nullptr() -> Self;
}

impl TrieNode for u32 {
    fn nullptr() -> Self {
        u32::MAX
    }
}
impl TrieNode for u128 {
    fn nullptr() -> Self {
        u128::MAX
    }
}
macro_rules! impl_trie {
    ($trie_name:tt, $ip_type:tt) => {
        struct $trie_name {
            left: Vec<$ip_type>,
            right: Vec<$ip_type>,
            value: Vec<u32>,
            size: usize,
        }

        impl $trie_name {
            pub fn new() -> Self {
                Self {
                    left: vec![$ip_type::nullptr()],
                    right: vec![$ip_type::nullptr()],
                    value: vec![u32::MAX],
                    size: 1,
                }
            }
            pub fn put(&mut self, key: $ip_type, prefix: u8, value: u32) {
                let bit = std::mem::size_of::<$ip_type>() * 8;
                let mask = ((1 << (bit - prefix as usize)) - 1) ^ ($ip_type::nullptr());
                let mut bit = 1 << (bit - 1);
                let mut node = 0;
                let mut next = 0;
                while (bit & mask) != 0 {
                    next = if key & bit != 0 {
                        self.right[node as usize]
                    } else {
                        self.left[node as usize]
                    };
                    if next == $ip_type::nullptr() {
                        break;
                    }
                    bit >>= 1;
                    node = next;
                }
                if next != $ip_type::nullptr() {
                    self.value[node as usize] = value;
                    return;
                }
                while (bit & mask) != 0 {
                    next = self.size as $ip_type;
                    //println!("next:{},len:{}", next, self.value.len());
                    self.value.push(u32::MAX);
                    self.left.push($ip_type::nullptr());
                    self.right.push($ip_type::nullptr());
                    if (key & bit) != 0 {
                        self.right[node as usize] = next;
                    } else {
                        self.left[node as usize] = next;
                    }

                    bit >>= 1;
                    node = next;
                    self.size += 1;
                }
                self.value[node as usize] = value;
            }

            pub fn get(&self, key: $ip_type) -> Option<u32> {
                let bit = std::mem::size_of::<u32>() * 8;
                let mut bit = (1 as $ip_type) << (bit - 1);
                let mut value = u32::MAX;
                let mut node = 0;
                while node != $ip_type::nullptr() {
                    if self.value[node as usize] != u32::MAX {
                        value = self.value[node as usize];
                    }
                    node = if key & bit != 0 {
                        self.right[node as usize]
                    } else {
                        self.left[node as usize]
                    };
                    bit >>= 1;
                }
                return if value == u32::MAX { None } else { Some(value) };
            }
        }
    };
}

impl_trie!(PatriciaTrie4, u32);
impl_trie!(PatriciaTrie6, u128);

pub struct GeoIPMatcher {
    trie4: PatriciaTrie4,
    trie6: PatriciaTrie6,
    outbound: Vec<String>,
}

impl Default for GeoIPMatcher {
    fn default() -> Self {
        GeoIPMatcher::new()
    }
}

impl GeoIPMatcher {
    pub fn match4(&self, ip: u32) -> &str {
        return if let Some(c) = self.trie4.get(ip) {
            self.outbound[c as usize].as_str()
        } else {
            ""
        };
    }

    pub fn match6(&self, ip: u128) -> &str {
        return if let Some(c) = self.trie6.get(ip) {
            self.outbound[c as usize].as_str()
        } else {
            ""
        };
    }

    fn get_outbound_pos(&mut self, outbound: String) -> usize {
        return if let Some(p) = self.outbound.iter().position(|x| x == &outbound) {
            p
        } else {
            let len = self.outbound.len();
            self.outbound.push(outbound);
            len
        };
    }

    pub fn put_v6(&mut self, ip6: u128, prefix: u8, outbound: String) {
        let pos = self.get_outbound_pos(outbound);
        let ip6 = normalize6(ip6, prefix);
        self.trie6.put(ip6, prefix, pos as u32);
    }
    pub fn put_v4(&mut self, ip4: u32, prefix: u8, outbound: String) {
        let pos = self.get_outbound_pos(outbound);
        let ip4 = normalize(ip4, prefix);
        self.trie4.put(ip4, prefix, pos as u32);
    }

    pub fn build(&mut self) {}

    pub fn new() -> GeoIPMatcher {
        GeoIPMatcher {
            trie4: PatriciaTrie4::new(),
            trie6: PatriciaTrie6::new(),
            outbound: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ip_trie::PatriciaTrie4;

    #[test]
    fn test4() {
        let mut trie = PatriciaTrie4::new();
        let ip1 = u32::from_be_bytes([10, 0, 0, 0]);
        let ip2 = u32::from_be_bytes([10, 0, 3, 0]);
        trie.put(ip1, 8, 69);
        trie.put(ip1, 24, 42);
        trie.put(ip2, 24, 123);

        let ip3 = u32::from_be_bytes([10, 32, 32, 32]);
        assert_eq!(trie.get(ip3).unwrap(), 69);
        let ip4 = u32::from_be_bytes([10, 0, 0, 32]);
        assert_eq!(trie.get(ip4).unwrap(), 42);
        let ip5 = u32::from_be_bytes([10, 0, 3, 5]);
        assert_eq!(trie.get(ip5).unwrap(), 123);
    }
}
