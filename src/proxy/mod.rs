use std::num::ParseIntError;

pub mod shadowsocks;
pub mod socks;
pub mod vmess;

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn show_utf8_lossy(bs: &[u8]) -> String {
    String::from_utf8_lossy(bs).into_owned()
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_log {
    ($( $args:expr ),*) => { {use log::debug;debug!( $( $args ),* ); }}
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_log {
    ($( $args:expr ),*) => {};
}
