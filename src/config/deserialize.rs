use crate::common::new_error;
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::{Address, AddressError};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use tokio_tungstenite::tungstenite::http::Uri;
use uuid::Uuid;
use webpki::DnsNameRef;

pub(super) fn from_str_to_cipher_kind<'de, D>(deserializer: D) -> Result<CipherKind, D::Error>
where
    D: Deserializer<'de>,
{
    let method: &str = Deserialize::deserialize(deserializer)?;
    let method = match method {
        "none" | "plain" => CipherKind::None,
        "aes-128-gcm" => CipherKind::Aes128Gcm,
        "aes-256-gcm" => CipherKind::Aes256Gcm,
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => CipherKind::ChaCha20Poly1305,
        _ => return Err(D::Error::custom("wrong ss encryption method")),
    };
    Ok(method)
}
pub(super) fn from_str_to_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let addr: &str = Deserialize::deserialize(deserializer)?;
    addr.parse()
        .map_err(|e: AddressError| D::Error::custom(e.as_str()))
}
pub(super) fn from_str_to_option_address<'de, D>(
    deserializer: D,
) -> Result<Option<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    from_str_to_address(deserializer).map(|addr| Some(addr))
}

pub(super) fn from_str_to_security_num<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let security_num: u8;
    let security: &str = Deserialize::deserialize(deserializer)?;
    if security == "aes-128-gcm" {
        security_num = 0x03;
    } else if security == "chacha20-poly1305" {
        security_num = 0x04;
    } else if security == "none" {
        security_num = 0x05;
    } else if security == "auto" {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            security_num = 0x03;
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            security_num = 0x04;
        }
    } else {
        let msg = format!("unknown security type {}", security);
        return Err(D::Error::custom(msg.as_str()));
    };
    Ok(security_num)
}

pub(super) fn from_str_to_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let uuid_str: &str = Deserialize::deserialize(deserializer)?;
    Uuid::parse_str(uuid_str).map_err(D::Error::custom)
}

#[derive(Clone)]
pub struct EarlyDataUri {
    pub(super) uri: Uri,
    pub(super) early_data_header_name: String,
    pub(super) max_early_data: usize,
}

impl EarlyDataUri {
    fn new(uri: &str) -> std::io::Result<EarlyDataUri> {
        let ws_uri: Uri = uri.parse().map_err(new_error)?;
        if let Some(query) = ws_uri.query() {
            let mut tmp_key = String::new();
            let mut tmp_value = String::new();
            let mut read_key = true;
            let mut found_ed = false;
            let mut start_idx = 0;
            let mut end_idx = query.len();
            for (idx, c) in query.chars().enumerate() {
                match c {
                    '=' => {
                        read_key = false;
                    }
                    '&' => {
                        read_key = true;
                        if tmp_key == "ed" {
                            found_ed = true;
                            end_idx = idx;
                            start_idx = idx - tmp_value.len() - tmp_key.len() - 1;
                            break;
                        }
                        tmp_key.clear();
                        tmp_value.clear();
                    }
                    _ => {
                        if read_key {
                            tmp_key.push(c);
                        } else {
                            tmp_value.push(c);
                        }
                    }
                }
            }
            if tmp_key == "ed" && !found_ed {
                found_ed = true;
                start_idx = end_idx - tmp_value.len() - tmp_key.len() - 1; // key_len + value_len + '&'
            }
            if found_ed {
                let max_early_data: usize = tmp_value.parse::<usize>().map_err(new_error)?;
                if max_early_data == 0 {
                    return Err(new_error("read from query max early data is zero."));
                }
                tmp_value.clear();
                let mut new_query = tmp_value;
                new_query.push_str(ws_uri.path());
                new_query.push('?');
                for (idx, c) in query.chars().enumerate() {
                    if idx >= start_idx && idx < end_idx {
                        continue;
                    }
                    new_query.push(c);
                }
                let parts = ws_uri.into_parts();
                let mut new_uri = Uri::builder();
                if let Some(s) = parts.scheme {
                    new_uri = new_uri.scheme(s);
                }
                if let Some(a) = parts.authority {
                    new_uri = new_uri.authority(a);
                }
                let uri = new_uri
                    .path_and_query(new_query.as_str())
                    .build()
                    .map_err(new_error)?;

                return Ok(EarlyDataUri {
                    uri,
                    early_data_header_name: "Sec-WebSocket-Protocol".to_string(),
                    max_early_data,
                });
            }
        }
        return Ok(EarlyDataUri {
            uri: ws_uri,
            early_data_header_name: String::new(),
            max_early_data: 0,
        });
    }
}

pub(super) fn from_str_to_ws_uri<'de, D>(deserializer: D) -> Result<EarlyDataUri, D::Error>
where
    D: Deserializer<'de>,
{
    let uri: &str = Deserialize::deserialize(deserializer)?;
    EarlyDataUri::new(uri).map_err(D::Error::custom)
}

pub(super) fn from_str_to_sni<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let sni: &str = Deserialize::deserialize(deserializer)?;
    let dns_name = DnsNameRef::try_from_ascii_str(sni).map_err(D::Error::custom)?;
    let res = std::str::from_utf8(dns_name.as_ref()).map_err(D::Error::custom)?;
    Ok(res.to_owned())
}

#[cfg(test)]
mod tests {
    use crate::config::deserialize::EarlyDataUri;

    #[test]
    fn test_ws_uri() {
        let e = EarlyDataUri::new("ws://example.com/?ed=2048").unwrap();
        assert!(!e.early_data_header_name.is_empty());
        assert_eq!(e.max_early_data, 2048);
        let e = EarlyDataUri::new("ws://example.com/?key=xx&ed=20488").unwrap();
        assert!(!e.early_data_header_name.is_empty());
        assert_eq!(e.max_early_data, 20488);
        let e = EarlyDataUri::new("ws://example.com/?key=xx&ed=20488&n=q").unwrap();
        assert!(!e.early_data_header_name.is_empty());
        assert_eq!(e.max_early_data, 20488);
    }
}
