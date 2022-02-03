use crate::proxy::{Address, AddressError};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use tokio_tungstenite::tungstenite::http::Uri;
use uuid::Uuid;
use webpki::DnsNameRef;

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

pub(super) fn from_str_to_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let uri: &str = Deserialize::deserialize(deserializer)?;
    uri.parse().map_err(D::Error::custom)
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
