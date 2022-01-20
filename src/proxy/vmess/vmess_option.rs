use crate::proxy::Address;
use anyhow::anyhow;
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: Uuid,
    pub alter_id: u16,
    pub addr: Address,
    pub security_num: u8,
    pub is_udp: bool,
}

impl VmessOption {
    pub fn new(
        uuid_str: &String,
        alter_id: u16,
        security: &String,
        addr: Address,
        is_udp: bool,
    ) -> Result<VmessOption> {
        let security_num: u8;
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
            return Err(anyhow!("unknown security type {}", security));
        };
        let uuid = Uuid::parse_str(&uuid_str)?;
        if alter_id > 0 {
            // don't support non vmess aead
            return Err(anyhow!("found non alter_id>0, not vmess aead"));
        }
        Ok(VmessOption {
            uuid,
            alter_id,
            addr,
            security_num,
            is_udp,
        })
    }
}
