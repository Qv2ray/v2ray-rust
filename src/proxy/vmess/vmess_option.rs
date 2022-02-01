use crate::proxy::Address;
use uuid::Uuid;

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: Uuid,
    pub alter_id: u16,
    pub addr: Address,
    pub security_num: u8,
    pub is_udp: bool,
}
