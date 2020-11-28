mod inbound;
mod server_client;

const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

pub(crate) mod auth_methods {
    pub const NO_AUTH: u8 = 0x00;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_METHODS: u8 = 0xff;
}

pub(crate) mod response_code {
    pub const SUCCESS: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    pub const RULE_FAILURE: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

pub(crate) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const UDP_ASSOSIATE: u8 = 0x3;
}
