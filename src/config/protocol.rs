use super::{Address, AddressPort, NetworkType, Port, Time, UserLevel};

/// All protocols List
pub enum List {
    /// `"blackhole"`
    Blackhole,
    /// `"dns"`
    Dns,
    /// `"dokodemo-door"`
    DockodemoDoor,
    /// `"freedom"`
    Freedom,
    /// `"http"`
    Http,
    /// `"socks"`
    Socks,
    /// `"vless"`
    Vless,
    /// `"vmess"`
    Vmess,
    /// `"shadowsocks"`
    Shadowsocks,
    /// `"trojan"`
    Trojan,
    /// `"mtproto"`
    MtprotoV1,
}

pub mod dns {
    use super::{Address, Port};
    pub enum Network {
        /// `"tcp"`
        Tcp,
        /// `"udp"`
        Udp,
    }

    /// ```json
    /// {
    ///     "network": "tcp",
    ///     "address": "1.1.1.1",
    ///     "port": 53
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// (V2Ray 4.16+) to modify the transport layer protocol DNS traffic, optional values
        /// are `"tcp"` and `"udp"`. When not specified, the transmission mode of the
        /// source remains
        /// unchanged.
        network: Network,
        /// (V2Ray 4.16+) Modify the DNS server address. When not specified, keep the address
        /// specified in the source unchanged.
        address: Address,
        /// (V2Ray 4.16+) Modify the DNS server port. When not specified, keep the port
        /// specified in the source unchanged.
        port: Port,
    }
}

pub mod blackhole {

    pub enum ResponseType {
        /// `"http"` : Blackhole to close the connection
        Http,
        /// `"none"` : Blackhole will send back a simple HTTP 403 packets, and then closes the
        /// connection.
        None,
    }

    /// ```json
    /// {
    ///     "type": "none"
    /// }
    /// ```
    pub struct Response {
        /// See [ResponseType](../blackhole/enum.ResponseType.html)
        r#type: ResponseType,
    }

    /// ```json
    /// {
    ///     "response": {
    ///         "type": "none"
    ///     }
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// Configure the response data of the black hole. Blackhole will send the specified
        /// response data after receiving the data to be forwarded, and then close the
        /// connection. The data to be forwarded will be discarded. If this item is not
        /// specified, Blackhole will close the connection directly.
        response: Response,
    }
}

pub mod dokodemo_door {
    use super::{Address, NetworkType, Port, Time, UserLevel};

    /// ```json
    /// {
    ///     "address": "8.8.8.8",
    ///     "port": 53,
    ///     "network": "tcp",
    ///     "timeout": 0,
    ///     "followRedirect": false,
    ///     "userLevel": 0
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// Forward traffic to this address. It can be an IP address with the form `"1.2.3.4"`
        /// or a domain name with the form `"v2ray.com"`. String type.
        ///
        /// When `followRedirect` (see below) is a `true`, `address` it may be empty.
        address: Address,
        /// Forward traffic to the designated port of the destination address, range [1,
        /// 65535], numeric type. Required parameters.
        port: Port,
        /// The type of network protocol that can be received. For example, when the designated
        /// `"tcp"`, any door receives only TCP traffic. The default value is `"tcp"`.
        network: NetworkType,
        /// The time limit of inbound data (seconds), the default value is 300.
        ///
        /// After V2Ray 3.1 is equivalent to the corresponding user level `connIdle` policy
        timeout: Time,
        /// When the value `true`, dokodemo-door will recognize from the data forwarded by
        /// the iptables and forwarded to the appropriate destination address. See [transmission
        /// configuration](../transport/index.html) is `tproxy` provided.
        follow_redirect: bool,
        /// User level, all connections will use this user level.
        user_level: UserLevel,
    }
}

pub mod freedom {
    use super::{AddressPort, UserLevel};
    pub enum DomainStrategy {
        /// `"AsIs"`
        AsIs,
        /// `"UseIP"`
        UseIP,
        /// `"UseIPv4"`
        UseIPv4,
        /// `"UseIPv6"`
        UseIPv6,
    }

    /// ```json
    /// {
    ///     "domainStrategy": "AsIs",
    ///     "redirect": "127.0.0.1:3366",
    ///     "userLevel": 0
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// When the target address is a domain name, Freedom can directly send a connection
        /// to this domain name ( `"AsIs"`), or resolve the domain name to an IP before
        /// establishing a connection ( `"UseIP"`, `"UseIPv4"` and `"UseIPv6"`). The steps to
        /// resolve IP will use V2Ray's built-in DNS . The default value is `"AsIs"`.
        ///
        /// (V2Ray 4.6+) When using the `"UseIP"` mode and outbound connection configuration
        /// specified `sendThrough`, based Freedom `sendThrough` value to automatically
        /// determine the required IP type, the IPv4 or IPv6.
        ///
        /// (V2Ray 4.7+) when used `"UseIPv4"` or `"UseIPv6"` a mode, Freedom use only IPv4 or
        /// IPv6 address. When sendThroughyou specify a local address does not match,
        /// the connection fails.
        domain_strategy: DomainStrategy,
        /// Freedom will force all data to be sent to the specified address (instead of the
        /// address specified by the inbound protocol). Its value is a string, example:
        /// `"127.0.0.1:80"`, `":1234"`. When the address is not specified, for example `":443"`,
        /// Freedom will not modify the original target address. When the port is `0`, such
        /// as `"v2ray.com: 0"`, Freedom does not modify the original port.
        redirect: AddressPort,
        /// User level, all connections use this level.
        user_level: UserLevel,
    }
}

pub mod http {
    use super::{Address, Port, Time};

    /// ```json
    /// {
    ///     "user": "my-username",
    ///     "pass": "my-password"
    /// }
    /// ```
    pub struct Account {
        /// User name, string type. Required.
        user: String,
        /// Password, string type. Required.
        pass: String,
    }

    /// ```json
    /// {
    ///     "timeout": 0,
    ///     "accounts": [
    ///         {
    ///             "user": "my-username",
    ///             "pass": "my-password"
    ///         }
    ///     ],
    ///     "allowTransparent": false,
    ///     "userLevel": 0
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// The timeout setting (seconds) for reading data from the client, 0 means unlimited
        /// time. The default value is 300. After V2Ray 3.1 is equivalent to the corresponding
        /// user level `connIdle` strategy.
        timeout: Time,
        /// An array, each element in the array is a user account. The default value is empty.
        ///
        /// When `accounts` not empty, HTTP proxy inbound connection will be verified Basic
        /// Authentication.
        accounts: Vec<Account>,
        /// When is `true` the time, it will forward all HTTP requests, and not just proxy
        /// requests. If the configuration is improper, turning on this option will cause an
        /// endless loop.
        allow_transparent: bool,
        /// User level, all connections use this level.
        user_level: u8,
    }

    pub struct Server {
        /// HTTP proxy server address, required.
        address: Address,
        /// HTTP proxy server port, required.
        port: Port,
        /// An array, each element in the array is a user account. The default value is empty.
        users: Vec<Account>,
    }

    /// ```json
    /// {
    ///     "servers": [
    ///         {
    ///             "address": "192.168.108.1",
    ///             "port": 3128,
    ///             "users": [
    ///                 {
    ///                     "user": "my-username",
    ///                     "pass": "my-password"
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// HTTP proxy server configuration, if you configure more than one, use (RoundRobin)
        /// circularly.
        servers: Vec<Server>,
    }
}

pub mod socks {
    use super::{Address, Port, UserLevel};

    /// ```json
    /// {
    ///     "user": "test user",
    ///     "pass": "test pass",
    ///     "level": 0
    /// }
    /// ```
    pub struct User {
        user: String,
        pass: String,
        level: UserLevel,
    }

    /// ```json
    /// {
    ///     "address": "127.0.0.1",
    ///     "port": 1234,
    ///     "users": [
    ///         {
    ///             "user": "test user",
    ///             "pass": "test pass",
    ///             "level": 0
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct Server {
        /// server address.
        address: Address,
        /// Server port
        port: Port,
        /// User list, each of which has a user configuration. When the list is not empty, the
        /// Socks client will use this user information for authentication; if not specified,
        /// it will not be authenticated.
        users: Vec<User>,
    }

    /// ```json
    /// {
    ///     "servers": [
    ///         {
    ///             "address": "127.0.0.1",
    ///             "port": 1234,
    ///             "users": [
    ///                 {
    ///                     "user": "test user",
    ///                     "pass": "test pass",
    ///                     "level": 0
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// Socks server list, each item is a server configuration.
        servers: Vec<Server>,
    }

    /// ```json
    /// {
    ///     "user": "my-username",
    ///     "pass": "my-password"
    /// }
    /// ```
    pub struct Account {
        user: String,
        pass: String,
    }

    pub enum Auth {
        /// `"noauth"`
        NoAuth,
        /// `"password"`
        Password,
    }

    /// It should be noted that although socks inbound can be a public service port, the socks
    /// protocol does not encrypt the transmission and is not suitable for transmission over
    /// the public network. A more meaningful usage of socks inbound is to provide local
    /// services for other programs in a local area network or local environment.
    ///
    /// ```json
    /// {
    ///     "auth": "noauth",
    ///     "accounts": [
    ///         {
    ///             "user": "my-username",
    ///             "pass": "my-password"
    ///         }
    ///     ],
    ///     "udp": false,
    ///     "ip": "127.0.0.1",
    ///     "userLevel": 0
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// Socks authentication protocol that supports `"noauth"` anonymous and `"password"`
        /// user password mode. The default value is `"noauth"`.
        auth: Auth,
        /// An array, each element in the array is a user account. The default value is empty.
        /// This option only if `auth` is `password` valid.
        accounts: Vec<Account>,
        /// Whether to enable UDP protocol support. The default value is `false`.
        udp: bool,
        /// When UDP is turned on, V2Ray needs to know the IP address of the machine.
        /// The default value is `"127.0.0.1"`.
        ip: Address,
        /// User level, all connections use this level.
        user_level: UserLevel,
    }
}

pub mod vless {
    use super::{Address, Port, UserLevel};

    /// ```json
    /// {
    ///     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///     "flow": "",
    ///     "encryption": "none",
    ///     "level": 0
    /// }
    /// ```
    pub struct User {
        /// VLESS user ID, you must be a legitimate UUID, you can use online tools to generate it.
        id: String,
        /// v4.29.0+, flow control, currently only used to select XTLS algorithm.
        flow: String,
        /// User level, see [local policy](../../policy/struct.UserLevel).
        user_level: UserLevel,
        /// User mailbox, used to distinguish traffic (logs, statistics) of different users.
        email: String,
    }

    /// ```json
    /// {
    ///     "address": "example.com",
    ///     "port": 443,
    ///     "users": []
    /// }
    /// ```
    pub struct Server {
        /// Address, point to the server, support domain name, IPv4, IPv6.
        address: Address,
        /// The port is usually the same as the port monitored by the server.
        port: Port,
        /// A group of users approved by the server.
        users: Vec<User>,
    }

    /// ```json
    /// {
    ///     "vnext": [
    ///         {
    ///             "address": "example.com",
    ///             "port": 443,
    ///             "users": [
    ///                 {
    ///                     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///                     "flow": "",
    ///                     "encryption": "none",
    ///                     "level": 0
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// An array containing a series of configurations pointing to the server.
        vnext: Vec<Server>,
    }

    /// ```json
    /// {
    ///     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///     "flow": "",
    ///     "level": 0,
    ///     "email": "love@v2fly.org"
    /// }
    /// ```
    pub struct Client {
        /// The user ID of VLESS must be a legal UUID, and you can also use V2Ctl to generate
        /// it.
        id: String,
        /// v4.29.0+, flow control, currently only used to select XTLS algorithm.
        flow: String,
        /// User level, see [local policy](../../policy/struct.UserLevel.html).
        level: UserLevel,
        /// User mailbox, used to distinguish traffic (logs, statistics) of different users.
        email: String,
    }

    /// It is strongly recommended to use: The new protocol fallback mode based on the first
    /// packet length shunt (VLESS original) is more concise, efficient, safe and more powerful
    /// than other protocol fallback solutions.
    ///
    /// ```json
    /// {
    ///     "alpn": "",
    ///     "path": "",
    ///     "dest": 80,
    ///     "xver": 0
    /// }
    /// ```
    pub struct Fallback {
        /// (Novices ignore it first) Try to match the TLS ALPN negotiation result , empty is
        /// any, the default is empty. It is recommended to use only two filling methods as
        /// needed: omit and fill `"h2"`.
        ///
        /// Smart: When necessary, VLESS will try to read the TLS ALPN negotiation result,
        /// if successful, output info `realAlpn =` to the log.
        /// Purpose: To solve the problem that Nginx's h2c service cannot be compatible
        /// with http/1.1 at the same time. Nginx needs to write two lines of listen,
        /// which are used for 1.1 and h2c respectively.
        /// Note: fallbacks alpn exist `"h2"` when, [inbound
        /// TLS](../../transport/struct.Tls.html) to be set up
        /// `"alpn":["h2","http/1.1"]` to support h2 access.
        alpn: String,
        /// (Novice to ignore) try to match the first packet in the HTTP PATH, any empty, the
        /// default is empty. It must be non-empty to `"/"` begin with, does not support h2c.
        ///
        /// Smart: When necessary, VLESS will try to take a look at the PATH (no more than 55
        /// bytes; the fastest algorithm, which does not fully parse HTTP), and if
        /// successful, it will output info `realPath =` to the log.
        /// Purpose: Distribute other inbound WebSocket traffic or HTTP masquerading traffic,
        /// without redundant processing, purely forwarding traffic, the [actual test is
        /// stronger than Nginx anti-generation](https://github.com/badO1a5A90/v2ray-doc/blob/master/v2ray%20speed%20test%20v4.27.2.md).
        /// Note: Be sure to note that the inbound where fallbacks are located must be
        /// TCP+TLS , which is used for inbound diverting to other WS, and the diverted
        /// inbound does not need to configure TLS.
        path: String,
        /// Determine the destination of TCP layer traffic after TLS decryption . Currently,
        /// two types of addresses are supported: (This item is required, otherwise it cannot
        /// be started)
        ///
        /// TCP, the format is `"addr:port"`, where addr supports IPv4, domain name, and IPv6.
        /// If you fill in the domain name, it will also directly initiate a TCP connection
        /// (without using the built-in DNS).
        /// Unix domain socket, an absolute path form, shaped like `"/dev/shm/domain.socket"`,
        /// can be added at the beginning of `"@"` the representative abstract,
        /// It `"@@"` represents [abstract](https://www.man7.org/linux/man-pages/man7/unix.7.html)
        /// with padding.
        ///
        /// If you only fill in the port, it can be a number or a string, like `80`, `"80"` and
        /// usually points to a plaintext http service (addr will be filled in `"127.0.0.1"`).
        dest: String,
        /// (Ignore for beginners) Send [PROXY protocol](https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt),
        /// Dedicated to the true source IP and port of the request, fill in version 1 or 2,
        /// the default is 0, that is, do not send. It is recommended to fill in 1 if necessary.
        ///
        /// Fill in 1 or 2 at present, the function is exactly the same, but the structure is
        /// different, and the former can be printed while the latter is binary. Both TCP and
        /// WS inbound of V2Ray have supported receiving PROXY protocol.
        xver: u8,
    }

    pub enum Decryption {
        None,
    }

    /// ```json
    /// {
    ///     "clients": [
    ///         {
    ///             "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///             "flow": "",
    ///             "level": 0,
    ///             "email": "love@v2fly.org"
    ///         }
    ///     ],
    ///     "decryption": "none",
    ///     "fallbacks": [
    ///         {
    ///             "dest": 80
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// A group of users approved by the server.
        clients: Vec<Client>,
        /// Note that this is decryption, the same level as clients. It also needs to be
        /// filled at this stage `"none"` and cannot be left blank. The location of decryption
        /// and encryption is different, because if a layer of agreed encryption is set, the
        /// server needs to decrypt before knowing which user it is.
        /// If the decryption value is not set correctly, you will receive an error message
        /// when using v2ray or -test.
        decryption: Decryption,
        /// An array containing a series of powerful [fallback](../vless/struct.Fallback.html) shunt configurations (optional).
        fallbacks: Vec<Fallback>,
    }
}

pub mod vmess {

    use super::{Address, Port, UserLevel};

    pub enum Security {
        /// `"aes-128-gcm"` : Recommend to use on PC
        Aes128Gcm,
        /// `"chacha20-poly1305"` : Recommended to use on mobile
        Chacha20Poly1305,
        /// `"auto"` : Default value, automatic selection (aes-128-gcm encryption method when the
        /// running framework is AMD64, ARM64 or s390x, otherwise it is Chacha20-Poly1305
        /// encryption method)
        Auto,
        /// `"none"` : No encryption
        None,
    }

    /// ```json
    /// {
    ///     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///     "alterId": 0,
    ///     "security": "auto",
    ///     "level": 0
    /// }
    /// ```
    pub struct User {
        /// The primary ID of the VMess user. Must be a valid UUID.
        id: String,
        /// In order to further prevent detection, a user can generate multiple IDs in addition
        /// to the main ID. You only need to specify the number of additional IDs. The
        /// recommended value is 0 to enable VMessAEAD. If not specified, the default value is
        /// `0`. Maximum value `65535`. This value cannot exceed the value specified by the
        /// server.
        alter_id: u16,
        /// user level
        user_level: UserLevel,
        /// Encryption method, the client will use the configured encryption method to send
        /// data, and the server will automatically recognize it without configuration.
        security: Security,
    }

    /// ```json
    /// {
    ///     "address": "127.0.0.1",
    ///     "port": 37192,
    ///     "users": []
    /// }
    /// ```
    pub struct Server {
        /// Server address, supports IP address or domain name.
        address: Address,
        /// Server port number.
        port: Port,
        /// A group of users recognized by the server
        users: Vec<User>,
    }

    /// ```json
    /// {
    ///     "vnext": [
    ///         {
    ///             "address": "127.0.0.1",
    ///             "port": 37192,
    ///             "users": [
    ///                 {
    ///                     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///                     "alterId": 0,
    ///                     "security": "auto",
    ///                     "level": 0
    ///                 }
    ///             ]
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// An array containing a series of server configurations
        vnext: Vec<Server>,
    }

    /// ```json
    /// {
    ///     "to": "tag_to_detour"
    /// }
    /// ```
    pub struct Detour {
        /// For an inbound protocol tag, see the [configuration file](../index.html) for details . The specified
        /// inbound protocol must be a VMess
        to: String,
    }

    /// ```json
    /// {
    ///     "level": 0,
    ///     "alterId": 0
    /// }
    /// ```
    pub struct Default {
        /// User level, meaning the same as above. The default value is 0.
        level: UserLevel,
        /// The `alterId` default value of the dynamic port , the default value `32`, the filling
        /// `0` will also be rewritten `32`. Recommended value `4`.
        alter_id: u8,
    }

    /// ```json
    /// {
    ///     "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///     "level": 0,
    ///     "alterId": 4,
    ///     "email": "love@v2ray.com"
    /// }
    /// ```
    pub struct Client {
        /// The user ID of VMess. Must be a valid UUID.
        id: String,
        /// User level, see [local policy](../../policy/struct.UserLevel.html) for details
        level: UserLevel,
        /// It has the same meaning as in the outbound agreement above.
        alter_id: u8,
        /// User email address, used to distinguish the traffic of different users.
        email: String,
    }

    /// ```json
    /// {
    ///     "clients": [
    ///         {
    ///             "id": "27848739-7e62-4138-9fd3-098a63964b6b",
    ///             "level": 0,
    ///             "alterId": 0,
    ///             "email": "love@v2ray.com"
    ///         }
    ///     ],
    ///     "default": {
    ///         "level": 0,
    ///         "alterId": 0
    ///     },
    ///     "detour": {
    ///         "to": "tag_to_detour"
    ///     },
    ///     "disableInsecureEncryption": false
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// A group of users recognized by the server. clients can be empty. When this
        /// configuration is used as a dynamic port, V2Ray will automatically create a user.
        clients: Vec<Client>,
        /// Optional, the default configuration of clients. It is only `detour` effective when
        /// matched .
        default: Option<Default>,
        /// Instruct the corresponding outbound protocol to use another server.
        detour: Detour,
        /// Whether to prohibit the client from using insecure encryption methods, when the
        /// client specifies the following encryption methods, the server will actively
        /// disconnect. The default value is `false`.
        ///
        /// - `"none"`
        /// - `"aes-128-cfb"`
        disable_insecure_encryption: bool,
    }
}

pub mod shadowsocks {
    use super::{Address, Port, UserLevel};

    /// ```json
    /// {
    ///     "email": "love@v2ray.com",
    ///     "address": "127.0.0.1",
    ///     "port": 1234,
    ///     "method": "method",
    ///     "password": "password",
    ///     "level": 0
    /// }
    /// ```
    pub struct Server {
        /// Email address, optional, used to identify the user
        email: Option<String>,
        /// Shadowsocks server address, supports IPv4, IPv6 and domain name. Required.
        address: Address,
        /// Shadowsocks server port. Required.
        port: Port,
        /// Required. See the list of [encryption
        /// methods](../shadowsocks/enum.EncryptionMethod.html) for optional values
        method: EncryptionMethod,
        /// Required. Any string. The Shadowsocks protocol does not limit the password length,
        /// but short passwords are more likely to be cracked. It is recommended to use 16
        /// characters or longer passwords.
        password: String,
        /// user level
        level: UserLevel,
    }

    /// ```json
    /// {
    ///     "servers": [
    ///         {
    ///             "email": "love@v2ray.com",
    ///             "address": "127.0.0.1",
    ///             "port": 1234,
    ///             "method": "method",
    ///             "password": "password",
    ///             "level": 0
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// An array, each of which is a [ServerObject](../shadowsocks/struct.Server.html).
        servers: Vec<Server>,
    }

    pub enum EncryptionMethod {
        /// `"aes-128-gcm"`
        Aes128Gcm,
        /// `"aes-256-gcm"`
        Aes256Gcm,
        /// `"chacha20-poly1305"|"chacha20-ietf-poly1305"`
        Chacha20Poly1305,
        /// `"none"|"plain"`
        None,
    }

    pub struct InboundConfiguration {
        /// Email address, optional, used to identify the user
        email: Option<String>,
        /// Required. Possible values see [encryption
        /// list](../shadowsocks/enum.EncryptionMethod.html)
        method: EncryptionMethod,
        /// Required. Any string. The Shadowsocks protocol does not limit the password length,
        /// but short passwords are more likely to be cracked. It is recommended to use 16
        /// characters or longer passwords.
        password: String,
        /// user level
        level: UserLevel,
    }
}

pub mod trojan {
    use super::{Address, Port, UserLevel};

    /// V4.31.0+, V2Ray's Trojan has complete VLESS fallbacks support, and the configuration
    /// method is exactly the same. Follow-up VLESS fallbacks will be
    /// followed up synchronously.

    /// The conditions for triggering the fallback are basically the same: the first
    /// packet length <58 or the 57th byte is not'\r' (because Trojan does not have a
    /// protocol version) or the identity authentication fails.
    pub type Fallback = super::vless::Fallback;

    /// ```json
    /// {
    ///     "password": "password",
    ///     "email": "love@v2fly.org",
    ///     "level": 0,
    /// }
    /// ```
    pub struct Client {
        /// Required, any string.
        password: String,
        /// Email address, optional, used to identify the user
        email: Option<String>,
        /// User level, the default value is 0. See [local
        /// policy](../../policy/struct.UserLevel.html).
        level: UserLevel,
    }

    /// ```json
    /// {
    ///     "clients":[
    ///         {
    ///             "password": "password",
    ///             "email": "love@v2fly.org",
    ///             "level": 0,
    ///         }
    ///     ],
    ///     "fallbacks": [
    ///         {
    ///             "dest": 80
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// An array, each of which is a [ClientObject](../trojan/struct.Client.html).
        clients: Vec<Client>,
        /// An array containing a series of powerful fallback shunt configurations (optional).
        fallbacks: Vec<Fallback>,
    }

    /// ```json
    /// {
    ///     "address": "127.0.0.1",
    ///     "port": 1234,
    ///     "password": "password",
    ///     "email": "love@v2fly.org",
    ///     "level": 0
    /// }
    /// ```
    pub struct Server {
        /// Server address, supports IPv4, IPv6 and domain name. Required.
        address: Address,
        /// Server port, required.
        port: Port,
        /// Required, any string.
        password: String,
        /// Email address, optional, used to identify the user
        email: Option<String>,
        /// user level
        level: UserLevel,
    }

    /// ```json
    /// {
    ///     "servers": [
    ///         {
    ///             "address": "127.0.0.1",
    ///             "port": 1234,
    ///             "password": "password",
    ///             "email": "love@v2fly.org",
    ///             "level": 0
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct OutboundConfiguration {
        /// An array, each of which is a [ServerObject](../trojan/struct.Server.html).
        servers: Vec<Server>,
    }
}

pub mod mtproto {
    use super::UserLevel;
    /// ```json
    /// {
    ///     "email": "love@v2ray.com",
    ///     "level": 0,
    ///     "secret": "b0cbcef5a486d9636472ac27f8e11a9d"
    /// }
    /// ```
    pub struct User {
        /// User mailbox, used for auxiliary functions such as traffic statistics
        email: String,
        /// user level.
        level: UserLevel,
        /// User key. Must be 32 characters, can only contain `0-9a-f` characters.
        secret: String,
    }

    /// ```json
    /// {
    ///     "users": [
    ///         {
    ///             "email": "love@v2ray.com",
    ///             "level": 0,
    ///             "secret": "b0cbcef5a486d9636472ac27f8e11a9d"
    ///         }
    ///     ]
    /// }
    /// ```
    pub struct InboundConfiguration {
        /// An array, where each element represents a user. Currently only the first user will
        /// take effect.
        users: Vec<User>,
    }

    /// ```json
    /// {
    /// }
    /// ```
    pub struct OutboundConfiguration {}
}
