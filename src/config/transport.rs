use std::collections::HashMap;

/// No header obfuscation.
/// ```json
/// {
///     "type": "none"
/// }
/// ```
pub struct NoneHeader {
    /// `"none"`
    ///
    /// Disable header obfuscation.
    r#type: String,
}

/// ```json
/// {
///     "version": "1.1",
///     "method": "GET",
///     "path": ["/"],
///     "headers": {
///         "Host": ["www.baidu.com", "www.bing.com"],
///         "User-Agent": [
///             "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
///             "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"
///         ],
///         "Accept-Encoding": ["gzip, deflate"],
///         "Connection": ["keep-alive"],
///         "Pragma": "no-cache"
///     }
/// }
/// ```
pub struct HttpRequest {
    /// HTTP version. Default value is `"1.1"`.
    version: String,
    /// HTTP method. Default value is `"GET"`
    method: String,
    /// HTTP path. An array is string. The path will be chosen randomly for every connection.
    path: Vec<String>,
    /// HTTP header. The key of each entry is the key of HTTP header. The value of each
    /// entry is a list of strings. The actual HTTP header value will be chosen
    /// randomly from the list for each connection. Default value is the values
    /// in the example above.
    ///
    /// In a connection, all keys in the specified map will be set to the HTTP header.
    headers: HashMap<String, Vec<String>>,
}

/// ```json
/// {
///     "version": "1.1",
///     "status": "200",
///     "reason": "OK",
///     "headers": {
///         "Content-Type": ["application/octet-stream", "video/mpeg"],
///         "Transfer-Encoding": ["chunked"],
///         "Connection": ["keep-alive"],
///         "Pragma": "no-cache"
///     }
/// }
/// ```
pub struct HttpResponse {
    /// HTTP version. Default value is `"1.1"`.
    version: String,
    /// HTTP status. Default value is `"200"`
    status: String,
    /// HTTP status message. Default value is `"OK"`.
    reason: String,
    /// HTTP header. The key of each entry is the key of HTTP header. The value of each
    /// entry is a list of strings. The actual HTTP header value will be chosen
    /// randomly from the list for each connection. Default value is the values
    /// in the example above.
    ///
    /// In a connection, all keys in the specified map will be set to the HTTP header.
    headers: HashMap<String, Vec<String>>,
}

/// HTTP header obfuscation. The configuration must be the same between
/// connecting inbound and outbound.
///
/// ```json
/// {
///     "type": "http",
///     "request": {},
///     "response": {}
/// }
/// ```
pub struct HttpHeader {
    /// `"http"`
    /// Enable HTTP header obfuscation.
    r#type: String,
    /// HTTP request template.
    request: HttpRequest,
    /// HTTP response template.
    response: HttpResponse,
}

/// `TcpObject` Corresponding to the transmission configuration `tcpSettings` items.
/// ```json
/// {
///     "acceptProxyProtocol": false,
///     "header": {
///         "type": "none"
///     }
/// }
/// ```
pub struct Tcp {
    /// v4.27.1+, only used for inbound, whether to receive PROXY protocol, the default
    /// value `false`. Fill `true`, the lowest level after the TCP connection is
    /// established, the requesting party must send PROXY protocol v1 or v2, or the
    /// connection will be closed.
    ///
    /// [PROXY protocol](https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt) It is
    /// dedicated to the true source IP and port of the request.
    /// If you don’t know it, please ignore this item . Common anti-generation software
    /// (such as HAProxy, Nginx) can be configured to send it, and VLESS fallbacks
    /// xver can also send it.
    accept_proxy_protocol: bool,
    /// Header obfuscation. Default value is `NoneHeaderObject`. Valid header types are "http"
    /// and "none"
    header: HeaderType,
}

/// ```json
/// {
///     "mtu": 1350,
///     "tti": 20,
///     "uplinkCapacity": 5,
///     "downlinkCapacity": 20,
///     "congestion": false,
///     "readBufferSize": 1,
///     "writeBufferSize": 1,
///     "header": {
///         "type": "none"
///     }
/// }
/// ```
pub struct Kcp {
    /// Maximum transmission unit. It indicates the maxium number bytes that an UDP
    /// packet can carry. Recommended value is between `576` and `1460`.
    /// Default value `1350`.
    mtu: u16,
    /// Transmission time interval, in milli-second. mKCP sends data in this
    /// interval. Recommended value is between `10` and `100`. Default value `50`.
    tti: u8,
    /// Uplink bandwidth, in MB/s. The maximum bandwidth for the V2Ray instance
    /// to upload data to a remote one. Default value is `5`. Please note it is
    /// byte (in MB/s), not bit. One may use value `0` for a small bandwidth.
    uplink_capacity: u8,
    /// Downlink bandwidth, in MB/s. The maximum bandwidth for the V2Ray instance
    /// to download data. Default value is `20`. Please note it is byte (in MB/s),
    /// not bit. One may use value `0` for a small bandwidth.
    downlink_capacity: u8,
    /// Whether or not to enable congestion control. Default value is `false`.
    /// When congestion control is enabled, V2Ray will detect network quality.
    /// It will send less packets when packet loss is severe, or more data
    /// when network is not fully filled.
    congestion: bool,
    /// Read buffer size for a single connection, in MB. Default value is `2`.
    read_buffer_size: u8,
    /// Write buffer size for a single connection, in MB. Default value is `2`.
    write_buffer_size: u8,
    /// Configuration for packet header obfuscation.
    header: Header,
    /// v4.24.2+, optional obfuscation password, use AES-128-GCM algorithm to obfuscate traffic
    /// data, client and server need to be consistent, after enabling it, it will output
    /// "NewAEADAESGCMBasedOnSeed Used" to the command line. This obfuscation mechanism cannot
    /// be used to ensure the security of communication content, but it may be able to fight
    /// against partial blocking. After enabling this setting in the developer test
    /// environment, there is no port blocking of the original unobfuscated version.
    seed: Option<String>,
}

/// `WebSocketObject` Corresponding to the transmission configuration `wsSettings` items.
///
/// ```json
/// {
///     "acceptProxyProtocol": false,
///     "path": "/",
///     "headers": {
///         "Host": "v2ray.com"
///     }
/// }
/// ```
pub struct WebSocket {
    /// v4.27.1+, only used for inbound, whether to receive PROXY protocol,
    /// the default value `false`. Fill `true`, the lowest level after the TCP
    /// connection is established, the requesting party must send PROXY protocol
    /// v1 or v2, or the connection will be closed.
    ///
    /// [PROXY protocol](https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt) It is
    /// dedicated to the true source IP and port of the request. If you don’t know it,
    /// please ignore this item . Common anti-generation software (such as HAProxy, Nginx)
    /// can be configured to send it, and VLESS fallbacks xver can also send it.
    accept_proxy_protocol: bool,
    /// The HTTP protocol path used by WebSocket, the default value is `"/"`.
    path: String,
    /// Custom HTTP header, a key-value pair, each key represents the name of an HTTP header,
    /// and the corresponding value is a string. The default value is empty.
    headers: HashMap<String, String>,
}

/// `HttpObject` Corresponding to the transmission configuration `httpSettings` items.
///
/// ```json
/// {
///     "host": ["v2ray.com"],
///     "path": "/random/path"
/// }
/// ```
pub struct Http {
    /// A string array. Each element is a domain. Client picks up a domain at random for each
    /// request. Server checks whether the domain in incoming request is in the list.
    host: Vec<String>,
    /// HTTP path from `/` the beginning. The client and server must be consistent. Optional
    /// parameter, default value `"/"`.
    path: String,
}

/// Type of obfuscation
pub enum HeaderType {
    /// `"none"` : Default value. No obfuscation is used.
    None(Header),
    /// `"srtp"` : Obfuscated as SRTP traffic. It may be recognized as video calls such
    /// as Facetime.
    Srtp(Header),
    /// `"utp"` : Obfuscated as uTP traffic. It may be recognized as Bittorrent traffic.
    Utp(Header),
    /// `"wechat-video"` : Obfuscated to WeChat traffic.
    WechatVideo(Header),
    /// `"dtls"` : Obfuscated as DTLS 1.2 packets.
    Dtls(Header),
    /// `"wireguard"` : Obfuscated as WireGuard packets. (NOT true WireGuard protocol)
    Wireguard(Header),
    /// `"http"` : Enable HTTP header obfuscation.
    Http(HttpHeader),
}

/// ```json
/// {
///     "type": "none"
/// }
/// ```
pub struct Header {
    /// Type of obfuscation. Corresponding inbound and outbound proxy must have the same
    /// setting. Expected values are "none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
    r#type: String,
}

pub enum QuicSecurity {
    /// `"none"`
    None,
    /// `"aes-128-gcm"`
    Aes128Gcm,
    /// `"chacha20-poly1305"`
    Chacha20Poly1305,
}

/// `QuicObject` Corresponding to the transmission configuration `quicSettings` items. The
/// configurations on both ends of the connection must be exactly the same, otherwise the
/// connection fails. QUIC mandates to enable TLS. When TLS is not enabled in the transmission
/// configuration, V2Ray will issue a certificate for TLS communication by itself. When using
/// QUIC transmission, VMess encryption can be turned off.
///
/// ```json
/// {
///     "security": "none",
///     "key": "",
///     "header": {
///         "type": "none"
///     }
/// }
/// ```
pub struct Quic {
    /// Extra encryption over entire QUIC packet, include the frame head part. Default value is
    /// "none" for no encryption. After being encrypted, QUIC packets can't be sniff'ed.
    security: QuicSecurity,
    /// Key for the encryption above. Can be any string. Only effective when `security` is not
    /// `"none"`.
    key: String,
    /// Configuration for packet header obfuscation. Valid header types are "none", "srtp",
    /// "utp", "wechat-video", "dtls", "wireguard"
    header: HeaderType,
}

/// `DomainSocketObject` is used in `dsSettings` field in `TransportObject` and
/// `StreamSettingsObject`
///
/// ```json
/// {
///     "path": "/path/to/ds/file",
///     "abstract": false,
///     "padding": false
/// }
/// ```
pub struct DomainSocket {
    /// A valid file path. Before running V2Ray, this file must not exist.
    path: String,
    /// Whether it is an abstract domain socket, the default `false`.
    r#abstract: bool,
    /// v4.28.1+, whether abstract domain socket with padding, default `false`.
    padding: bool,
}

/// The purpose of the certificate
pub enum CertificateUsage {
    /// `"encipherment"` : The certificate is used for TLS authentication and encryption.
    Encipherment,
    /// `"verify"` : The certificate is used to verify the remote TLS certificate. When using this
    /// option, the current certificate must be a CA certificate.
    Verify,
    /// `"issue"` : The certificate is used to issue other certificates. When using this option,
    /// the current certificate must be a CA certificate.
    Issue,
}

/// ```json
/// {
///     "usage": "encipherment",
///     "certificateFile": "/path/to/certificate.crt",
///     "keyFile": "/path/to/key.key",
///     "certificate": [
///         "-----BEGIN CERTIFICATE-----",
///         "MIICwDCCAaigAwIBAgIRAO16JMdESAuHidFYJAR/7kAwDQYJKoZIhvcNAQELBQAw",
///         "ADAeFw0xODA0MTAxMzU1MTdaFw0xODA0MTAxNTU1MTdaMAAwggEiMA0GCSqGSIb3",
///         "d4q7MD/dkzRDsch7t2cIjM/PYeMuzh87admSyL6hdtK0Nm/Q",
///         "-----END CERTIFICATE-----"
///     ],
///     "key": [
///         "-----BEGIN RSA PRIVATE KEY-----",
///         "MIIEowIBAAKCAQEArNj19HxUgoznppnZvVGzr3C3LRfeDseAaUnyft5SR8GW75zh",
///         "GxvNAoGBAM4g2z8NTPMqX+8IBGkGgqmcYuRQxd3cs7LOSEjF9hPy1it2ZFe/yUKq",
///         "ePa2E8osffK5LBkFzhyQb0WrGC9ijM9E6rv10gyuNjlwXdFJcdqVamxwPUBtxRJR",
///         "cYTY2HRkJXDdtT0Bkc3josE6UUDvwMpO0CfAETQPto1tjNEDhQhT",
///         "-----END RSA PRIVATE KEY-----"
///     ]
/// }
/// ```
pub struct Certificate {
    /// The purpose of the certificate, the default value is `"encipherment"`.
    usage: CertificateUsage,
    /// The path of the certificate file, if generated using OpenSSL, the suffix is .crt.
    certificate_file: String,
    /// List of strings as content of the certificate. See the example above. Either
    /// `certificate` or `certificateFile` must not be empty.
    certificate: Vec<String>,
    /// File path to the private key. If generated by OpenSSL, the file usually ends with
    /// ".key". Key file with password is not supported.
    key_file: String,
    /// List of strings as content of the private key. See the example above. Either `key` or
    /// `keyFile` must not be empty.
    ///
    /// When `certificateFile` and `certificate` are both filled in. V2Ray uses
    /// `certificateFile`. Same for `keyFile` and `key`.
    key: Vec<String>,
}

/// ```json
/// {
///     "serverName": "v2ray.com",
///     "allowInsecure": false,
///     "alpn": ["http/1.1"],
///     "certificates": [],
///     "disableSystemRoot": false
/// }
/// ```
pub struct Tls {
    /// Server name (usually domain) used for TLS authentication. Typically this is used when
    /// corressponding inbound/outbound uses IP for communication.
    ///
    /// When domain name is specified from inbound proxy, or get sniffed from the connection,
    /// it will be automatically used for connection. It is not necessary to set `serverName`
    /// in such case.
    server_name: String,
    /// If `true`, V2Ray allowss insecure connection at TLS client, e.g., TLS server uses
    /// unverifiable certificates.
    allow_insecure: bool,
    /// An array of strings, to specifiy the ALPN value in TLS handshake. Default value is `["http/1.1"]`.
    alpn: Vec<String>,
    /// (V2Ray 4.18+) Whether or not to disable system root CAs for TLS handshake. Default
    /// value is `false`. If set to `true`, V2Ray will use only `certificates` for
    /// TLS handshake.
    disable_system_root: bool,
    /// List of TLS certificates. Each entry is one certificate.
    certificates: Vec<Certificate>,
}

/// Whether or not to enable transparent proxy on Linux
pub enum SockoptTproxy {
    /// `"redirect"`: Enable TProxy with Redirect mode. Supports TCP/IPv4 and UDP traffic.
    Redirect,
    /// `"tproxy"` : Enable TProxy with TProxy mode. Supports TCP and UDP traffic.
    Tproxy,
    /// `"off"` : Default value. Not enable TProxy at all.
    Off,
}

/// ```json
/// {
///     "mark": 0,
///     "tcpFastOpen": false,
///     "tproxy": "off"
/// }
/// ```
pub struct Sockopt {
    /// An integer. If non-zero, the value will be set to out-going connections via socket
    /// option SO_MARK. This mechanism only applies on Linux and requires CAP_NET_ADMIN
    /// permission,
    mark: i32,
    /// Whether or not to enable [TCP Fast Open](https://en.wikipedia.org/wiki/TCP_Fast_Open).
    /// When set to `true`, V2Ray enables TFO for current connection. When set to `false`,
    /// V2Ray disables TFO. If this entry doesn't exist, V2Ray uses default settings
    /// from operating system.
    ///
    /// - Only apply on the following operating systems:
    ///     - Windows 10 (1604) or later
    ///     - Mac OS 10.11 / iOS 9 or later
    ///     - Linux 3.16 or later: Enabled by system default.
    /// - Applicable for both inbound and outbound connections.
    tcp_fast_open: bool,
    /// Whether or not to enable transparent proxy on Linux
    tproxy: SockoptTproxy,
}

pub enum StreamSettingsNetwork {
    /// `"tcp"`
    Tcp,
    /// `"kcp"`
    Kcp,
    /// `"ws"`
    Ws,
    /// `"http"`
    Http,
    /// `"domainsocket"`
    DomainSocket,
    /// `"quic"`
    Quic,
}

pub enum StreamSettingsSecurity {
    /// `"none"`
    None,
    /// `"tls"`
    Tls,
}

/// Each inbound and outbound proxy may has its own transport settings, as specified in
/// streamSettings field in top level configuration.
///
/// ```json
/// {
///     "network": "tcp",
///     "security": "none",
///     "tlsSettings": {},
///     "tcpSettings": {},
///     "kcpSettings": {},
///     "wsSettings": {},
///     "httpSettings": {},
///     "dsSettings": {},
///     "quicSettings": {},
///     "sockopt": {
///         "mark": 0,
///         "tcpFastOpen": false,
///         "tproxy": "off"
///     }
/// }
/// ```
pub struct StreamSettings {
    /// Network type of the stream transport. Default value "tcp".
    network: StreamSettingsNetwork,
    /// Type of security. Choices are "none" (default) for no extra security, or "tls" for
    /// using TLS.
    security: StreamSettingsSecurity,
    /// TLS settings. TLS is provided by rust-lang. Support up to TLS 1.3. DTLS is not supported.
    tls_settings: Tls,
    /// TCP transport configuration for current proxy. Effective only when the proxy uses TCP
    /// transport. Configuration is the same as it is in global configuration.
    tcp_settings: Tcp,
    /// mKCP transport configuration for current proxy. Effective only when the proxy uses mKCP
    /// transport. Configuration is the same as it is in global configuration.
    kcp_settings: Kcp,
    /// WebSocket transport configuration for current proxy. Effective only when the proxy uses
    /// WebSocket transport. Configuration is the same as it is in global configuration.
    ws_settings: WebSocket,
    /// HTTP/2 transport configuration for current proxy. Effective only when the proxy uses
    /// HTTP/2 transport. Configuration is the same as it is in global configuration.
    http_settings: Http,
    /// (V2Ray 4.7+) QUIC transport configuration for current proxy. Effective only when the
    /// proxy uses QUIC transport. Configuration is the same as it is in global configuration.
    quic_settings: Quic,
    /// Domain socket transport configuration for current proxy. Effective only when the proxy
    /// uses domain socket transport. Configuration is the same as it is in global
    /// configuration.
    ds_settings: DomainSocket,
    /// Socket options for incoming and out-going connections.
    sockopt: Sockopt,
}

/// `TransportObject` is used as `transport` field in top level configuration.
///
/// ```json
/// {
///     "tcpSettings": {},
///     "kcpSettings": {},
///     "wsSettings": {},
///     "httpSettings": {},
///     "dsSettings": {},
///     "quicSettings": {}
/// }
/// ```
pub struct Transport {
    /// Settings for [TCP transport](../transport/struct.Tcp.html).
    tcp_settings: Tcp,
    /// Settings for [mKCP transport](../transport/struct.Kcp.html).
    kcp_settings: Kcp,
    /// Settings for [WebSocket transport](../transport/struct.WebSocket.html).
    ws_settings: WebSocket,
    /// Settings for [HTTP/2 transport](../transport/struct.Http.html).
    http_settings: Http,
    /// (V2Ray 4.7+) Settings for [QUIC transport](../transport/struct.Quic.html).
    quic_settings: Quic,
    /// Settings for [Domain Socket transport](../transport/struct.DomainSocket.html).
    ds_settings: DomainSocket,
}
