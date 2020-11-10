use super::transport::StreamSettings;
use super::{Ports, Time};

pub enum SniffingProtocol {
    /// `"http"`
    Http,
    /// `"tls"`
    Tls,
}

/// ```json
/// {
///     "enabled": false,
///     "destOverride": ["http", "tls"]
/// }
/// ```
pub struct Sniffing {
    /// Whether or not to enable content sniffing.
    enabled: bool,
    /// An array of content type. If the content type of incoming traffic is specified in the
    /// list, the destination of the connection will be overwritten by sniffed value.
    dest_override: Vec<SniffingProtocol>,
}

pub enum AllocateStrategy {
    /// `"always"` : all port in the `port` field will be allocated for listening.
    Always,
    /// `"random"` : V2Ray will listen on number of `concurrency` ports, and the list of ports
    /// are refereshed every `refresh` minutes.
    Random,
}

/// ```json
/// {
///     "strategy": "always",
///     "refresh": 5,
///     "concurrency": 3
/// }
/// ```
pub struct Allocate {
    /// Strategy of port allocation.
    strategy: AllocateStrategy,
    /// Number of minutes to refresh the ports of listening. Min value is `2`. This setting is
    /// only effective when `strategy` is set to `"random"`.
    refresh: Time,
    /// Number of ports to listen. Min value is `1`. Max value is one third of entire port range.
    concurrency: u8,
}

// FIXME: Put Inbound configurations
pub enum InboundConfiguration {
    Blackhole,
    Dns,
    DockodemoDoor(super::protocol::dokodemo_door::InboundConfiguration),
    Freedom,
    Http(super::protocol::http::InboundConfiguration),
    Socks(super::protocol::socks::InboundConfiguration),
    Vless(super::protocol::vless::InboundConfiguration),
    Vmess(super::protocol::vmess::InboundConfiguration),
    Shadowsocks(super::protocol::shadowsocks::InboundConfiguration),
    Trojan(super::protocol::trojan::InboundConfiguration),
    MtprotoV1(super::protocol::mtproto::InboundConfiguration),
}

/// `InboundObject` The configuration file corresponds to `inbounds` a sub-element of the item.
///
/// ```json
/// {
///     "listen": "127.0.0.1",
///     "port": 1080,
///     "protocol": "Protocol Name",
///     "settings": {},
///     "streamSettings": {},
///     "tag": "标识",
///     "sniffing": {
///         "enabled": true,
///         "destOverride": [
///             "http",
///             "tls"
///         ]
///     },
///     "allocate": {
///         "strategy": "always",
///         "refresh": 5,
///         "concurrency": 3
///     }
/// }
/// ```
pub struct Inbound {
    listen: String,
    /// Port that the proxy is listening on. Acceptable formats are:
    ///
    /// - Integer: actual port number.
    /// - Environment variable: Beginning with `"env:"`, an env variable specifies the port in
    /// string format, such as `"env:PORT"`. V2Ray will decode the variable as string.
    /// - String: A numberic string value, such as `"1234"`, or a range of ports,
    /// such as `"5-10"` for 6 ports in total.
    ///
    /// The actual ports to open also depend on allocate setting. See below.
    port: Ports,
    /// Name of the inbound protocol. See each individual for available values.
    protocol: String,
    /// Protocol-specific settings. See `InboundConfigurationObject` defined in each protocol.
    settings: InboundConfiguration,
    /// The tag of the inbound proxy. It can be used for routing decisions. If not empty,
    /// it must be unique among all inbound proxies.
    tag: String,
    /// [Low-level transmission configuration](../transport/struct.StreamSettings.html)
    stream_settings: StreamSettings,
    /// Configuration for content sniffing.
    sniffing: Sniffing,
    /// Configuration for port allocation.
    allocate: Allocate,
}
