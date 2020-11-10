use super::protocol::List as ProtocolList;
use super::transport::StreamSettings;
use super::Address;

pub enum OutboundConfiguration {
    Blackhole(super::protocol::blackhole::OutboundConfiguration),
    Dns(super::protocol::dns::OutboundConfiguration),
    DockodemoDoor,
    Freedom(super::protocol::freedom::OutboundConfiguration),
    Http(super::protocol::http::OutboundConfiguration),
    Socks(super::protocol::socks::OutboundConfiguration),
    Vless(super::protocol::vless::OutboundConfiguration),
    Vmess(super::protocol::vmess::OutboundConfiguration),
    Shadowsocks(super::protocol::shadowsocks::OutboundConfiguration),
    Trojan(super::protocol::trojan::OutboundConfiguration),
    MtprotoV1(super::protocol::mtproto::OutboundConfiguration),
}

/// ```json
/// {
///     "tag": "another-outbound-tag"
/// }
/// ```
pub struct ProxySettings {
    /// When `tag` is set to the tag of another outbound, the out-going traffic of current
    /// outbound will be delegated to the specified one,
    tag: String,
}

/// Multiplexing, or Mux, is to use one physical TCP connections for multiple virtual
/// TCP connections.
///
/// Mux is designed to reduce TCP handshake latency. It is NOT for high throughput.
/// When used for downloading large files or speed measurement, Mux is usually slower
/// than a normal TCP connection.
///
/// ```json
/// {
///     "enabled": false,
///     "concurrency": 8
/// }
/// ```
pub struct Mux {
    /// Whether or not to enable Mux on an outbound.
    enabled: bool,
    /// Max number of multiplexed connections that one physical connection can handle at a
    /// time. Max value `1024`, min value `1`, default `8`.
    concurrency: i16,
}

/// An `OutboundObject` defines an outbound proxy for handling out-going connections. Available
/// protocols are listed [here](../protocol/enum.List.html).
///
/// ```json
/// {
///     "sendThrough": "0.0.0.0",
///     "protocol": "protocol_name",
///     "settings": {},
///     "tag": "this_outbound_tag_name",
///     "streamSettings": {},
///     "proxySettings": {
///         "tag": "another_outbound_tag_name"
///     },
///     "mux": {}
/// }
/// ```
pub struct Outbound {
    /// An IP address for sending traffic out. The default value, `"0.0.0.0"` is for randomly
    /// choosing an IP available on the host. Otherwise the value has to be an IP address from
    /// existing network interfaces.
    send_through: Address,
    /// The protocol name of this outbound. See [Protocols](../protocol/enum.List.html)
    /// for all available values.
    protocol: ProtocolList,
    /// Protocol-specific settings. See `OutboundConfigurationObject` in each individual protocols.
    settings: OutboundConfiguration,
    /// The tag of this outbound. If not empty, it must be unique among all outbounds.
    tag: String,
    /// Low-level transport settings. See [Protocol Transport
    /// Options](../transport/struct.StreamSettings.html).
    stream_settings: StreamSettings,
    /// Configuration for delegating traffic from this outbound to another. When this is set,
    /// `streamSettings` of this outbound will has no effect.
    proxy_settings: ProxySettings,
    /// See [Mux](../transport/struct.Mux.html) configuration for detail.
    mux: Mux,
}
