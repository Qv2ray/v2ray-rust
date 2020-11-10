use super::{Address, DomainName, Port};
use serde::Deserialize;
use std::collections::HashMap;

/// ```json
/// {
///     "address": "1.2.3.4",
///     "port": 5353,
///     "domains": [
///         "domain:v2ray.com"
///     ],
///     "expectIPs": [
///         "geoip:cn"
///     ]
/// }
/// ```
pub struct Server {
    /// DNS server address, eg `"8.8.8.8"`. For ordinary DNS IP addresses only supports
    /// UDP protocol DNS server, if the address is `"https://"` or `"https+local://"`
    /// URL form the beginning, use the DOH mode, with regular string pattern DOH
    /// configuration.
    address: Address,
    /// DNS server port, eg `53`. This item defaults to default `53`. When using DOH mode,
    /// this item is invalid, non-standard port should be specified in the URL.
    port: Port,
    /// A list of domain names. The domain names contained in this list will be queried
    /// by this server first. Domain name format and [routing
    /// configuration](../routing/index.html)
    /// the same as.
    domains: Vec<DomainName>,
    /// (V2Ray 4.22.0+) a list of IP ranges, format and [routing
    /// configuration](../routing/index.html)
    /// same as.
    ///
    /// When this option is configured, V2Ray DNS will verify the returned IP and only
    /// return the addresses in the expectedIPs list.
    ///
    /// If this item is not configured, the IP address will be returned as is.
    expect_ips: Vec<String>,
}

pub enum ServerType {
    ServerAddress(String),
    ServerConfig(Server),
}

/// `DnsObject` The corresponding configuration file `dns` entries.
///
/// ```json
/// {
///     "hosts": {
///         "baidu.com": "127.0.0.1"
///     },
///     "servers": [
///         {
///             "address": "1.2.3.4",
///             "port": 5353,
///             "domains": [
///                 "domain:v2ray.com"
///             ],
///             "expectIPs": [
///                 "geoip:cn"
///             ]
///         },
///         "8.8.8.8",
///         "8.8.4.4",
///         "localhost"
///     ],
///     "clientIp": "1.2.3.4",
///     "tag": "dns_inbound"
/// }
/// ```
pub struct Dns {
    /// Static IP list, its value is a series of `"domain name": "address"`.
    /// The address can be an IP or domain name. When resolving a domain name,
    /// if the domain name matches an item in this list, when the address
    /// of the item is an IP, the resolution result will be the IP of the
    /// item, and the following servers will not be used for resolution;
    /// when the address of the item is When it is a domain name, this
    /// domain name will be used for IP resolution instead of the original
    /// domain name.
    hosts: HashMap<DomainName, Address>,
    /// A DNS server list supports two types: DNS address (string form) and
    /// [ServerObject](struct.Server.html) .
    ///
    /// When its value is a DNS IP address, for example `"8.8.8.8"`, V2Ray
    /// will use port 53 of this address for DNS query.
    ///
    /// When the value `"localhost"` when using the machine default DNS configuration.
    ///
    /// When the value is `"https://host:port/dns-query"` in the form of, such as
    /// `"https://dns.google/dns-query"`, V2Ray use `DNS over HTTPS`
    /// (RFC8484, referred DOH) query. Some service providers have certificates of
    /// IP aliases and can write IP directly, for example `https://1.1.1.1/dns-query`.
    /// Non-standard ports and paths can also be used, such as
    /// `"https://a.b.c.d:8443/my-dns-query"` (4.22.0+)
    ///
    /// When the value is `"https+local://host:port/dns-query"` in the form of, such
    /// as `"https+local://dns.google/dns-query"`, V2Ray uses the `DOH Local mode` query,
    /// i.e., the request will not pass DOH Routing / Outbound other components,
    /// direct foreign request, to reduce time-consuming. Generally suitable for
    /// use on the server side. Non-standard ports and paths can also be used. (4.22.0+)
    ///
    /// > TIP
    /// > When `localhost` the time, a DNS request is not V2Ray the machine control,
    /// the need for additional configuration can make the DNS requests forwarded by V2Ray.
    ///
    /// Different rules initialized via DNS client will start in V2Ray log `info` level
    /// reflected, for example `local DOH` , `remote DOH` and `udp` other models. (4.22.0+)
    servers: Vec<ServerType>,
    /// The IP address of the current system. Used to notify the server of the location
    /// of the client during DNS query. It cannot be a private address.
    client_ip: String,
    /// (V2Ray 4.13+) DNS query traffic thus emitted, in addition to `localhost` and `DOHL_`
    /// outside the pattern, are identified with this, the route can be used `inboundTag`
    /// for matching.
    tag: String,
}
