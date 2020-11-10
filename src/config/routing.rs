use super::{DomainName, NetworkType, Ports};
/// Domain name resolution strategy
pub enum DomainStrategy {
    /// `"AsIs"` : Only use the domain name for routing. Defaults.
    AsIs,
    /// `"IPIfNonMatch"` : When the domain name does not match any rules,
    /// the domain name is resolved into IP (A record or AAAA record) for matching again;
    ///
    /// - When a domain name has multiple A records, it will try to match all A records
    /// until one of them matches a certain rule;
    /// - The resolved IP only works during routing, and the original domain name is
    /// still used in the forwarded data packet;
    IPIfNonMatch,
    /// `"IPOnDemand"` : When encountering any IP-based rules during matching, the domain
    /// name will be immediately resolved to IP for matching;
    IPOnDemand,
}

pub enum RouteType {
    /// `"field"`
    Field,
}

pub enum Protocol {
    /// `"http"`
    Http,
    /// `"tls"`
    Tls,
    /// `"bittorrent"`
    Bittorrent,
}

/// ```json
/// {
///     "type": "field",
///     "domain": [
///         "baidu.com",
///         "qq.com",
///         "geosite:cn"
///     ],
///     "ip": [
///         "0.0.0.0/8",
///         "10.0.0.0/8",
///         "fc00::/7",
///         "fe80::/10",
///         "geoip:cn"
///     ],
///     "port": "53,443,1000-2000",
///     "sourcePort": "53,443,1000-2000",
///     "network": "tcp",
///     "source": [
///         "10.0.0.1"
///     ],
///     "user": [
///         "love@v2ray.com"
///     ],
///     "inboundTag": [
///         "tag-vmess"
///     ],
///     "protocol": [
///         "http",
///         "tls",
///         "bittorrent"
///     ],
///     "attrs": "attrs[':method'] == 'GET'",
///     "outboundTag": "direct",
///     "balancerTag": "balancer"
/// }
/// ```
pub struct Rule {
    /// Only `"field"` this option is currently supported .
    route_type: RouteType,
    /// An array, each item of the array is a match of a domain name
    domain: Vec<DomainName>,
    /// An array, each element in the array represents an IP range.
    /// When an element matches the target IP, this rule takes effect.
    /// There are several forms:
    ///
    /// - IP: Shaped `"127.0.0.1"`.
    /// - [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing): Shaped
    /// like `"10.0.0.0/8"`.
    /// - GeoIP: The form `"geoip:cn"` must start with `geoip:` (lowercase) followed
    /// by a two-character country code, which supports almost all countries that
    /// can access the Internet.
    ///     - Special value: `"geoip:private"` (V2Ray 3.5+), including all private
    ///     addresses, such as `127.0.0.1`.
    /// - Loaded from a file IP: the form `"ext:file:tag"` , must `ext:` begin
    /// with (lowercase), followed by the file name and label files are stored
    /// in the resource directory , the file format with the `geoip.dat` same
    /// tag must be present in the file.
    ip: Vec<String>,
    /// Port range.
    port: String,
    /// The source port
    source_port: Ports,
    /// Optional values are "tcp", "udp" or "tcp, udp". When the connection
    /// method is the specified method, this rule takes effect.
    network: NetworkType,
    /// An array, each element in the array is an IP or CIDR. This rule takes effect
    /// when an element matches the source IP.
    source: Vec<String>,
    /// An array, each element in the array is an email address. When an element
    /// matches the source user, this rule takes effect. Currently Shadowsocks
    /// and VMess support this rule.
    user: Vec<String>,
    /// An array, each element in the array is an identifier. When an element
    /// matches the identifier of the inbound protocol, this rule takes effect.
    inbound_tag: Vec<String>,
    /// An array, each element in the array represents a protocol. This rule
    /// takes effect when a certain protocol matches the current connection
    /// traffic. Inbound agent must open `sniffing` option.
    protocol: Vec<Protocol>,
    /// (V2Ray 4.18+) A script to detect the attribute value of traffic.
    /// When this script returns a true value, this rule takes effect.
    ///
    /// The scripting language is [Starlark](https://github.com/bazelbuild/starlark)
    /// Its syntax is a subset of Python. The script accepts a global variable attrs,
    /// which contains traffic-related attributes.
    ///
    /// Currently only http inbound proxy will set this attribute.
    ///
    /// Example:
    ///
    /// - Detect HTTP GET: `"attrs[':method'] == 'GET'"`
    /// - Check HTTP Path: `"attrs[':path'].startswith('/test')"`
    /// - Check Content Type: `"attrs['accept'].index('text/html') >= 0"`
    attrs: Vec<String>,
    /// A corresponding one [additional outbound connection
    /// configuration](../protocol/index.html)
    /// identified.
    outbound_tag: String,
    /// Corresponds to the identity of a load balancer. `balancerTag` And `outboundTag`
    /// to be a second election. When specified at the same time, it `outboundTag`
    /// takes effect.
    balancer_tag: String,
}

/// Load balancer configuration. When a load balancer takes effect, it will select
/// the most appropriate outbound protocol from the specified outbound protocol
/// according to the configuration, and then forward the traffic.
///
/// ```json
/// {
///     "tag": "balancer",
///     "selector": []
/// }
/// ```
pub struct Balancer {
    /// This identification of the load balancer, for matching `RuleObject` the `balancerTag`.
    tag: String,
    /// An array of strings, each of which will be used to match the prefix of the outbound
    /// protocol identifier. In the following the outbound protocol identification:
    /// `[ "a", "ab", "c", "ba" ]`, `"selector": ["a"]` will be matched `[ "a", "ab" ]`.
    ///
    /// If multiple outbound protocols are matched, the load balancer will currently
    /// randomly select one of them as the final outbound protocol.
    selector: Vec<String>,
}

/// `RoutingObject` The corresponding configuration file for `routing` entries.
///
/// ```json
/// {
///     "domainStrategy": "AsIs",
///     "rules": [],
///     "balancers": []
/// }
/// ```
pub struct Routing {
    /// Domain name resolution strategy, use different strategies according to
    /// different settings.
    domain_strategy: DomainStrategy,
    /// Corresponding to an array, each element in the array is a rule. For each
    /// connection, the routing will be judged according to these rules in turn.
    /// When a rule takes effect, the connection will be forwarded to its
    /// designated `outboundTag` (or `balancerTag` , V2Ray 4.4+). When no rules are matched,
    /// the traffic is sent by the main outbound protocol by default.
    rules: Vec<Rule>,
    /// (V2Ray 4.4+) An array, each element in the array is the configuration of
    /// a load balancer. When a rule points to a load balancer, V2Ray will select an
    /// outbound protocol through the load balancer, and then it will forward the traffic.
    balancers: Vec<Balancer>,
}
