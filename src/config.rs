pub type Time = u32;
pub type Address = String;
pub type Port = u16;
/// Ports formats as follows:
/// - `"a-b"` : Both `a` and `b` are positive integers and less than 65536. When the
/// targeting port is in [`a`, `b`), this rule takes effect.
/// - `a` : `a` is a positive integer, and less than 65536. When the targeting port is `a`,
/// this rule takes effect.
/// - Mix of the two above, separated by `","`. Such as `"53,443,1000-2000"`.
pub type Ports = Vec<Port>;
pub type UserLevel = u8;
pub struct AddressPort(String, Port);

/// The domain name
pub enum DomainName {
    /// Pure string: When this domain name completely matches the target
    /// domain name, the rule takes effect. For example, "v2ray.com" matches
    /// "v2ray.com" but not "www.v2ray.com".
    Pure(String),
    /// Regular expression: from the `"regexp:"` beginning, and the remaining
    /// part is a regular expression. When this regular expression matches the
    /// target domain name, the rule takes effect. For example,
    /// "regexp:\\.goo.*\\.com$" matches "www.google.com", "fonts.googleapis.com",
    /// but not "google.com".
    Regexp(String),
    /// Subdomain (recommended): from the `"domain:"` start, the remainder of
    /// a domain name. This rule takes effect when the domain name is the target
    /// domain name or its subdomain name. For example, "domain:v2ray.com"
    /// matches "www.v2ray.com", "v2ray.com", but not "xv2ray.com".
    Subdomain(String),
    /// Substring: from the `"keyword:"` beginning, the remainder is a string.
    /// When this string matches any part of the target domain name, the rule
    /// takes effect. For example, "keyword:sina.com" can match "sina.com",
    /// "sina.com.cn" and "www.sina.com" but not "sina.cn".
    Substring(String),
    /// Predefined list of domain names: from the `"geosite:"` beginning, with
    /// the remainder being a name, such as `geosite:google` or `geosite:cn` .
    /// The domain name and reference list
    /// [of predefined list of domain names](https://www.v2fly.org/config/routing.html#预定义域名列表) .
    Predefined(String),
    /// Loaded from a file domain: the form `"ext:file:tag"`, must begin with `ext:`(lowercase),
    /// followed by the file name and label files are stored in the resource directory ,
    /// the file format is `geosite.dat` the same, the label must exist in the file.
    File(String),
}

pub enum NetworkType {
    /// `"tcp"`
    Tcp,
    /// `"udp"`
    Udp,
    /// `"tcp,udp"`
    TcpAndUdp,
}

/// The configuration file format of V2Ray is as follows, the client and server
/// share the same format, but the actual configuration is different.
///
/// If you are new to V2Ray, you should start with understanding Inbounds and
/// Outbounds, and start the program by filling in only the necessary options.
/// Next, learn about other components step by step, you will find that V2Ray
/// is not difficult to master.
///
/// ```json
/// {
///     "log": {},
///     "api": {},
///     "dns": {},
///     "routing": {},
///     "policy": {},
///     "inbounds": [],
///     "outbounds": [],
///     "transport": {},
///     "stats": {},
///     "reverse": {}
/// }
/// ```
pub struct Config {
    /// Log configuration indicates how V2Ray outputs logs.
    log: log::Log,
    /// remote control.
    api: api::Api,
    /// The built-in DNS server, if this item does not exist, the DNS settings
    /// of this machine will be used by default.
    dns: dns::Dns,
    /// Routing function.
    routing: routing::Routing,
    /// Local policies can be configured for some permissions.
    policy: policy::Policy,
    /// An array, each element is an inbound connection configuration.
    inbounds: Vec<inbound::Inbound>,
    /// An array, each element is an outbound connection configuration.
    /// The first element in the list is the primary outbound protocol.
    /// When the route matching does not exist or the matching is not
    /// successful, the traffic is sent by the main outbound protocol.
    outbounds: Vec<outbound::Outbound>,
    /// Used to configure how V2Ray establishes and uses network connections
    /// with other servers.
    transport: transport::Transport,
    /// Statistics.
    stats: stats::Stats,
    /// Reverse proxy.
    reverse: reverse::Reverse,
}

pub mod log {
    /// The level of the log.
    pub enum LogLevel {
        /// `"debug"` : Information that only developers can understand.
        /// It contains all the `"info"` content.
        Debug,
        /// `"info"` : The state of V2Ray at runtime, does not affect
        /// normal use. It contains all the `"warning"` content.
        Info,
        /// `"warning"` : V2Ray has encountered some problems, usually
        /// external problems, which do not affect the normal operation
        /// of V2Ray, but may affect the user experience. It contains
        /// all the `"error"` content.
        Warning,
        /// `"error"` : V2Ray has encountered a problem that cannot run
        /// normally and needs to be resolved immediately.
        Error,
        /// `"none"` : Do not record anything.
        None,
    }

    /// `LogObject` The corresponding configuration file `log` entries.
    ///
    /// ```json
    /// {
    ///     "access": "文件地址",",
    ///     "error": "文件地址",",
    ///     "loglevel": "warning",
    /// }
    /// ```
    pub struct Log {
        /// The file address of the access log. Its value is a legal file
        /// address, such as `"/var/log/v2ray/access.log"` (Linux) or
        /// `"C:\\Temp\\v2ray\\_access.log"` (Windows). When this item is
        /// not specified or is empty, it means that the log is output to
        /// stdout. V2Ray 4.20 added a special value `none`, that is, close
        /// the access log.
        access: String,
        /// The file address of the error log. Its value is a legal file
        /// address, such as `"/var/log/v2ray/error.log"` (Linux) or
        /// `"C:\\Temp\\v2ray\\_error.log"` (Windows). When this item
        /// is not specified or is empty, it means that the log is output
        /// to stdout. V2Ray 4.20 added a special value none, that is, close
        /// the error log ( `loglevel: "none"` equal to).
        error: String,
        /// The level of the log. The default value is `"warning"`.
        log_level: LogLevel,
    }
}

pub mod api {
    pub enum Service {
        /// `"HandlerService"`
        ///
        /// Some of the APIs that modify the inbound and outbound proxy,
        /// the available functions are as follows:
        ///
        /// - Add a new inbound agent;
        /// - Add a new outbound agent;
        /// - Delete an existing inbound proxy;
        /// - Delete an existing outbound proxy;
        /// - Add a user to an inbound proxy (only support VMess, VLESS, Trojan);
        /// - Delete a user in an inbound proxy (only support VMess, VLESS, Trojan);
        HandlerService,
        /// `"LoggerService"`
        ///
        /// Support the restart of the built-in Logger, and can cooperate with
        /// logrotate to perform some operations on the log file.
        LoggerService,
        /// `"StatsService"`
        ///
        /// Built-in statistical services, as detailed [statistical
        /// information](../stats/index.html).
        StatsService,
    }

    /// `ApiObject` is used as `api` field in top level configuration.
    /// ```json
    /// {
    ///     "tag": "api",
    ///     "services": [
    ///         "HandlerService",
    ///         "LoggerService",
    ///         "StatsService"
    ///     ]
    /// }
    /// ```
    pub struct Api {
        /// Outbound proxy ID.
        tag: String,
        /// List of enabled [API](../api/index.html)s . See the [API list](../api/enum.Service.html) for
        /// optional values.
        services: Vec<Service>,
    }
}

pub mod dns {
    use super::{Address, DomainName, Port};
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
        domains: Vec<String>,
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
}

pub mod routing {
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
}

pub mod policy {
    use super::Time;
    use std::collections::HashMap;

    /// ```json
    /// {
    ///     "handshake": 4,
    ///     "connIdle": 300,
    ///     "uplinkOnly": 2,
    ///     "downlinkOnly": 5,
    ///     "statsUserUplink": false,
    ///     "statsUserDownlink": false,
    ///     "bufferSize": 10240
    /// }
    /// ```
    pub struct LevelPolicy {
        /// Handshake time limit when the connection is established. The unit is seconds.
        /// The default value is `4`. When the inbound proxy processes a new connection,
        /// during the handshake phase (for example, VMess reads the header data and
        /// determines the target server address), if the time used exceeds this time,
        /// the connection is terminated.
        handshake: Time,
        /// Timeout for idle connections, in seconds. Default value `300`. If there is
        /// no data passed through the connection in `connIdle` time,
        /// V2Ray aborts the conneciton.
        conn_idle: Time,
        /// Time for keeping connections open after the uplink of the connection is closed,
        /// in seconds. Default value `2`. After remote (server) closes the downlink of the
        /// connection, V2Ray aborts the connection after `uplinkOnly` times.
        uplink_only: Time,
        /// Time for keeping connections open after the downlink of the connection is closed,
        /// in seconds. Default value `5`. After client (browser) closes the uplink of the
        /// connection, V2Ray aborts the connection after `downlinkOnly` time.
        downlink_only: Time,
        /// When set to `true`, V2Ray enables stat counter to uplink traffic for all
        /// users in this level.
        stats_user_uplink: bool,
        /// When set to `true`, V2Ray enables stat counter to downlink traffic for all
        /// users in this level.
        stats_user_downlink: bool,
        /// Size of internal buffer per connection, in kilo-bytes. Default value is `10240`.
        /// When it is set to `0`, the internal buffer is disabled.
        ///
        /// Default value (V2Ray 4.4+):
        ///
        /// - `0` on ARM, MIPS and MIPSLE.
        /// - `4` on ARM64, MIPS64 and MIPS64LE.
        /// - `512` on other platforms.
        ///
        /// Default value (V2Ray 4.3-):
        ///
        /// - `16` on ARM, ARM64, MIPS, MIPS64, MIPSLE and MIPS64LE.
        /// - `2048` on other platforms.
        buffer_size: u16,
    }

    /// ```json
    /// {
    ///     "statsInboundUplink": false,
    ///     "statsInboundDownlink": false
    /// }
    /// ```
    pub struct SystemPolicy {
        /// When the value is `true`, the opening up of all inbound traffic statistics agents.
        stats_inbound_uplink: bool,
        /// When the value is `true`, the opening of all inbound proxy downlink traffic statistics.
        stats_inbound_downlink: bool,
        /// (V2Ray 4.26.0+) When the value is `true`, the open upstream traffic statistics for
        /// all outbound proxy.
        stats_outbound_uplink: bool,
        /// (V2Ray 4.26.0+) When the value is `true`, the open downstream traffic statistics
        /// for all outbound proxy.
        stats_outbound_downlink: bool,
    }

    /// `PolicyObject` The corresponding configuration file `policy` entries.
    ///
    /// ```json
    /// {
    ///     "levels": {
    ///         "0": {
    ///             "handshake": 4,
    ///             "connIdle": 300,
    ///             "uplinkOnly": 2,
    ///             "downlinkOnly": 5,
    ///             "statsUserUplink": false,
    ///             "statsUserDownlink": false,
    ///             "bufferSize": 10240
    ///         }
    ///     },
    ///     "system": {
    ///         "statsInboundUplink": false,
    ///         "statsInboundDownlink": false,
    ///         "statsOutboundUplink": false,
    ///         "statsOutboundDownlink": false
    ///     }
    /// }
    /// ```
    pub struct Policy {
        /// A set of key-value pairs, each key is a number in the form of a string
        /// (required by JSON), such as `"0"`, `"1"` etc. The double quotes cannot
        /// be omitted, and this number corresponds to the user level. Each
        /// value is a [LevelPolicyObject](../policy/struct.LevelPolicy.html) .
        levels: HashMap<String, LevelPolicy>,
        /// V2Ray system strategy
        system: SystemPolicy,
    }
}

pub mod inbound {
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
}

pub mod outbound {
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
}

pub mod transport {
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
}

pub mod stats {
    /// `StatsObject` is used as stats field in top level configuration.
    ///
    /// At the moment there is no parameter in stats settings. Stats is enabled automatically when
    /// the StatsObject is set in top level configuration. You need also enable the corresponding
    /// settings in Policy, in order to keep track of user or system stats.
    pub struct Stats {}
}

pub mod reverse {
    /// ```json
    /// {
    ///     "tag": "bridge",
    ///     "domain": "test.v2ray.com"
    /// }
    /// ```
    pub struct Bridge {
        /// A tag. All traffic initiated by this `bridge` will have this tag. It can be used for
        /// [routing](../routing/index.html), identified as `inboundTag`.
        tag: String,
        /// A domain. All connections initiated by `bridge` towards `portal` will use this domain as
        /// target. This domain is only used for communication between `bridge` and `portal`. It is
        /// not necessary to be actually registered.
        domain: String,
    }

    pub struct Portal {
        /// A Tag. You need to redirect all traffic to this `portal`, by targeting `outboundTag` to
        /// this `tag`. The traffic includes the connections from `bridge`, as well as internet
        /// traffic.
        tag: String,
        /// A domain. When a connection targeting this domain, `portal` considers it is a connection
        /// from `bridge`, otherwise it is an internet connection.
        domain: String,
    }

    /// `ReverseObject` is used as `reverse` field in top level configuration.
    ///
    /// ```json
    /// {
    ///     "bridges": [{
    ///         "tag": "bridge",
    ///         "domain": "test.v2ray.com"
    ///     }],
    ///     "portals": [{
    ///         "tag": "portal",
    ///         "domain": "test.v2ray.com"
    ///     }]
    /// }
    /// ```
    pub struct Reverse {
        /// An array of `bridge`s. Each `bridge` is a [BridgeObject](../reverse/struct.Bridge.html).
        bridges: Vec<Bridge>,
        /// An array of `portal`s. Each `portal` is a [PortalObject](../reverse/struct.Portal.html).
        portals: Vec<Portal>,
    }
}

pub mod protocol {
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
            default: Default,
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
        ///     "method": "加密方式",
        ///     "password": "密码",
        ///     "level": 0
        /// }
        /// ```
        pub struct Server {
            /// Email address, optional, used to identify the user
            email: String,
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
        ///             "method": "加密方式",
        ///             "password": "密码",
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
            email: String,
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
            email: String,
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
            email: String,
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
}
