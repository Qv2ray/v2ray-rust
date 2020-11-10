use serde::de::Visitor;
use serde::{Deserialize, Deserializer};
use serde_json::{from_reader as inner_from_reader, from_str as inner_from_str, Error};
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;

/*
pub fn from_reader<R>(reader: R) -> Result<Config, Error>
where
R: Read,
{
inner_from_reader(reader)
}

pub fn from_str(s: &str) -> Result<Config, Error> {
inner_from_str(s)
}
*/

#[derive(Debug, PartialEq)]
pub enum Address {
    IpAddr(IpAddr),
    Domain(String),
}

impl<'a> From<&'a str> for Address {
    fn from(addr: &str) -> Address {
        match IpAddr::from_str(&addr) {
            Ok(ipaddr) => Address::IpAddr(ipaddr),
            Err(_) => Address::Domain(String::from(addr)),
        }
    }
}

#[derive(Debug, PartialEq)]

struct AddressVisitor;

impl<'de> Visitor<'de> for AddressVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "IP Address or a domain address")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Address::from(s))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor)
    }
}

pub type Time = u32;

#[derive(Clone, Debug, PartialEq)]
pub struct Port(u16);
/// Ports formats as follows:
/// - `"a-b"` : Both `a` and `b` are positive integers and less than 65536. When the
/// targeting port is in [`a`, `b`), this rule takes effect.
/// - `a` : `a` is a positive integer, and less than 65536. When the targeting port is `a`,
/// this rule takes effect.
/// - Mix of the two above, separated by `","`. Such as `"53,443,1000-2000"`.
#[derive(Clone, Debug, PartialEq)]
pub struct Ports(Vec<Port>);

struct PortsVisitor;

impl<'de> Visitor<'de> for PortsVisitor {
    type Value = Ports;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "a string with comma separated ports and port ranges or a port number"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut ports: Vec<Port> = vec![];
        for p_str in s.split(',') {
            let mut splitted = p_str.splitn(2, '-');

            match splitted.next() {
                Some(start) => {
                    let start_port = u16::from_str(start).map_err(|_| {
                        serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?;
                    match splitted.next() {
                        Some(end) => {
                            let end_port = u16::from_str(end).map_err(|_| {
                                serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Str(s),
                                    &self,
                                )
                            })?;

                            if end_port <= start_port {
                                return Err(serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Str(s),
                                    &self,
                                ));
                            }

                            for port in start_port..end_port {
                                ports.push(Port(port));
                            }
                        }
                        None => {
                            ports.push(Port(start_port));
                        }
                    }
                }
                None => {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &self,
                    ));
                }
            }
        }

        Ok(Ports(ports))
    }

    fn visit_u64<E>(self, u: u64) -> Result<Self::Value, E> {
        Ok(Ports(vec![Port(u as u16)]))
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PortsVisitor)
    }
}

pub type UserLevel = u8;
pub struct AddressPort(String, Port);

#[derive(Debug, PartialEq)]
pub struct DomainNameFile {
    pub file: String,
    pub tag: String,
}

/// The domain name
#[derive(Debug, PartialEq)]
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
    File(DomainNameFile),
}

struct DomainNameVisitor;

impl<'de> Visitor<'de> for DomainNameVisitor {
    type Value = DomainName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "A plain domain string or string that starting with regexp:/domain:/keyword:/geosite:/ext:")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut splitted = s.splitn(2, ':');
        match splitted.next() {
            Some(nxt) => {
                let second_part = String::from(splitted.next().unwrap_or(""));
                match nxt {
                    "ext" => {
                        let mut rsplitted = second_part.rsplitn(2, ':');

                        match rsplitted.next() {
                            Some(first) => match rsplitted.next() {
                                Some(scnd) => Ok(DomainName::File(DomainNameFile {
                                    file: String::from(scnd),
                                    tag: String::from(first),
                                })),
                                None => Err(serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Str(s),
                                    &self,
                                )),
                            },
                            None => Err(serde::de::Error::invalid_value(
                                serde::de::Unexpected::Str(s),
                                &self,
                            )),
                        }
                    }
                    "geosite" => Ok(DomainName::Predefined(second_part)),
                    "keyword" => Ok(DomainName::Substring(second_part)),
                    "domain" => Ok(DomainName::Subdomain(second_part)),
                    "regexp" => Ok(DomainName::Regexp(second_part)),
                    _ => Ok(DomainName::Pure(String::from(s))),
                }
            }
            None => Ok(DomainName::Pure(String::from(s))),
        }
    }
}

impl<'de> Deserialize<'de> for DomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DomainNameVisitor)
    }
}

#[derive(Deserialize, PartialEq, Debug)]
pub enum NetworkType {
    /// `"tcp"`
    #[serde(rename = "tcp")]
    Tcp,
    /// `"udp"`
    #[serde(rename = "udp")]
    Udp,
    /// `"tcp,udp"`
    #[serde(rename = "tcp,udp")]
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

pub mod api;
pub mod dns;
pub mod inbound;
pub mod log;
pub mod outbound;
pub mod policy;
pub mod protocol;
pub mod reverse;
pub mod routing;
pub mod transport;

pub mod stats {
    /// `StatsObject` is used as stats field in top level configuration.
    ///
    /// At the moment there is no parameter in stats settings. Stats is enabled automatically when
    /// the StatsObject is set in top level configuration. You need also enable the corresponding
    /// settings in Policy, in order to keep track of user or system stats.
    pub struct Stats {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_deserialize_domain_name() {
        let domain_name = from_value::<DomainName>(json!("https://v2ray.com"));

        assert!(domain_name.is_ok());
        assert_eq!(
            domain_name.unwrap(),
            DomainName::Pure(String::from("https://v2ray.com"))
        );

        let domain_name = from_value::<DomainName>(json!("domain:v2ray.com"));
        assert!(domain_name.is_ok());
        assert_eq!(
            domain_name.unwrap(),
            DomainName::Subdomain(String::from("v2ray.com"))
        );

        let domain_name = from_value::<DomainName>(json!("ext:/var/data/h2y.dat:my_tag"));

        assert!(domain_name.is_ok());
        assert_eq!(
            domain_name.unwrap(),
            DomainName::File(DomainNameFile {
                file: String::from("/var/data/h2y.dat"),
                tag: String::from("my_tag")
            })
        );

        let domain_name = from_value::<DomainName>(json!("ext:/var/data/h2y.dat"));
        assert!(domain_name.is_err());
    }

    #[test]
    fn test_deserialize_address() {
        let address = from_value::<Address>(json!("domainaddress"));

        assert!(address.is_ok());
        assert_eq!(
            address.unwrap(),
            Address::Domain(String::from("domainaddress"))
        );

        let address = from_value::<Address>(json!("192.168.0.2"));

        assert!(address.is_ok());
        assert_eq!(
            address.unwrap(),
            Address::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)))
        );
    }

    #[test]
    fn test_deserialize_ports() {
        let ports = from_value::<Ports>(json!("1,2,3-6,7"));
        assert!(ports.is_ok());

        let ports = ports.unwrap();
        assert_eq!(ports.0.len(), 6);

        let mut ports_iter = ports.0.iter();
        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 1);

        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 2);

        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 3);

        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 4);

        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 5);

        let nxt = ports_iter.next();
        assert!(nxt.is_some());
        assert_eq!(nxt.unwrap().0, 7);

        let single_port = from_value::<Ports>(json!(88));
        assert!(single_port.is_ok());
        let mut ports = single_port.unwrap().0;
        assert_eq!(ports.len(), 1);
        assert_eq!(ports.pop().unwrap().0, 88);
    }
}
