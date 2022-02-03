use crate::common::new_error;
use crate::proxy::Address;
use domain_matcher::ac_automaton::HybridMatcher;
use domain_matcher::mph::MphMatcher;
use domain_matcher::DomainMatcher;
use domain_matcher::MatchType;

use crate::config::{geoip, geosite};
use crate::debug_log;
use bytes::Buf;
use protobuf::CodedInputStream;
use regex;
use regex::{RegexSet, RegexSetBuilder};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::ip_trie::GeoIPMatcher;

pub(super) struct RouterBuilder {
    domain_matchers: HashMap<String, Box<dyn DomainMatcher>>,
    ip_matcher: GeoIPMatcher,
    regex_matchers: HashMap<String, Vec<String>>,
}

impl RouterBuilder {
    pub fn new() -> RouterBuilder {
        RouterBuilder {
            domain_matchers: HashMap::new(),
            ip_matcher: GeoIPMatcher::new(),
            regex_matchers: HashMap::new(),
        }
    }

    // regex_rules: (outbound_tag, vec of regex expr)
    pub fn add_regex_rules(&mut self, outbound_tag: &str, regex_rules: Vec<String>) {
        if let Some(exprs) = self.regex_matchers.get_mut(outbound_tag) {
            regex_rules.into_iter().for_each(|expr| exprs.push(expr));
        } else {
            self.regex_matchers
                .insert(outbound_tag.to_string(), regex_rules);
        }
    }

    // domain_rules -> (rule, (outbound_tag, match_type))
    pub fn add_domain_rules(
        &mut self,
        rule: &str,
        outbound_tag: &str,
        match_type: MatchType,
        use_mph: bool,
    ) {
        if let Some(matcher) = self.domain_matchers.get_mut(outbound_tag) {
            matcher.reverse_insert(rule, match_type);
        } else {
            if use_mph {
                let mut matcher = Box::new(MphMatcher::new(1));
                matcher.reverse_insert(rule, match_type);
                self.domain_matchers
                    .insert(outbound_tag.to_string(), matcher);
            } else {
                let mut matcher = Box::new(HybridMatcher::new(1));
                matcher.reverse_insert(rule, match_type);
                self.domain_matchers
                    .insert(outbound_tag.to_string(), matcher);
            }
        }
    }

    // geosite_tags => Map(geosite rule,outbound_tags)
    pub fn read_geosite_file(
        &mut self,
        file_name: &str,
        geosite_tags: HashMap<String, &str>,
        use_mph: bool,
    ) -> io::Result<()> {
        for tag in geosite_tags.iter() {
            if !self.domain_matchers.contains_key(*tag.1) {
                if use_mph {
                    self.domain_matchers
                        .insert(tag.1.to_string(), Box::new(MphMatcher::new(1)));
                } else {
                    self.domain_matchers
                        .insert(tag.1.to_string(), Box::new(HybridMatcher::new(1)));
                }
            }
        }
        let mut f = File::open(&file_name)?;
        let mut is = CodedInputStream::new(&mut f);
        let mut domain: geosite::Domain;
        let mut site_group_tag = String::new();
        let mut skip_field = None;
        while !is.eof()? {
            is.read_tag_unpack()?;
            is.read_raw_varint64()?;
            while !is.eof().unwrap() {
                let (field_number, wire_type) = is.read_tag_unpack()?;
                match field_number {
                    1 => {
                        is.read_string_into(&mut site_group_tag)?;
                        skip_field = geosite_tags.get(site_group_tag.as_str());
                    }
                    2 => {
                        if skip_field.is_none() {
                            is.skip_field(wire_type)?;
                            continue;
                        }
                        domain = is.read_message()?;
                        {
                            if let Some(outbound_tag) = skip_field {
                                let matcher = self.domain_matchers.get_mut(*outbound_tag).unwrap();
                                {
                                    match domain.field_type {
                                        geosite::Domain_Type::Plain => matcher.reverse_insert(
                                            domain.get_value(),
                                            MatchType::SubStr(true),
                                        ),
                                        geosite::Domain_Type::Domain => matcher.reverse_insert(
                                            domain.get_value(),
                                            MatchType::Domain(true),
                                        ),
                                        geosite::Domain_Type::Full => matcher.reverse_insert(
                                            domain.get_value(),
                                            MatchType::Full(true),
                                        ),
                                        _ => {
                                            if let Some(regex_exprs) =
                                                self.regex_matchers.get_mut(*outbound_tag)
                                            {
                                                regex_exprs.push(domain.get_value().to_string())
                                            } else {
                                                let regex_exprs = vec![domain.value];
                                                self.regex_matchers
                                                    .insert(outbound_tag.to_string(), regex_exprs);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        // is.skip_field(wire_type);
                    }
                }
            }
        }
        Ok(())
    }

    // geoip_tags => Map(geoip rule, outbound tag)
    pub fn read_geoip_file(
        &mut self,
        file_name: &str,
        outbound_tag: &str,
        geoip_tags: HashSet<String>,
    ) -> io::Result<()> {
        let mut f = match File::open(&file_name) {
            Ok(f) => f,
            Err(e) => {
                return Err(new_error(format!(
                    "open geoip file {} failed: {}",
                    file_name, e
                )));
            }
        };
        let mut is = CodedInputStream::new(&mut f);
        let mut cidr = geoip::CIDR::new();
        let mut country_code = String::new();
        let mut skip_field: bool = false;
        while !is.eof()? {
            is.read_tag_unpack()?;
            // assert_eq!(field_number, 1);
            is.read_raw_varint64()?;
            while !is.eof()? {
                let (field_number, wire_type) = is.read_tag_unpack()?;
                match field_number {
                    1 => {
                        if !country_code.is_empty() {
                            is.read_raw_varint64()?;
                            country_code.clear();
                            continue;
                        }
                        country_code = is.read_string()?.to_lowercase();
                        skip_field = !geoip_tags.contains(country_code.as_str());
                    }
                    2 => {
                        if skip_field {
                            is.skip_field(wire_type)?;
                            continue;
                        }
                        is.merge_message(&mut cidr)?;
                        let len = cidr.ip.len();
                        match len {
                            16 => {
                                let ip6 = cidr.ip.get_u128();
                                self.ip_matcher.put_v6(
                                    ip6,
                                    cidr.prefix as u8,
                                    outbound_tag.to_string(),
                                );
                            }
                            4 => {
                                println!(
                                    "{}:{}.{}.{}.{}/{}",
                                    country_code,
                                    cidr.ip[0],
                                    cidr.ip[1],
                                    cidr.ip[2],
                                    cidr.ip[3],
                                    cidr.prefix
                                );
                                let ip4 = cidr.ip.get_u32();
                                self.ip_matcher.put_v4(
                                    ip4,
                                    cidr.prefix as u8,
                                    outbound_tag.to_string(),
                                );
                            }
                            _ => {
                                debug_log!("invalid ip length detected");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn build(mut self, default_outbound_tag: String) -> io::Result<Router> {
        let mut regex_matchers = HashMap::new();
        for (outbound_tag, rules) in self.regex_matchers {
            let rule_set = match RegexSetBuilder::new(rules).build() {
                Ok(r) => r,
                Err(e) => {
                    return Err(new_error(format!(
                        "router builder build regex set failed:{}",
                        e.to_string()
                    )));
                }
            };
            regex_matchers.insert(outbound_tag, rule_set);
        }
        self.domain_matchers.iter_mut().for_each(|x| x.1.build());
        let mut domain_matchers: Vec<(String, Box<dyn DomainMatcher>)> =
            std::mem::take(&mut self.domain_matchers)
                .into_iter()
                .collect();
        domain_matchers.shrink_to_fit();
        let mut regex_matchers: Vec<(String, RegexSet)> =
            std::mem::take(&mut regex_matchers).into_iter().collect();
        regex_matchers.shrink_to_fit();
        let mut ip_matcher = std::mem::take(&mut self.ip_matcher);
        ip_matcher.build();

        Ok(Router {
            domain_matchers,
            ip_matcher,
            regex_matchers,
            default_outbound_tag,
        })
    }
}

pub struct Router {
    domain_matchers: Vec<(String, Box<dyn DomainMatcher>)>,
    ip_matcher: GeoIPMatcher,
    regex_matchers: Vec<(String, RegexSet)>,
    default_outbound_tag: String,
}

// safe: DomainMatcher are Send and Sync
unsafe impl Send for Router {}
unsafe impl Sync for Router {}

fn socket_addr_v4_to_u32(ip4: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip4.octets())
}
fn socket_addr_v6_to_u128(ip6: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip6.octets())
}

impl Router {
    pub fn match_socket_addr(&self, addr: &SocketAddr) -> &str {
        use std::net::IpAddr;
        let addr = addr.ip();
        match addr {
            IpAddr::V4(e) => {
                let ip4 = socket_addr_v4_to_u32(e);
                let res = self.ip_matcher.match4(ip4);
                return if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                };
            }
            IpAddr::V6(e) => {
                let ip6 = socket_addr_v6_to_u128(e);
                let res = self.ip_matcher.match6(ip6);
                return if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                };
            }
        }
    }
    pub fn match_addr(&self, addr: &Address) -> &str {
        match addr {
            Address::SocketAddress(SocketAddr::V4(ip4)) => {
                let ip4 = socket_addr_v4_to_u32(*ip4.ip());
                let res = self.ip_matcher.match4(ip4);
                return if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                };
            }
            Address::SocketAddress(SocketAddr::V6(ip6)) => {
                let ip6 = socket_addr_v6_to_u128(*ip6.ip());
                let res = self.ip_matcher.match6(ip6);
                return if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                };
            }
            Address::DomainNameAddress(ref domain_name, _) => {
                for (tag, matcher) in self.domain_matchers.iter() {
                    if matcher.reverse_query(domain_name.as_str()) {
                        return tag.as_str();
                    }
                }
                for (tag, matcher) in self.regex_matchers.iter() {
                    if matcher.is_match(domain_name.as_str()) {
                        return tag.as_str();
                    }
                }
            }
        }
        self.default_outbound_tag.as_str()
    }
}
