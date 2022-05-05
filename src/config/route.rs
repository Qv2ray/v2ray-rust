use crate::common::new_error;
use crate::proxy::Address;
use domain_matcher::ac_automaton::HybridMatcher;
use domain_matcher::mph::MphMatcher;
use domain_matcher::DomainMatcher;
use domain_matcher::MatchType;

use crate::config::{geoip, geosite, DomainRoutingRules, GeoIpRules, GeoSiteRules, IpRoutingRules};
use crate::debug_log;
use bytes::Buf;
use cidr_utils::cidr::IpCidr;
use protobuf::CodedInputStream;

use regex::{RegexSet, RegexSetBuilder};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;

use crate::config::utils::KeepInsertOrderMap;
use protobuf::rt::WireType;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use super::ip_trie::GeoIPMatcher;
const TAG_TYPE_BITS: u32 = 3;
const TAG_TYPE_MASK: u32 = (1u32 << TAG_TYPE_BITS as usize) - 1;

fn to_field_num_and_wire_type(value: u32) -> io::Result<(u32, WireType)> {
    let wire_type = WireType::new(value & TAG_TYPE_MASK);
    if wire_type.is_none() {
        return Err(new_error(format!(
            "unexpected wire type: {}",
            value & TAG_TYPE_MASK
        )));
    }
    let field_number = value >> TAG_TYPE_BITS;
    if field_number == 0 {
        return Err(new_error("unexpected field number: 0"));
    }
    Ok((field_number, wire_type.unwrap()))
}

pub(super) struct RouterBuilder {
    domain_matchers: KeepInsertOrderMap<Box<dyn DomainMatcher>>,
    ip_matcher: GeoIPMatcher,
    regex_matchers: KeepInsertOrderMap<Vec<String>>,
}

impl RouterBuilder {
    pub fn new() -> RouterBuilder {
        RouterBuilder {
            domain_matchers: KeepInsertOrderMap::new(),
            ip_matcher: GeoIPMatcher::new(),
            regex_matchers: KeepInsertOrderMap::new(),
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

    pub fn add_cidr_rules(&mut self, outbound_tag: &str, ip_rules: &[String]) {
        for rule in ip_rules {
            if IpCidr::is_ip_cidr(rule) {
                let cidr = IpCidr::from_str(rule).unwrap();
                match cidr {
                    IpCidr::V4(v4) => {
                        self.ip_matcher.put_v4(
                            v4.get_prefix(),
                            v4.get_bits(),
                            outbound_tag.to_string(),
                        );
                    }
                    IpCidr::V6(v6) => {
                        self.ip_matcher.put_v6(
                            v6.get_prefix(),
                            v6.get_bits(),
                            outbound_tag.to_string(),
                        );
                    }
                }
            } else {
                log::warn!("Add IP rule failed. Ignore invalid IP CIDR:{}", rule)
            }
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
        } else if use_mph {
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

    // geosite_tags => Map(geosite rule,outbound_tags)
    pub fn read_geosite_file<P: AsRef<Path>>(
        &mut self,
        file_name: P,
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
        let mut f = match File::open(&file_name) {
            Ok(f) => f,
            Err(e) => {
                return Err(new_error(format!(
                    "open geosite file {} failed: {}",
                    file_name.as_ref().display(),
                    e
                )));
            }
        };
        let mut is = CodedInputStream::new(&mut f);
        let mut domain: geosite::Domain;
        let mut site_group_tag = String::new();
        let mut skip_field = None;
        while !is.eof()? {
            is.read_raw_varint32()?;
            is.read_raw_varint64()?;
            while !is.eof().unwrap() {
                let (field_number, wire_type) =
                    to_field_num_and_wire_type(is.read_raw_varint32()?)?;
                match field_number {
                    1 => {
                        if !site_group_tag.is_empty() {
                            is.read_raw_varint64()?;
                            site_group_tag.clear();
                            continue;
                        }
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
                                match domain.type_() {
                                    geosite::domain::Type::Plain => matcher
                                        .reverse_insert(domain.value(), MatchType::SubStr(true)),
                                    geosite::domain::Type::Domain => matcher
                                        .reverse_insert(domain.value(), MatchType::Domain(true)),
                                    geosite::domain::Type::Full => matcher
                                        .reverse_insert(domain.value(), MatchType::Full(true)),
                                    _ => {
                                        if let Some(regex_exprs) =
                                            self.regex_matchers.get_mut(*outbound_tag)
                                        {
                                            regex_exprs.push(domain.value().to_string())
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
                    _ => {
                        // is.skip_field(wire_type);
                    }
                }
            }
        }
        Ok(())
    }

    // geoip_tags => Map(geoip rule, outbound tag)
    pub fn read_geoip_file<P: AsRef<Path>>(
        &mut self,
        file_name: P,
        outbound_tag: &str,
        geoip_tags: HashSet<String>,
    ) -> io::Result<()> {
        let mut tags = HashSet::new();
        for t in geoip_tags.into_iter() {
            tags.insert(t.to_uppercase());
        }
        let geoip_tags = tags;
        let mut f = match File::open(&file_name) {
            Ok(f) => f,
            Err(e) => {
                return Err(new_error(format!(
                    "open geoip file {} failed: {}",
                    file_name.as_ref().display(),
                    e
                )));
            }
        };
        let mut is = CodedInputStream::new(&mut f);
        let mut cidr = geoip::CIDR::new();
        let mut country_code = String::new();
        let mut skip_field: bool = false;
        while !is.eof()? {
            is.read_raw_varint32()?;
            // assert_eq!(field_number, 1);
            is.read_raw_varint64()?;
            while !is.eof()? {
                let (field_number, wire_type) =
                    to_field_num_and_wire_type(is.read_raw_varint32()?)?;
                match field_number {
                    1 => {
                        if !country_code.is_empty() {
                            is.read_raw_varint64()?;
                            country_code.clear();
                            continue;
                        }
                        country_code = is.read_string()?.to_uppercase();
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
                                // debug_log!(
                                //     "{}:{}.{}.{}.{}/{}",
                                //     country_code,
                                //     cidr.ip[0],
                                //     cidr.ip[1],
                                //     cidr.ip[2],
                                //     cidr.ip[3],
                                //     cidr.prefix
                                // );
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
        for (outbound_tag, rules) in self.regex_matchers.into_iter() {
            let rule_set = match RegexSetBuilder::new(rules).build() {
                Ok(r) => r,
                Err(e) => {
                    return Err(new_error(format!(
                        "router builder build regex set failed:{}",
                        e
                    )));
                }
            };
            regex_matchers.insert(outbound_tag, rule_set);
        }
        self.domain_matchers.iter_mut().for_each(|x| x.1.build());
        let mut domain_matchers: Vec<(String, Box<dyn DomainMatcher>)> =
            self.domain_matchers.into();
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
        return match addr {
            IpAddr::V4(e) => {
                let ip4 = socket_addr_v4_to_u32(e);
                let res = self.ip_matcher.match4(ip4);
                if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                }
            }
            IpAddr::V6(e) => {
                let ip6 = socket_addr_v6_to_u128(e);
                let res = self.ip_matcher.match6(ip6);
                if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                }
            }
        };
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

pub(super) fn build_router(
    vec_domain_routing_rules: Vec<DomainRoutingRules>,
    vec_ip_routing_rules: Vec<IpRoutingRules>,
    vec_geosite_rules: Vec<GeoSiteRules>,
    vec_geoip_rules: Vec<GeoIpRules>,
    default_outbound_tag: String,
) -> io::Result<Router> {
    let mut builder = RouterBuilder::new();
    for domain_routing_rules in vec_domain_routing_rules {
        let use_mph = domain_routing_rules.use_mph;
        for full in domain_routing_rules.full_rules {
            builder.add_domain_rules(
                full.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::Full(true),
                use_mph,
            );
        }
        for domain in domain_routing_rules.domain_rules {
            builder.add_domain_rules(
                domain.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::Domain(true),
                use_mph,
            );
        }
        for substr in domain_routing_rules.substr_rules {
            builder.add_domain_rules(
                substr.as_str(),
                domain_routing_rules.tag.as_str(),
                MatchType::SubStr(true),
                use_mph,
            );
        }
        builder.add_regex_rules(
            domain_routing_rules.tag.as_str(),
            domain_routing_rules.regex_rules,
        );
    }
    for cidr_rules in vec_ip_routing_rules {
        builder.add_cidr_rules(cidr_rules.tag.as_str(), &cidr_rules.cidr_rules);
    }
    for geosite_rule in vec_geosite_rules {
        let mut geosite_tag_map = HashMap::new();
        for rule in geosite_rule.rules {
            geosite_tag_map.insert(rule.to_uppercase(), geosite_rule.tag.as_str());
        }
        builder.read_geosite_file(
            geosite_rule.file_path,
            geosite_tag_map,
            geosite_rule.use_mph,
        )?;
    }
    for geoip_rule in vec_geoip_rules {
        builder.read_geoip_file(
            geoip_rule.file_path,
            geoip_rule.tag.as_str(),
            geoip_rule.rules,
        )?;
    }
    builder.build(default_outbound_tag)
}
