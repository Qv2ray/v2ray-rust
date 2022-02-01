use crate::common::new_error;
use crate::proxy::Address;
use cidr_matcher::geoip;
use cidr_matcher::lpc_trie::LPCTrie;
use domain_matcher::ac_automaton::HybridMatcher;
use domain_matcher::mph::MphMatcher;
use domain_matcher::DomainMatcher;
use domain_matcher::{geosite, MatchType};
use regex;
use regex::{RegexSet, RegexSetBuilder};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub(super) struct RouterBuilder {
    domain_matchers: HashMap<String, Box<dyn DomainMatcher>>,
    lpc_matcher_v4: LPCTrie<u32>,
    lpc_matcher_v6: LPCTrie<u128>,
    regex_matchers: HashMap<String, Vec<String>>,
}

impl RouterBuilder {
    pub fn new() -> RouterBuilder {
        RouterBuilder {
            domain_matchers: HashMap::new(),
            lpc_matcher_v4: LPCTrie::new(),
            lpc_matcher_v6: LPCTrie::new(),
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
        let mut f = match File::open(&file_name) {
            Ok(f) => f,
            Err(e) => {
                return Err(new_error(e.to_string()));
            }
        };
        let site_group_list: geosite::SiteGroupList =
            match protobuf::Message::parse_from_reader(&mut f) {
                Ok(v) => v,
                Err(e) => return Err(new_error(e.to_string())),
            };
        for i in site_group_list.site_group.into_iter() {
            if let Some(outbound_tag) = geosite_tags.get(i.tag.as_str()) {
                let matcher = self.domain_matchers.get_mut(*outbound_tag).unwrap();
                for domain in i.domain.into_iter() {
                    match domain.field_type {
                        geosite::Domain_Type::Plain => {
                            matcher.reverse_insert(domain.get_value(), MatchType::SubStr(true))
                        }
                        geosite::Domain_Type::Domain => {
                            matcher.reverse_insert(domain.get_value(), MatchType::Domain(true))
                        }
                        geosite::Domain_Type::Full => {
                            matcher.reverse_insert(domain.get_value(), MatchType::Full(true))
                        }
                        _ => {
                            if let Some(regex_exprs) = self.regex_matchers.get_mut(*outbound_tag) {
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
        let geoip_list: geoip::GeoIPList = match protobuf::Message::parse_from_reader(&mut f) {
            Ok(v) => v,
            Err(e) => {
                return Err(new_error(format!(
                    "geoip file {} has invalid format: {}",
                    file_name, e
                )));
            }
        };
        for i in geoip_list.entry.into_iter() {
            let country_code = i.country_code.to_lowercase();
            if geoip_tags.contains(country_code.as_str()) {
                for pair in i.cidr.into_iter() {
                    let len = pair.ip.len();
                    match len {
                        16 => {
                            let inner = pair.ip.try_into().unwrap();
                            self.lpc_matcher_v6.put(
                                u128::from_be_bytes(inner) >> (128 - pair.prefix)
                                    << (128 - pair.prefix),
                                pair.prefix as u8,
                                outbound_tag.to_string(),
                            );
                        }
                        4 => {
                            let inner = pair.ip.try_into().unwrap();
                            self.lpc_matcher_v4.put(
                                u32::from_be_bytes(inner) >> (32 - pair.prefix)
                                    << (32 - pair.prefix),
                                pair.prefix as u8,
                                outbound_tag.to_string(),
                            );
                        }
                        _ => {
                            eprintln!("invalid ip length detected");
                        }
                    }
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
        Ok(Router {
            domain_matchers: self.domain_matchers,
            lpc_matcher_v4: self.lpc_matcher_v4,
            lpc_matcher_v6: self.lpc_matcher_v6,
            regex_matchers,
            default_outbound_tag,
        })
    }
}
pub struct Router {
    domain_matchers: HashMap<String, Box<dyn DomainMatcher>>,
    lpc_matcher_v4: LPCTrie<u32>,
    lpc_matcher_v6: LPCTrie<u128>,
    regex_matchers: HashMap<String, RegexSet>,
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
    pub fn match_addr(&self, addr: &Address) -> &str {
        match addr {
            Address::SocketAddress(SocketAddr::V4(ip4)) => {
                let ip4 = socket_addr_v4_to_u32(*ip4.ip());
                let res = self.lpc_matcher_v4.get_with_value(ip4);
                return if res.is_empty() {
                    self.default_outbound_tag.as_str()
                } else {
                    res
                };
            }
            Address::SocketAddress(SocketAddr::V6(ip6)) => {
                let ip6 = socket_addr_v6_to_u128(*ip6.ip());
                let res = self.lpc_matcher_v6.get_with_value(ip6);
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
