# v2ray-rust
[![Rust](https://github.com/Qv2ray/v2ray-rust/actions/workflows/rust.yml/badge.svg)](https://github.com/Qv2ray/v2ray-rust/actions/workflows/rust.yml)

An Opinionated Lightweight Implementation of V2Ray, in Rust Programming Language

## Config example

````toml
default_outbound = "out2"

[[ss]]
addr = "127.0.0.1:9000"
password = "123456"
method = "chacha20-poly1305"
tag = "ss"

[[vmess]]
addr = "127.0.0.1:10002"
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
method = "aes-128-gcm"
tag = "v"

[[ws]]
uri = "ws://127.0.0.1:10002/"
tag = "w"

[[direct]]
tag = "d"

[[outbounds]]
chain = ["d"]
# debug
tag = "out"

[[outbounds]]
chain = ["w","v","ss"]
# debug
tag = "out2"

[[outbounds]]
chain = ["d"]
tag = "private"

[[inbounds]]
addr = "127.0.0.1:1087"

[[dokodemo]]
addr = "127.0.0.1:12345"
tproxy = true

[[geosite_rules]]
tag = "out"
file_path = "/usr/share/v2ray/geosite.dat"
rules = ["cn"]

[[geoip_rules]]
tag = "out"
file_path = "/usr/share/v2ray/geoip.dat"
rules = ["cn"]

[[geoip_rules]]
tag="private"
file_path = "/usr/share/v2ray/geoip.dat"
rules = ["private"]
````

## Roadmap

🚧 Interested but not implemented yet ✅ Implemented ❌ Not Interested 🤔 

### geosite fast matcher
- ✅ [DomainMatcher](https://github.com/Qv2ray/DomainMatcher)

### geoip fast matcher
- ✅ [CIDRMatcher](https://github.com/Qv2ray/CIDRMatcher)

### Rust generator
- ✅ [gentian: a proc macro that transforms generators to state machines](https://crates.io/crates/gentian)

### socks5
- ✅ socks5 Inbound
- 🚧 UDP support

### http
- 🚧 http Inbound
- 🚧 mixed Inbound

### Vmess

- ✅ Vmess Aead Outbound
- 🚧 UDP support

### Shadowsocks

- ✅ Shadowsocks Outbound
- 🚧 UDP support

### Trojan
- ✅ Trojan
- 🚧 UDP support

### VLESS
- ❌ 

### Chainable Steam
- ✅

### Stream settings

- ✅ TLS
- 🚧 HTTP/2
- ✅ WebSocket
- ❌ QUIC
- ❌ DomainSocket
- ❌ mKCP

### Router

- ✅ geosite 
- ✅ geoip



