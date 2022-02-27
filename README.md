# v2ray-rust
[![Rust](https://github.com/Qv2ray/v2ray-rust/actions/workflows/rust.yml/badge.svg)](https://github.com/Qv2ray/v2ray-rust/actions/workflows/rust.yml)

An Opinionated Lightweight Implementation of V2Ray, in Rust Programming Language


## Features

* Proxy chains
* Full Cone UDP for Shadowsocks/Trojan/Direct
* Fast route algorithm
  * Hybrid/Mph Domain matcher
  * Longest prefix match for CIDR route
* ClientHello fingerprinting resistance
* Easy configuration


## Config example

````toml
default_outbound = "proxy"

[[ss]]
addr = "127.0.0.1:9000"
password = "123456"
method = "chacha20-poly1305"
tag = "ss0"
[[ss]]
addr = "127.0.0.1:9001"
password = "123456"
method = "chacha20-poly1305"
tag = "ss1"
[[ss]]
addr = "127.0.0.1:9002"
password = "123456"
method = "chacha20-poly1305"
tag = "ss2"
[[ss]]
addr = "127.0.0.1:9004"
password = "123456"
method = "chacha20-poly1305"
tag = "ss3"

[[vmess]]
addr = "127.0.0.1:10002"
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
method = "aes-128-gcm"
tag = "v"

[[trojan]]
addr = "127.0.0.1:10003"
password = "password"
tag = "t"

[[ws]]
uri = "ws://127.0.0.1:10002/"
tag = "w"

[[direct]]
tag = "d"

[[outbounds]]
chain = ["ss0","ss1","ss2","ss3"]
tag = "proxy"

[[outbounds]]
chain = ["w","v","ss0","ss1"]
# chain = ["w","v","ss2"]
# chain = ["t","w","v"]
# chain = ["ss0","ss1","ss2","ss3"]
# chain = ["ss0","ss1","ss2","ss3","w","v"]
# chain = ["ss0"]
# debug
tag = "cn"

[[outbounds]]
chain = ["d"]
tag = "private"

[[inbounds]]
addr = "127.0.0.1:1087"
enable_udp = true

# [[dokodemo]]
# addr = "127.0.0.1:12345"
# tproxy = true

[[geosite_rules]]
tag = "cn"
file_path = "/usr/share/v2ray/geosite.dat"
rules = ["cn"]

[[geoip_rules]]
tag = "cn"
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
- ✅ UDP support

### http
- ✅ http Inbound
  - 🚧 RFC 7230
- ✅ mixed Inbound

### Vmess

- ✅ Vmess Aead Outbound
- ✅ UDP support

### Shadowsocks

- ✅ Shadowsocks Outbound
- ✅ UDP support

### Trojan
- ✅ Trojan
- ✅ UDP support

### VLESS
- ❌ 

### Chainable Steam
- ✅

### Chainable UDP
- ✅

### Stream settings

- ✅ TLS
- ✅ HTTP/2
- ✅ WebSocket
- ✅ WebSocket-0-rtt
- ❌ QUIC
- ❌ DomainSocket
- ❌ mKCP

### Router

- ✅ geosite 
- ✅ geoip



