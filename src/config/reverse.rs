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

/// ```json
/// {
///     "tag": "portal",
///     "domain": "test.v2fly.org"
/// }
/// ```
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
