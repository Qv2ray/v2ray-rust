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
