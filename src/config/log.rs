use serde::Deserialize;
/// The level of the log.
#[derive(Deserialize, Debug)]
pub enum LogLevel {
    /// `"debug"` : Information that only developers can understand.
    /// It contains all the `"info"` content.
    #[serde(rename = "debug")]
    Debug,
    /// `"info"` : The state of V2Ray at runtime, does not affect
    /// normal use. It contains all the `"warning"` content.
    #[serde(rename = "info")]
    Info,
    /// `"warning"` : V2Ray has encountered some problems, usually
    /// external problems, which do not affect the normal operation
    /// of V2Ray, but may affect the user experience. It contains
    /// all the `"error"` content.
    #[serde(rename = "warning")]
    Warning,
    /// `"error"` : V2Ray has encountered a problem that cannot run
    /// normally and needs to be resolved immediately.
    #[serde(rename = "error")]
    Error,
    /// `"none"` : Do not record anything.
    #[serde(rename = "none")]
    None,
}

/// `LogObject` The corresponding configuration file `log` entries.
///
/// ```json
/// {
///     "access": "/path/to/file",
///     "error": "/path/to/file",
///     "loglevel": "warning",
/// }
/// ```
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, from_value, json};

    #[test]
    pub fn test_deserialize_log_level() {
        let ds = from_str::<LogLevel>("\"warning\"");
        assert_eq!(ds.is_ok(), true);
        assert!(matches!(ds.unwrap(), LogLevel::Warning));

        let ds = from_str::<LogLevel>("\"info\"");
        assert!(matches!(ds.unwrap(), LogLevel::Info));
    }

    #[test]
    pub fn test_deserialize_log() {
        let result = from_value::<Log>(json!({
            "access": "/var/log/v2ray/access.log",
            "error": "/var/log/v2ray/error.log",
            "logLevel": "info"
        }));

        assert!(result.is_ok());
        assert_eq!(result.unwrap().access, "/var/log/v2ray/access.log");
    }
}
