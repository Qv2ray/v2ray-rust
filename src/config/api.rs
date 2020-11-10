use serde::Deserialize;

#[derive(Deserialize, Debug)]
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
#[derive(Deserialize)]
pub struct Api {
    /// Outbound proxy ID.
    tag: String,
    /// List of enabled [API](../api/index.html)s . See the [API list](../api/enum.Service.html) for
    /// optional values.
    services: Vec<Service>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, from_value, json};

    #[test]
    pub fn test_deserialize_api_service() {
        let ds = from_str("\"HandlerService\"");
        assert!(matches!(ds, Ok(Service::HandlerService)));

        assert!(matches!(
            from_str("\"LoggerService\""),
            Ok(Service::LoggerService)
        ));
    }

    #[test]
    pub fn test_deserialize_api() {
        let ds = from_value::<Api>(json!({
            "tag": "api",
            "services": ["HandlerService", "StatsService"]
        }));

        assert!(ds.is_ok());
        let ds = ds.unwrap();
        assert_eq!(ds.tag, "api");
        assert_eq!(ds.services.len(), 2);
    }
}
