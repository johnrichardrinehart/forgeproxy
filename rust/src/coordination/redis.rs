//! KeyDB / Redis client pool creation.
//!
//! Builds a [`fred::clients::Pool`] configured for the KeyDB instance
//! described in [`crate::config::KeyDbConfig`], optionally enabling TLS
//! via `rustls` and reading the auth token from an environment variable.

use anyhow::{Context, Result};

/// Parse a `host:port` string.  If the port is omitted, defaults to `6379`.
pub fn parse_host_port(endpoint: &str) -> Result<(&str, u16)> {
    // Strip any trailing path segments (e.g. from URIs).
    let endpoint = endpoint.split('/').next().unwrap_or(endpoint);

    if let Some((host, port_str)) = endpoint.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in endpoint: {endpoint}"))?;
        Ok((host, port))
    } else {
        Ok((endpoint, 6379))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("keydb.local:6380").unwrap();
        assert_eq!(host, "keydb.local");
        assert_eq!(port, 6380);
    }

    #[test]
    fn test_parse_host_port_default() {
        let (host, port) = parse_host_port("keydb.local").unwrap();
        assert_eq!(host, "keydb.local");
        assert_eq!(port, 6379);
    }
}
