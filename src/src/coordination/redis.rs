//! KeyDB / Redis client pool creation.
//!
//! Builds a [`fred::clients::Pool`] configured for the KeyDB instance
//! described in [`crate::config::KeyDbConfig`], optionally enabling TLS
//! via `rustls` and reading the auth token from an environment variable.

use anyhow::{Context, Result};
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::types::config::{ReconnectPolicy, ServerConfig, TlsConnector};
use fred::types::Builder;

/// Create a KeyDB connection pool from the application configuration.
///
/// The pool is initialised (connected + PING verified) before being returned.
/// If `config.tls` is `true`, the connection uses `rustls` via fred's built-in
/// TLS support.  The auth token is read from the environment variable whose
/// name is given in `config.auth_token_env`.
pub async fn create_keydb_pool(config: &crate::config::KeyDbConfig) -> Result<Pool> {
    // Read the auth token from the environment variable specified in config.
    let auth_token = std::env::var(&config.auth_token_env).ok();

    // Parse host:port from the endpoint string.  The endpoint may optionally
    // include a `rediss://` or `redis://` scheme prefix which we strip.
    let endpoint = config
        .endpoint
        .trim_start_matches("rediss://")
        .trim_start_matches("redis://");

    let (host, port) = parse_host_port(endpoint)?;

    let server_config = ServerConfig::new_centralized(host, port);

    let mut fred_config = fred::types::config::Config {
        server: server_config,
        ..fred::types::config::Config::default()
    };

    // TLS configuration.
    if config.tls {
        fred_config.tls = Some(TlsConnector::default_rustls()?.into());
    }

    // Auth token (password).
    if let Some(ref token) = auth_token {
        fred_config.password = Some(token.clone());
    }

    let mut builder = Builder::from_config(fred_config);

    // Exponential reconnect: initial 0ms, base 100ms, max 30s, factor 2.
    builder.set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2));

    // Build a pool with ~4 connections for concurrency.
    let pool = builder
        .build_pool(4)
        .context("failed to build KeyDB connection pool")?;

    pool.init().await.context("failed to connect to KeyDB")?;

    // Verify connectivity with a PING.
    let _: String = pool
        .ping(None)
        .await
        .context("KeyDB PING failed after connect")?;

    tracing::info!(
        host = host,
        port = port,
        tls = config.tls,
        pool_size = 4,
        "KeyDB pool created and verified"
    );

    Ok(pool)
}

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
