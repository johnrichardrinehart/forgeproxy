//! Linux kernel keyring integration.
//!
//! Reads secrets from the user keyring via the `linux-keyutils` crate
//! (direct syscall) or the `keyctl` CLI tool as fallback.

use anyhow::{Context, Result};
use tracing::{debug, warn};

/// Read a key from the Linux kernel user keyring by name.
///
/// Tries the `linux-keyutils` crate first for direct syscall access,
/// then falls back to shelling out to the `keyctl` CLI tool.
pub async fn read_key(key_name: &str) -> Result<String> {
    match read_key_native(key_name) {
        Ok(val) => {
            debug!(key_name, "read key via native keyutils");
            Ok(val)
        }
        Err(e) => {
            warn!(
                key_name,
                error = %e,
                "native keyring read failed, falling back to keyctl CLI"
            );
            read_key_cli(key_name).await
        }
    }
}

/// Resolve a secret by name: try the kernel keyring first, then fall back to
/// an environment variable with the same name.  Returns `None` if neither source
/// has a non-empty value.
pub async fn resolve_secret(name: &str) -> Option<String> {
    if let Ok(val) = read_key(name).await
        && !val.is_empty()
    {
        return Some(val);
    }
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Read a key from the user keyring using the `linux-keyutils` crate (direct syscall).
pub(crate) fn read_key_native(key_name: &str) -> Result<String> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let ring = KeyRing::from_special_id(KeyRingIdentifier::User, false)
        .map_err(|e| anyhow::anyhow!("failed to open user keyring: {e:?}"))?;

    let key = ring
        .search(key_name)
        .map_err(|e| anyhow::anyhow!("key '{}' not found in user keyring: {e:?}", key_name))?;

    let data = key
        .read_to_vec()
        .map_err(|e| anyhow::anyhow!("failed to read key payload: {e:?}"))?;

    String::from_utf8(data).context("key payload is not valid UTF-8")
}

/// Read a key from the user keyring by shelling out to the `keyctl` CLI.
async fn read_key_cli(key_name: &str) -> Result<String> {
    // First, search for the key ID in the user keyring (@u)
    let search = tokio::process::Command::new("keyctl")
        .args(["search", "@u", "user", key_name])
        .output()
        .await
        .context("keyctl search failed to execute")?;

    if !search.status.success() {
        let stderr = String::from_utf8_lossy(&search.stderr);
        anyhow::bail!(
            "keyctl search failed for key '{}': {}",
            key_name,
            stderr.trim()
        );
    }

    let key_id = String::from_utf8_lossy(&search.stdout).trim().to_string();
    if key_id.is_empty() {
        anyhow::bail!("keyctl search returned empty key id for '{}'", key_name);
    }

    // Then read the raw key data via `keyctl pipe`
    let pipe = tokio::process::Command::new("keyctl")
        .args(["pipe", &key_id])
        .output()
        .await
        .context("keyctl pipe failed to execute")?;

    if !pipe.status.success() {
        let stderr = String::from_utf8_lossy(&pipe.stderr);
        anyhow::bail!(
            "keyctl pipe failed for key id '{}': {}",
            key_id,
            stderr.trim()
        );
    }

    String::from_utf8(pipe.stdout).context("key data is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_key_native_missing_key() {
        // Attempting to read a non-existent key should return an error.
        let result = read_key_native("forgeproxy_test_nonexistent_key_12345");
        assert!(result.is_err());
    }
}
