use anyhow::{Context, Result};
use tracing::{debug, warn};

/// Read a key from the Linux kernel session keyring by name.
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

/// Check if a key exists in the session keyring.
pub async fn key_exists(key_name: &str) -> Result<bool> {
    match read_key(key_name).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Read a key from the session keyring using the `linux-keyutils` crate (direct syscall).
pub(crate) fn read_key_native(key_name: &str) -> Result<String> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| anyhow::anyhow!("failed to open session keyring: {e:?}"))?;

    let key = ring
        .search(key_name)
        .map_err(|e| anyhow::anyhow!("key '{}' not found in session keyring: {e:?}", key_name))?;

    let data = key
        .read_to_vec()
        .map_err(|e| anyhow::anyhow!("failed to read key payload: {e:?}"))?;

    String::from_utf8(data).context("key payload is not valid UTF-8")
}

/// Read a key from the session keyring by shelling out to the `keyctl` CLI.
async fn read_key_cli(key_name: &str) -> Result<String> {
    // First, search for the key ID in the session keyring (@s)
    let search = tokio::process::Command::new("keyctl")
        .args(["search", "@s", "user", key_name])
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
        // This test may behave differently depending on whether a session
        // keyring is available in the test environment.
        let result = read_key_native("gheproxy_test_nonexistent_key_12345");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_key_exists_missing() {
        // A key that almost certainly does not exist should return false
        // (or an error that we map to false).
        let exists = key_exists("gheproxy_test_nonexistent_key_12345").await;
        // key_exists returns Ok(false) when the key is not found
        if let Ok(val) = exists {
            assert!(!val);
        }
        // Err is acceptable in environments without keyring support
    }
}
