use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use tracing::{debug, instrument};

use crate::config::Config;

/// Represents the credential mode for authenticating to an upstream GHE instance.
#[derive(Debug, Clone)]
pub enum CredentialMode {
    /// Personal access token embedded in HTTPS URLs.
    Pat { token: String },
    /// SSH private key data for git+ssh transport.
    SshKey { key_data: String },
}

/// Process-wide cache of resolved credentials, keyed by org/owner name.
static CREDENTIAL_CACHE: std::sync::LazyLock<Mutex<HashMap<String, CredentialMode>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve the upstream credential for a given repository owner/org.
///
/// Checks the in-process cache first, then looks up the org-specific or default
/// credential configuration and reads the secret from the Linux kernel keyring.
#[instrument(skip(config), fields(owner))]
pub fn resolve_credential(config: &Config, owner: &str) -> Result<CredentialMode> {
    // Check cache first
    if let Some(cached) = CREDENTIAL_CACHE.lock().unwrap().get(owner) {
        debug!(owner, "credential cache hit");
        return Ok(cached.clone());
    }

    // Determine mode and keyring key name from config
    let (mode, key_name) = if let Some(org_config) = config.upstream_credentials.orgs.get(owner) {
        (
            org_config.mode,
            org_config.keyring_key_name.clone(),
        )
    } else {
        let default_key = match config.upstream_credentials.default_mode {
            crate::config::CredentialMode::Pat => "default-pat",
            crate::config::CredentialMode::Ssh => "default-ssh",
        };
        (
            config.upstream_credentials.default_mode,
            default_key.to_string(),
        )
    };

    let credential = match mode {
        crate::config::CredentialMode::Pat => {
            let token =
                crate::credentials::keyring::read_key_native(&key_name).with_context(|| {
                    format!(
                        "failed to read PAT for org '{}' from keyring key '{}'",
                        owner, key_name
                    )
                })?;
            CredentialMode::Pat { token }
        }
        crate::config::CredentialMode::Ssh => {
            let key_data =
                crate::credentials::keyring::read_key_native(&key_name).with_context(|| {
                    format!(
                        "failed to read SSH key for org '{}' from keyring key '{}'",
                        owner, key_name
                    )
                })?;
            CredentialMode::SshKey { key_data }
        }
    };

    CREDENTIAL_CACHE
        .lock()
        .unwrap()
        .insert(owner.to_string(), credential.clone());

    debug!(owner, mode = ?mode, "resolved upstream credential");
    Ok(credential)
}

/// Build a clone URL and return it alongside the resolved credential.
///
/// For PAT mode, the token is embedded in the HTTPS URL.
/// For SSH mode, the standard git@host:owner/repo.git format is used.
pub fn get_clone_url(
    config: &Config,
    owner: &str,
    repo: &str,
) -> Result<(String, CredentialMode)> {
    let credential = resolve_credential(config, owner)?;
    let url = match &credential {
        CredentialMode::Pat { token } => {
            format!(
                "https://x-access-token:{token}@{}/{owner}/{repo}.git",
                config.ghe.hostname
            )
        }
        CredentialMode::SshKey { .. } => {
            format!("git@{}:{owner}/{repo}.git", config.ghe.hostname)
        }
    };
    Ok((url, credential))
}

/// Build environment variables needed for git fetch/clone operations.
///
/// For PAT mode, the token is already embedded in the URL so no extra env is needed.
/// For SSH mode, writes the key to a temp file and sets `GIT_SSH_COMMAND`.
pub fn get_fetch_env(credential: &CredentialMode) -> Result<Vec<(String, String)>> {
    match credential {
        CredentialMode::Pat { .. } => Ok(vec![]), // token is embedded in the URL
        CredentialMode::SshKey { key_data } => {
            use std::io::Write;

            let mut tmpfile =
                tempfile::NamedTempFile::new().context("failed to create temp SSH key file")?;
            tmpfile.write_all(key_data.as_bytes())?;

            // Set restrictive permissions on the temp key file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    tmpfile.path(),
                    std::fs::Permissions::from_mode(0o600),
                )?;
            }

            let path = tmpfile.into_temp_path();
            let ssh_cmd = format!(
                "ssh -i {} -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null",
                path.display()
            );
            Ok(vec![("GIT_SSH_COMMAND".to_string(), ssh_cmd)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_mode_pat_clone() {
        let cred = CredentialMode::Pat {
            token: "ghp_test".to_string(),
        };
        let cloned = cred.clone();
        match cloned {
            CredentialMode::Pat { token } => assert_eq!(token, "ghp_test"),
            _ => panic!("expected Pat variant"),
        }
    }

    #[test]
    fn test_credential_mode_ssh_clone() {
        let cred = CredentialMode::SshKey {
            key_data: "ssh-rsa AAAA...".to_string(),
        };
        let cloned = cred.clone();
        match cloned {
            CredentialMode::SshKey { key_data } => assert_eq!(key_data, "ssh-rsa AAAA..."),
            _ => panic!("expected SshKey variant"),
        }
    }

    #[test]
    fn test_get_fetch_env_pat_is_empty() {
        let cred = CredentialMode::Pat {
            token: "ghp_test".to_string(),
        };
        let env = get_fetch_env(&cred).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn test_get_fetch_env_ssh_sets_git_ssh_command() {
        let cred = CredentialMode::SshKey {
            key_data: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n"
                .to_string(),
        };
        let env = get_fetch_env(&cred).unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "GIT_SSH_COMMAND");
        assert!(env[0].1.contains("ssh -i "));
        assert!(env[0].1.contains("-o StrictHostKeyChecking=yes"));
        assert!(env[0].1.contains("-o UserKnownHostsFile=/dev/null"));
    }

    #[test]
    fn test_credential_debug_format() {
        let cred = CredentialMode::Pat {
            token: "secret".to_string(),
        };
        let debug = format!("{:?}", cred);
        // Debug should include the variant name
        assert!(debug.contains("Pat"));
    }
}
