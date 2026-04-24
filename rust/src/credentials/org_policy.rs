use crate::AppState;
use crate::config::CredentialMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedOrgCredentialStatus {
    Eligible { mode: CredentialMode },
    Missing { reason: String },
    Unusable { reason: String },
}

impl ManagedOrgCredentialStatus {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible { .. })
    }
}

/// Decide whether forgeproxy may use local acceleration for an organisation.
///
/// The `upstream_credentials.orgs` map is intentionally treated as the
/// whitelist for local disk, pack-cache, bundle-uri, and hydration paths.  A
/// missing org entry or unavailable secret delegates traffic directly upstream.
/// Configured PAT credentials are probed against the requested repo so expired,
/// invalid, or insufficient tokens fail closed before local acceleration.
pub async fn local_acceleration_status_for_repo(
    state: &AppState,
    owner: &str,
    repo: &str,
) -> ManagedOrgCredentialStatus {
    let org_credential = {
        let config = state.config();
        config.upstream_credentials.orgs.get(owner).cloned()
    };
    let Some(org_credential) = org_credential else {
        return ManagedOrgCredentialStatus::Missing {
            reason: format!("no configured upstream credential for organization '{owner}'"),
        };
    };

    let secret = crate::credentials::keyring::resolve_secret(&org_credential.keyring_key_name)
        .await
        .unwrap_or_default();
    if secret.is_empty() {
        return ManagedOrgCredentialStatus::Missing {
            reason: format!(
                "configured upstream credential '{}' for organization '{}' is empty or unavailable",
                org_credential.keyring_key_name, owner
            ),
        };
    }

    match org_credential.mode {
        CredentialMode::Pat => {
            let auth_header = format!("Bearer {secret}");
            let repo = crate::repo_identity::canonical_repo_leaf(repo);
            match state
                .forge
                .validate_http_auth(
                    &state.http_client,
                    Some(&auth_header),
                    owner,
                    repo,
                    &state.rate_limit,
                )
                .await
            {
                Ok(permission) if permission.has_read() => ManagedOrgCredentialStatus::Eligible {
                    mode: CredentialMode::Pat,
                },
                Ok(permission) => ManagedOrgCredentialStatus::Unusable {
                    reason: format!(
                        "managed credential for organization '{owner}' has insufficient permission '{}' on {owner}/{repo}",
                        permission.as_str()
                    ),
                },
                Err(error) => ManagedOrgCredentialStatus::Unusable {
                    reason: credential_probe_error_reason(error),
                },
            }
        }
        CredentialMode::Ssh => ManagedOrgCredentialStatus::Eligible {
            mode: CredentialMode::Ssh,
        },
    }
}

pub fn local_acceleration_status_from_owner_repo_missing_ok(
    owner_repo: &str,
) -> Option<(&str, &str)> {
    owner_repo.split_once('/')
}

pub fn log_local_acceleration_bypass(
    status: &ManagedOrgCredentialStatus,
    owner_repo: &str,
    protocol: &str,
    phase: &str,
) {
    match status {
        ManagedOrgCredentialStatus::Eligible { .. } => {}
        ManagedOrgCredentialStatus::Missing { reason } => {
            tracing::info!(
                repo = %owner_repo,
                protocol,
                phase,
                reason,
                "organization credentials are not managed by forgeproxy; proxying directly upstream"
            );
        }
        ManagedOrgCredentialStatus::Unusable { reason } => {
            tracing::warn!(
                repo = %owner_repo,
                protocol,
                phase,
                reason,
                "organization credentials are invalid, expired, or insufficient; proxying directly upstream"
            );
        }
    }
}

fn credential_probe_error_reason(error: crate::forge::AuthError) -> String {
    match error {
        crate::forge::AuthError::RateLimited(response) => {
            format!(
                "managed credential probe was rate limited by upstream: {}",
                response.status
            )
        }
        crate::forge::AuthError::Other(error) => {
            format!("managed credential probe failed: {error}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_repo_split_accepts_nested_repo_path() {
        assert_eq!(
            local_acceleration_status_from_owner_repo_missing_ok("org/deep/repo"),
            Some(("org", "deep/repo"))
        );
    }

    #[test]
    fn status_reports_eligibility() {
        assert!(
            ManagedOrgCredentialStatus::Eligible {
                mode: CredentialMode::Pat
            }
            .is_eligible()
        );
        assert!(
            !ManagedOrgCredentialStatus::Missing {
                reason: "missing".to_string()
            }
            .is_eligible()
        );
        assert!(
            !ManagedOrgCredentialStatus::Unusable {
                reason: "bad".to_string()
            }
            .is_eligible()
        );
    }
}
