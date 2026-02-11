use super::upstream::CredentialMode;

/// Translate an SSH upstream URL to HTTPS with an embedded PAT for authentication.
///
/// Produces a URL of the form:
///   `https://x-access-token:{pat}@{ghe_hostname}/{owner}/{repo}.git`
pub fn translate_upstream_url(
    ghe_hostname: &str,
    owner: &str,
    repo: &str,
    pat: &str,
) -> String {
    format!("https://x-access-token:{pat}@{ghe_hostname}/{owner}/{repo}.git")
}

/// Check if upstream operations should use HTTPS translation (PAT mode)
/// instead of native SSH transport.
pub fn should_translate(credential: &CredentialMode) -> bool {
    matches!(credential, CredentialMode::Pat { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_url() {
        let url = translate_upstream_url("ghe.example.com", "acme", "widgets", "ghp_abc123");
        assert_eq!(
            url,
            "https://x-access-token:ghp_abc123@ghe.example.com/acme/widgets.git"
        );
    }

    #[test]
    fn test_translate_url_with_special_chars_in_pat() {
        let url = translate_upstream_url("ghe.corp.net", "org", "repo", "ghp_x+y/z=");
        assert_eq!(
            url,
            "https://x-access-token:ghp_x+y/z=@ghe.corp.net/org/repo.git"
        );
    }

    #[test]
    fn test_translate_url_preserves_case() {
        let url = translate_upstream_url("GHE.Example.COM", "MyOrg", "MyRepo", "token");
        assert_eq!(
            url,
            "https://x-access-token:token@GHE.Example.COM/MyOrg/MyRepo.git"
        );
    }

    #[test]
    fn test_should_translate_pat() {
        assert!(should_translate(&CredentialMode::Pat {
            token: "x".into()
        }));
    }

    #[test]
    fn test_should_not_translate_ssh() {
        assert!(!should_translate(&CredentialMode::SshKey {
            key_data: "x".into()
        }));
    }
}
