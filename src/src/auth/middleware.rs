use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub allowed: bool,
    pub username: Option<String>,
    pub permission: Permission,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    None = 0,
    Read = 1,
    Write = 2,
    Admin = 3,
}

impl Permission {
    pub fn has_read(&self) -> bool {
        *self >= Permission::Read
    }
}

impl Default for Permission {
    fn default() -> Self {
        Permission::None
    }
}

/// Extract owner/repo from URL path like "/owner/repo/info/refs" or "owner/repo.git"
pub fn extract_owner_repo(path: &str) -> Option<(String, String)> {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() >= 2 {
        let owner = parts[0].to_string();
        let repo = parts[1].trim_end_matches(".git").to_string();
        Some((owner, repo))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Permission ordering ──────────────────────────────────────────

    #[test]
    fn test_permission_ordering() {
        assert!(Permission::None < Permission::Read);
        assert!(Permission::Read < Permission::Write);
        assert!(Permission::Write < Permission::Admin);
    }

    #[test]
    fn test_permission_has_read() {
        assert!(!Permission::None.has_read());
        assert!(Permission::Read.has_read());
        assert!(Permission::Write.has_read());
        assert!(Permission::Admin.has_read());
    }

    #[test]
    fn test_permission_default() {
        assert_eq!(Permission::default(), Permission::None);
    }

    // ── Permission equality ──────────────────────────────────────────

    #[test]
    fn test_permission_equality() {
        assert_eq!(Permission::Read, Permission::Read);
        assert_ne!(Permission::Read, Permission::Write);
    }

    // ── Serde round-trip ─────────────────────────────────────────────

    #[test]
    fn test_permission_serde_roundtrip() {
        let perms = [
            Permission::None,
            Permission::Read,
            Permission::Write,
            Permission::Admin,
        ];
        for perm in &perms {
            let json = serde_json::to_string(perm).unwrap();
            let back: Permission = serde_json::from_str(&json).unwrap();
            assert_eq!(*perm, back);
        }
    }

    #[test]
    fn test_permission_serde_values() {
        assert_eq!(serde_json::to_string(&Permission::None).unwrap(), "\"none\"");
        assert_eq!(serde_json::to_string(&Permission::Read).unwrap(), "\"read\"");
        assert_eq!(serde_json::to_string(&Permission::Write).unwrap(), "\"write\"");
        assert_eq!(serde_json::to_string(&Permission::Admin).unwrap(), "\"admin\"");
    }

    #[test]
    fn test_auth_result_serde() {
        let result = AuthResult {
            allowed: true,
            username: Some("alice".to_string()),
            permission: Permission::Write,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: AuthResult = serde_json::from_str(&json).unwrap();
        assert!(back.allowed);
        assert_eq!(back.username.as_deref(), Some("alice"));
        assert_eq!(back.permission, Permission::Write);
        assert!(back.reason.is_none());
    }

    #[test]
    fn test_auth_result_denied() {
        let result = AuthResult {
            allowed: false,
            username: None,
            permission: Permission::None,
            reason: Some("bad credentials".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: AuthResult = serde_json::from_str(&json).unwrap();
        assert!(!back.allowed);
        assert!(back.username.is_none());
        assert_eq!(back.permission, Permission::None);
        assert_eq!(back.reason.as_deref(), Some("bad credentials"));
    }

    // ── extract_owner_repo ───────────────────────────────────────────

    #[test]
    fn test_extract_basic_path() {
        let result = extract_owner_repo("/acme/widgets/info/refs");
        assert_eq!(result, Some(("acme".to_string(), "widgets".to_string())));
    }

    #[test]
    fn test_extract_dotgit_suffix() {
        let result = extract_owner_repo("/acme/widgets.git");
        assert_eq!(result, Some(("acme".to_string(), "widgets".to_string())));
    }

    #[test]
    fn test_extract_dotgit_with_trailing() {
        let result = extract_owner_repo("/acme/widgets.git/info/refs");
        assert_eq!(result, Some(("acme".to_string(), "widgets".to_string())));
    }

    #[test]
    fn test_extract_no_leading_slash() {
        let result = extract_owner_repo("acme/widgets/git-upload-pack");
        assert_eq!(result, Some(("acme".to_string(), "widgets".to_string())));
    }

    #[test]
    fn test_extract_just_owner_repo() {
        let result = extract_owner_repo("/acme/widgets");
        assert_eq!(result, Some(("acme".to_string(), "widgets".to_string())));
    }

    #[test]
    fn test_extract_single_segment() {
        let result = extract_owner_repo("/acme");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_empty_path() {
        let result = extract_owner_repo("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_slash_only() {
        let result = extract_owner_repo("/");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_deep_nested_path() {
        let result = extract_owner_repo("/org/repo/objects/pack/pack-abc.pack");
        assert_eq!(result, Some(("org".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_preserves_owner_case() {
        let result = extract_owner_repo("/MyOrg/MyRepo.git/info/refs");
        assert_eq!(result, Some(("MyOrg".to_string(), "MyRepo".to_string())));
    }
}
