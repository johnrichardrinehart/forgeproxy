use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    #[default]
    None = 0,
    Read = 1,
    Write = 2,
    Admin = 3,
}

impl Permission {
    pub fn has_read(&self) -> bool {
        *self >= Permission::Read
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "admin" => Permission::Admin,
            "write" | "push" => Permission::Write,
            "read" | "pull" => Permission::Read,
            _ => Permission::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Admin => "admin",
            Permission::Write => "write",
            Permission::Read => "read",
            Permission::None => "none",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_permission_equality() {
        assert_eq!(Permission::Read, Permission::Read);
        assert_ne!(Permission::Read, Permission::Write);
    }

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
        assert_eq!(
            serde_json::to_string(&Permission::None).unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&Permission::Read).unwrap(),
            "\"read\""
        );
        assert_eq!(
            serde_json::to_string(&Permission::Write).unwrap(),
            "\"write\""
        );
        assert_eq!(
            serde_json::to_string(&Permission::Admin).unwrap(),
            "\"admin\""
        );
    }
}
