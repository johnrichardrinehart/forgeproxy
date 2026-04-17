#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIdentity {
    requested: String,
    canonical: String,
}

impl RepoIdentity {
    pub fn new(owner: &str, repo: &str) -> Self {
        let requested = format!("{}/{}", owner.trim_matches('/'), repo.trim_matches('/'));
        let canonical = canonical_owner_repo(owner, repo);
        Self {
            requested,
            canonical,
        }
    }

    #[cfg(test)]
    pub fn from_owner_repo(owner_repo: &str) -> Self {
        Self {
            requested: owner_repo.to_string(),
            canonical: canonicalize_owner_repo(owner_repo),
        }
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn matches_upstream_full_name(&self, upstream_full_name: &str) -> bool {
        self.canonical == canonicalize_owner_repo(upstream_full_name)
    }
}

pub fn canonical_owner_repo(owner: &str, repo: &str) -> String {
    let owner = owner.trim_matches('/');
    let repo = canonical_repo_leaf(repo);
    if owner.is_empty() {
        repo.to_string()
    } else {
        format!("{owner}/{repo}")
    }
}

pub fn canonicalize_owner_repo(owner_repo: &str) -> String {
    let trimmed = owner_repo.trim().trim_matches('/');
    let Some((owner, repo)) = trimmed.split_once('/') else {
        return canonical_repo_leaf(trimmed).to_string();
    };
    canonical_owner_repo(owner, repo)
}

pub fn canonical_repo_leaf(repo: &str) -> &str {
    let repo = repo.trim().trim_matches('/');
    repo.strip_suffix(".git").unwrap_or(repo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_owner_repo_strips_git_transport_suffix() {
        assert_eq!(
            canonical_owner_repo("octocat", "widgets.git"),
            "octocat/widgets"
        );
        assert_eq!(
            canonical_owner_repo("octocat", "widgets"),
            "octocat/widgets"
        );
    }

    #[test]
    fn canonicalize_owner_repo_preserves_nested_namespace() {
        assert_eq!(
            canonicalize_owner_repo("/group/sub/project.git/"),
            "group/sub/project"
        );
    }

    #[test]
    fn identity_matches_suffix_variants() {
        let identity = RepoIdentity::from_owner_repo("octocat/widgets.git");
        assert!(identity.matches_upstream_full_name("octocat/widgets"));
        assert!(identity.matches_upstream_full_name("octocat/widgets.git"));
        assert!(!identity.matches_upstream_full_name("octocat/other"));
    }
}
