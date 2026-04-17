use std::path::{Path, PathBuf};

pub(crate) const GENERATIONS_ROOT_DIR: &str = "published";
pub(crate) const MIRRORS_ROOT_DIR: &str = "mirrors";
pub(crate) const SNAPSHOTS_ROOT_DIR: &str = "snapshots";
pub(crate) const STATE_ROOT_DIR: &str = ".state";
pub(crate) const STATE_GENERATIONS_DIR: &str = "generations";
pub(crate) const STATE_DELTA_DIR: &str = "delta";
pub(crate) const STATE_TEE_DIR: &str = "tee";
pub(crate) const STATE_BUNDLE_TMP_DIR: &str = "bundle-tmp";

pub(crate) fn generations_root(base_path: &Path) -> PathBuf {
    base_path.join(GENERATIONS_ROOT_DIR)
}

pub(crate) fn mirrors_root(base_path: &Path) -> PathBuf {
    base_path.join(MIRRORS_ROOT_DIR)
}

pub(crate) fn snapshots_root(base_path: &Path) -> PathBuf {
    base_path.join(SNAPSHOTS_ROOT_DIR)
}

pub(crate) fn state_root(base_path: &Path) -> PathBuf {
    base_path.join(STATE_ROOT_DIR)
}

pub(crate) fn state_generations_root(base_path: &Path) -> PathBuf {
    state_root(base_path).join(STATE_GENERATIONS_DIR)
}

pub(crate) fn state_delta_root(base_path: &Path) -> PathBuf {
    state_root(base_path).join(STATE_DELTA_DIR)
}

pub(crate) fn state_tee_root(base_path: &Path) -> PathBuf {
    state_root(base_path).join(STATE_TEE_DIR)
}

pub(crate) fn state_bundle_tmp_root(base_path: &Path) -> PathBuf {
    state_root(base_path).join(STATE_BUNDLE_TMP_DIR)
}

pub(crate) fn repo_path_under(
    root: &Path,
    owner_repo: &str,
    keep_repo_git_suffix: bool,
) -> PathBuf {
    if let Some((owner, repo)) = split_owner_repo(owner_repo) {
        if keep_repo_git_suffix {
            root.join(owner)
                .join(format!("{}.git", normalize_repo_name(repo)))
        } else {
            root.join(owner).join(normalize_repo_name(repo))
        }
    } else if keep_repo_git_suffix {
        root.join(format!("{}.git", normalize_repo_name(owner_repo)))
    } else {
        root.join(normalize_repo_name(owner_repo))
    }
}

pub(crate) fn reader_repo_path(base_path: &Path, owner_repo: &str) -> PathBuf {
    repo_path_under(&generations_root(base_path), owner_repo, true)
}

pub(crate) fn state_generation_repo_dir(base_path: &Path, owner_repo: &str) -> PathBuf {
    repo_path_under(&state_generations_root(base_path), owner_repo, true)
}

pub(crate) fn mirror_repo_path(base_path: &Path, owner_repo: &str) -> PathBuf {
    repo_path_under(&mirrors_root(base_path), owner_repo, true)
}

pub(crate) fn delta_repo_dir(base_path: &Path, owner_repo: &str) -> PathBuf {
    repo_path_under(&state_delta_root(base_path), owner_repo, true)
}

pub(crate) fn tee_repo_dir(base_path: &Path, owner_repo: &str) -> PathBuf {
    repo_path_under(&state_tee_root(base_path), owner_repo, false)
}

pub(crate) fn snapshot_repo_dir(base_path: &Path, owner: &str, repo: &str) -> PathBuf {
    snapshots_root(base_path).join(owner).join(repo)
}

fn split_owner_repo(owner_repo: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = owner_repo.splitn(2, '/').collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

fn normalize_repo_name(name: &str) -> &str {
    crate::repo_identity::canonical_repo_leaf(name)
}
