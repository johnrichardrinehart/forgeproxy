//! Archive cache helpers for local disk + S3 archive caching.
//!
//! Archives (tarballs, zip files) are cached by their resolved commit SHA so
//! that mutable refs (branches, tags) are properly tracked while immutable
//! refs (commit SHAs) are served from cache indefinitely.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Recognised archive extensions.
const ARCHIVE_EXTENSIONS: &[&str] = &[".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip"];

/// Parse the `rest` segment of an archive URL into `(ref_name, extension)`.
///
/// Examples:
/// - `"refs/heads/main.tar.gz"` → `("refs/heads/main", ".tar.gz")`
/// - `"v1.2.3.zip"` → `("v1.2.3", ".zip")`
/// - `"main.tar.gz"` → `("main", ".tar.gz")`
pub fn parse_archive_rest(rest: &str) -> Option<(String, String)> {
    for ext in ARCHIVE_EXTENSIONS {
        if let Some(ref_name) = rest.strip_suffix(ext)
            && !ref_name.is_empty()
        {
            return Some((ref_name.to_string(), ext.to_string()));
        }
    }
    None
}

/// Sanitize a ref name for safe use as a filesystem path component.
///
/// Replaces `/` with `-` so that `refs/heads/main` becomes `refs-heads-main`.
pub fn sanitize_ref_name(ref_name: &str) -> String {
    ref_name.replace('/', "-")
}

// ---------------------------------------------------------------------------
// Path / key construction
// ---------------------------------------------------------------------------

/// Build the cache filename: `{sanitized_ref}-{sha_prefix}{ext}`.
///
/// The SHA is truncated to 12 characters for readability.
pub fn archive_cache_filename(ref_name: &str, sha: &str, ext: &str) -> String {
    let sanitized = sanitize_ref_name(ref_name);
    let sha_prefix = &sha[..sha.len().min(12)];
    format!("{sanitized}-{sha_prefix}{ext}")
}

/// Compute the local disk path for a cached archive.
///
/// Layout: `{base_path}/_archives/{owner}/{repo}/{filename}`
pub fn archive_local_path(
    base_path: &Path,
    owner: &str,
    repo: &str,
    ref_name: &str,
    sha: &str,
    ext: &str,
) -> PathBuf {
    let filename = archive_cache_filename(ref_name, sha, ext);
    base_path
        .join("_archives")
        .join(owner)
        .join(repo)
        .join(filename)
}

/// Compute the S3 object key for a cached archive.
///
/// Layout: `{prefix}archives/{owner}/{repo}/{filename}`
pub fn archive_s3_key(
    prefix: &str,
    owner: &str,
    repo: &str,
    ref_name: &str,
    sha: &str,
    ext: &str,
) -> String {
    let filename = archive_cache_filename(ref_name, sha, ext);
    format!("{prefix}archives/{owner}/{repo}/{filename}")
}

// ---------------------------------------------------------------------------
// S3 helpers
// ---------------------------------------------------------------------------

/// Check whether an object exists in S3 via `HeadObject`.
pub async fn s3_cache_hit(client: &S3Client, bucket: &str, key: &str) -> bool {
    client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .is_ok()
}

/// Download an S3 object to a local file path, creating parent directories
/// as needed.
pub async fn download_from_s3(
    client: &S3Client,
    bucket: &str,
    key: &str,
    local_path: &Path,
) -> Result<()> {
    if let Some(parent) = local_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create parent dirs for {}", local_path.display()))?;
    }

    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 GetObject for archive")?;

    let body = resp
        .body
        .collect()
        .await
        .context("reading S3 object body")?;

    let tmp_path = local_path.with_extension("tmp");
    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("create temp file {}", tmp_path.display()))?;
    file.write_all(&body.into_bytes())
        .await
        .context("write S3 body to temp file")?;
    file.flush().await?;

    tokio::fs::rename(&tmp_path, local_path)
        .await
        .with_context(|| format!("rename {} → {}", tmp_path.display(), local_path.display()))?;

    debug!(path = %local_path.display(), "archive downloaded from S3");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tee streaming (upstream → client + disk)
// ---------------------------------------------------------------------------

/// Consume an upstream response, writing chunks to both an mpsc sender (for
/// the client response body) and a temp file on disk.  On success, renames
/// the temp file to the final path.
///
/// Returns the receiver stream that produces `Result<Bytes>` chunks.
pub fn tee_upstream_to_cache(
    upstream_resp: reqwest::Response,
    local_path: PathBuf,
) -> (
    tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    let handle = tokio::spawn(async move {
        use futures::StreamExt;

        // Ensure parent dirs exist.
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create parent dirs for {}", local_path.display()))?;
        }

        let tmp_path = local_path.with_extension("tmp");
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .with_context(|| format!("create temp file {}", tmp_path.display()))?;

        let mut stream = upstream_resp.bytes_stream();
        let mut success = true;

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    if let Err(e) = file.write_all(&chunk).await {
                        warn!(error = %e, "failed to write archive chunk to disk");
                        success = false;
                        // Still try to send to client.
                        let _ = tx.send(Ok(chunk)).await;
                        break;
                    }
                    if tx.send(Ok(chunk)).await.is_err() {
                        // Client disconnected.
                        success = false;
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    success = false;
                    break;
                }
            }
        }

        if success {
            file.flush().await?;
            drop(file);
            tokio::fs::rename(&tmp_path, &local_path)
                .await
                .with_context(|| {
                    format!("rename {} → {}", tmp_path.display(), local_path.display())
                })?;
            debug!(path = %local_path.display(), "archive cached to local disk");
        } else {
            // Clean up partial temp file.
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }

        Ok(())
    });

    (rx, handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_archive_rest ─────────────────────────────────────────────

    #[test]
    fn parse_tar_gz() {
        let (ref_name, ext) = parse_archive_rest("main.tar.gz").unwrap();
        assert_eq!(ref_name, "main");
        assert_eq!(ext, ".tar.gz");
    }

    #[test]
    fn parse_zip() {
        let (ref_name, ext) = parse_archive_rest("v1.2.3.zip").unwrap();
        assert_eq!(ref_name, "v1.2.3");
        assert_eq!(ext, ".zip");
    }

    #[test]
    fn parse_refs_heads_prefix() {
        let (ref_name, ext) = parse_archive_rest("refs/heads/feature/foo.tar.gz").unwrap();
        assert_eq!(ref_name, "refs/heads/feature/foo");
        assert_eq!(ext, ".tar.gz");
    }

    #[test]
    fn parse_tgz() {
        let (ref_name, ext) = parse_archive_rest("release-1.0.tgz").unwrap();
        assert_eq!(ref_name, "release-1.0");
        assert_eq!(ext, ".tgz");
    }

    #[test]
    fn parse_no_extension_returns_none() {
        assert!(parse_archive_rest("main").is_none());
    }

    #[test]
    fn parse_extension_only_returns_none() {
        assert!(parse_archive_rest(".tar.gz").is_none());
    }

    // ── sanitize_ref_name ──────────────────────────────────────────────

    #[test]
    fn sanitize_simple_ref() {
        assert_eq!(sanitize_ref_name("main"), "main");
    }

    #[test]
    fn sanitize_slashes() {
        assert_eq!(
            sanitize_ref_name("refs/heads/feature/foo"),
            "refs-heads-feature-foo"
        );
    }

    #[test]
    fn sanitize_no_slashes() {
        assert_eq!(sanitize_ref_name("v1.2.3"), "v1.2.3");
    }

    // ── archive_cache_filename ─────────────────────────────────────────

    #[test]
    fn filename_basic() {
        let f = archive_cache_filename("main", "a1b2c3d4e5f6a7b8c9d0", ".tar.gz");
        assert_eq!(f, "main-a1b2c3d4e5f6.tar.gz");
    }

    #[test]
    fn filename_with_slashes_in_ref() {
        let f = archive_cache_filename("refs/heads/main", "abcdef123456", ".zip");
        assert_eq!(f, "refs-heads-main-abcdef123456.zip");
    }

    #[test]
    fn filename_short_sha() {
        let f = archive_cache_filename("v1.0", "abc", ".tar.gz");
        assert_eq!(f, "v1.0-abc.tar.gz");
    }

    // ── archive_local_path ─────────────────────────────────────────────

    #[test]
    fn local_path_construction() {
        let path = archive_local_path(
            Path::new("/var/cache/forgeproxy/repos"),
            "acme",
            "widgets",
            "main",
            "a1b2c3d4e5f6a7b8",
            ".tar.gz",
        );
        assert_eq!(
            path,
            PathBuf::from(
                "/var/cache/forgeproxy/repos/_archives/acme/widgets/main-a1b2c3d4e5f6.tar.gz"
            )
        );
    }

    // ── archive_s3_key ─────────────────────────────────────────────────

    #[test]
    fn s3_key_construction() {
        let key = archive_s3_key(
            "forgeproxy/",
            "acme",
            "widgets",
            "main",
            "a1b2c3d4e5f6a7b8",
            ".tar.gz",
        );
        assert_eq!(
            key,
            "forgeproxy/archives/acme/widgets/main-a1b2c3d4e5f6.tar.gz"
        );
    }

    #[test]
    fn s3_key_with_branch_slash() {
        let key = archive_s3_key(
            "prefix/",
            "org",
            "repo",
            "feature/branch",
            "deadbeef1234",
            ".zip",
        );
        assert_eq!(
            key,
            "prefix/archives/org/repo/feature-branch-deadbeef1234.zip"
        );
    }
}
