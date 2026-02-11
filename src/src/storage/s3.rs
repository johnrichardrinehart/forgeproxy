use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use tracing::{debug, instrument};

/// High-level wrapper around an S3 bucket used for bundle storage.
pub struct S3Storage {
    pub client: Client,
    pub bucket: String,
    pub prefix: String,
    pub presigned_url_ttl: Duration,
}

impl S3Storage {
    /// Create a new `S3Storage` from an already-configured `Client` and an
    /// application-level S3 config section.
    pub fn new(client: Client, bucket: String, prefix: String, presigned_url_ttl: Duration) -> Self {
        Self {
            client,
            bucket,
            prefix,
            presigned_url_ttl,
        }
    }

    /// Build the full S3 object key for a named artifact inside a repository.
    fn s3_key(&self, owner_repo: &str, name: &str) -> String {
        format!("{}{}/{}", self.prefix, owner_repo, name)
    }

    // -----------------------------------------------------------------------
    // Convenience wrappers that delegate to the free functions using this
    // instance's bucket and prefix.
    // -----------------------------------------------------------------------

    pub async fn upload(&self, owner_repo: &str, name: &str, file_path: &Path) -> Result<()> {
        let key = self.s3_key(owner_repo, name);
        upload_bundle(&self.client, &self.bucket, &key, file_path).await
    }

    pub async fn download(&self, owner_repo: &str, name: &str, dest: &Path) -> Result<()> {
        let key = self.s3_key(owner_repo, name);
        download_bundle(&self.client, &self.bucket, &key, dest).await
    }

    pub async fn presigned_url(&self, owner_repo: &str, name: &str) -> Result<String> {
        let key = self.s3_key(owner_repo, name);
        generate_presigned_url(
            &self.client,
            &self.bucket,
            &key,
            self.presigned_url_ttl.as_secs(),
        )
        .await
    }

    pub async fn delete(&self, owner_repo: &str, name: &str) -> Result<()> {
        let key = self.s3_key(owner_repo, name);
        delete_bundle(&self.client, &self.bucket, &key).await
    }

    pub async fn list(&self, owner_repo: &str) -> Result<Vec<String>> {
        let prefix = format!("{}{}/", self.prefix, owner_repo);
        list_bundles(&self.client, &self.bucket, &prefix).await
    }

    pub async fn exists(&self, owner_repo: &str, name: &str) -> Result<bool> {
        let key = self.s3_key(owner_repo, name);
        bundle_exists(&self.client, &self.bucket, &key).await
    }
}

// ---------------------------------------------------------------------------
// Free functions — operate on explicit bucket / key parameters.
// ---------------------------------------------------------------------------

/// Upload a local file to S3.
#[instrument(skip(client), fields(%bucket, %key))]
pub async fn upload_bundle(
    client: &Client,
    bucket: &str,
    key: &str,
    file_path: &Path,
) -> Result<()> {
    let body = ByteStream::from_path(file_path)
        .await
        .with_context(|| format!("open file for upload: {}", file_path.display()))?;

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .context("S3 PutObject")?;

    debug!(path = %file_path.display(), "bundle uploaded");
    Ok(())
}

/// Download an S3 object to a local file.
#[instrument(skip(client), fields(%bucket, %key))]
pub async fn download_bundle(
    client: &Client,
    bucket: &str,
    key: &str,
    dest: &Path,
) -> Result<()> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 GetObject")?;

    let bytes = resp
        .body
        .collect()
        .await
        .context("read S3 GetObject body")?
        .into_bytes();

    // Ensure the parent directory exists.
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create parent dirs for {}", dest.display()))?;
    }

    tokio::fs::write(dest, &bytes)
        .await
        .with_context(|| format!("write downloaded bundle to {}", dest.display()))?;

    debug!(path = %dest.display(), bytes = bytes.len(), "bundle downloaded");
    Ok(())
}

/// Upload a text blob (e.g. a bundle-list manifest) to S3.
#[instrument(skip(client, content), fields(%bucket, %key))]
pub async fn upload_bundle_list(
    client: &Client,
    bucket: &str,
    key: &str,
    content: &str,
) -> Result<()> {
    let body = ByteStream::from(content.as_bytes().to_vec());

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .content_type("text/plain")
        .send()
        .await
        .context("S3 PutObject bundle list")?;

    debug!(len = content.len(), "bundle list uploaded");
    Ok(())
}

/// Generate a pre-signed GET URL for an S3 object.
#[instrument(skip(client), fields(%bucket, %key, ttl_secs))]
pub async fn generate_presigned_url(
    client: &Client,
    bucket: &str,
    key: &str,
    ttl_secs: u64,
) -> Result<String> {
    let presigning = PresigningConfig::builder()
        .expires_in(Duration::from_secs(ttl_secs))
        .build()
        .context("build PresigningConfig")?;

    let req = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .presigned(presigning)
        .await
        .context("generate presigned URL")?;

    let url = req.uri().to_string();
    debug!(%url, "presigned URL generated");
    Ok(url)
}

/// Delete an object from S3.
#[instrument(skip(client), fields(%bucket, %key))]
pub async fn delete_bundle(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<()> {
    client
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 DeleteObject")?;

    debug!("bundle deleted");
    Ok(())
}

/// List all object keys under a given prefix.
///
/// Automatically paginates through all results.
#[instrument(skip(client), fields(%bucket, %prefix))]
pub async fn list_bundles(
    client: &Client,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix);

        if let Some(ref token) = continuation_token {
            req = req.continuation_token(token);
        }

        let resp = req.send().await.context("S3 ListObjectsV2")?;

        for obj in resp.contents() {
            if let Some(k) = obj.key() {
                keys.push(k.to_string());
            }
        }

        match resp.next_continuation_token() {
            Some(token) => {
                continuation_token = Some(token.to_string());
            }
            None => break,
        }
    }

    debug!(count = keys.len(), "listed bundles");
    Ok(keys)
}

/// Check whether an object exists in S3 (HEAD request).
#[instrument(skip(client), fields(%bucket, %key))]
pub async fn bundle_exists(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<bool> {
    match client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
    {
        Ok(_) => {
            debug!("bundle exists");
            Ok(true)
        }
        Err(err) => {
            // The SDK returns a service error with code "NotFound" (or an
            // HTTP 404) when the object does not exist.
            if err
                .as_service_error()
                .map_or(false, |e| e.is_not_found())
            {
                debug!("bundle does not exist");
                Ok(false)
            } else {
                Err(err).context("S3 HeadObject")
            }
        }
    }
}
