use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use tracing::{debug, instrument};

// ---------------------------------------------------------------------------
// Free functions — operate on explicit bucket / key parameters.
// ---------------------------------------------------------------------------

/// Upload a local file to S3.
#[instrument(skip(client, metrics), fields(%bucket, %key))]
pub async fn upload_bundle(
    client: &Client,
    metrics: &crate::metrics::MetricsRegistry,
    bucket: &str,
    key: &str,
    file_path: &Path,
) -> Result<()> {
    let size_bytes = tokio::fs::metadata(file_path)
        .await
        .with_context(|| format!("stat file for upload: {}", file_path.display()))?
        .len();
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

    metrics.metrics.s3_upload_bytes.inc_by(size_bytes);
    debug!(path = %file_path.display(), "bundle uploaded");
    Ok(())
}

/// Download an S3 object to a local file path, creating parent directories if
/// needed.
#[instrument(skip(client, metrics), fields(%bucket, %key, path = %file_path.display()))]
pub async fn download_to_path(
    client: &Client,
    metrics: &crate::metrics::MetricsRegistry,
    bucket: &str,
    key: &str,
    file_path: &Path,
) -> Result<()> {
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create parent directories for {}", file_path.display()))?;
    }

    let response = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 GetObject")?;

    let bytes = response
        .body
        .collect()
        .await
        .context("read S3 object body")?
        .into_bytes();

    tokio::fs::write(file_path, &bytes)
        .await
        .with_context(|| format!("write downloaded object to {}", file_path.display()))?;

    metrics.metrics.s3_download_bytes.inc_by(bytes.len() as u64);
    debug!(path = %file_path.display(), bytes = bytes.len(), "S3 object downloaded");
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
