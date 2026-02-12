use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use tracing::{debug, instrument};

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
