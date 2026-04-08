use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use tokio::io::AsyncWriteExt;
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

/// Upload an in-memory UTF-8 object to S3.
#[instrument(skip(client), fields(%bucket, %key, size_bytes = contents.len()))]
pub async fn upload_text(client: &Client, bucket: &str, key: &str, contents: &str) -> Result<()> {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(contents.as_bytes().to_vec()))
        .send()
        .await
        .context("S3 PutObject")?;

    debug!(bytes = contents.len(), "S3 text object uploaded");
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

    let mut file = tokio::fs::File::create(file_path)
        .await
        .with_context(|| format!("create downloaded object at {}", file_path.display()))?;

    let mut reader = response.body.into_async_read();
    let total_bytes = tokio::io::copy(&mut reader, &mut file)
        .await
        .context("stream S3 object body to disk")?;
    file.flush()
        .await
        .with_context(|| format!("flush downloaded object to {}", file_path.display()))?;

    metrics.metrics.s3_download_bytes.inc_by(total_bytes);
    debug!(path = %file_path.display(), bytes = total_bytes, "S3 object downloaded");
    Ok(())
}

/// Download an S3 object into memory, returning `None` if the object does not
/// exist.
#[instrument(skip(client, metrics), fields(%bucket, %key))]
pub async fn download_bytes_if_exists(
    client: &Client,
    metrics: &crate::metrics::MetricsRegistry,
    bucket: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let response = match client.get_object().bucket(bucket).key(key).send().await {
        Ok(response) => response,
        Err(error) => {
            if let Some(service_error) = error.as_service_error()
                && (service_error.code() == Some("NoSuchKey")
                    || service_error.code() == Some("NotFound"))
            {
                return Ok(None);
            }
            return Err(error).context("S3 GetObject");
        }
    };

    let bytes = response
        .body
        .collect()
        .await
        .context("read S3 object body")?
        .into_bytes();

    metrics.metrics.s3_download_bytes.inc_by(bytes.len() as u64);
    debug!(bytes = bytes.len(), "S3 object downloaded into memory");
    Ok(Some(bytes.to_vec()))
}

/// Download an S3 UTF-8 text object, returning `None` if the object does not
/// exist.
#[instrument(skip(client, metrics), fields(%bucket, %key))]
pub async fn download_text_if_exists(
    client: &Client,
    metrics: &crate::metrics::MetricsRegistry,
    bucket: &str,
    key: &str,
) -> Result<Option<String>> {
    let Some(bytes) = download_bytes_if_exists(client, metrics, bucket, key).await? else {
        return Ok(None);
    };

    let contents = String::from_utf8(bytes).context("S3 object body was not valid UTF-8")?;
    Ok(Some(contents))
}

/// List S3 object keys under a prefix.
#[instrument(skip(client), fields(%bucket, %prefix))]
pub async fn list_object_keys(client: &Client, bucket: &str, prefix: &str) -> Result<Vec<String>> {
    let mut continuation_token: Option<String> = None;
    let mut keys = Vec::new();

    loop {
        let mut request = client.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(token) = continuation_token.as_deref() {
            request = request.continuation_token(token);
        }

        let response = request.send().await.context("S3 ListObjectsV2")?;

        for object in response.contents() {
            if let Some(key) = object.key() {
                keys.push(key.to_string());
            }
        }

        if response.is_truncated().unwrap_or(false) {
            continuation_token = response.next_continuation_token().map(str::to_owned);
        } else {
            break;
        }
    }

    Ok(keys)
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
