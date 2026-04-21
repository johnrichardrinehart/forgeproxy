use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, instrument, warn};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const S3_SINGLE_PUT_MAX_BYTES: u64 = 5 * GIB;
const S3_MULTIPART_MIN_PART_SIZE_BYTES: u64 = 5 * MIB;
const S3_MULTIPART_DEFAULT_PART_SIZE_BYTES: u64 = 64 * MIB;
const S3_MULTIPART_MAX_PART_SIZE_BYTES: u64 = 5 * GIB;
const S3_MULTIPART_MAX_PARTS: u64 = 10_000;

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
    if size_bytes > S3_SINGLE_PUT_MAX_BYTES {
        upload_bundle_multipart(client, bucket, key, file_path, size_bytes).await?;
        metrics.metrics.s3_upload_bytes.inc_by(size_bytes);
        debug!(path = %file_path.display(), size_bytes, "bundle uploaded with S3 multipart upload");
        return Ok(());
    }

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

async fn upload_bundle_multipart(
    client: &Client,
    bucket: &str,
    key: &str,
    file_path: &Path,
    size_bytes: u64,
) -> Result<()> {
    let part_size = multipart_part_size(size_bytes)?;
    debug!(
        path = %file_path.display(),
        size_bytes,
        part_size,
        "starting S3 multipart bundle upload"
    );

    let response = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 CreateMultipartUpload")?;
    let upload_id = response
        .upload_id()
        .context("S3 CreateMultipartUpload response did not include upload_id")?
        .to_string();

    match upload_bundle_multipart_parts(client, bucket, key, file_path, &upload_id, part_size).await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            warn!(
                bucket,
                key,
                %upload_id,
                error = %error,
                "aborting failed S3 multipart bundle upload"
            );
            if let Err(abort_error) = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await
            {
                warn!(
                    bucket,
                    key,
                    %upload_id,
                    error = %abort_error,
                    "failed to abort S3 multipart bundle upload"
                );
            }
            Err(error)
        }
    }
}

async fn upload_bundle_multipart_parts(
    client: &Client,
    bucket: &str,
    key: &str,
    file_path: &Path,
    upload_id: &str,
    part_size: u64,
) -> Result<()> {
    let buffer_len: usize = part_size
        .try_into()
        .context("multipart part size does not fit usize")?;
    let mut file = tokio::fs::File::open(file_path)
        .await
        .with_context(|| format!("open file for multipart upload: {}", file_path.display()))?;
    let mut buffer = vec![0_u8; buffer_len];
    let mut completed_parts = Vec::new();
    let mut part_number = 1;

    loop {
        let bytes_read = read_multipart_part(&mut file, &mut buffer)
            .await
            .with_context(|| format!("read multipart upload part from {}", file_path.display()))?;
        if bytes_read == 0 {
            break;
        }

        let response = client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(buffer[..bytes_read].to_vec()))
            .send()
            .await
            .with_context(|| format!("S3 UploadPart part_number={part_number}"))?;
        let e_tag = response
            .e_tag()
            .with_context(|| format!("S3 UploadPart part_number={part_number} missing ETag"))?
            .to_string();
        completed_parts.push(
            CompletedPart::builder()
                .set_e_tag(Some(e_tag))
                .set_part_number(Some(part_number))
                .build(),
        );
        part_number += 1;
    }

    anyhow::ensure!(
        !completed_parts.is_empty(),
        "cannot complete multipart upload without parts"
    );
    let multipart_upload = CompletedMultipartUpload::builder()
        .set_parts(Some(completed_parts))
        .build();
    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(multipart_upload)
        .send()
        .await
        .context("S3 CompleteMultipartUpload")?;
    Ok(())
}

async fn read_multipart_part<R>(reader: &mut R, buffer: &mut [u8]) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buffer.len() {
        let bytes_read = reader
            .read(&mut buffer[filled..])
            .await
            .context("read multipart upload part")?;
        if bytes_read == 0 {
            break;
        }
        filled += bytes_read;
    }
    Ok(filled)
}

fn multipart_part_size(size_bytes: u64) -> Result<u64> {
    let minimum_for_part_limit = size_bytes.div_ceil(S3_MULTIPART_MAX_PARTS);
    let part_size = S3_MULTIPART_DEFAULT_PART_SIZE_BYTES
        .max(S3_MULTIPART_MIN_PART_SIZE_BYTES)
        .max(minimum_for_part_limit);
    anyhow::ensure!(
        part_size <= S3_MULTIPART_MAX_PART_SIZE_BYTES,
        "object is too large for S3 multipart upload"
    );
    Ok(part_size)
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

/// Delete an S3 object if present.
#[instrument(skip(client), fields(%bucket, %key))]
pub async fn delete_object_if_exists(client: &Client, bucket: &str, key: &str) -> Result<()> {
    client
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 DeleteObject")?;
    debug!("S3 object deleted");
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn multipart_part_size_uses_default_for_typical_large_bundle() {
        let size = S3_SINGLE_PUT_MAX_BYTES + 1;

        assert_eq!(
            multipart_part_size(size).unwrap(),
            S3_MULTIPART_DEFAULT_PART_SIZE_BYTES
        );
    }

    #[test]
    fn multipart_part_size_grows_to_stay_under_part_limit() {
        let size = S3_MULTIPART_DEFAULT_PART_SIZE_BYTES * (S3_MULTIPART_MAX_PARTS + 1);
        let part_size = multipart_part_size(size).unwrap();

        assert!(size.div_ceil(part_size) <= S3_MULTIPART_MAX_PARTS);
        assert!(part_size > S3_MULTIPART_DEFAULT_PART_SIZE_BYTES);
    }

    #[tokio::test]
    async fn read_multipart_part_fills_non_final_part_across_short_reads() {
        let (mut writer, mut reader) = tokio::io::duplex(4);
        let write_task = tokio::spawn(async move {
            writer.write_all(&[1, 2, 3]).await.unwrap();
            writer.write_all(&[4, 5, 6, 7]).await.unwrap();
            writer.write_all(&[8, 9, 10, 11, 12]).await.unwrap();
        });

        let mut buffer = vec![0_u8; 10];
        let first_len = read_multipart_part(&mut reader, &mut buffer).await.unwrap();
        assert_eq!(first_len, 10);
        assert_eq!(&buffer[..first_len], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        write_task.await.unwrap();
        let second_len = read_multipart_part(&mut reader, &mut buffer).await.unwrap();
        assert_eq!(second_len, 2);
        assert_eq!(&buffer[..second_len], &[11, 12]);

        let eof_len = read_multipart_part(&mut reader, &mut buffer).await.unwrap();
        assert_eq!(eof_len, 0);
    }
}
