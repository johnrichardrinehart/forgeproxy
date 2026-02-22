//! Cache eviction telemetry.
//!
//! Records structured JSON events on each eviction sweep and periodically
//! flushes them to S3 as zstd-compressed JSON lines.  Entries older than 1
//! year are pruned on each flush.

use std::io::{BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::AppState;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// A single eviction sweep event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionEvent {
    /// Unix timestamp of the sweep.
    pub ts: i64,
    /// Policy used (`lfu` or `lru`).
    pub policy: String,
    /// Number of candidates considered.
    pub candidates: usize,
    /// Number of repos actually evicted.
    pub evicted: usize,
    /// Per-repo detail.
    pub repos: Vec<RepoDetail>,
}

/// Per-repo metadata captured at eviction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoDetail {
    pub name: String,
    pub clone_count: u64,
    pub last_fetch_ts: i64,
    pub size_bytes: u64,
    pub evicted: bool,
}

// ---------------------------------------------------------------------------
// Telemetry buffer
// ---------------------------------------------------------------------------

/// In-memory buffer for eviction events.  Flushed to S3 periodically.
#[derive(Clone)]
pub struct TelemetryBuffer {
    events: Arc<Mutex<Vec<EvictionEvent>>>,
}

impl TelemetryBuffer {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Append an eviction event to the buffer.
    pub async fn record(&self, event: EvictionEvent) {
        self.events.lock().await.push(event);
    }

    /// Drain all buffered events.
    async fn drain(&self) -> Vec<EvictionEvent> {
        let mut buf = self.events.lock().await;
        std::mem::take(&mut *buf)
    }
}

// ---------------------------------------------------------------------------
// S3 flush
// ---------------------------------------------------------------------------

const RETENTION_SECS: i64 = 365 * 24 * 3600; // 1 year
const FLUSH_INTERVAL_SECS: u64 = 600; // 10 minutes
const TELEMETRY_LOCK_KEY: &str = "forgeproxy:lock:telemetry";
const TELEMETRY_LOCK_TTL: u64 = 60;

fn telemetry_s3_key(prefix: &str) -> String {
    format!("{prefix}telemetry/cache-eviction.jsonl.zst")
}

/// Run the periodic flush loop.  Should be spawned as a background task.
pub async fn run_telemetry_flusher(state: Arc<AppState>, buffer: TelemetryBuffer) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS));
    loop {
        interval.tick().await;
        if let Err(e) = flush_to_s3(&state, &buffer).await {
            warn!(error = %e, "telemetry flush failed");
        }
    }
}

/// Flush buffered events to S3.  Acquires a distributed lock to serialize
/// concurrent writers across nodes.
pub async fn flush_to_s3(state: &AppState, buffer: &TelemetryBuffer) -> Result<()> {
    let events = buffer.drain().await;
    if events.is_empty() {
        return Ok(());
    }

    let node_id = &state.node_id;

    // Acquire lock to serialize writers.
    let locked = crate::coordination::locks::acquire_lock(
        &state.keydb,
        TELEMETRY_LOCK_KEY,
        node_id,
        TELEMETRY_LOCK_TTL,
    )
    .await?;

    if !locked {
        // Another node is flushing; re-buffer our events and retry next cycle.
        for event in events {
            buffer.record(event).await;
        }
        debug!("telemetry flush deferred: lock held by another node");
        return Ok(());
    }

    let result = flush_inner(state, &events).await;

    // Always release the lock.
    let _ =
        crate::coordination::locks::release_lock(&state.keydb, TELEMETRY_LOCK_KEY, node_id).await;

    result
}

async fn flush_inner(state: &AppState, new_events: &[EvictionEvent]) -> Result<()> {
    let s3_key = telemetry_s3_key(&state.config.storage.s3.prefix);
    let bucket = &state.config.storage.s3.bucket;
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - RETENTION_SECS;

    // 1. Download existing file (if any).
    let existing = download_existing(&state.s3_client, bucket, &s3_key).await;

    // 2. Parse existing events, prune old ones.
    let mut all_events: Vec<EvictionEvent> = match existing {
        Ok(data) => decompress_and_parse(&data, cutoff),
        Err(_) => Vec::new(),
    };

    // 3. Append new events.
    all_events.extend(new_events.iter().cloned());

    // 4. Compress and upload.
    let compressed = compress_events(&all_events)?;
    upload_bytes(&state.s3_client, bucket, &s3_key, compressed).await?;

    debug!(
        events = all_events.len(),
        new = new_events.len(),
        "telemetry flushed to S3"
    );
    Ok(())
}

async fn download_existing(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 GetObject for telemetry")?;

    let data = resp
        .body
        .collect()
        .await
        .context("read telemetry body")?
        .into_bytes()
        .to_vec();

    Ok(data)
}

fn decompress_and_parse(compressed: &[u8], cutoff_ts: i64) -> Vec<EvictionEvent> {
    let decompressed = match zstd::decode_all(std::io::Cursor::new(compressed)) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let reader = std::io::BufReader::new(std::io::Cursor::new(decompressed));
    reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<EvictionEvent>(&line).ok())
        .filter(|e| e.ts >= cutoff_ts)
        .collect()
}

fn compress_events(events: &[EvictionEvent]) -> Result<Vec<u8>> {
    let mut json_lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json_lines, event)?;
        json_lines.push(b'\n');
    }

    let mut encoder = zstd::Encoder::new(Vec::new(), 3)?;
    encoder.write_all(&json_lines)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

async fn upload_bytes(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    data: Vec<u8>,
) -> Result<()> {
    let body = aws_sdk_s3::primitives::ByteStream::from(data);
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .content_type("application/zstd")
        .send()
        .await
        .context("S3 PutObject for telemetry")?;
    Ok(())
}
