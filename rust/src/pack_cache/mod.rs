use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

use crate::config::PackCacheConfig;
use crate::metrics::{MetricsRegistry, Protocol};

const PACK_CACHE_DIR: &str = "pack-cache";

#[derive(Clone)]
pub struct PackCache {
    root: PathBuf,
    config: PackCacheConfig,
    max_bytes: u64,
    inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    metrics: MetricsRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackCacheKey {
    digest: String,
}

impl PackCacheKey {
    pub fn as_str(&self) -> &str {
        &self.digest
    }
}

pub struct PackCacheHit {
    pub path: PathBuf,
    pub size_bytes: u64,
}

pub enum PackCacheLookup {
    Hit(PackCacheHit),
    Generate(Box<PackCacheWriter>),
    BypassAfterWait,
}

pub struct PackCacheWriter {
    key: PackCacheKey,
    final_path: PathBuf,
    tmp_path: PathBuf,
    root: PathBuf,
    max_bytes: u64,
    writer: BufWriter<File>,
    bytes_written: u64,
    min_response_bytes: u64,
    started_at: Instant,
    inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    notify: Arc<Notify>,
    metrics: MetricsRegistry,
    completed: bool,
}

impl PackCache {
    pub fn new(
        base_path: &Path,
        config: PackCacheConfig,
        local_cache_max_bytes: u64,
        metrics: MetricsRegistry,
    ) -> Self {
        let max_bytes = config.effective_max_bytes(local_cache_max_bytes);
        Self {
            root: base_path
                .join(crate::cache::layout::STATE_ROOT_DIR)
                .join(PACK_CACHE_DIR),
            config,
            max_bytes,
            inflight: Arc::new(Mutex::new(HashMap::new())),
            metrics,
        }
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        if self.config.enabled {
            tokio::fs::create_dir_all(&self.root)
                .await
                .with_context(|| format!("create pack cache root {}", self.root.display()))?;
            self.refresh_size_metric().await;
        }
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn key_for_fresh_clone(
        &self,
        owner_repo: &str,
        repo_path: &Path,
        request_body: &[u8],
        git_protocol: Option<&str>,
    ) -> std::result::Result<PackCacheKey, &'static str> {
        if !self.config.enabled {
            return Err("disabled");
        }
        if git_protocol != Some("version=2") {
            return Err("non_v2");
        }

        let normalized_request = normalize_fresh_clone_request(request_body)?;
        let ref_tips = repo_ref_tips_digest(repo_path)?;
        let mut hasher = Sha256::new();
        hasher.update(b"forgeproxy-pack-cache-v1\0");
        hasher.update(owner_repo.as_bytes());
        hasher.update(b"\0");
        hasher.update(ref_tips.as_bytes());
        hasher.update(b"\0");
        hasher.update(normalized_request.as_bytes());

        Ok(PackCacheKey {
            digest: hex_digest(hasher.finalize().as_slice()),
        })
    }

    pub async fn lookup_or_reserve(
        &self,
        protocol: Protocol,
        key: PackCacheKey,
    ) -> Result<PackCacheLookup> {
        if let Some(hit) = self.lookup(&key).await? {
            crate::metrics::inc_pack_cache_request(&self.metrics, protocol, "hit", "ready");
            return Ok(PackCacheLookup::Hit(hit));
        }

        let notified = {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(key.as_str()) {
                Some(Arc::clone(notify).notified_owned())
            } else {
                if let Some(hit) = self.lookup_sync(&key)? {
                    crate::metrics::inc_pack_cache_request(
                        &self.metrics,
                        protocol,
                        "hit",
                        "ready_after_lock",
                    );
                    return Ok(PackCacheLookup::Hit(hit));
                }
                let notify = Arc::new(Notify::new());
                inflight.insert(key.as_str().to_string(), Arc::clone(&notify));
                None
            }
        };

        if let Some(notified) = notified {
            crate::metrics::inc_pack_cache_request(
                &self.metrics,
                protocol.clone(),
                "wait",
                "inflight",
            );
            let timeout = Duration::from_secs(self.config.wait_for_inflight_secs);
            let wait_result = tokio::time::timeout(timeout, notified).await;
            match wait_result {
                Ok(()) => {
                    if let Some(hit) = self.lookup(&key).await? {
                        crate::metrics::inc_pack_cache_inflight_wait(
                            &self.metrics,
                            protocol.clone(),
                            "hit",
                        );
                        crate::metrics::inc_pack_cache_request(
                            &self.metrics,
                            protocol,
                            "hit",
                            "after_wait",
                        );
                        return Ok(PackCacheLookup::Hit(hit));
                    }
                    crate::metrics::inc_pack_cache_inflight_wait(
                        &self.metrics,
                        protocol.clone(),
                        "miss",
                    );
                    crate::metrics::inc_pack_cache_request(
                        &self.metrics,
                        protocol,
                        "miss",
                        "after_wait",
                    );
                }
                Err(_) => {
                    crate::metrics::inc_pack_cache_inflight_wait(
                        &self.metrics,
                        protocol.clone(),
                        "timeout",
                    );
                    crate::metrics::inc_pack_cache_request(
                        &self.metrics,
                        protocol,
                        "bypass",
                        "wait_timeout",
                    );
                }
            }
            return Ok(PackCacheLookup::BypassAfterWait);
        }

        crate::metrics::inc_pack_cache_request(&self.metrics, protocol, "miss", "reserved");
        match self.open_writer(key.clone()).await {
            Ok(writer) => Ok(PackCacheLookup::Generate(Box::new(writer))),
            Err(error) => {
                if let Some(notify) = self.inflight.lock().await.remove(key.as_str()) {
                    notify.notify_waiters();
                }
                Err(error)
            }
        }
    }

    async fn lookup(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        let path = self.final_path(key);
        self.lookup_path(&path)
    }

    fn lookup_sync(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        let path = self.final_path(key);
        self.lookup_path(&path)
    }

    fn lookup_path(&self, path: &Path) -> Result<Option<PackCacheHit>> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("stat pack cache artifact {}", path.display()));
            }
        };

        if artifact_is_expired(&metadata, self.config.ttl_secs) {
            if let Err(error) = std::fs::remove_file(path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %path.display(), error = %error, "failed to remove expired pack cache artifact");
            }
            return Ok(None);
        }

        Ok(Some(PackCacheHit {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
        }))
    }

    async fn open_writer(&self, key: PackCacheKey) -> Result<PackCacheWriter> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| format!("create pack cache root {}", self.root.display()))?;
        let final_path = self.final_path(&key);
        let tmp_path = self
            .root
            .join(format!("{}.tmp.{}", key.as_str(), std::process::id()));
        let file = File::create(&tmp_path)
            .await
            .with_context(|| format!("create pack cache temp artifact {}", tmp_path.display()))?;
        let notify = self
            .inflight
            .lock()
            .await
            .get(key.as_str())
            .cloned()
            .context("pack cache reservation missing in-flight notifier")?;

        Ok(PackCacheWriter {
            key,
            final_path,
            tmp_path,
            root: self.root.clone(),
            max_bytes: self.max_bytes,
            writer: BufWriter::with_capacity(1024 * 1024, file),
            bytes_written: 0,
            min_response_bytes: self.config.min_response_bytes,
            started_at: Instant::now(),
            inflight: Arc::clone(&self.inflight),
            notify,
            metrics: self.metrics.clone(),
            completed: false,
        })
    }

    fn final_path(&self, key: &PackCacheKey) -> PathBuf {
        self.root.join(format!("{}.pack-response", key.as_str()))
    }

    async fn refresh_size_metric(&self) {
        let size = tokio::task::spawn_blocking({
            let root = self.root.clone();
            move || directory_size(&root).unwrap_or(0)
        })
        .await
        .unwrap_or(0);
        crate::metrics::set_pack_cache_size_bytes(&self.metrics, size);
    }
}

impl PackCacheWriter {
    pub async fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .await
            .context("write pack cache artifact chunk")?;
        self.bytes_written = self.bytes_written.saturating_add(bytes.len() as u64);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<()> {
        self.writer
            .flush()
            .await
            .context("flush pack cache artifact")?;
        self.writer
            .shutdown()
            .await
            .context("shutdown pack cache artifact writer")?;

        if self.bytes_written >= self.min_response_bytes {
            tokio::fs::rename(&self.tmp_path, &self.final_path)
                .await
                .with_context(|| {
                    format!(
                        "promote pack cache artifact {} to {}",
                        self.tmp_path.display(),
                        self.final_path.display()
                    )
                })?;
            crate::metrics::observe_pack_cache_artifact_generation(
                &self.metrics,
                self.started_at.elapsed(),
            );
            if let Err(error) = prune_to_limit(&self.root, self.max_bytes) {
                warn!(
                    root = %self.root.display(),
                    max_bytes = self.max_bytes,
                    error = %error,
                    "failed to prune pack cache after artifact promotion"
                );
            }
            crate::metrics::set_pack_cache_size_bytes(
                &self.metrics,
                directory_size(&self.root).unwrap_or(0),
            );
            debug!(
                key = %self.key.as_str(),
                bytes = self.bytes_written,
                path = %self.final_path.display(),
                "stored pack cache artifact"
            );
        } else if let Err(error) = tokio::fs::remove_file(&self.tmp_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_path.display(), error = %error, "failed to remove undersized pack cache temp artifact");
        }

        self.completed = true;
        crate::metrics::set_pack_cache_size_bytes(
            &self.metrics,
            directory_size(&self.root).unwrap_or(0),
        );
        self.release_inflight().await;
        Ok(())
    }

    pub async fn abort(mut self) {
        if let Err(error) = tokio::fs::remove_file(&self.tmp_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_path.display(), error = %error, "failed to remove aborted pack cache temp artifact");
        }
        self.completed = true;
        crate::metrics::set_pack_cache_size_bytes(
            &self.metrics,
            directory_size(&self.root).unwrap_or(0),
        );
        self.release_inflight().await;
    }

    async fn release_inflight(&self) {
        self.inflight.lock().await.remove(self.key.as_str());
        self.notify.notify_waiters();
    }
}

impl Drop for PackCacheWriter {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        let key = self.key.as_str().to_string();
        let tmp_path = self.tmp_path.clone();
        let inflight = Arc::clone(&self.inflight);
        let notify = Arc::clone(&self.notify);
        tokio::spawn(async move {
            if let Err(error) = tokio::fs::remove_file(&tmp_path).await
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %tmp_path.display(), error = %error, "failed to remove dropped pack cache temp artifact");
            }
            inflight.lock().await.remove(&key);
            notify.notify_waiters();
        });
    }
}

/// Compute a stable digest of a bare repo's ref→OID mapping.
///
/// Reads `packed-refs` and loose refs under `refs/`, collects every
/// `(refname, oid)` pair into a sorted map (so rename-free reorderings are
/// neutral), then hashes them.  The result changes if and only if the actual
/// tip-OIDs change, regardless of which generation path on disk is live.
fn repo_ref_tips_digest(repo_path: &Path) -> std::result::Result<String, &'static str> {
    let mut tips: BTreeMap<String, String> = BTreeMap::new();

    // Read packed-refs first (lower priority than loose refs).
    let packed_refs_path = repo_path.join("packed-refs");
    if let Ok(content) = std::fs::read_to_string(&packed_refs_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            let mut parts = line.splitn(2, ' ');
            if let (Some(oid), Some(refname)) = (parts.next(), parts.next()) {
                tips.insert(refname.to_string(), oid.to_string());
            }
        }
    }

    // Walk loose refs, overwriting any packed-refs entries.
    let refs_dir = repo_path.join("refs");
    collect_loose_refs(&refs_dir, "refs", &mut tips);

    if tips.is_empty() {
        return Err("no_refs");
    }

    let mut hasher = Sha256::new();
    for (refname, oid) in &tips {
        hasher.update(refname.as_bytes());
        hasher.update(b" ");
        hasher.update(oid.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn collect_loose_refs(dir: &Path, prefix: &str, tips: &mut BTreeMap<String, String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let full_ref = format!("{prefix}/{name}");
        if path.is_dir() {
            collect_loose_refs(&path, &full_ref, tips);
        } else if let Ok(content) = std::fs::read_to_string(&path) {
            let oid = content.trim().to_string();
            if oid.len() >= 40 {
                tips.insert(full_ref, oid);
            }
        }
    }
}

fn normalize_fresh_clone_request(bytes: &[u8]) -> std::result::Result<String, &'static str> {
    let mut offset = 0usize;
    let mut command_fetch = false;
    let mut has_done = false;
    let mut wants = Vec::new();
    let mut normalized = Vec::new();

    while offset + 4 <= bytes.len() {
        let len = parse_pkt_len(&bytes[offset..offset + 4]).ok_or("invalid_pkt_len")?;
        if len == 0 {
            normalized.push("flush".to_string());
            offset += 4;
            continue;
        }
        if len == 1 {
            normalized.push("delimiter".to_string());
            offset += 4;
            continue;
        }
        if len == 2 {
            normalized.push("response_end".to_string());
            offset += 4;
            continue;
        }
        if len < 4 || offset + len > bytes.len() {
            return Err("truncated_pkt");
        }

        let payload = &bytes[offset + 4..offset + len];
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        let line = std::str::from_utf8(payload).map_err(|_| "non_utf8_request")?;
        offset += len;

        if line == "command=fetch" {
            command_fetch = true;
        }
        if line == "done" {
            has_done = true;
        }
        if line.starts_with("agent=") || line.starts_with("session-id=") {
            continue;
        }
        if line.starts_with("have ") {
            return Err("has_haves");
        }
        if line.starts_with("filter ") {
            return Err("filtered");
        }
        if line.starts_with("deepen ")
            || line.starts_with("deepen-not ")
            || line.starts_with("deepen-since ")
            || line == "deepen-relative"
            || line.starts_with("shallow ")
        {
            return Err("shallow");
        }
        if line.starts_with("want-ref ") {
            return Err("want_ref");
        }
        if let Some(want) = line.strip_prefix("want ") {
            wants.push(want.to_string());
            continue;
        }
        normalized.push(line.to_string());
    }

    if offset != bytes.len() {
        return Err("trailing_partial_pkt");
    }
    if !command_fetch {
        return Err("not_fetch");
    }
    if wants.is_empty() {
        return Err("no_wants");
    }
    if !has_done {
        return Err("no_done");
    }

    wants.sort();
    for want in wants {
        normalized.push(format!("want {want}"));
    }

    Ok(normalized.join("\n"))
}

fn parse_pkt_len(header: &[u8]) -> Option<usize> {
    if header.len() != 4 {
        return None;
    }
    let text = std::str::from_utf8(header).ok()?;
    usize::from_str_radix(text, 16).ok()
}

fn artifact_is_expired(metadata: &std::fs::Metadata, ttl_secs: u64) -> bool {
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        > Duration::from_secs(ttl_secs)
}

fn directory_size(root: &Path) -> std::io::Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn prune_to_limit(root: &Path, max_bytes: u64) -> std::io::Result<()> {
    if !root.exists() {
        return Ok(());
    }

    let mut artifacts = Vec::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".pack-response"))
        {
            continue;
        }
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        total = total.saturating_add(metadata.len());
        artifacts.push((modified, metadata.len(), path));
    }

    if total <= max_bytes {
        return Ok(());
    }

    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= max_bytes {
            break;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => total = total.saturating_sub(size),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                total = total.saturating_sub(size);
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::normalize_fresh_clone_request;

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn fresh_clone_key_ignores_agent_and_session_id() {
        let mut first = Vec::new();
        first.extend_from_slice(&pkt(b"command=fetch\n"));
        first.extend_from_slice(&pkt(b"agent=git/2.44.1\n"));
        first.extend_from_slice(&pkt(b"session-id=abc\n"));
        first.extend_from_slice(&pkt(b"want bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"));
        first.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        first.extend_from_slice(&pkt(b"done\n"));
        first.extend_from_slice(b"0000");

        let mut second = Vec::new();
        second.extend_from_slice(&pkt(b"command=fetch\n"));
        second.extend_from_slice(&pkt(b"agent=git/2.51.0\n"));
        second.extend_from_slice(&pkt(b"session-id=def\n"));
        second.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        second.extend_from_slice(&pkt(b"want bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"));
        second.extend_from_slice(&pkt(b"done\n"));
        second.extend_from_slice(b"0000");

        assert_eq!(
            normalize_fresh_clone_request(&first).unwrap(),
            normalize_fresh_clone_request(&second).unwrap()
        );
    }

    #[test]
    fn fresh_clone_key_rejects_incremental_fetches() {
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"have bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"));
        request.extend_from_slice(b"0000");

        assert_eq!(
            normalize_fresh_clone_request(&request).unwrap_err(),
            "has_haves"
        );
    }

    #[test]
    fn fresh_clone_key_rejects_filtered_fetches() {
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"filter blob:none\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(b"0000");

        assert_eq!(
            normalize_fresh_clone_request(&request).unwrap_err(),
            "filtered"
        );
    }

    #[test]
    fn fresh_clone_key_rejects_negotiation_round_without_done() {
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(b"0000");

        assert_eq!(
            normalize_fresh_clone_request(&request).unwrap_err(),
            "no_done"
        );
    }
}
