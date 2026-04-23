pub(crate) mod stitch;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{Mutex, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::{debug, warn};

use crate::config::{EvictionPolicy, PackCacheConfig};
use crate::metrics::{MetricsRegistry, Protocol};

const PACK_CACHE_DIR: &str = "pack-cache";
const ENTRY_MANIFEST_EXT: &str = "pack-entry.json";
const METADATA_EXT: &str = "pack-cache-meta.json";
const PACK_ENTRY_MANIFEST_VERSION: u32 = 1;
const PACK_CACHE_METADATA_VERSION: u32 = 4;
const MAX_RECENT_ENTRIES_PER_REPO: usize = 16;
const METADATA_HIT_UPDATE_INTERVAL_SECS: u64 = 60;
const DEFAULT_FULL_TIP_WARMING_TEMPLATE: &[&str] = &["command=fetch", "done", "flush"];
// Capacity for large pack-cache response streams. Production profiles justify
// extra read-ahead while keeping bounded backpressure between producer and body.
const PACK_CACHE_STREAM_CHANNEL_CAPACITY: usize = 256;
const PACKSTORE_DIR: &str = "packstore";
const PACKSTORE_OBJECTS_DIR: &str = "objects";
const PACKSTORE_PACK_DIR: &str = "pack";

#[derive(Clone)]
pub struct PackCache {
    root: PathBuf,
    config: PackCacheConfig,
    local_cache_max_percent: f64,
    index_pack_threads: usize,
    inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    artifact_lifecycle: Arc<std::sync::Mutex<()>>,
    active_readers: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    recent_pack_cache_keys: Arc<std::sync::Mutex<HashMap<String, Vec<PackCacheRecentEntry>>>>,
    metrics: MetricsRegistry,
}

#[derive(Debug, Clone)]
pub struct PackCacheKey {
    digest: String,
    pub(crate) owner_repo: String,
    base: Option<PackCacheBaseMetadata>,
}

impl PartialEq for PackCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for PackCacheKey {}

impl Hash for PackCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl PackCacheKey {
    pub fn as_str(&self) -> &str {
        &self.digest
    }

    pub(crate) fn base_request_wants(&self) -> Option<&[String]> {
        self.base.as_ref().map(|base| base.request_wants.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct PackCacheRecentEntry {
    pub key: PackCacheKey,
    pub request_wants: Vec<String>,
    pub covered_wants: Vec<String>,
    pub request_template: Vec<String>,
    pub full_tip: bool,
}

#[derive(Debug, Clone)]
struct PackCacheBaseMetadata {
    request_wants: Vec<String>,
    request_template: Vec<String>,
    full_tip: bool,
}

struct PackCacheHit {
    key: PackCacheKey,
    manifest: PackEntryManifest,
}

enum PackCacheReadArtifact {
    SinglePack {
        file: File,
    },
    Entry {
        packs: Vec<stitch::OpenedPack>,
        synthetic_trailer_sha1: Option<[u8; 20]>,
    },
}

pub struct PackCacheReadLease {
    artifact: PackCacheReadArtifact,
    _guard: PackCacheReadGuard,
}

struct PackCacheReadGuard {
    keys: Vec<String>,
    active_readers: Arc<std::sync::Mutex<HashMap<String, usize>>>,
}

struct LeasedPackCacheStream {
    inner: Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>,
    _guard: PackCacheReadGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackEntryManifest {
    version: u32,
    pack_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stitched_trailer_sha1: Option<String>,
}

impl PackCacheReadLease {
    #[cfg(test)]
    fn is_composite(&self) -> bool {
        matches!(
            &self.artifact,
            PackCacheReadArtifact::Entry { packs, .. } if packs.len() > 1
        )
    }

    pub fn into_stream(self) -> Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>> {
        let Self { artifact, _guard } = self;
        match artifact {
            PackCacheReadArtifact::SinglePack { file } => {
                let packfile = stream::once(async {
                    Ok::<Bytes, io::Error>(Bytes::from(stitch::packfile_section_pkt()))
                });
                let framed_pack =
                    ReaderStream::with_capacity(file, stitch::MAX_SIDEBAND_PACK_CHUNK).map(
                        |chunk| {
                            chunk.and_then(|chunk| {
                            if chunk.len() > stitch::MAX_SIDEBAND_PACK_CHUNK {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "single-pack async replay chunk exceeded sideband packet limit",
                                ));
                            }
                            Ok(Bytes::from(stitch::encode_sideband1_pkt(&chunk)))
                        })
                        },
                    );
                let flush = stream::once(async {
                    Ok::<Bytes, io::Error>(Bytes::from(stitch::flush_pkt()))
                });
                Box::pin(LeasedPackCacheStream {
                    inner: Box::pin(packfile.chain(framed_pack).chain(flush)),
                    _guard,
                })
            }
            PackCacheReadArtifact::Entry {
                packs,
                synthetic_trailer_sha1,
            } => {
                let (sender, receiver) =
                    tokio::sync::mpsc::channel(PACK_CACHE_STREAM_CHANNEL_CAPACITY);
                tokio::task::spawn_blocking(move || {
                    let result = stitch::stream_packfile_response_from_open_files_with_trailer(
                        packs,
                        synthetic_trailer_sha1,
                        |chunk| {
                            sender.blocking_send(Ok(Bytes::from(chunk))).map_err(|_| {
                                io::Error::new(io::ErrorKind::BrokenPipe, "receiver closed")
                            })
                        },
                    );
                    if let Err(error) = result {
                        let _ = sender.blocking_send(Err(io::Error::other(error.to_string())));
                    }
                });
                Box::pin(LeasedPackCacheStream {
                    inner: Box::pin(ReceiverStream::new(receiver)),
                    _guard,
                })
            }
        }
    }
}

impl Drop for PackCacheReadGuard {
    fn drop(&mut self) {
        let mut active = self.active_readers.lock().unwrap();
        for key in &self.keys {
            if let Some(count) = active.get_mut(key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.remove(key);
                }
            }
        }
    }
}

impl Stream for LeasedPackCacheStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PackCacheMetadata {
    version: u32,
    key: String,
    owner_repo: String,
    request_wants: Vec<String>,
    #[serde(default)]
    covered_wants: Vec<String>,
    request_template: Vec<String>,
    full_tip: bool,
    created_at_unix_secs: u64,
    last_accessed_unix_secs: u64,
    hit_count: u64,
}

impl PackCacheMetadata {
    fn covered_wants_or_request_wants(&self) -> Vec<String> {
        if self.covered_wants.is_empty() {
            self.request_wants.clone()
        } else {
            self.covered_wants.clone()
        }
    }
}

pub enum PackCacheLookup {
    Hit(PackCacheReadLease),
    Generate(Box<PackCacheWriter>),
    BypassAfterWait,
}

pub struct PackCacheWriter {
    key: PackCacheKey,
    root: PathBuf,
    config: PackCacheConfig,
    local_cache_max_percent: f64,
    index_pack_threads: usize,
    tmp_pack_path: PathBuf,
    pack_writer: BufWriter<File>,
    pack_extractor: RawPackExtractor,
    response_bytes_written: u64,
    raw_pack_bytes_written: u64,
    min_response_bytes: u64,
    started_at: Instant,
    inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    artifact_lifecycle: Arc<std::sync::Mutex<()>>,
    active_readers: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    recent_pack_cache_keys: Arc<std::sync::Mutex<HashMap<String, Vec<PackCacheRecentEntry>>>>,
    notify: Arc<Notify>,
    metrics: MetricsRegistry,
    completed: bool,
}

#[derive(Default)]
struct RawPackExtractor {
    buffer: Vec<u8>,
    wrote_pack: bool,
    disabled: bool,
}

impl RawPackExtractor {
    async fn write_response_chunk(
        &mut self,
        bytes: &[u8],
        pack_writer: &mut BufWriter<File>,
    ) -> Result<u64> {
        if self.disabled {
            return Ok(0);
        }
        self.buffer.extend_from_slice(bytes);
        let mut bytes_written = 0u64;

        loop {
            if self.buffer.len() < 4 {
                return Ok(bytes_written);
            }

            let Some(len) = std::str::from_utf8(&self.buffer[..4])
                .ok()
                .and_then(|text| usize::from_str_radix(text, 16).ok())
            else {
                self.disabled = true;
                self.buffer.clear();
                return Ok(bytes_written);
            };

            if len == 0 || len == 1 || len == 2 {
                self.buffer.drain(..4);
                continue;
            }
            if len < 4 {
                self.disabled = true;
                self.buffer.clear();
                return Ok(bytes_written);
            }
            if self.buffer.len() < len {
                return Ok(bytes_written);
            }

            let packet = self.buffer[4..len].to_vec();
            self.buffer.drain(..len);
            if packet == b"packfile\n" {
                continue;
            }
            if let Some((band, rest)) = packet.split_first()
                && *band == 1
            {
                pack_writer
                    .write_all(rest)
                    .await
                    .context("write pack cache raw pack chunk")?;
                bytes_written = bytes_written.saturating_add(rest.len() as u64);
                self.wrote_pack = true;
            }
        }
    }
}

impl PackCache {
    pub fn new(
        base_path: &Path,
        config: PackCacheConfig,
        local_cache_max_percent: f64,
        metrics: MetricsRegistry,
    ) -> Self {
        Self::new_with_index_pack_threads(
            base_path,
            config,
            local_cache_max_percent,
            metrics,
            crate::config::DEFAULT_INDEX_PACK_THREADS,
        )
    }

    pub fn new_with_index_pack_threads(
        base_path: &Path,
        config: PackCacheConfig,
        local_cache_max_percent: f64,
        metrics: MetricsRegistry,
        index_pack_threads: usize,
    ) -> Self {
        Self {
            root: base_path
                .join(crate::cache::layout::STATE_ROOT_DIR)
                .join(PACK_CACHE_DIR),
            config,
            local_cache_max_percent,
            index_pack_threads,
            inflight: Arc::new(Mutex::new(HashMap::new())),
            artifact_lifecycle: Arc::new(std::sync::Mutex::new(())),
            active_readers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            recent_pack_cache_keys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            metrics,
        }
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        if self.config.enabled {
            tokio::fs::create_dir_all(&self.root)
                .await
                .with_context(|| format!("create pack cache root {}", self.root.display()))?;
            self.ensure_packstore_git_dir().await?;
            tokio::fs::create_dir_all(self.packstore_pack_dir())
                .await
                .with_context(|| {
                    format!(
                        "create pack cache packstore {}",
                        self.packstore_pack_dir().display()
                    )
                })?;
            self.reload_recent_metadata()
                .with_context(|| format!("reload pack cache metadata {}", self.root.display()))?;
            self.refresh_size_metric().await;
        }
        Ok(())
    }

    async fn ensure_packstore_git_dir(&self) -> Result<()> {
        let packstore_root = self.packstore_root();
        let head_path = packstore_root.join("HEAD");
        if tokio::fs::try_exists(&head_path)
            .await
            .with_context(|| format!("stat synthetic packstore head {}", head_path.display()))?
        {
            return Ok(());
        }

        crate::git::commands::git_init_bare(&packstore_root)
            .await
            .with_context(|| {
                format!(
                    "initialize synthetic packstore {}",
                    packstore_root.display()
                )
            })
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

        let request = normalize_fresh_clone_request_parts(request_body)?;
        let ref_tips = collect_repo_ref_tips(repo_path)?;
        self.key_for_normalized_fresh_clone(owner_repo, request, &ref_tips)
    }

    pub fn key_for_fresh_clone_with_ref_tips(
        &self,
        owner_repo: &str,
        request_body: &[u8],
        git_protocol: Option<&str>,
        ref_tips: &BTreeMap<String, String>,
    ) -> std::result::Result<PackCacheKey, &'static str> {
        if !self.config.enabled {
            return Err("disabled");
        }
        if git_protocol != Some("version=2") {
            return Err("non_v2");
        }

        let request = normalize_fresh_clone_request_parts(request_body)?;
        self.key_for_normalized_fresh_clone(owner_repo, request, ref_tips)
    }

    fn key_for_normalized_fresh_clone(
        &self,
        owner_repo: &str,
        request: NormalizedFreshCloneRequest,
        ref_tips: &BTreeMap<String, String>,
    ) -> std::result::Result<PackCacheKey, &'static str> {
        if ref_tips.is_empty() {
            return Err("no_refs");
        }
        let tip_oids = unique_tip_oids(ref_tips);
        let ref_tips_digest = repo_ref_tips_digest(ref_tips);
        let base = Some(PackCacheBaseMetadata {
            full_tip: request.wants == tip_oids,
            request_wants: request.wants.clone(),
            request_template: request.non_want_lines.clone(),
        });

        Ok(pack_cache_key(
            owner_repo,
            &ref_tips_digest,
            &request.normalized,
            base,
        ))
    }

    pub fn key_for_warming(
        &self,
        owner_repo: &str,
        repo_path: &Path,
        request_template: &[String],
    ) -> std::result::Result<PackCacheKey, &'static str> {
        if !self.config.enabled {
            return Err("disabled");
        }

        let ref_tips = collect_repo_ref_tips(repo_path)?;
        let tip_oids = unique_tip_oids(&ref_tips);
        let ref_tips_digest = repo_ref_tips_digest(&ref_tips);
        let normalized_request = normalized_request_from_parts(request_template, &tip_oids);

        Ok(pack_cache_key(
            owner_repo,
            &ref_tips_digest,
            &normalized_request,
            Some(PackCacheBaseMetadata {
                request_wants: tip_oids,
                request_template: request_template.to_vec(),
                full_tip: true,
            }),
        ))
    }

    pub fn key_for_default_full_tip_warming(
        &self,
        owner_repo: &str,
        repo_path: &Path,
    ) -> std::result::Result<PackCacheKey, &'static str> {
        let request_template = DEFAULT_FULL_TIP_WARMING_TEMPLATE
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        self.key_for_warming(owner_repo, repo_path, &request_template)
    }

    pub fn lookup_recent_compatible_keys(&self, key: &PackCacheKey) -> Vec<PackCacheRecentEntry> {
        let Some(base) = key.base.as_ref() else {
            return Vec::new();
        };
        self.recent_pack_cache_keys
            .lock()
            .ok()
            .and_then(|entries| entries.get(&key.owner_repo).cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.key != *key && entry.request_template == base.request_template)
            .collect()
    }

    pub fn lookup_recent_compatible_key(&self, key: &PackCacheKey) -> Option<PackCacheRecentEntry> {
        self.lookup_recent_compatible_keys(key)
            .into_iter()
            .find(|entry| {
                key.base
                    .as_ref()
                    .is_some_and(|base| entry.request_wants == base.request_wants)
            })
    }

    pub fn lookup_recent_full_tip_keys(&self, owner_repo: &str) -> Vec<PackCacheRecentEntry> {
        self.recent_pack_cache_keys
            .lock()
            .ok()
            .and_then(|entries| entries.get(owner_repo).cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.full_tip)
            .collect()
    }

    pub async fn lookup_or_reserve(
        &self,
        protocol: Protocol,
        key: PackCacheKey,
    ) -> Result<PackCacheLookup> {
        if let Some(hit) = self.lookup_read_lease(&key)? {
            crate::metrics::inc_pack_cache_request(&self.metrics, protocol, "hit", "ready");
            return Ok(PackCacheLookup::Hit(hit));
        }
        if let Some(hit) = self.lookup_compatible_read_lease(&key)? {
            crate::metrics::inc_pack_cache_request(&self.metrics, protocol, "hit", "compatible");
            return Ok(PackCacheLookup::Hit(hit));
        }

        let notified = {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(key.as_str()) {
                Some(Arc::clone(notify).notified_owned())
            } else {
                if let Some(hit) = self.lookup_read_lease(&key)? {
                    crate::metrics::inc_pack_cache_request(
                        &self.metrics,
                        protocol,
                        "hit",
                        "ready_after_lock",
                    );
                    return Ok(PackCacheLookup::Hit(hit));
                }
                if let Some(hit) = self.lookup_compatible_read_lease(&key)? {
                    crate::metrics::inc_pack_cache_request(
                        &self.metrics,
                        protocol,
                        "hit",
                        "compatible_after_lock",
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
                    if let Some(hit) = self.lookup_read_lease(&key)? {
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
                    if let Some(hit) = self.lookup_compatible_read_lease(&key)? {
                        crate::metrics::inc_pack_cache_inflight_wait(
                            &self.metrics,
                            protocol.clone(),
                            "hit",
                        );
                        crate::metrics::inc_pack_cache_request(
                            &self.metrics,
                            protocol,
                            "hit",
                            "compatible_after_wait",
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

    pub async fn lookup_by_key(&self, key: &PackCacheKey) -> Result<Option<PackCacheReadLease>> {
        self.lookup_read_lease(key)
    }

    pub fn has_usable_full_tip_entry(
        &self,
        owner_repo: &str,
        repo_path: &Path,
    ) -> std::result::Result<bool, &'static str> {
        let ref_tips = collect_repo_ref_tips(repo_path)?;
        let current_wants = unique_tip_oids(&ref_tips);
        if current_wants.is_empty() {
            return Ok(false);
        }
        let _lifecycle = self.artifact_lifecycle.lock().unwrap();
        Ok(self
            .recent_pack_cache_keys
            .lock()
            .ok()
            .and_then(|entries| entries.get(owner_repo).cloned())
            .unwrap_or_default()
            .into_iter()
            .any(|entry| {
                entry.full_tip
                    && entry.covered_wants == current_wants
                    && self.lookup_sync(&entry.key).ok().flatten().is_some()
            }))
    }

    pub fn pack_paths_for_key(&self, key: &PackCacheKey) -> Result<Vec<PathBuf>> {
        let manifest = self.read_entry_manifest(key)?;
        self.entry_pack_paths(&manifest)
    }

    fn lookup_compatible_read_lease(
        &self,
        key: &PackCacheKey,
    ) -> Result<Option<PackCacheReadLease>> {
        let Some(compatible) = self.lookup_recent_compatible_key(key) else {
            return Ok(None);
        };
        let _lifecycle = self.artifact_lifecycle.lock().unwrap();
        let Some(hit) = self.lookup_sync(&compatible.key)? else {
            return Ok(None);
        };
        self.open_read_lease_for_hit(hit).map(Some)
    }

    fn lookup_read_lease(&self, key: &PackCacheKey) -> Result<Option<PackCacheReadLease>> {
        let _lifecycle = self.artifact_lifecycle.lock().unwrap();
        let Some(hit) = self.lookup_sync(key)? else {
            return Ok(None);
        };
        self.open_read_lease_for_hit(hit).map(Some)
    }

    fn lookup_sync(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        let path = self.entry_manifest_path(key);
        let Some(_metadata) = self.lookup_existing_file(&path)? else {
            return Ok(None);
        };
        let manifest = match self.read_entry_manifest(key) {
            Ok(manifest) => manifest,
            Err(error) => {
                warn!(
                    key = %key.as_str(),
                    error = %error,
                    "invalid pack cache entry manifest; removing stale entry"
                );
                self.remove_entry_files(key);
                return Ok(None);
            }
        };
        if self.entry_replay_pack_paths(&manifest).is_err() {
            self.remove_entry_files(key);
            return Ok(None);
        }
        if let Err(error) = record_metadata_hit_if_present(&self.root, key.as_str()) {
            warn!(
                key = %key.as_str(),
                error = %error,
                "failed to update pack cache hit metadata"
            );
        }

        Ok(Some(PackCacheHit {
            key: key.clone(),
            manifest,
        }))
    }

    fn lookup_existing_file(&self, path: &Path) -> Result<Option<std::fs::Metadata>> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("stat pack cache artifact {}", path.display()));
            }
        };

        Ok(Some(metadata))
    }

    fn open_read_lease_for_hit(&self, hit: PackCacheHit) -> Result<PackCacheReadLease> {
        let synthetic_trailer_sha1 = hit
            .manifest
            .stitched_trailer_sha1
            .as_deref()
            .map(parse_sha1_hex)
            .transpose()?;
        let guard = self.acquire_read_guard(vec![hit.key.as_str().to_string()]);
        let pack_paths = self.entry_replay_pack_paths(&hit.manifest)?;
        if pack_paths.len() == 1 && synthetic_trailer_sha1.is_none() {
            let pack_path = &pack_paths[0];
            let file = std::fs::File::open(pack_path)
                .with_context(|| format!("open pack {}", pack_path.display()))?;
            return Ok(PackCacheReadLease {
                artifact: PackCacheReadArtifact::SinglePack {
                    file: File::from_std(file),
                },
                _guard: guard,
            });
        }
        let packs = pack_paths
            .into_iter()
            .map(|path| stitch::OpenedPack::from_path(&path))
            .collect::<Result<Vec<_>>>()?;
        Ok(PackCacheReadLease {
            artifact: PackCacheReadArtifact::Entry {
                packs,
                synthetic_trailer_sha1,
            },
            _guard: guard,
        })
    }

    fn acquire_read_guard(&self, keys: Vec<String>) -> PackCacheReadGuard {
        let mut keys = keys;
        keys.sort();
        keys.dedup();

        let mut active = self.active_readers.lock().unwrap();
        for key in &keys {
            *active.entry(key.clone()).or_insert(0) += 1;
        }
        PackCacheReadGuard {
            keys,
            active_readers: Arc::clone(&self.active_readers),
        }
    }

    fn read_entry_manifest(&self, key: &PackCacheKey) -> Result<PackEntryManifest> {
        let path = self.entry_manifest_path(key);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read pack cache entry manifest {}", path.display()))?;
        let manifest: PackEntryManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pack cache entry manifest {}", path.display()))?;
        anyhow::ensure!(
            manifest.version == PACK_ENTRY_MANIFEST_VERSION,
            "unsupported pack cache entry manifest version {}",
            manifest.version
        );
        Ok(manifest)
    }

    fn remove_entry_files(&self, key: &PackCacheKey) {
        let manifest_path = self.entry_manifest_path(key);
        if let Err(error) = std::fs::remove_file(&manifest_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %manifest_path.display(), error = %error, "failed to remove invalid pack cache entry manifest");
        }
        let stale_metadata_path = metadata_path(&self.root, key.as_str());
        if let Err(error) = std::fs::remove_file(&stale_metadata_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %stale_metadata_path.display(), error = %error, "failed to remove invalid pack cache metadata");
        }
        if let Err(error) = garbage_collect_unreferenced_pack_files(&self.root)
            && !matches!(error.kind(), std::io::ErrorKind::NotFound)
        {
            warn!(root = %self.root.display(), error = %error, "failed to garbage collect pack cache packstore after entry removal");
        }
    }

    async fn open_writer(&self, key: PackCacheKey) -> Result<PackCacheWriter> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| format!("create pack cache root {}", self.root.display()))?;
        let packstore_pack_dir = self.packstore_pack_dir();
        tokio::fs::create_dir_all(&packstore_pack_dir)
            .await
            .with_context(|| {
                format!(
                    "create pack cache pack dir {}",
                    packstore_pack_dir.display()
                )
            })?;
        let tmp_pack_path = packstore_pack_dir.join(format!(
            "pack-{}.tmp.{}.pack",
            key.as_str(),
            std::process::id()
        ));
        let file = File::create(&tmp_pack_path)
            .await
            .with_context(|| format!("create pack cache temp pack {}", tmp_pack_path.display()))?;
        let notify = self
            .inflight
            .lock()
            .await
            .get(key.as_str())
            .cloned()
            .context("pack cache reservation missing in-flight notifier")?;

        Ok(PackCacheWriter {
            key,
            root: self.root.clone(),
            config: self.config.clone(),
            local_cache_max_percent: self.local_cache_max_percent,
            index_pack_threads: self.index_pack_threads,
            tmp_pack_path,
            pack_writer: BufWriter::with_capacity(1024 * 1024, file),
            pack_extractor: RawPackExtractor::default(),
            response_bytes_written: 0,
            raw_pack_bytes_written: 0,
            min_response_bytes: self.config.min_response_bytes,
            started_at: Instant::now(),
            inflight: Arc::clone(&self.inflight),
            artifact_lifecycle: Arc::clone(&self.artifact_lifecycle),
            active_readers: Arc::clone(&self.active_readers),
            recent_pack_cache_keys: Arc::clone(&self.recent_pack_cache_keys),
            notify,
            metrics: self.metrics.clone(),
            completed: false,
        })
    }

    fn entry_manifest_path(&self, key: &PackCacheKey) -> PathBuf {
        self.root
            .join(format!("{}.{}", key.as_str(), ENTRY_MANIFEST_EXT))
    }

    fn packstore_root(&self) -> PathBuf {
        self.root.join(PACKSTORE_DIR)
    }

    pub(crate) fn packstore_object_dir(&self) -> PathBuf {
        self.packstore_root().join(PACKSTORE_OBJECTS_DIR)
    }

    fn packstore_pack_dir(&self) -> PathBuf {
        self.packstore_object_dir().join(PACKSTORE_PACK_DIR)
    }

    fn pack_path_for_id(&self, pack_id: &str) -> PathBuf {
        self.packstore_pack_dir()
            .join(format!("pack-{pack_id}.pack"))
    }

    #[cfg(test)]
    fn pack_index_path_for_id(&self, pack_id: &str) -> PathBuf {
        self.packstore_pack_dir()
            .join(format!("pack-{pack_id}.idx"))
    }

    fn entry_pack_paths(&self, manifest: &PackEntryManifest) -> Result<Vec<PathBuf>> {
        let paths = self.entry_replay_pack_paths(manifest)?;
        for pack_path in &paths {
            let idx_path = pack_path.with_extension("idx");
            self.lookup_existing_file(&idx_path)?
                .with_context(|| format!("missing pack cache pack index {}", idx_path.display()))?;
        }
        Ok(paths)
    }

    fn entry_replay_pack_paths(&self, manifest: &PackEntryManifest) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::with_capacity(manifest.pack_ids.len());
        for pack_id in &manifest.pack_ids {
            let pack_path = self.pack_path_for_id(pack_id);
            self.lookup_existing_file(&pack_path)?
                .with_context(|| format!("missing pack cache pack {}", pack_path.display()))?;
            paths.push(pack_path);
        }
        Ok(paths)
    }

    fn reload_recent_metadata(&self) -> Result<()> {
        let mut recent = HashMap::new();
        if !self.root.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("read pack cache root {}", self.root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(METADATA_EXT))
            {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    warn!(path = %path.display(), error = %error, "failed to read pack cache metadata");
                    continue;
                }
            };
            let metadata: PackCacheMetadata = match serde_json::from_slice(&bytes) {
                Ok(metadata) => metadata,
                Err(error) => {
                    warn!(path = %path.display(), error = %error, "failed to parse pack cache metadata");
                    continue;
                }
            };
            if metadata.version != PACK_CACHE_METADATA_VERSION {
                warn!(path = %path.display(), version = metadata.version, "ignoring unsupported pack cache metadata version");
                continue;
            }
            if !cache_entry_artifact_exists(&self.root, &metadata.key) {
                continue;
            }
            let covered_wants = metadata.covered_wants_or_request_wants();
            insert_recent_entry(
                &mut recent,
                metadata.owner_repo.clone(),
                PackCacheRecentEntry {
                    key: PackCacheKey {
                        digest: metadata.key,
                        owner_repo: metadata.owner_repo.clone(),
                        base: Some(PackCacheBaseMetadata {
                            request_wants: metadata.request_wants.clone(),
                            request_template: metadata.request_template.clone(),
                            full_tip: metadata.full_tip,
                        }),
                    },
                    request_wants: metadata.request_wants,
                    covered_wants,
                    request_template: metadata.request_template,
                    full_tip: metadata.full_tip,
                },
            );
        }

        record_recent_entries_metric(&self.metrics, &recent);
        *self.recent_pack_cache_keys.lock().unwrap() = recent;
        Ok(())
    }

    async fn refresh_size_metric(&self) {
        let usage = tokio::task::spawn_blocking({
            let root = self.root.clone();
            move || directory_usage(&root).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        crate::metrics::set_pack_cache_usage_bytes(
            &self.metrics,
            usage.apparent_bytes,
            usage.physical_bytes,
        );
    }
}

impl PackCacheWriter {
    pub(crate) fn key(&self) -> &PackCacheKey {
        &self.key
    }

    pub async fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.response_bytes_written = self
            .response_bytes_written
            .saturating_add(bytes.len() as u64);
        self.raw_pack_bytes_written = self.raw_pack_bytes_written.saturating_add(
            self.pack_extractor
                .write_response_chunk(bytes, &mut self.pack_writer)
                .await?,
        );
        Ok(())
    }

    pub async fn finish(mut self) -> Result<()> {
        self.pack_writer
            .flush()
            .await
            .context("flush pack cache raw pack")?;
        self.pack_writer
            .shutdown()
            .await
            .context("shutdown pack cache raw pack writer")?;

        if self.response_bytes_written >= self.min_response_bytes && self.pack_extractor.wrote_pack
        {
            let pack_id = self
                .promote_pack_file_for_replay(&self.tmp_pack_path)
                .await?;
            self.write_entry_manifest(&PackEntryManifest {
                version: PACK_ENTRY_MANIFEST_VERSION,
                pack_ids: vec![pack_id],
                stitched_trailer_sha1: None,
            })?;
            self.completed = true;
            self.record_ready_entry(None);
            self.record_pack_cache_usage_metric();
            self.release_inflight().await;
            let pack_id = self.key.as_str().to_string();
            self.spawn_indexed_promotion(pack_id, None);
            return Ok(());
        } else if let Err(error) = tokio::fs::remove_file(&self.tmp_pack_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_pack_path.display(), error = %error, "failed to remove undersized pack cache temp pack");
            self.completed = true;
            self.record_pack_cache_usage_metric();
            self.release_inflight().await;
            return Ok(());
        }
        if !self.completed {
            self.completed = true;
            self.record_pack_cache_usage_metric();
            self.release_inflight().await;
        }
        Ok(())
    }

    pub async fn finish_composite(
        mut self,
        base_key: &PackCacheKey,
        delta_pack: &[u8],
    ) -> Result<()> {
        self.pack_writer
            .shutdown()
            .await
            .context("shutdown unused pack cache temp raw pack writer")?;
        if let Err(error) = tokio::fs::remove_file(&self.tmp_pack_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_pack_path.display(), error = %error, "failed to remove unused pack cache temp raw pack");
        }

        let pack_id = self
            .write_exact_pack_for_replay(delta_pack, "delta")
            .await?;
        let mut pack_ids = self.read_entry_manifest(base_key)?.pack_ids;
        pack_ids.push(pack_id);
        let pack_paths = pack_ids
            .iter()
            .map(|pack_id| self.pack_path_for_id(pack_id))
            .collect::<Vec<_>>();
        let stitched_trailer_sha1 = stitch::synthetic_pack_trailer_from_paths(&pack_paths)?;
        self.write_entry_manifest(&PackEntryManifest {
            version: PACK_ENTRY_MANIFEST_VERSION,
            pack_ids,
            stitched_trailer_sha1: Some(hex_digest(&stitched_trailer_sha1)),
        })?;
        self.raw_pack_bytes_written = delta_pack.len() as u64;
        self.completed = true;
        self.record_ready_entry(Some(base_key));
        self.record_pack_cache_usage_metric();
        self.release_inflight().await;
        let pack_id = format!("{}-delta", self.key.as_str());
        self.spawn_indexed_promotion(pack_id, Some(base_key.clone()));
        Ok(())
    }

    pub async fn finish_exact_pack(mut self, pack_bytes: &[u8], suffix: &str) -> Result<()> {
        self.pack_writer
            .shutdown()
            .await
            .context("shutdown unused exact pack cache temp raw pack writer")?;
        if let Err(error) = tokio::fs::remove_file(&self.tmp_pack_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_pack_path.display(), error = %error, "failed to remove unused exact pack cache temp raw pack");
        }

        let pack_id = self.write_exact_pack_for_replay(pack_bytes, suffix).await?;
        self.write_entry_manifest(&PackEntryManifest {
            version: PACK_ENTRY_MANIFEST_VERSION,
            pack_ids: vec![pack_id.clone()],
            stitched_trailer_sha1: None,
        })?;
        self.raw_pack_bytes_written = pack_bytes.len() as u64;
        self.completed = true;
        self.record_ready_entry(None);
        self.record_pack_cache_usage_metric();
        self.release_inflight().await;
        self.spawn_indexed_promotion(pack_id, None);
        Ok(())
    }

    pub async fn finish_alias(mut self, base_key: &PackCacheKey) -> Result<()> {
        self.pack_writer
            .shutdown()
            .await
            .context("shutdown unused alias pack cache temp raw pack writer")?;
        if let Err(error) = tokio::fs::remove_file(&self.tmp_pack_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_pack_path.display(), error = %error, "failed to remove unused alias pack cache temp raw pack");
        }

        let manifest = self.read_entry_manifest(base_key)?;
        self.write_entry_manifest(&manifest)?;
        self.raw_pack_bytes_written = 0;
        self.completed = true;
        self.record_ready_entry(Some(base_key));
        self.record_pack_cache_usage_metric();
        self.release_inflight().await;
        crate::metrics::observe_pack_cache_artifact_generation(
            &self.metrics,
            self.started_at.elapsed(),
        );
        Ok(())
    }

    pub async fn abort(mut self) {
        if let Err(error) = tokio::fs::remove_file(&self.tmp_pack_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_pack_path.display(), error = %error, "failed to remove aborted pack cache temp raw pack");
        }
        self.completed = true;
        self.record_pack_cache_usage_metric();
        self.release_inflight().await;
    }

    async fn release_inflight(&self) {
        self.inflight.lock().await.remove(self.key.as_str());
        self.notify.notify_waiters();
    }

    fn record_ready_entry(&self, composite_base_key: Option<&PackCacheKey>) {
        if let Some(base) = &self.key.base {
            let covered_wants = self.covered_wants_for_promotion(base, composite_base_key);
            let entry = PackCacheRecentEntry {
                key: self.key.clone(),
                request_wants: base.request_wants.clone(),
                covered_wants,
                request_template: base.request_template.clone(),
                full_tip: base.full_tip,
            };
            insert_recent_entry(
                &mut self.recent_pack_cache_keys.lock().unwrap(),
                self.key.owner_repo.clone(),
                entry.clone(),
            );
            if let Err(error) = self.write_metadata(&entry) {
                warn!(
                    key = %self.key.as_str(),
                    error = %error,
                    "failed to persist pack cache metadata"
                );
            }
        }
        {
            let _lifecycle = self.artifact_lifecycle.lock().unwrap();
            if let Err(error) = prune_to_watermarks(
                &self.root,
                self.local_cache_max_percent,
                &self.config,
                &self.active_readers,
            ) {
                warn!(
                    root = %self.root.display(),
                    error = %error,
                    "failed to prune pack cache after artifact promotion"
                );
            }
            let mut recent = self.recent_pack_cache_keys.lock().unwrap();
            retain_existing_recent_entries(&self.root, &mut recent);
            record_recent_entries_metric(&self.metrics, &recent);
            self.record_pack_cache_usage_metric();
        }
        debug!(
            key = %self.key.as_str(),
            bytes = self.raw_pack_bytes_written,
            path = %self.entry_manifest_path().display(),
            "stored pack cache artifact"
        );
    }

    fn record_pack_cache_usage_metric(&self) {
        let usage = directory_usage(&self.root).unwrap_or_default();
        crate::metrics::set_pack_cache_usage_bytes(
            &self.metrics,
            usage.apparent_bytes,
            usage.physical_bytes,
        );
    }

    async fn promote_pack_file_for_replay(&self, tmp_pack_path: &Path) -> Result<String> {
        let pack_id = self.key.as_str().to_string();
        let final_pack_path = self.pack_path_for_id(&pack_id);
        tokio::fs::rename(tmp_pack_path, &final_pack_path)
            .await
            .with_context(|| {
                format!(
                    "promote pack cache pack {} to {}",
                    tmp_pack_path.display(),
                    final_pack_path.display()
                )
            })?;
        Ok(pack_id)
    }

    async fn write_exact_pack_for_replay(&self, pack_bytes: &[u8], suffix: &str) -> Result<String> {
        let pack_id = format!("{}-{suffix}", self.key.as_str());
        let tmp_pack_path =
            self.root
                .join(format!("pack-{}.tmp.{}.pack", pack_id, std::process::id()));
        tokio::fs::write(&tmp_pack_path, pack_bytes)
            .await
            .with_context(|| format!("write pack cache pack {}", tmp_pack_path.display()))?;
        let final_pack_path = self.pack_path_for_id(&pack_id);
        tokio::fs::rename(&tmp_pack_path, &final_pack_path)
            .await
            .with_context(|| {
                format!(
                    "promote pack cache exact pack {} to {}",
                    tmp_pack_path.display(),
                    final_pack_path.display()
                )
            })?;
        Ok(pack_id)
    }

    fn spawn_indexed_promotion(
        mut self,
        pack_id: String,
        composite_base_key: Option<PackCacheKey>,
    ) {
        let key = self.key.as_str().to_string();
        tokio::spawn(async move {
            if let Err(error) = self
                .finalize_indexed_promotion(&pack_id, composite_base_key.as_ref())
                .await
            {
                warn!(
                    key = %key,
                    pack_id,
                    error = %error,
                    "failed to finalize pack cache index after replay-ready promotion"
                );
            }
        });
    }

    async fn finalize_indexed_promotion(
        &mut self,
        pack_id: &str,
        _composite_base_key: Option<&PackCacheKey>,
    ) -> Result<()> {
        let pack_path = self.pack_path_for_id(pack_id);
        let idx_path = self.pack_index_path_for_id(pack_id);
        crate::git::commands::git_index_pack_to_idx(&pack_path, &idx_path, self.index_pack_threads)
            .await?;
        self.refresh_packstore_midx().await?;
        crate::metrics::observe_pack_cache_artifact_generation(
            &self.metrics,
            self.started_at.elapsed(),
        );
        Ok(())
    }

    async fn refresh_packstore_midx(&self) -> Result<()> {
        crate::git::commands::git_multi_pack_index_write_for_object_dir(
            &self.packstore_object_dir(),
            false,
            1,
        )
        .await
        .or_else(|error| {
            warn!(root = %self.root.display(), error = %error, "failed to refresh pack cache packstore MIDX");
            Ok(())
        })
    }

    fn write_entry_manifest(&self, manifest: &PackEntryManifest) -> Result<()> {
        let path = self.entry_manifest_path();
        let tmp_path = self.root.join(format!(
            "{}.tmp.{}.{}",
            self.key.as_str(),
            std::process::id(),
            ENTRY_MANIFEST_EXT
        ));
        let bytes = serde_json::to_vec(manifest).context("serialize pack cache entry manifest")?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("write pack cache entry manifest {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "promote pack cache entry manifest {} to {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    }

    fn read_entry_manifest(&self, key: &PackCacheKey) -> Result<PackEntryManifest> {
        let path = self
            .root
            .join(format!("{}.{}", key.as_str(), ENTRY_MANIFEST_EXT));
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read pack cache entry manifest {}", path.display()))?;
        let manifest: PackEntryManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pack cache entry manifest {}", path.display()))?;
        anyhow::ensure!(
            manifest.version == PACK_ENTRY_MANIFEST_VERSION,
            "unsupported pack cache entry manifest version {}",
            manifest.version
        );
        Ok(manifest)
    }

    fn entry_manifest_path(&self) -> PathBuf {
        self.root
            .join(format!("{}.{}", self.key.as_str(), ENTRY_MANIFEST_EXT))
    }

    fn packstore_object_dir(&self) -> PathBuf {
        self.root.join(PACKSTORE_DIR).join(PACKSTORE_OBJECTS_DIR)
    }

    fn packstore_pack_dir(&self) -> PathBuf {
        self.packstore_object_dir().join(PACKSTORE_PACK_DIR)
    }

    fn pack_path_for_id(&self, pack_id: &str) -> PathBuf {
        self.packstore_pack_dir()
            .join(format!("pack-{pack_id}.pack"))
    }

    fn pack_index_path_for_id(&self, pack_id: &str) -> PathBuf {
        self.packstore_pack_dir()
            .join(format!("pack-{pack_id}.idx"))
    }

    fn covered_wants_for_promotion(
        &self,
        base: &PackCacheBaseMetadata,
        composite_base_key: Option<&PackCacheKey>,
    ) -> Vec<String> {
        let mut covered = composite_base_key
            .and_then(|base_key| match read_pack_cache_metadata(&self.root, base_key.as_str()) {
                Ok(metadata) => Some(metadata.covered_wants_or_request_wants()),
                Err(error) => {
                    warn!(
                        key = %base_key.as_str(),
                        error = %error,
                        "failed to read pack cache base metadata while deriving composite coverage"
                    );
                    base_key.base_request_wants().map(<[String]>::to_vec)
                }
            })
            .unwrap_or_default();
        covered.extend(base.request_wants.clone());
        normalize_oid_list(covered)
    }

    fn write_metadata(&self, entry: &PackCacheRecentEntry) -> Result<()> {
        let now = now_unix_secs();
        let metadata = PackCacheMetadata {
            version: PACK_CACHE_METADATA_VERSION,
            key: self.key.as_str().to_string(),
            owner_repo: self.key.owner_repo.clone(),
            request_wants: entry.request_wants.clone(),
            covered_wants: entry.covered_wants.clone(),
            request_template: entry.request_template.clone(),
            full_tip: entry.full_tip,
            created_at_unix_secs: now,
            last_accessed_unix_secs: now,
            hit_count: 0,
        };
        let path = self
            .root
            .join(format!("{}.{}", self.key.as_str(), METADATA_EXT));
        let tmp_path = self.root.join(format!(
            "{}.tmp.{}.{}",
            self.key.as_str(),
            std::process::id(),
            METADATA_EXT
        ));
        let bytes = serde_json::to_vec(&metadata).context("serialize pack cache metadata")?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("write pack cache metadata {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "promote pack cache metadata {} to {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    }
}

impl Drop for PackCacheWriter {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        let key = self.key.as_str().to_string();
        let tmp_path = self.tmp_pack_path.clone();
        let inflight = Arc::clone(&self.inflight);
        let notify = Arc::clone(&self.notify);
        tokio::spawn(async move {
            if let Err(error) = tokio::fs::remove_file(&tmp_path).await
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %tmp_path.display(), error = %error, "failed to remove dropped pack cache temp raw pack");
            }
            inflight.lock().await.remove(&key);
            notify.notify_waiters();
        });
    }
}

fn pack_cache_key(
    owner_repo: &str,
    ref_tips_digest: &str,
    normalized_request: &str,
    base: Option<PackCacheBaseMetadata>,
) -> PackCacheKey {
    let owner_repo = crate::repo_identity::canonicalize_owner_repo(owner_repo);
    let mut hasher = Sha256::new();
    hasher.update(b"forgeproxy-pack-cache-v1\0");
    hasher.update(owner_repo.as_bytes());
    hasher.update(b"\0");
    hasher.update(ref_tips_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_request.as_bytes());

    PackCacheKey {
        digest: hex_digest(hasher.finalize().as_slice()),
        owner_repo,
        base,
    }
}

fn insert_recent_entry(
    recent: &mut HashMap<String, Vec<PackCacheRecentEntry>>,
    owner_repo: String,
    mut entry: PackCacheRecentEntry,
) {
    entry.request_wants = normalize_oid_list(entry.request_wants);
    entry.covered_wants = normalize_oid_list(entry.covered_wants);
    let entries = recent.entry(owner_repo).or_default();
    entries.retain(|existing| {
        existing.key != entry.key
            && !(existing.request_template == entry.request_template
                && existing.request_wants.len() == entry.request_wants.len()
                && existing.request_wants == entry.request_wants)
    });
    entries.insert(0, entry);
    entries.truncate(MAX_RECENT_ENTRIES_PER_REPO);
}

fn record_recent_entries_metric(
    metrics: &crate::metrics::MetricsRegistry,
    recent: &HashMap<String, Vec<PackCacheRecentEntry>>,
) {
    let counts = recent
        .iter()
        .map(|(owner_repo, entries)| {
            (
                owner_repo.clone(),
                entries.len(),
                entries.iter().filter(|entry| entry.full_tip).count(),
            )
        })
        .collect::<Vec<_>>();
    crate::metrics::replace_pack_cache_recent_entries(metrics, &counts);
}

fn normalize_oid_list(mut oids: Vec<String>) -> Vec<String> {
    oids.sort();
    oids.dedup();
    oids
}

fn collect_repo_ref_tips(
    repo_path: &Path,
) -> std::result::Result<BTreeMap<String, String>, &'static str> {
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

    Ok(tips)
}

/// Compute a stable digest of a bare repo's ref->OID mapping.
///
/// The result changes if and only if the actual tip-OIDs change, regardless of
/// which generation path on disk is live.
fn repo_ref_tips_digest(tips: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (refname, oid) in tips {
        hasher.update(refname.as_bytes());
        hasher.update(b" ");
        hasher.update(oid.as_bytes());
        hasher.update(b"\n");
    }
    hex_digest(hasher.finalize().as_slice())
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

fn unique_tip_oids(tips: &BTreeMap<String, String>) -> Vec<String> {
    let mut oids = tips.values().cloned().collect::<Vec<_>>();
    oids.sort();
    oids.dedup();
    oids
}

#[cfg(test)]
fn normalize_fresh_clone_request(bytes: &[u8]) -> std::result::Result<String, &'static str> {
    Ok(normalize_fresh_clone_request_parts(bytes)?.normalized)
}

struct NormalizedFreshCloneRequest {
    normalized: String,
    non_want_lines: Vec<String>,
    wants: Vec<String>,
}

fn normalize_fresh_clone_request_parts(
    bytes: &[u8],
) -> std::result::Result<NormalizedFreshCloneRequest, &'static str> {
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
    wants.dedup();
    let non_want_lines = normalized;
    let normalized = normalized_request_from_parts(&non_want_lines, &wants);

    Ok(NormalizedFreshCloneRequest {
        normalized,
        non_want_lines,
        wants,
    })
}

fn normalized_request_from_parts(non_want_lines: &[String], wants: &[String]) -> String {
    let mut normalized = non_want_lines.to_vec();
    let mut wants = wants.to_vec();
    wants.sort();
    wants.dedup();
    for want in wants {
        normalized.push(format!("want {want}"));
    }
    normalized.join("\n")
}

fn parse_pkt_len(header: &[u8]) -> Option<usize> {
    if header.len() != 4 {
        return None;
    }
    let text = std::str::from_utf8(header).ok()?;
    usize::from_str_radix(text, 16).ok()
}

fn directory_usage(root: &Path) -> std::io::Result<crate::cache::manager::DiskUsage> {
    crate::cache::manager::dir_usage(root).map_err(std::io::Error::other)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_entry_artifact_exists(root: &Path, key: &str) -> bool {
    root.join(format!("{key}.{ENTRY_MANIFEST_EXT}")).is_file()
}

fn metadata_path(root: &Path, key: &str) -> PathBuf {
    root.join(format!("{key}.{METADATA_EXT}"))
}

fn read_pack_cache_metadata(root: &Path, key: &str) -> Result<PackCacheMetadata> {
    let path = metadata_path(root, key);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read pack cache metadata {}", path.display()))?;
    let metadata: PackCacheMetadata = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse pack cache metadata {}", path.display()))?;
    anyhow::ensure!(
        metadata.version == PACK_CACHE_METADATA_VERSION,
        "unsupported pack cache metadata version {}",
        metadata.version
    );
    Ok(metadata)
}

fn write_pack_cache_metadata(root: &Path, metadata: &PackCacheMetadata) -> Result<()> {
    let path = metadata_path(root, &metadata.key);
    let tmp_path = root.join(format!(
        "{}.tmp.{}.{}",
        metadata.key,
        std::process::id(),
        METADATA_EXT
    ));
    let bytes = serde_json::to_vec(metadata).context("serialize pack cache metadata")?;
    std::fs::write(&tmp_path, bytes)
        .with_context(|| format!("write pack cache metadata {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "promote pack cache metadata {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn record_metadata_hit(root: &Path, key: &str) -> Result<()> {
    let mut metadata = read_pack_cache_metadata(root, key)?;
    metadata.last_accessed_unix_secs = now_unix_secs();
    metadata.hit_count = metadata.hit_count.saturating_add(1);
    write_pack_cache_metadata(root, &metadata)
}

fn record_metadata_hit_if_present(root: &Path, key: &str) -> Result<()> {
    let path = metadata_path(root, key);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("stat pack cache metadata {}", path.display()));
        }
    };
    if let Ok(modified) = metadata.modified()
        && modified.elapsed().unwrap_or_default().as_secs() < METADATA_HIT_UPDATE_INTERVAL_SECS
    {
        return Ok(());
    }
    record_metadata_hit(root, key)
}

fn retain_existing_recent_entries(
    root: &Path,
    recent: &mut HashMap<String, Vec<PackCacheRecentEntry>>,
) {
    recent.retain(|_, entries| {
        entries.retain(|entry| cache_entry_artifact_exists(root, entry.key.as_str()));
        !entries.is_empty()
    });
}

#[derive(Debug)]
struct PackCachePruneEntry {
    key: String,
    paths: Vec<(PathBuf, u64)>,
    size_bytes: u64,
    created_at_unix_secs: u64,
    last_accessed_unix_secs: u64,
    hit_count: u64,
}

impl PackCachePruneEntry {
    fn new(key: String) -> Self {
        Self {
            key,
            paths: Vec::new(),
            size_bytes: 0,
            created_at_unix_secs: 0,
            last_accessed_unix_secs: 0,
            hit_count: 0,
        }
    }

    fn add_path(&mut self, path: PathBuf, size_bytes: u64) {
        self.size_bytes = self.size_bytes.saturating_add(size_bytes);
        self.paths.push((path, size_bytes));
    }

    fn add_owned_bytes(&mut self, size_bytes: u64) {
        self.size_bytes = self.size_bytes.saturating_add(size_bytes);
    }
}

fn pack_cache_key_from_file_name(name: &str) -> Option<String> {
    for ext in [ENTRY_MANIFEST_EXT, METADATA_EXT] {
        let suffix = format!(".{ext}");
        if let Some(key) = name.strip_suffix(&suffix) {
            return Some(key.to_string());
        }
    }
    None
}

fn collect_prune_entries(root: &Path) -> Result<(HashMap<String, PackCachePruneEntry>, u64)> {
    let mut entries = HashMap::<String, PackCachePruneEntry>::new();
    let mut manifests = HashMap::<String, PackEntryManifest>::new();
    let mut pack_refcounts = HashMap::<String, usize>::new();

    if !root.exists() {
        return Ok((entries, 0));
    }

    for entry in std::fs::read_dir(root)
        .with_context(|| format!("read pack cache root {}", root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.contains(".tmp.") {
            continue;
        }
        let Some(key) = pack_cache_key_from_file_name(file_name) else {
            continue;
        };
        let size = crate::cache::manager::file_disk_usage(&metadata).physical_bytes;
        entries
            .entry(key.clone())
            .or_insert_with(|| PackCachePruneEntry::new(key))
            .add_path(path, size);
    }

    let keys = entries.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        if let Ok(metadata) = read_pack_cache_metadata(root, &key)
            && let Some(entry) = entries.get_mut(&key)
        {
            entry.created_at_unix_secs = metadata.created_at_unix_secs;
            entry.last_accessed_unix_secs = metadata.last_accessed_unix_secs;
            entry.hit_count = metadata.hit_count;
        }

        let manifest_path = root.join(format!("{key}.{ENTRY_MANIFEST_EXT}"));
        if manifest_path.is_file()
            && let Ok(bytes) = std::fs::read(&manifest_path)
            && let Ok(manifest) = serde_json::from_slice::<PackEntryManifest>(&bytes)
            && manifest.version == PACK_ENTRY_MANIFEST_VERSION
        {
            for pack_id in &manifest.pack_ids {
                *pack_refcounts.entry(pack_id.clone()).or_insert(0) += 1;
            }
            manifests.insert(key.clone(), manifest);
        }
    }

    let pack_dir = root
        .join(PACKSTORE_DIR)
        .join(PACKSTORE_OBJECTS_DIR)
        .join(PACKSTORE_PACK_DIR);
    for (key, manifest) in manifests {
        if let Some(entry) = entries.get_mut(&key) {
            for pack_id in manifest.pack_ids {
                if pack_id != key && !pack_id.starts_with(&format!("{key}-")) {
                    continue;
                }
                if pack_refcounts.get(&pack_id).copied().unwrap_or_default() > 1 {
                    continue;
                }
                for path in [
                    pack_dir.join(format!("pack-{pack_id}.pack")),
                    pack_dir.join(format!("pack-{pack_id}.idx")),
                ] {
                    if let Ok(metadata) = std::fs::metadata(&path)
                        && metadata.is_file()
                    {
                        entry.add_owned_bytes(
                            crate::cache::manager::file_disk_usage(&metadata).physical_bytes,
                        );
                    }
                }
            }
        }
    }

    Ok((
        entries,
        directory_usage(root)
            .map(|usage| usage.physical_bytes)
            .unwrap_or(0),
    ))
}

fn remove_prune_entry(entry: PackCachePruneEntry) -> std::io::Result<u64> {
    let mut removed = 0u64;
    for (path, size) in entry.paths {
        match std::fs::remove_file(&path) {
            Ok(()) => removed = removed.saturating_add(size),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                removed = removed.saturating_add(size);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(removed)
}

fn garbage_collect_unreferenced_pack_files(root: &Path) -> std::io::Result<()> {
    let mut referenced = HashSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(ENTRY_MANIFEST_EXT) {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let manifest = match serde_json::from_slice::<PackEntryManifest>(&bytes) {
            Ok(manifest) if manifest.version == PACK_ENTRY_MANIFEST_VERSION => manifest,
            _ => continue,
        };
        referenced.extend(manifest.pack_ids);
    }

    let pack_dir = root
        .join(PACKSTORE_DIR)
        .join(PACKSTORE_OBJECTS_DIR)
        .join(PACKSTORE_PACK_DIR);
    if !pack_dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&pack_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == "multi-pack-index"
            || (name.starts_with("multi-pack-index-") && name.ends_with(".bitmap"))
        {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            continue;
        }
        let pack_id = name.strip_prefix("pack-").and_then(|value| {
            value
                .strip_suffix(".pack")
                .or_else(|| value.strip_suffix(".idx"))
        });
        let Some(pack_id) = pack_id else {
            continue;
        };
        if referenced.contains(pack_id) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn prune_to_watermarks(
    root: &Path,
    local_cache_max_percent: f64,
    config: &PackCacheConfig,
    active_readers: &Arc<std::sync::Mutex<HashMap<String, usize>>>,
) -> Result<()> {
    let budget_bytes = crate::cache::capacity::nested_budget_bytes_for_path(
        root,
        local_cache_max_percent,
        config.max_percent,
    )?;
    let high_bytes = crate::cache::capacity::percent_of_bytes(budget_bytes, config.high_water_mark);
    let low_bytes = crate::cache::capacity::percent_of_bytes(budget_bytes, config.low_water_mark);

    let active_keys = active_reader_keys(active_readers);
    prune_to_byte_watermarks_with_active(
        root,
        high_bytes,
        low_bytes,
        config.eviction_policy,
        &active_keys,
    )
}

#[cfg(test)]
fn prune_to_byte_watermarks(
    root: &Path,
    high_bytes: u64,
    low_bytes: u64,
    eviction_policy: EvictionPolicy,
) -> Result<()> {
    prune_to_byte_watermarks_with_active(
        root,
        high_bytes,
        low_bytes,
        eviction_policy,
        &HashSet::new(),
    )
}

fn prune_to_byte_watermarks_with_active(
    root: &Path,
    high_bytes: u64,
    low_bytes: u64,
    eviction_policy: EvictionPolicy,
    active_keys: &HashSet<String>,
) -> Result<()> {
    let (mut entries, mut total) = collect_prune_entries(root)?;
    if total <= high_bytes {
        return Ok(());
    }

    let mut candidates = entries
        .values()
        .map(|entry| {
            (
                entry.key.clone(),
                entry.hit_count,
                entry.last_accessed_unix_secs,
                entry.created_at_unix_secs,
            )
        })
        .collect::<Vec<_>>();
    match eviction_policy {
        EvictionPolicy::Lru => candidates.sort_by_key(|(key, _, last_accessed, created)| {
            (*last_accessed, *created, key.clone())
        }),
        EvictionPolicy::Lfu => candidates.sort_by_key(|(key, hit_count, last_accessed, _)| {
            (*hit_count, *last_accessed, key.clone())
        }),
    }

    let mut deleted = HashSet::new();
    for (candidate_key, _, _, _) in candidates {
        if total <= low_bytes {
            break;
        }
        if deleted.contains(&candidate_key) {
            continue;
        }
        if active_keys.contains(&candidate_key) {
            continue;
        }
        if !deleted.insert(candidate_key.clone()) {
            continue;
        }
        if let Some(entry) = entries.remove(&candidate_key) {
            remove_prune_entry(entry)
                .with_context(|| format!("remove pack cache entry {candidate_key}"))?;
            garbage_collect_unreferenced_pack_files(root).with_context(|| {
                format!(
                    "garbage collect unreferenced pack cache packs after removing {candidate_key}"
                )
            })?;
            total = directory_usage(root)
                .map(|usage| usage.physical_bytes)
                .unwrap_or(0);
        }
    }

    Ok(())
}

fn active_reader_keys(
    active_readers: &Arc<std::sync::Mutex<HashMap<String, usize>>>,
) -> HashSet<String> {
    active_readers
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(key, _)| key.clone())
        .collect()
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

fn parse_sha1_hex(value: &str) -> Result<[u8; 20]> {
    anyhow::ensure!(
        value.len() == 40,
        "pack cache stitched trailer SHA-1 must be 40 hex characters"
    );
    let mut out = [0u8; 20];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .with_context(|| format!("parse pack cache stitched trailer SHA-1 byte {idx}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        PackCache, PackCacheBaseMetadata, PackCacheKey, PackCacheLookup, PackCacheMetadata,
        active_reader_keys, collect_prune_entries, collect_repo_ref_tips, metadata_path,
        normalize_fresh_clone_request, normalize_fresh_clone_request_parts,
        prune_to_byte_watermarks, prune_to_byte_watermarks_with_active, unique_tip_oids,
        write_pack_cache_metadata,
    };
    use crate::config::{EvictionPolicy, PackCacheConfig};
    use crate::metrics::{MetricsRegistry, Protocol};
    use futures::StreamExt;
    use sha1::{Digest, Sha1};

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    fn sideband_packet(band: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 1);
        out.push(band);
        out.extend_from_slice(payload);
        out
    }

    fn raw_pack(count: u32, body: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&count.to_be_bytes());
        pack.extend_from_slice(body);
        let mut sha1 = Sha1::new();
        sha1.update(&pack);
        pack.extend_from_slice(&sha1.finalize());
        pack
    }

    fn pack_response(pack: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&pkt(b"packfile\n"));
        response.extend_from_slice(&pkt(&sideband_packet(1, pack)));
        response.extend_from_slice(b"0000");
        response
    }

    async fn wait_for_pack_cache_metadata(root: &std::path::Path, key: &str) -> PackCacheMetadata {
        for _ in 0..100 {
            if let Ok(metadata) = super::read_pack_cache_metadata(root, key) {
                return metadata;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        super::read_pack_cache_metadata(root, key).unwrap()
    }

    fn write_prune_test_entry(
        root: &std::path::Path,
        key: &str,
        size_bytes: usize,
        hit_count: u64,
        last_accessed_unix_secs: u64,
    ) {
        std::fs::create_dir_all(root).unwrap();
        let pack_dir = root
            .join(super::PACKSTORE_DIR)
            .join(super::PACKSTORE_OBJECTS_DIR)
            .join(super::PACKSTORE_PACK_DIR);
        std::fs::create_dir_all(&pack_dir).unwrap();
        let body_size = size_bytes.saturating_sub(32);
        std::fs::write(
            pack_dir.join(format!("pack-{key}.pack")),
            raw_pack(1, &vec![b'x'; body_size]),
        )
        .unwrap();
        std::fs::write(pack_dir.join(format!("pack-{key}.idx")), []).unwrap();
        std::fs::write(
            root.join(format!("{key}.{}", super::ENTRY_MANIFEST_EXT)),
            serde_json::to_vec(&super::PackEntryManifest {
                version: super::PACK_ENTRY_MANIFEST_VERSION,
                pack_ids: vec![key.to_string()],
                stitched_trailer_sha1: None,
            })
            .unwrap(),
        )
        .unwrap();
        write_pack_cache_metadata(
            root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: key.to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: last_accessed_unix_secs,
                last_accessed_unix_secs,
                hit_count,
            },
        )
        .unwrap();
    }

    fn write_test_pack(cache: &PackCache, pack_id: &str, bytes: &[u8]) {
        std::fs::create_dir_all(cache.packstore_pack_dir()).unwrap();
        std::fs::write(cache.pack_path_for_id(pack_id), bytes).unwrap();
        std::fs::write(cache.pack_index_path_for_id(pack_id), []).unwrap();
    }

    fn write_test_entry_manifest(cache: &PackCache, key: &PackCacheKey, pack_ids: &[String]) {
        std::fs::write(
            cache.entry_manifest_path(key),
            serde_json::to_vec(&super::PackEntryManifest {
                version: super::PACK_ENTRY_MANIFEST_VERSION,
                pack_ids: pack_ids.to_vec(),
                stitched_trailer_sha1: None,
            })
            .unwrap(),
        )
        .unwrap();
    }

    async fn valid_base_and_delta_packs() -> (Vec<u8>, Vec<u8>) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::process::Command::new("git")
            .arg("init")
            .arg(&repo)
            .status()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .status()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .status()
            .unwrap();

        std::fs::write(repo.join("file.txt"), "base\n").unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("add")
            .arg(".")
            .status()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("commit")
            .arg("-m")
            .arg("base")
            .status()
            .unwrap();
        let base_head = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .arg("rev-parse")
                .arg("HEAD")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let base_objects =
            crate::git::commands::git_rev_list_objects(&repo, std::slice::from_ref(&base_head))
                .await
                .unwrap();
        let base_pack = crate::git::commands::git_pack_objects_exact(&repo, &base_objects, 1)
            .await
            .unwrap();

        std::fs::write(repo.join("file.txt"), "base\ndelta\n").unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("add")
            .arg(".")
            .status()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("commit")
            .arg("-m")
            .arg("delta")
            .status()
            .unwrap();
        let delta_head = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .arg("rev-parse")
                .arg("HEAD")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let delta_objects = crate::git::commands::git_rev_list_objects(&repo, &[delta_head])
            .await
            .unwrap();
        let base_set = base_objects
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let missing_objects = delta_objects
            .into_iter()
            .filter(|oid| !base_set.contains(oid))
            .collect::<Vec<_>>();
        let delta_pack = crate::git::commands::git_pack_objects_exact(&repo, &missing_objects, 1)
            .await
            .unwrap();

        (base_pack, delta_pack)
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
    fn fresh_clone_request_parts_keep_template_and_dedupe_wants() {
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"thin-pack\n"));
        request.extend_from_slice(b"0001");
        request.extend_from_slice(&pkt(b"want bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"done\n"));
        request.extend_from_slice(b"0000");

        let parsed = normalize_fresh_clone_request_parts(&request).unwrap();

        assert_eq!(
            parsed.non_want_lines,
            vec!["command=fetch", "thin-pack", "delimiter", "done", "flush"]
        );
        assert_eq!(
            parsed.wants,
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ]
        );
    }

    #[test]
    fn fresh_clone_key_can_use_advertised_ref_tips_without_disk_walk() {
        let temp = tempfile::tempdir().unwrap();
        let refs_heads = temp.path().join("refs").join("heads");
        std::fs::create_dir_all(&refs_heads).unwrap();
        std::fs::write(
            refs_heads.join("main"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"done\n"));
        request.extend_from_slice(b"0000");
        let ref_tips = collect_repo_ref_tips(temp.path()).unwrap();

        let disk_key = cache
            .key_for_fresh_clone("owner/repo", temp.path(), &request, Some("version=2"))
            .unwrap();
        let advertised_key = cache
            .key_for_fresh_clone_with_ref_tips("owner/repo", &request, Some("version=2"), &ref_tips)
            .unwrap();

        assert_eq!(disk_key.as_str(), advertised_key.as_str());
        assert_eq!(
            advertised_key.base_request_wants().unwrap(),
            &["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
        );
    }

    #[test]
    fn repo_ref_tip_collection_dedupes_tip_oids() {
        let temp = tempfile::tempdir().unwrap();
        let refs_heads = temp.path().join("refs").join("heads");
        std::fs::create_dir_all(&refs_heads).unwrap();
        std::fs::write(
            refs_heads.join("main"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        std::fs::write(
            refs_heads.join("alias"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("packed-refs"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v1\n",
        )
        .unwrap();

        let tips = collect_repo_ref_tips(temp.path()).unwrap();

        assert_eq!(
            unique_tip_oids(&tips),
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ]
        );
    }

    #[test]
    fn metadata_hit_updates_are_throttled_when_metadata_file_is_fresh() {
        let temp = tempfile::tempdir().unwrap();
        write_pack_cache_metadata(
            temp.path(),
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: "hot".to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 1,
                last_accessed_unix_secs: 1,
                hit_count: 7,
            },
        )
        .unwrap();

        super::record_metadata_hit_if_present(temp.path(), "hot").unwrap();

        let metadata = super::read_pack_cache_metadata(temp.path(), "hot").unwrap();
        assert_eq!(metadata.hit_count, 7);
        assert_eq!(metadata.last_accessed_unix_secs, 1);
    }

    #[test]
    fn lru_pruning_evicts_oldest_accessed_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_prune_test_entry(root, "old", 128, 10, 10);
        write_prune_test_entry(root, "new", 128, 1, 20);

        let (entries, total) = collect_prune_entries(root).unwrap();
        let old_size = entries.get("old").unwrap().size_bytes;

        prune_to_byte_watermarks(
            root,
            total.saturating_sub(1),
            total.saturating_sub(old_size),
            EvictionPolicy::Lru,
        )
        .unwrap();

        assert!(
            !root
                .join(format!("old.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(!metadata_path(root, "old").exists());
        assert!(
            root.join(format!("new.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(metadata_path(root, "new").exists());
    }

    #[test]
    fn lfu_pruning_evicts_lowest_hit_count_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_prune_test_entry(root, "popular", 128, 10, 10);
        write_prune_test_entry(root, "cold", 128, 1, 20);

        let (entries, total) = collect_prune_entries(root).unwrap();
        let cold_size = entries.get("cold").unwrap().size_bytes;

        prune_to_byte_watermarks(
            root,
            total.saturating_sub(1),
            total.saturating_sub(cold_size),
            EvictionPolicy::Lfu,
        )
        .unwrap();

        assert!(
            !root
                .join(format!("cold.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(!metadata_path(root, "cold").exists());
        assert!(
            root.join(format!("popular.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(metadata_path(root, "popular").exists());
    }

    #[test]
    fn pruning_base_entry_keeps_shared_packs_needed_by_composites() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write_prune_test_entry(root, "base", 128, 0, 10);
        let pack_dir = root
            .join(super::PACKSTORE_DIR)
            .join(super::PACKSTORE_OBJECTS_DIR)
            .join(super::PACKSTORE_PACK_DIR);
        write_pack_cache_metadata(
            root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: "composite".to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 20,
                last_accessed_unix_secs: 20,
                hit_count: 5,
            },
        )
        .unwrap();
        std::fs::write(pack_dir.join("pack-composite-delta.pack"), vec![0_u8; 64]).unwrap();
        std::fs::write(pack_dir.join("pack-composite-delta.idx"), []).unwrap();
        std::fs::write(
            root.join(format!("composite.{}", super::ENTRY_MANIFEST_EXT)),
            serde_json::to_vec(&super::PackEntryManifest {
                version: super::PACK_ENTRY_MANIFEST_VERSION,
                pack_ids: vec!["base".to_string(), "composite-delta".to_string()],
                stitched_trailer_sha1: None,
            })
            .unwrap(),
        )
        .unwrap();

        let (entries, total) = collect_prune_entries(root).unwrap();
        let base_size = entries.get("base").unwrap().size_bytes;

        prune_to_byte_watermarks(
            root,
            total.saturating_sub(1),
            total.saturating_sub(base_size),
            EvictionPolicy::Lru,
        )
        .unwrap();

        assert!(
            !root
                .join(format!("base.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(!metadata_path(root, "base").exists());
        assert!(
            root.join(format!("composite.{}", super::ENTRY_MANIFEST_EXT))
                .exists()
        );
        assert!(metadata_path(root, "composite").exists());
        assert!(pack_dir.join("pack-base.pack").exists());
        assert!(pack_dir.join("pack-composite-delta.pack").exists());
    }

    #[tokio::test]
    async fn composite_artifact_replays_base_plus_delta_pack() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();

        let base_key = PackCacheKey {
            digest: "base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let composite_key = PackCacheKey {
            digest: "composite".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let (base_pack, delta_pack) = valid_base_and_delta_packs().await;
        write_test_pack(&cache, base_key.as_str(), &base_pack);
        write_test_entry_manifest(&cache, &base_key, &[base_key.as_str().to_string()]);
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: base_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 10,
                last_accessed_unix_secs: 10,
                hit_count: 0,
            },
        )
        .unwrap();

        let lookup = cache
            .lookup_or_reserve(Protocol::Https, composite_key.clone())
            .await
            .unwrap();
        let super::PackCacheLookup::Generate(writer) = lookup else {
            panic!("expected cache reservation");
        };
        writer
            .finish_composite(&base_key, &delta_pack)
            .await
            .unwrap();

        let hit = cache.lookup_by_key(&composite_key).await.unwrap().unwrap();
        assert!(hit.is_composite());
        let mut stream = hit.into_stream();
        let mut replayed = Vec::new();
        while let Some(chunk) = stream.next().await {
            replayed.extend_from_slice(&chunk.unwrap());
        }
        let raw = super::stitch::extract_raw_pack(&replayed).unwrap();
        let expected_count = u32::from_be_bytes(base_pack[8..12].try_into().unwrap())
            + u32::from_be_bytes(delta_pack[8..12].try_into().unwrap());
        let manifest = cache.read_entry_manifest(&composite_key).unwrap();
        let stitched_trailer_sha1 = manifest
            .stitched_trailer_sha1
            .as_deref()
            .map(super::parse_sha1_hex)
            .transpose()
            .unwrap()
            .expect("composite manifest should persist stitched trailer");

        assert_eq!(&raw[..4], b"PACK");
        assert_eq!(
            u32::from_be_bytes(raw[8..12].try_into().unwrap()),
            expected_count
        );
        assert_eq!(&raw[raw.len() - 20..], stitched_trailer_sha1.as_slice());
    }

    #[tokio::test]
    async fn replay_hit_is_available_before_index_is_written() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();

        let key = PackCacheKey {
            digest: "replay-only".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let pack = raw_pack(1, b"replay-before-index");
        std::fs::create_dir_all(cache.packstore_pack_dir()).unwrap();
        std::fs::write(cache.pack_path_for_id(key.as_str()), &pack).unwrap();
        write_test_entry_manifest(&cache, &key, &[key.as_str().to_string()]);

        let hit = cache.lookup_by_key(&key).await.unwrap().unwrap();
        let mut stream = hit.into_stream();
        let mut replayed = Vec::new();
        while let Some(chunk) = stream.next().await {
            replayed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(super::stitch::extract_raw_pack(&replayed).unwrap(), pack);
        assert!(cache.pack_paths_for_key(&key).is_err());
    }

    #[tokio::test]
    async fn composite_promotion_persists_transitive_covered_wants() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();

        let want_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let want_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        let want_c = "cccccccccccccccccccccccccccccccccccccccc".to_string();
        let want_d = "dddddddddddddddddddddddddddddddddddddddd".to_string();
        let base_key = PackCacheKey {
            digest: "base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec![want_b.clone()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let composite_key = PackCacheKey {
            digest: "composite".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec![want_c.clone()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let (base_pack, delta_pack) = valid_base_and_delta_packs().await;
        write_test_pack(&cache, base_key.as_str(), &base_pack);
        write_test_entry_manifest(&cache, &base_key, &[base_key.as_str().to_string()]);
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: base_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: vec![want_b.clone()],
                covered_wants: vec![want_a.clone(), want_b.clone()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
                created_at_unix_secs: 10,
                last_accessed_unix_secs: 10,
                hit_count: 0,
            },
        )
        .unwrap();

        let lookup = cache
            .lookup_or_reserve(Protocol::Https, composite_key.clone())
            .await
            .unwrap();
        let super::PackCacheLookup::Generate(writer) = lookup else {
            panic!("expected cache reservation");
        };
        writer
            .finish_composite(&base_key, &delta_pack)
            .await
            .unwrap();

        let metadata = wait_for_pack_cache_metadata(&cache.root, composite_key.as_str()).await;
        assert_eq!(metadata.request_wants, vec![want_c.clone()]);
        assert_eq!(
            metadata.covered_wants,
            vec![want_a.clone(), want_b.clone(), want_c.clone()]
        );

        let future_key = PackCacheKey {
            digest: "future".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec![want_d],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let candidates = cache.lookup_recent_compatible_keys(&future_key);
        assert_eq!(candidates.len(), 1);
        let recent = &candidates[0];
        assert_eq!(recent.key.as_str(), composite_key.as_str());
        assert_eq!(recent.request_wants, vec![want_c.clone()]);
        assert_eq!(recent.covered_wants, vec![want_a, want_b, want_c]);
    }

    #[tokio::test]
    async fn full_read_lease_survives_unlink_after_open() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();
        let key = PackCacheKey {
            digest: "active-full".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        write_prune_test_entry(&cache.root, key.as_str(), 128, 0, 10);

        let lease = cache.lookup_by_key(&key).await.unwrap().unwrap();
        std::fs::remove_file(cache.entry_manifest_path(&key)).unwrap();

        let mut replayed = Vec::new();
        let mut stream = lease.into_stream();
        while let Some(chunk) = stream.next().await {
            replayed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            super::stitch::extract_raw_pack(&replayed).unwrap().len(),
            128
        );
    }

    #[tokio::test]
    async fn composite_read_lease_survives_unlink_after_open() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();
        let base_key = PackCacheKey {
            digest: "base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let composite_key = PackCacheKey {
            digest: "composite".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let base_pack = raw_pack(1, b"base-body");
        let delta_pack = raw_pack(2, b"delta-body");
        write_test_pack(&cache, base_key.as_str(), &base_pack);
        write_test_pack(&cache, "composite-delta", &delta_pack);
        write_test_entry_manifest(&cache, &base_key, &[base_key.as_str().to_string()]);
        write_test_entry_manifest(
            &cache,
            &composite_key,
            &[base_key.as_str().to_string(), "composite-delta".to_string()],
        );
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: base_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 10,
                last_accessed_unix_secs: 10,
                hit_count: 0,
            },
        )
        .unwrap();
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: composite_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 20,
                last_accessed_unix_secs: 20,
                hit_count: 0,
            },
        )
        .unwrap();

        let lease = cache.lookup_by_key(&composite_key).await.unwrap().unwrap();
        std::fs::remove_file(cache.entry_manifest_path(&base_key)).unwrap();
        std::fs::remove_file(cache.pack_path_for_id(base_key.as_str())).unwrap();
        std::fs::remove_file(cache.pack_path_for_id("composite-delta")).unwrap();
        std::fs::remove_file(cache.entry_manifest_path(&composite_key)).unwrap();

        let mut replayed = Vec::new();
        let mut stream = lease.into_stream();
        while let Some(chunk) = stream.next().await {
            replayed.extend_from_slice(&chunk.unwrap());
        }
        let raw = super::stitch::extract_raw_pack(&replayed).unwrap();

        assert_eq!(&raw[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(raw[8..12].try_into().unwrap()), 3);
        assert_eq!(&raw[12..raw.len() - 20], b"base-bodydelta-body");
    }

    #[tokio::test]
    async fn pruning_skips_active_full_readers() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();
        let key = PackCacheKey {
            digest: "active-full".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        write_prune_test_entry(&cache.root, key.as_str(), 128, 0, 10);

        let lease = cache.lookup_by_key(&key).await.unwrap().unwrap();
        let (_, total) = collect_prune_entries(&cache.root).unwrap();
        prune_to_byte_watermarks_with_active(
            &cache.root,
            total.saturating_sub(1),
            0,
            EvictionPolicy::Lru,
            &active_reader_keys(&cache.active_readers),
        )
        .unwrap();
        assert!(cache.entry_manifest_path(&key).exists());

        drop(lease);
        prune_to_byte_watermarks(&cache.root, total.saturating_sub(1), 0, EvictionPolicy::Lru)
            .unwrap();
        assert!(!cache.entry_manifest_path(&key).exists());
    }

    #[tokio::test]
    async fn pruning_skips_active_composite_dependency_closure() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();
        let base_key = PackCacheKey {
            digest: "base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let composite_key = PackCacheKey {
            digest: "composite".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: None,
        };
        let base_pack = raw_pack(1, b"base-body");
        let delta_pack = raw_pack(2, b"delta-body");
        write_test_pack(&cache, base_key.as_str(), &base_pack);
        write_test_pack(&cache, "composite-delta", &delta_pack);
        write_test_entry_manifest(&cache, &base_key, &[base_key.as_str().to_string()]);
        write_test_entry_manifest(
            &cache,
            &composite_key,
            &[base_key.as_str().to_string(), "composite-delta".to_string()],
        );
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: base_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 10,
                last_accessed_unix_secs: 10,
                hit_count: 0,
            },
        )
        .unwrap();
        write_pack_cache_metadata(
            &cache.root,
            &PackCacheMetadata {
                version: super::PACK_CACHE_METADATA_VERSION,
                key: composite_key.as_str().to_string(),
                owner_repo: "owner/repo".to_string(),
                request_wants: Vec::new(),
                covered_wants: Vec::new(),
                request_template: Vec::new(),
                full_tip: false,
                created_at_unix_secs: 20,
                last_accessed_unix_secs: 20,
                hit_count: 0,
            },
        )
        .unwrap();

        let lease = cache.lookup_by_key(&composite_key).await.unwrap().unwrap();
        let (_, total) = collect_prune_entries(&cache.root).unwrap();
        prune_to_byte_watermarks_with_active(
            &cache.root,
            total.saturating_sub(1),
            0,
            EvictionPolicy::Lru,
            &active_reader_keys(&cache.active_readers),
        )
        .unwrap();
        assert!(cache.entry_manifest_path(&composite_key).exists());
        assert!(
            cache.pack_path_for_id(base_key.as_str()).exists()
                && cache.pack_path_for_id("composite-delta").exists()
        );

        drop(lease);
        let (_, total_after_drop) = collect_prune_entries(&cache.root).unwrap();
        prune_to_byte_watermarks(
            &cache.root,
            total_after_drop.saturating_sub(1),
            0,
            EvictionPolicy::Lru,
        )
        .unwrap();
        assert!(!cache.entry_manifest_path(&base_key).exists());
        assert!(!cache.entry_manifest_path(&composite_key).exists());
        assert!(
            !cache.pack_path_for_id(base_key.as_str()).exists()
                && !cache.pack_path_for_id("composite-delta").exists()
        );
    }

    #[test]
    fn partial_fresh_clone_key_keeps_actual_request_wants_as_base_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let refs_heads = temp.path().join("refs").join("heads");
        std::fs::create_dir_all(&refs_heads).unwrap();
        std::fs::write(
            refs_heads.join("main"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        std::fs::write(
            refs_heads.join("other"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"done\n"));
        request.extend_from_slice(b"0000");

        let key = cache
            .key_for_fresh_clone("owner/repo", temp.path(), &request, Some("version=2"))
            .unwrap();
        let base = key
            .base
            .as_ref()
            .expect("fresh clone key should carry base metadata");

        assert_eq!(
            base.request_wants,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        assert!(!base.full_tip);
    }

    #[test]
    fn fresh_clone_key_canonicalizes_git_suffix_for_cross_protocol_hits() {
        let temp = tempfile::tempdir().unwrap();
        let refs_heads = temp.path().join("refs").join("heads");
        std::fs::create_dir_all(&refs_heads).unwrap();
        std::fs::write(
            refs_heads.join("main"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        let mut request = Vec::new();
        request.extend_from_slice(&pkt(b"command=fetch\n"));
        request.extend_from_slice(&pkt(b"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        request.extend_from_slice(&pkt(b"done\n"));
        request.extend_from_slice(b"0000");

        let without_suffix = cache
            .key_for_fresh_clone("owner/repo", temp.path(), &request, Some("version=2"))
            .unwrap();
        let with_suffix = cache
            .key_for_fresh_clone("owner/repo.git", temp.path(), &request, Some("version=2"))
            .unwrap();

        assert_eq!(without_suffix.as_str(), with_suffix.as_str());
        assert_eq!(without_suffix.owner_repo, "owner/repo");
        assert_eq!(with_suffix.owner_repo, "owner/repo");
    }

    #[tokio::test]
    async fn persisted_metadata_reloads_recent_compatible_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let config = PackCacheConfig {
            enabled: true,
            max_percent: 1.0,
            wait_for_inflight_secs: 1,
            min_response_bytes: 0,
            ..PackCacheConfig::default()
        };
        let cache = PackCache::new(temp.path(), config.clone(), 1.0, MetricsRegistry::new());
        cache.ensure_ready().await.unwrap();
        let base_key = PackCacheKey {
            digest: "persisted-base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let lookup = cache
            .lookup_or_reserve(Protocol::Https, base_key.clone())
            .await
            .unwrap();
        let super::PackCacheLookup::Generate(mut writer) = lookup else {
            panic!("expected cache reservation");
        };
        let (base_pack, _) = valid_base_and_delta_packs().await;
        writer
            .write_chunk(&pack_response(&base_pack))
            .await
            .unwrap();
        writer.finish().await.unwrap();
        cache.lookup_by_key(&base_key).await.unwrap().unwrap();

        let metadata_root = temp
            .path()
            .join(crate::cache::layout::STATE_ROOT_DIR)
            .join(super::PACK_CACHE_DIR);
        let metadata = wait_for_pack_cache_metadata(&metadata_root, base_key.as_str()).await;
        assert_eq!(metadata.hit_count, 0);
        assert_eq!(
            metadata.covered_wants,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );

        let reloaded = PackCache::new(temp.path(), config, 1.0, MetricsRegistry::new());
        reloaded.ensure_ready().await.unwrap();
        let future_key = PackCacheKey {
            digest: "future".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };

        let candidates = reloaded.lookup_recent_compatible_keys(&future_key);

        assert_eq!(candidates.len(), 1);
        let recent = &candidates[0];
        assert_eq!(recent.key.as_str(), "persisted-base");
        assert_eq!(
            recent.request_wants,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        assert_eq!(
            recent.covered_wants,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        assert!(!recent.full_tip);
    }

    #[tokio::test]
    async fn lookup_or_reserve_does_not_reuse_full_tip_entry_when_templates_differ() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();

        let base_key = PackCacheKey {
            digest: "full-tip-base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: true,
            }),
        };
        let lookup = cache
            .lookup_or_reserve(Protocol::Https, base_key.clone())
            .await
            .unwrap();
        let PackCacheLookup::Generate(mut writer) = lookup else {
            panic!("expected cache reservation");
        };
        let (base_pack, _) = valid_base_and_delta_packs().await;
        writer
            .write_chunk(&pack_response(&base_pack))
            .await
            .unwrap();
        writer.finish().await.unwrap();

        let future_key = PackCacheKey {
            digest: "compatible-full-tip".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "thin-pack".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: true,
            }),
        };

        let lookup = cache
            .lookup_or_reserve(Protocol::Https, future_key)
            .await
            .unwrap();
        let PackCacheLookup::Generate(writer) = lookup else {
            panic!("expected cache reservation");
        };
        writer.abort().await;
    }

    #[tokio::test]
    async fn lookup_or_reserve_does_not_reuse_entry_when_wants_differ() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
                ..PackCacheConfig::default()
            },
            1.0,
            MetricsRegistry::new(),
        );
        cache.ensure_ready().await.unwrap();

        let base_key = PackCacheKey {
            digest: "single-branch-base".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };
        let lookup = cache
            .lookup_or_reserve(Protocol::Https, base_key.clone())
            .await
            .unwrap();
        let PackCacheLookup::Generate(mut writer) = lookup else {
            panic!("expected cache reservation");
        };
        let (base_pack, _) = valid_base_and_delta_packs().await;
        writer
            .write_chunk(&pack_response(&base_pack))
            .await
            .unwrap();
        writer.finish().await.unwrap();

        let future_key = PackCacheKey {
            digest: "single-branch-fast-forward".to_string(),
            owner_repo: "owner/repo".to_string(),
            base: Some(PackCacheBaseMetadata {
                request_wants: vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()],
                request_template: vec![
                    "command=fetch".to_string(),
                    "done".to_string(),
                    "flush".to_string(),
                ],
                full_tip: false,
            }),
        };

        let lookup = cache
            .lookup_or_reserve(Protocol::Https, future_key)
            .await
            .unwrap();
        let PackCacheLookup::Generate(writer) = lookup else {
            panic!("expected cache reservation");
        };
        writer.abort().await;
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
