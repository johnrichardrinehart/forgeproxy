pub(crate) mod stitch;

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{Mutex, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::config::PackCacheConfig;
use crate::metrics::{MetricsRegistry, Protocol};

const PACK_CACHE_DIR: &str = "pack-cache";
const PACK_RESPONSE_EXT: &str = "pack-response";
const COMPOSITE_MANIFEST_EXT: &str = "pack-composite.json";
const DELTA_PACK_EXT: &str = "delta.pack";
const METADATA_EXT: &str = "pack-cache-meta.json";
const COMPOSITE_MANIFEST_VERSION: u32 = 1;
const PACK_CACHE_METADATA_VERSION: u32 = 1;
const MAX_RECENT_ENTRIES_PER_REPO: usize = 16;

#[derive(Clone)]
pub struct PackCache {
    root: PathBuf,
    config: PackCacheConfig,
    max_bytes: u64,
    inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
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

    fn from_digest(digest: String) -> Self {
        Self {
            digest,
            owner_repo: String::new(),
            base: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackCacheRecentEntry {
    pub key: PackCacheKey,
    pub request_wants: Vec<String>,
    pub request_template: Vec<String>,
    pub full_tip: bool,
}

#[derive(Debug, Clone)]
struct PackCacheBaseMetadata {
    request_wants: Vec<String>,
    request_template: Vec<String>,
    full_tip: bool,
}

pub struct PackCacheHit {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub artifact: PackCacheArtifact,
}

pub enum PackCacheArtifact {
    Full,
    Composite { key: PackCacheKey },
}

#[derive(Debug, Serialize, Deserialize)]
struct CompositeManifest {
    version: u32,
    base_key: String,
    delta_pack_file: String,
    delta_size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PackCacheMetadata {
    version: u32,
    key: String,
    owner_repo: String,
    request_wants: Vec<String>,
    request_template: Vec<String>,
    full_tip: bool,
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
    recent_pack_cache_keys: Arc<std::sync::Mutex<HashMap<String, Vec<PackCacheRecentEntry>>>>,
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
            recent_pack_cache_keys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            metrics,
        }
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        if self.config.enabled {
            tokio::fs::create_dir_all(&self.root)
                .await
                .with_context(|| format!("create pack cache root {}", self.root.display()))?;
            self.reload_recent_metadata()
                .with_context(|| format!("reload pack cache metadata {}", self.root.display()))?;
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

        let request = normalize_fresh_clone_request_parts(request_body)?;
        let ref_tips = collect_repo_ref_tips(repo_path)?;
        let tip_oids = unique_tip_oids(&ref_tips);
        let ref_tips_digest = repo_ref_tips_digest(&ref_tips);
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

    pub fn lookup_recent_compatible_key(&self, key: &PackCacheKey) -> Option<PackCacheRecentEntry> {
        let base = key.base.as_ref()?;
        self.recent_pack_cache_keys
            .lock()
            .ok()?
            .get(&key.owner_repo)?
            .iter()
            .find(|entry| {
                entry.request_template == base.request_template
                    && entry.request_wants.len() == base.request_wants.len()
                    && entry.key != *key
            })
            .cloned()
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

    pub async fn lookup_by_key(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        self.lookup(key).await
    }

    pub fn stream_composite_response(
        &self,
        hit: &PackCacheHit,
    ) -> Result<ReceiverStream<io::Result<Bytes>>> {
        let PackCacheArtifact::Composite { key } = &hit.artifact else {
            anyhow::bail!("pack cache hit is not a composite artifact");
        };
        let (base_path, delta_paths) = self.composite_chain(key)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(8);

        tokio::task::spawn_blocking(move || {
            let result =
                stitch::stream_stitched_response_from_paths(&base_path, &delta_paths, |chunk| {
                    sender
                        .blocking_send(Ok(Bytes::from(chunk)))
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "receiver closed"))
                });
            if let Err(error) = result {
                let _ = sender.blocking_send(Err(io::Error::other(error.to_string())));
            }
        });

        Ok(ReceiverStream::new(receiver))
    }

    async fn lookup(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        if let Some(hit) = self.lookup_full_path(key)? {
            return Ok(Some(hit));
        }
        self.lookup_composite_path(key)
    }

    fn lookup_sync(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        if let Some(hit) = self.lookup_full_path(key)? {
            return Ok(Some(hit));
        }
        self.lookup_composite_path(key)
    }

    fn lookup_full_path(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        let path = self.final_path(key);
        self.lookup_existing_file(&path).map(|metadata| {
            metadata.map(|metadata| PackCacheHit {
                path,
                size_bytes: metadata.len(),
                artifact: PackCacheArtifact::Full,
            })
        })
    }

    fn lookup_composite_path(&self, key: &PackCacheKey) -> Result<Option<PackCacheHit>> {
        let manifest_path = self.composite_manifest_path(key);
        let Some(metadata) = self.lookup_existing_file(&manifest_path)? else {
            return Ok(None);
        };
        if self.composite_chain(key).is_err() {
            self.remove_composite_files(key);
            return Ok(None);
        }

        Ok(Some(PackCacheHit {
            path: manifest_path,
            size_bytes: metadata.len(),
            artifact: PackCacheArtifact::Composite { key: key.clone() },
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

        if artifact_is_expired(&metadata, self.config.ttl_secs) {
            if let Err(error) = std::fs::remove_file(path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %path.display(), error = %error, "failed to remove expired pack cache artifact");
            }
            return Ok(None);
        }

        Ok(Some(metadata))
    }

    fn composite_chain(&self, key: &PackCacheKey) -> Result<(PathBuf, Vec<PathBuf>)> {
        let mut current_key = key.clone();
        let mut delta_paths = Vec::new();
        let mut seen = std::collections::HashSet::new();

        loop {
            if !seen.insert(current_key.as_str().to_string()) {
                anyhow::bail!("cycle in pack cache composite chain");
            }

            let full_path = self.final_path(&current_key);
            if self.lookup_existing_file(&full_path)?.is_some() {
                delta_paths.reverse();
                return Ok((full_path, delta_paths));
            }

            let manifest = self.read_composite_manifest(&current_key)?;
            let delta_path = self.root.join(&manifest.delta_pack_file);
            self.lookup_existing_file(&delta_path)?
                .with_context(|| format!("missing pack cache delta {}", delta_path.display()))?;
            delta_paths.push(delta_path);
            current_key = PackCacheKey::from_digest(manifest.base_key);
        }
    }

    fn read_composite_manifest(&self, key: &PackCacheKey) -> Result<CompositeManifest> {
        let path = self.composite_manifest_path(key);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read pack cache composite manifest {}", path.display()))?;
        let manifest: CompositeManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse pack cache composite manifest {}", path.display()))?;
        anyhow::ensure!(
            manifest.version == COMPOSITE_MANIFEST_VERSION,
            "unsupported pack cache composite manifest version {}",
            manifest.version
        );
        Ok(manifest)
    }

    fn remove_composite_files(&self, key: &PackCacheKey) {
        if let Ok(manifest) = self.read_composite_manifest(key) {
            let delta_path = self.root.join(manifest.delta_pack_file);
            if let Err(error) = std::fs::remove_file(&delta_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %delta_path.display(), error = %error, "failed to remove invalid pack cache delta");
            }
        }
        let manifest_path = self.composite_manifest_path(key);
        if let Err(error) = std::fs::remove_file(&manifest_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %manifest_path.display(), error = %error, "failed to remove invalid pack cache composite manifest");
        }
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
            recent_pack_cache_keys: Arc::clone(&self.recent_pack_cache_keys),
            notify,
            metrics: self.metrics.clone(),
            completed: false,
        })
    }

    fn final_path(&self, key: &PackCacheKey) -> PathBuf {
        self.root
            .join(format!("{}.{}", key.as_str(), PACK_RESPONSE_EXT))
    }

    fn composite_manifest_path(&self, key: &PackCacheKey) -> PathBuf {
        self.root
            .join(format!("{}.{}", key.as_str(), COMPOSITE_MANIFEST_EXT))
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
            let key = PackCacheKey::from_digest(metadata.key.clone());
            if self.lookup_sync(&key)?.is_none() {
                continue;
            }
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
                    request_template: metadata.request_template,
                    full_tip: metadata.full_tip,
                },
            );
        }

        *self.recent_pack_cache_keys.lock().unwrap() = recent;
        Ok(())
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
    pub(crate) fn key(&self) -> &PackCacheKey {
        &self.key
    }

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
            self.record_promotion();
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

    pub async fn finish_composite(
        mut self,
        base_key: &PackCacheKey,
        delta_pack: &[u8],
    ) -> Result<PackCacheHit> {
        self.writer
            .shutdown()
            .await
            .context("shutdown unused full pack cache temp artifact writer")?;
        if let Err(error) = tokio::fs::remove_file(&self.tmp_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %self.tmp_path.display(), error = %error, "failed to remove unused full pack cache temp artifact");
        }

        let final_delta_path = self
            .root
            .join(format!("{}.{}", self.key.as_str(), DELTA_PACK_EXT));
        let final_manifest_path =
            self.root
                .join(format!("{}.{}", self.key.as_str(), COMPOSITE_MANIFEST_EXT));
        let tmp_delta_path = self.root.join(format!(
            "{}.tmp.{}.{}",
            self.key.as_str(),
            std::process::id(),
            DELTA_PACK_EXT
        ));
        let tmp_manifest_path = self.root.join(format!(
            "{}.tmp.{}.{}",
            self.key.as_str(),
            std::process::id(),
            COMPOSITE_MANIFEST_EXT
        ));
        let delta_file_name = final_delta_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("pack cache delta path is not valid UTF-8")?
            .to_string();

        tokio::fs::write(&tmp_delta_path, delta_pack)
            .await
            .with_context(|| format!("write pack cache delta {}", tmp_delta_path.display()))?;
        let manifest = CompositeManifest {
            version: COMPOSITE_MANIFEST_VERSION,
            base_key: base_key.as_str().to_string(),
            delta_pack_file: delta_file_name,
            delta_size_bytes: delta_pack.len() as u64,
        };
        let manifest_bytes =
            serde_json::to_vec(&manifest).context("serialize pack cache composite manifest")?;
        tokio::fs::write(&tmp_manifest_path, manifest_bytes)
            .await
            .with_context(|| {
                format!(
                    "write pack cache composite manifest {}",
                    tmp_manifest_path.display()
                )
            })?;
        tokio::fs::rename(&tmp_delta_path, &final_delta_path)
            .await
            .with_context(|| {
                format!(
                    "promote pack cache delta {} to {}",
                    tmp_delta_path.display(),
                    final_delta_path.display()
                )
            })?;
        tokio::fs::rename(&tmp_manifest_path, &final_manifest_path)
            .await
            .with_context(|| {
                format!(
                    "promote pack cache composite manifest {} to {}",
                    tmp_manifest_path.display(),
                    final_manifest_path.display()
                )
            })?;

        self.bytes_written = delta_pack.len() as u64;
        self.record_promotion();
        self.completed = true;
        crate::metrics::set_pack_cache_size_bytes(
            &self.metrics,
            directory_size(&self.root).unwrap_or(0),
        );
        self.release_inflight().await;

        Ok(PackCacheHit {
            path: final_manifest_path,
            size_bytes: delta_pack.len() as u64,
            artifact: PackCacheArtifact::Composite {
                key: self.key.clone(),
            },
        })
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

    fn record_promotion(&self) {
        crate::metrics::observe_pack_cache_artifact_generation(
            &self.metrics,
            self.started_at.elapsed(),
        );
        if let Some(base) = &self.key.base {
            let entry = PackCacheRecentEntry {
                key: self.key.clone(),
                request_wants: base.request_wants.clone(),
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
    }

    fn write_metadata(&self, entry: &PackCacheRecentEntry) -> Result<()> {
        let metadata = PackCacheMetadata {
            version: PACK_CACHE_METADATA_VERSION,
            key: self.key.as_str().to_string(),
            owner_repo: self.key.owner_repo.clone(),
            request_wants: entry.request_wants.clone(),
            request_template: entry.request_template.clone(),
            full_tip: entry.full_tip,
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

fn pack_cache_key(
    owner_repo: &str,
    ref_tips_digest: &str,
    normalized_request: &str,
    base: Option<PackCacheBaseMetadata>,
) -> PackCacheKey {
    let mut hasher = Sha256::new();
    hasher.update(b"forgeproxy-pack-cache-v1\0");
    hasher.update(owner_repo.as_bytes());
    hasher.update(b"\0");
    hasher.update(ref_tips_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_request.as_bytes());

    PackCacheKey {
        digest: hex_digest(hasher.finalize().as_slice()),
        owner_repo: owner_repo.to_string(),
        base,
    }
}

fn insert_recent_entry(
    recent: &mut HashMap<String, Vec<PackCacheRecentEntry>>,
    owner_repo: String,
    entry: PackCacheRecentEntry,
) {
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

fn is_pack_cache_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.ends_with(PACK_RESPONSE_EXT)
                || name.ends_with(COMPOSITE_MANIFEST_EXT)
                || name.ends_with(DELTA_PACK_EXT)
        })
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
        if !is_pack_cache_artifact(&path) {
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
    use super::{
        PackCache, PackCacheArtifact, PackCacheBaseMetadata, PackCacheKey, collect_repo_ref_tips,
        normalize_fresh_clone_request, normalize_fresh_clone_request_parts, unique_tip_oids,
    };
    use crate::config::PackCacheConfig;
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

    #[tokio::test]
    async fn composite_artifact_replays_base_plus_delta_pack() {
        let temp = tempfile::tempdir().unwrap();
        let cache = PackCache::new(
            temp.path(),
            PackCacheConfig {
                enabled: true,
                max_percent: 1.0,
                ttl_secs: 900,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
            },
            1024 * 1024,
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
        let base_pack = raw_pack(1, b"base-body");
        let delta_pack = raw_pack(2, b"delta-body");
        tokio::fs::write(cache.final_path(&base_key), pack_response(&base_pack))
            .await
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
        assert!(matches!(hit.artifact, PackCacheArtifact::Composite { .. }));
        let mut stream = cache.stream_composite_response(&hit).unwrap();
        let mut replayed = Vec::new();
        while let Some(chunk) = stream.next().await {
            replayed.extend_from_slice(&chunk.unwrap());
        }
        let raw = super::stitch::extract_raw_pack(&replayed).unwrap();

        assert_eq!(&raw[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(raw[8..12].try_into().unwrap()), 3);
        assert_eq!(&raw[12..raw.len() - 20], b"base-bodydelta-body");
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
                ttl_secs: 900,
                wait_for_inflight_secs: 1,
                min_response_bytes: 0,
            },
            1024 * 1024,
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

    #[tokio::test]
    async fn persisted_metadata_reloads_recent_compatible_base() {
        let temp = tempfile::tempdir().unwrap();
        let config = PackCacheConfig {
            enabled: true,
            max_percent: 1.0,
            ttl_secs: 900,
            wait_for_inflight_secs: 1,
            min_response_bytes: 0,
        };
        let cache = PackCache::new(
            temp.path(),
            config.clone(),
            1024 * 1024,
            MetricsRegistry::new(),
        );
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
        writer.write_chunk(b"not a real response").await.unwrap();
        writer.finish().await.unwrap();

        let reloaded = PackCache::new(temp.path(), config, 1024 * 1024, MetricsRegistry::new());
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

        let recent = reloaded.lookup_recent_compatible_key(&future_key).unwrap();

        assert_eq!(recent.key.as_str(), "persisted-base");
        assert_eq!(
            recent.request_wants,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        assert!(!recent.full_tip);
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
