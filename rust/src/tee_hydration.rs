use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use uuid::Uuid;

const INFO_REFS_ADVERTISEMENT_FILE: &str = "info_refs_advertisement.bin";
const LS_REFS_REQUEST_FILE: &str = "ls_refs_request.bin";
const LS_REFS_RESPONSE_FILE: &str = "ls_refs_response.bin";
const SHARED_DIR_MODE: u32 = 0o775;
const SHARED_FILE_MODE: u32 = 0o664;
// The tee writer intentionally prioritizes client progress over preserving a
// complete disk capture:
// - response bytes are buffered in memory and handed off to a background disk
//   writer so normal disk latency does not directly slow the client stream
// - if disk falls behind long enough to exhaust this budget, the capture is
//   aborted and cleaned up instead of backpressuring the client
// - slow clients still backpressure the overall stream; that is intentional,
//   because we prefer client/network pacing over unbounded buffering
pub const CAPTURE_BUFFER_BYTES: usize = 128 * 1024 * 1024;
const CAPTURE_WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const CAPTURE_CHUNK_QUEUE_DEPTH: usize = 2048;

pub struct TeeCapture {
    dir: PathBuf,
    request_file: BufWriter<File>,
    response_file: BufWriter<File>,
}

impl TeeCapture {
    pub async fn start(base_path: &Path, owner_repo: &str, protocol: &str) -> Result<Self> {
        let dir = capture_dir(base_path, owner_repo);
        ensure_capture_tree(&dir).await?;

        let meta_path = dir.join("meta.json");
        let metadata = serde_json::json!({
            "owner_repo": owner_repo,
            "protocol": protocol,
            "started_at": Utc::now().to_rfc3339(),
        });
        tokio::fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)
            .await
            .with_context(|| format!("write tee metadata {}", meta_path.display()))?;
        ensure_shared_file(&meta_path, "tee metadata").await?;

        let request_path = dir.join("request.bin");
        let response_path = dir.join("response.bin");
        let request_file = File::create(&request_path)
            .await
            .with_context(|| format!("create request capture {}", request_path.display()))?;
        let response_file = File::create(&response_path)
            .await
            .with_context(|| format!("create response capture {}", response_path.display()))?;
        ensure_shared_file(&request_path, "tee request capture").await?;
        ensure_shared_file(&response_path, "tee response capture").await?;

        Ok(Self {
            dir,
            request_file: BufWriter::with_capacity(CAPTURE_WRITE_BUFFER_BYTES, request_file),
            response_file: BufWriter::with_capacity(CAPTURE_WRITE_BUFFER_BYTES, response_file),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub async fn write_request(&mut self, bytes: &[u8]) -> Result<()> {
        self.request_file
            .write_all(bytes)
            .await
            .context("write tee request bytes")?;
        self.request_file
            .flush()
            .await
            .context("flush tee request")?;
        Ok(())
    }

    pub async fn write_response_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.response_file
            .write_all(bytes)
            .await
            .context("write tee response bytes")?;
        Ok(())
    }

    pub async fn write_info_refs_advertisement(&self, bytes: &[u8]) -> Result<()> {
        write_capture_artifact(
            &self.dir.join(INFO_REFS_ADVERTISEMENT_FILE),
            bytes,
            "tee info/refs advertisement",
        )
        .await
    }

    pub async fn write_ls_refs_request(&self, bytes: &[u8]) -> Result<()> {
        write_capture_artifact(
            &self.dir.join(LS_REFS_REQUEST_FILE),
            bytes,
            "tee ls-refs request",
        )
        .await
    }

    pub async fn write_ls_refs_response(&self, bytes: &[u8]) -> Result<()> {
        write_capture_artifact(
            &self.dir.join(LS_REFS_RESPONSE_FILE),
            bytes,
            "tee ls-refs response",
        )
        .await
    }

    pub async fn finish(mut self, success: bool) -> Result<()> {
        self.response_file
            .flush()
            .await
            .context("flush tee response")?;
        self.request_file
            .flush()
            .await
            .context("flush tee request")?;
        let status_path = self.dir.join("status.json");
        let status = serde_json::json!({
            "success": success,
            "finished_at": Utc::now().to_rfc3339(),
        });
        tokio::fs::write(&status_path, serde_json::to_vec_pretty(&status)?)
            .await
            .with_context(|| format!("write tee status {}", status_path.display()))?;
        ensure_shared_file(&status_path, "tee status").await?;
        Ok(())
    }
}

struct CaptureChunk {
    bytes: Bytes,
    _buffer_permit: OwnedSemaphorePermit,
}

pub struct BufferedTeeCapture {
    sender: Option<mpsc::Sender<CaptureChunk>>,
    buffer_permits: Arc<Semaphore>,
    success: Arc<AtomicBool>,
    join_handle: tokio::task::JoinHandle<Result<Option<PathBuf>>>,
}

impl BufferedTeeCapture {
    pub fn new(capture: TeeCapture) -> Self {
        let (tx, mut rx) = mpsc::channel::<CaptureChunk>(CAPTURE_CHUNK_QUEUE_DEPTH);
        let buffer_permits = Arc::new(Semaphore::new(CAPTURE_BUFFER_BYTES));
        let success = Arc::new(AtomicBool::new(false));
        let success_flag = Arc::clone(&success);
        let join_handle = tokio::spawn(async move {
            let mut capture = capture;
            let capture_dir = capture.dir().to_path_buf();

            while let Some(chunk) = rx.recv().await {
                capture
                    .write_response_chunk(&chunk.bytes)
                    .await
                    .context("write buffered tee response chunk")?;
            }

            let completed = success_flag.load(Ordering::Relaxed);
            capture.finish(completed).await?;

            if completed {
                Ok(Some(capture_dir))
            } else {
                if capture_dir.exists() {
                    tokio::fs::remove_dir_all(&capture_dir)
                        .await
                        .with_context(|| {
                            format!("remove aborted tee capture {}", capture_dir.display())
                        })?;
                }
                Ok(None)
            }
        });

        Self {
            sender: Some(tx),
            buffer_permits,
            success,
            join_handle,
        }
    }

    pub fn try_write_response_chunk(&mut self, bytes: Bytes) -> Result<()> {
        let Some(sender) = self.sender.as_ref() else {
            anyhow::bail!("tee capture writer already closed");
        };

        let permit = Arc::clone(&self.buffer_permits)
            .try_acquire_many_owned(bytes.len() as u32)
            .context("tee capture buffer is full")?;

        sender
            .try_send(CaptureChunk {
                bytes,
                _buffer_permit: permit,
            })
            .context("tee capture queue is full")?;

        Ok(())
    }

    pub async fn finish_success(mut self) -> Result<Option<PathBuf>> {
        self.success.store(true, Ordering::Relaxed);
        self.sender.take();
        self.join_handle
            .await
            .context("buffered tee capture task join failed")?
    }

    pub async fn abort(mut self) -> Result<()> {
        self.success.store(false, Ordering::Relaxed);
        self.sender.take();
        let _ = self
            .join_handle
            .await
            .context("buffered tee capture task join failed")??;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedRefMetadata {
    pub refs: BTreeMap<String, String>,
    pub head_symref_target: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedFetchMetadata {
    pub want_oids: Vec<String>,
    pub uses_shallow: bool,
}

async fn write_capture_artifact(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    tokio::fs::write(path, bytes)
        .await
        .with_context(|| format!("write {label} {}", path.display()))?;
    ensure_shared_file(path, label).await?;
    Ok(())
}

pub async fn extract_pack_from_capture(capture_dir: &Path) -> Result<Option<PathBuf>> {
    let response_path = capture_dir.join("response.bin");
    if !response_path.is_file() {
        return Ok(None);
    }

    let mut response_file = File::open(&response_path)
        .await
        .with_context(|| format!("open tee response {}", response_path.display()))?;
    let pack_path = capture_dir.join("pack.bin");
    let mut pack_file = File::create(&pack_path)
        .await
        .with_context(|| format!("create extracted pack {}", pack_path.display()))?;
    ensure_shared_file(&pack_path, "extracted pack").await?;
    let mut wrote_pack = false;
    let mut header = [0u8; 4];

    loop {
        match response_file.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("read pkt-line header from {}", response_path.display())
                });
            }
        }

        let Some(len) = std::str::from_utf8(&header)
            .ok()
            .and_then(|text| usize::from_str_radix(text, 16).ok())
        else {
            anyhow::bail!("invalid pkt-line header in {}", response_path.display());
        };

        if len == 0 || len == 1 || len == 2 {
            continue;
        }

        if len < 4 {
            anyhow::bail!(
                "invalid pkt-line length {len} in {}",
                response_path.display()
            );
        }

        let payload_len = len - 4;
        let mut payload = vec![0u8; payload_len];
        response_file
            .read_exact(&mut payload)
            .await
            .with_context(|| format!("read pkt-line payload from {}", response_path.display()))?;

        if let Some((band, rest)) = payload.split_first()
            && *band == 1
        {
            pack_file
                .write_all(rest)
                .await
                .context("write extracted pack payload")?;
            wrote_pack = true;
        }
    }

    pack_file
        .flush()
        .await
        .context("flush extracted pack file")?;

    if wrote_pack {
        Ok(Some(pack_path))
    } else {
        Ok(None)
    }
}

pub async fn extract_captured_fetch_metadata(capture_dir: &Path) -> Result<CapturedFetchMetadata> {
    let request_path = capture_dir.join("request.bin");
    let response_path = capture_dir.join("response.bin");
    let mut metadata = CapturedFetchMetadata::default();

    if request_path.is_file() {
        let request = tokio::fs::read(&request_path)
            .await
            .with_context(|| format!("read tee request {}", request_path.display()))?;
        metadata = parse_captured_fetch_request(&request)
            .with_context(|| format!("parse tee request {}", request_path.display()))?;
    }

    if response_path.is_file() {
        let response = tokio::fs::read(&response_path)
            .await
            .with_context(|| format!("read tee response {}", response_path.display()))?;
        metadata.uses_shallow |= parse_response_mentions_shallow(&response)
            .with_context(|| format!("parse tee response {}", response_path.display()))?;
    }

    Ok(metadata)
}

pub async fn extract_captured_ref_metadata(capture_dir: &Path) -> Result<CapturedRefMetadata> {
    let mut metadata = CapturedRefMetadata::default();

    let ls_refs_response_path = capture_dir.join(LS_REFS_RESPONSE_FILE);
    if ls_refs_response_path.is_file() {
        let response = tokio::fs::read(&ls_refs_response_path)
            .await
            .with_context(|| format!("read {}", ls_refs_response_path.display()))?;
        metadata = parse_ls_refs_response(&response);
    }

    if metadata.refs.is_empty() {
        let info_refs_path = capture_dir.join(INFO_REFS_ADVERTISEMENT_FILE);
        if info_refs_path.is_file() {
            let advert = tokio::fs::read(&info_refs_path)
                .await
                .with_context(|| format!("read {}", info_refs_path.display()))?;
            metadata = parse_info_refs_advertisement(&advert);
        }
    }

    Ok(metadata)
}

pub fn parse_info_refs_advertisement_metadata(bytes: &[u8]) -> CapturedRefMetadata {
    parse_info_refs_advertisement(bytes)
}

pub fn parse_ls_refs_response_metadata(bytes: &[u8]) -> CapturedRefMetadata {
    parse_ls_refs_response(bytes)
}

fn parse_ls_refs_response(bytes: &[u8]) -> CapturedRefMetadata {
    let packets = crate::http::protocolv2::decode_pkt_lines(bytes);
    let mut metadata = CapturedRefMetadata::default();

    for packet in packets {
        let crate::http::protocolv2::PktLine::Data(line) = packet else {
            continue;
        };
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = String::from_utf8_lossy(line);
        let mut fields = text.split(' ');
        let Some(oid) = fields.next() else {
            continue;
        };
        let Some(refname) = fields.next() else {
            continue;
        };
        if !looks_like_oid(oid) || !refname.starts_with("refs/") {
            continue;
        }
        metadata.refs.insert(refname.to_string(), oid.to_string());
        for extra in fields {
            if let Some(target) = extra.strip_prefix("symref-target:")
                && refname == "HEAD"
            {
                metadata.head_symref_target = Some(target.to_string());
            }
        }
    }

    metadata
}

fn parse_info_refs_advertisement(bytes: &[u8]) -> CapturedRefMetadata {
    let mut metadata = CapturedRefMetadata::default();

    for packet in crate::http::protocolv2::decode_pkt_lines(bytes) {
        let crate::http::protocolv2::PktLine::Data(line) = packet else {
            continue;
        };
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = String::from_utf8_lossy(line);
        if text.starts_with('#') || text.trim().is_empty() {
            continue;
        }
        if let Some((oid, tail)) = text.split_once(' ')
            && looks_like_oid(oid)
        {
            let mut fields = tail.split('\0');
            let Some(refname) = fields.next() else {
                continue;
            };
            if refname == "HEAD" {
                if let Some(target) = fields
                    .flat_map(|f| f.split(' '))
                    .find_map(|field| field.strip_prefix("symref=HEAD:"))
                {
                    metadata.head_symref_target = Some(target.to_string());
                }
                continue;
            }
            if refname.starts_with("refs/") {
                metadata.refs.insert(refname.to_string(), oid.to_string());
            }
        }
    }

    metadata
}

fn looks_like_oid(text: &str) -> bool {
    text.len() == 40 && text.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn parse_captured_fetch_request(bytes: &[u8]) -> Result<CapturedFetchMetadata> {
    let mut wants = BTreeSet::new();
    let mut uses_shallow = false;

    for_each_pkt_line(bytes, |payload| {
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        if let Some(rest) = payload.strip_prefix(b"want ") {
            let mut fields = rest.split(|b| *b == b' ');
            if let Some(oid) = fields.next()
                && oid.len() == 40
                && oid.iter().all(u8::is_ascii_hexdigit)
            {
                wants.insert(String::from_utf8_lossy(oid).into_owned());
            }
        }

        if payload.starts_with(b"deepen ")
            || payload.starts_with(b"deepen-not ")
            || payload.starts_with(b"deepen-since ")
            || payload == b"deepen-relative"
            || payload.starts_with(b"shallow ")
        {
            uses_shallow = true;
        }
    })?;

    Ok(CapturedFetchMetadata {
        want_oids: wants.into_iter().collect(),
        uses_shallow,
    })
}

pub fn parse_fetch_request_metadata(bytes: &[u8]) -> Result<CapturedFetchMetadata> {
    parse_captured_fetch_request(bytes)
}

fn parse_response_mentions_shallow(bytes: &[u8]) -> Result<bool> {
    let mut uses_shallow = false;

    for_each_pkt_line(bytes, |payload| {
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        if payload.starts_with(b"shallow ") || payload.starts_with(b"unshallow ") {
            uses_shallow = true;
        }
    })?;

    Ok(uses_shallow)
}

fn for_each_pkt_line(mut bytes: &[u8], mut f: impl FnMut(&[u8])) -> Result<()> {
    while bytes.len() >= 4 {
        let Some(len) = std::str::from_utf8(&bytes[..4])
            .ok()
            .and_then(|text| usize::from_str_radix(text, 16).ok())
        else {
            anyhow::bail!("invalid pkt-line header");
        };

        if len == 0 || len == 1 || len == 2 {
            bytes = &bytes[4..];
            continue;
        }

        if len < 4 || len > bytes.len() {
            anyhow::bail!("invalid pkt-line length {len}");
        }

        f(&bytes[4..len]);
        bytes = &bytes[len..];
    }

    if bytes.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("trailing partial pkt-line")
    }
}

fn capture_dir(base_path: &Path, owner_repo: &str) -> PathBuf {
    let mut parts = owner_repo.splitn(2, '/');
    let owner = parts.next().unwrap_or("_unknown");
    let repo = parts.next().unwrap_or("_unknown");
    let stamp = format!("{}-{}", Utc::now().timestamp(), Uuid::new_v4());
    base_path
        .join("_tee")
        .join(owner)
        .join(repo.strip_suffix(".git").unwrap_or(repo))
        .join(stamp)
}

async fn ensure_capture_tree(capture_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(capture_dir)
        .await
        .with_context(|| format!("create tee capture dir {}", capture_dir.display()))?;

    let repo_dir = capture_dir
        .parent()
        .context("tee capture dir missing repo parent")?;
    let owner_dir = repo_dir
        .parent()
        .context("tee capture dir missing owner parent")?;
    let tee_root = owner_dir
        .parent()
        .context("tee capture dir missing _tee parent")?;

    for dir in [tee_root, owner_dir, repo_dir, capture_dir] {
        ensure_shared_dir(dir, "tee capture dir").await?;
    }

    Ok(())
}

async fn ensure_shared_dir(path: &Path, label: &str) -> Result<()> {
    let existing_mode = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {label} {}", path.display()))?
        .permissions()
        .mode();
    let mode = (existing_mode & 0o2000) | SHARED_DIR_MODE;

    match tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && existing_mode & SHARED_DIR_MODE == SHARED_DIR_MODE =>
        {
            // tmpfiles-managed shared roots can already have the desired mode
            // but still be owned by root, so a DynamicUser service cannot chmod
            // them again. If the directory is already group-shareable, keep
            // using it.
        }
        Err(error) => {
            return Err(error).with_context(|| format!("chmod {label} {}", path.display()));
        }
    }

    Ok(())
}

async fn ensure_shared_file(path: &Path, label: &str) -> Result<()> {
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(SHARED_FILE_MODE))
        .await
        .with_context(|| format!("chmod {label} {}", path.display()))?;
    Ok(())
}

pub async fn run_tee_cleanup_loop(
    base_path: PathBuf,
    interval: Duration,
    retention: Duration,
) -> Result<()> {
    loop {
        if let Err(error) = cleanup_stale_captures(&base_path, retention) {
            tracing::warn!(
                base_path = %base_path.display(),
                error = %format!("{error:#}"),
                error_debug = ?error,
                "tee capture cleanup sweep failed"
            );
        }
        tokio::time::sleep(interval).await;
    }
}

pub fn cleanup_stale_captures(base_path: &Path, retention: Duration) -> Result<usize> {
    let tee_root = base_path.join("_tee");
    if !tee_root.exists() {
        return Ok(0);
    }

    let now = SystemTime::now();
    let mut stale_capture_paths = Vec::new();

    for owner_entry in std::fs::read_dir(&tee_root)
        .with_context(|| format!("read tee root {}", tee_root.display()))?
    {
        let owner_entry = owner_entry?;
        if !owner_entry.file_type()?.is_dir() {
            continue;
        }

        for repo_entry in std::fs::read_dir(owner_entry.path())
            .with_context(|| format!("read tee owner dir {}", owner_entry.path().display()))?
        {
            let repo_entry = repo_entry?;
            if !repo_entry.file_type()?.is_dir() {
                continue;
            }

            for capture_entry in std::fs::read_dir(repo_entry.path())
                .with_context(|| format!("read tee repo dir {}", repo_entry.path().display()))?
            {
                let capture_entry = capture_entry?;
                let capture_path = capture_entry.path();
                if !capture_entry.file_type()?.is_dir() {
                    continue;
                }

                let modified = capture_entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .unwrap_or(now);
                let age = now.duration_since(modified).unwrap_or_default();
                if age < retention {
                    continue;
                }

                stale_capture_paths.push(capture_path);
            }
        }
    }

    let mut removed = 0usize;
    for capture_path in stale_capture_paths {
        match std::fs::remove_dir_all(&capture_path) {
            Ok(()) => {
                removed += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("remove stale tee capture {}", capture_path.display())
                });
            }
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn tee_capture_writes_request_and_response_files() {
        let tmp = tempdir().unwrap();
        let mut capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        capture.write_request(b"want-have").await.unwrap();
        capture.write_response_chunk(b"pack-bytes").await.unwrap();
        capture.finish(true).await.unwrap();

        let tee_root = tmp.path().join("_tee").join("acme").join("widgets");
        let mut entries = std::fs::read_dir(&tee_root).unwrap();
        let capture_dir = entries.next().unwrap().unwrap().path();
        assert!(capture_dir.join("meta.json").is_file());
        assert!(capture_dir.join("request.bin").is_file());
        assert!(capture_dir.join("response.bin").is_file());
        assert!(capture_dir.join("status.json").is_file());
    }

    #[tokio::test]
    async fn extract_pack_from_capture_strips_sideband_headers() {
        let tmp = tempdir().unwrap();
        let mut capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        let pkt = crate::http::protocolv2::encode_pkt_line(b"\x01PACKabcd");
        capture.write_response_chunk(&pkt).await.unwrap();
        let capture_dir = capture.dir().to_path_buf();
        capture.finish(true).await.unwrap();

        let pack_path = extract_pack_from_capture(&capture_dir)
            .await
            .unwrap()
            .unwrap();
        let pack = tokio::fs::read(pack_path).await.unwrap();
        assert_eq!(pack, b"PACKabcd");
    }

    #[tokio::test]
    async fn extract_captured_fetch_metadata_dedupes_wants_and_ignores_capabilities() {
        let tmp = tempdir().unwrap();
        let mut capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        let mut request = Vec::new();
        request.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"want 0123456789abcdef0123456789abcdef01234567 thin-pack ofs-delta\n",
        ));
        request.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"want 89abcdef0123456789abcdef0123456789abcdef\n",
        ));
        request.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"want 0123456789abcdef0123456789abcdef01234567\n",
        ));
        capture.write_request(&request).await.unwrap();
        let capture_dir = capture.dir().to_path_buf();
        capture.finish(true).await.unwrap();

        let metadata = extract_captured_fetch_metadata(&capture_dir).await.unwrap();
        assert_eq!(
            metadata.want_oids,
            vec![
                "0123456789abcdef0123456789abcdef01234567".to_string(),
                "89abcdef0123456789abcdef0123456789abcdef".to_string(),
            ]
        );
        assert!(!metadata.uses_shallow);
    }

    #[test]
    fn cleanup_stale_captures_prunes_old_capture_dirs() {
        let tmp = tempdir().unwrap();
        let capture_dir = tmp
            .path()
            .join("_tee")
            .join("acme")
            .join("widgets")
            .join("old-capture");
        std::fs::create_dir_all(&capture_dir).unwrap();
        std::fs::write(capture_dir.join("meta.json"), b"{}").unwrap();
        std::process::Command::new("touch")
            .arg("-d")
            .arg("2000-01-01 00:00:00 UTC")
            .arg(&capture_dir)
            .status()
            .unwrap();

        let removed = cleanup_stale_captures(tmp.path(), Duration::from_secs(1)).unwrap();

        assert_eq!(removed, 1);
        assert!(!capture_dir.exists());
    }

    #[tokio::test]
    async fn extract_captured_fetch_metadata_marks_shallow_requests() {
        let tmp = tempdir().unwrap();
        let mut capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        let mut request = Vec::new();
        request.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"want 0123456789abcdef0123456789abcdef01234567 thin-pack ofs-delta\n",
        ));
        request.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(b"deepen 1\n"));
        request.extend_from_slice(b"0000");
        capture.write_request(&request).await.unwrap();
        let capture_dir = capture.dir().to_path_buf();
        capture.finish(true).await.unwrap();

        let metadata = extract_captured_fetch_metadata(&capture_dir).await.unwrap();
        assert!(metadata.uses_shallow);
        assert_eq!(
            metadata.want_oids,
            vec!["0123456789abcdef0123456789abcdef01234567".to_string()]
        );
    }

    #[tokio::test]
    async fn extract_captured_fetch_metadata_marks_shallow_responses() {
        let tmp = tempdir().unwrap();
        let mut capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        capture
            .write_response_chunk(&crate::http::protocolv2::encode_pkt_line(
                b"shallow 0123456789abcdef0123456789abcdef01234567\n",
            ))
            .await
            .unwrap();
        let capture_dir = capture.dir().to_path_buf();
        capture.finish(true).await.unwrap();

        let metadata = extract_captured_fetch_metadata(&capture_dir).await.unwrap();
        assert!(metadata.uses_shallow);
        assert!(metadata.want_oids.is_empty());
    }

    #[tokio::test]
    async fn extract_captured_ref_metadata_prefers_ls_refs_response() {
        let tmp = tempdir().unwrap();
        let capture = TeeCapture::start(tmp.path(), "acme/widgets", "ssh")
            .await
            .unwrap();
        capture
            .write_ls_refs_response(
                &[
                    crate::http::protocolv2::encode_pkt_line(
                        b"0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
                    ),
                    crate::http::protocolv2::encode_pkt_line(
                        b"89abcdef0123456789abcdef0123456789abcdef refs/tags/v1.0.0\n",
                    ),
                    b"0000".to_vec(),
                ]
                .concat(),
            )
            .await
            .unwrap();

        let metadata = extract_captured_ref_metadata(capture.dir()).await.unwrap();
        assert_eq!(
            metadata.refs.get("refs/heads/main"),
            Some(&"0123456789abcdef0123456789abcdef01234567".to_string())
        );
        assert_eq!(
            metadata.refs.get("refs/tags/v1.0.0"),
            Some(&"89abcdef0123456789abcdef0123456789abcdef".to_string())
        );
    }

    #[tokio::test]
    async fn extract_captured_ref_metadata_falls_back_to_info_refs() {
        let tmp = tempdir().unwrap();
        let capture = TeeCapture::start(tmp.path(), "acme/widgets", "https")
            .await
            .unwrap();
        let mut advertisement = Vec::new();
        advertisement.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"# service=git-upload-pack\n",
        ));
        advertisement.extend_from_slice(b"0000");
        advertisement.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"0123456789abcdef0123456789abcdef01234567 HEAD\0symref=HEAD:refs/heads/main\n",
        ));
        advertisement.extend_from_slice(&crate::http::protocolv2::encode_pkt_line(
            b"0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
        ));
        advertisement.extend_from_slice(b"0000");
        capture
            .write_info_refs_advertisement(&advertisement)
            .await
            .unwrap();

        let metadata = extract_captured_ref_metadata(capture.dir()).await.unwrap();
        assert_eq!(
            metadata.head_symref_target,
            Some("refs/heads/main".to_string())
        );
        assert_eq!(
            metadata.refs.get("refs/heads/main"),
            Some(&"0123456789abcdef0123456789abcdef01234567".to_string())
        );
    }
}
