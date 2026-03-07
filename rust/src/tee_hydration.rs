use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::BTreeSet;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub struct TeeCapture {
    dir: PathBuf,
    request_file: File,
    response_file: File,
}

impl TeeCapture {
    pub async fn start(base_path: &Path, owner_repo: &str, protocol: &str) -> Result<Self> {
        let dir = capture_dir(base_path, owner_repo);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create tee capture dir {}", dir.display()))?;
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .await
            .with_context(|| format!("chmod tee capture dir {}", dir.display()))?;

        let meta_path = dir.join("meta.json");
        let metadata = serde_json::json!({
            "owner_repo": owner_repo,
            "protocol": protocol,
            "started_at": Utc::now().to_rfc3339(),
        });
        tokio::fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)
            .await
            .with_context(|| format!("write tee metadata {}", meta_path.display()))?;
        tokio::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o666))
            .await
            .with_context(|| format!("chmod tee metadata {}", meta_path.display()))?;

        let request_path = dir.join("request.bin");
        let response_path = dir.join("response.bin");
        let request_file = File::create(&request_path)
            .await
            .with_context(|| format!("create request capture {}", request_path.display()))?;
        let response_file = File::create(&response_path)
            .await
            .with_context(|| format!("create response capture {}", response_path.display()))?;
        tokio::fs::set_permissions(&request_path, std::fs::Permissions::from_mode(0o666))
            .await
            .with_context(|| format!("chmod tee request capture {}", request_path.display()))?;
        tokio::fs::set_permissions(&response_path, std::fs::Permissions::from_mode(0o666))
            .await
            .with_context(|| format!("chmod tee response capture {}", response_path.display()))?;

        Ok(Self {
            dir,
            request_file,
            response_file,
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

    pub async fn finish(mut self, success: bool) -> Result<()> {
        self.response_file
            .flush()
            .await
            .context("flush tee response")?;
        let status_path = self.dir.join("status.json");
        let status = serde_json::json!({
            "success": success,
            "finished_at": Utc::now().to_rfc3339(),
        });
        tokio::fs::write(&status_path, serde_json::to_vec_pretty(&status)?)
            .await
            .with_context(|| format!("write tee status {}", status_path.display()))?;
        tokio::fs::set_permissions(&status_path, std::fs::Permissions::from_mode(0o666))
            .await
            .with_context(|| format!("chmod tee status {}", status_path.display()))?;
        Ok(())
    }
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
    tokio::fs::set_permissions(&pack_path, std::fs::Permissions::from_mode(0o666))
        .await
        .with_context(|| format!("chmod extracted pack {}", pack_path.display()))?;
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

pub async fn extract_want_oids_from_capture(capture_dir: &Path) -> Result<Vec<String>> {
    let request_path = capture_dir.join("request.bin");
    if !request_path.is_file() {
        return Ok(Vec::new());
    }

    let request = tokio::fs::read(&request_path)
        .await
        .with_context(|| format!("read tee request {}", request_path.display()))?;
    let mut wants = BTreeSet::new();
    let mut offset = 0usize;

    while offset + 4 <= request.len() {
        let Some(len) = std::str::from_utf8(&request[offset..offset + 4])
            .ok()
            .and_then(|text| usize::from_str_radix(text, 16).ok())
        else {
            anyhow::bail!("invalid pkt-line header in {}", request_path.display());
        };

        if len == 0 || len == 1 || len == 2 {
            offset += 4;
            continue;
        }

        if len < 4 || offset + len > request.len() {
            anyhow::bail!(
                "invalid pkt-line length {len} in {}",
                request_path.display()
            );
        }

        let payload = &request[offset + 4..offset + len];
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

        offset += len;
    }

    Ok(wants.into_iter().collect())
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
    async fn extract_want_oids_from_capture_dedupes_and_ignores_capabilities() {
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

        let wants = extract_want_oids_from_capture(&capture_dir).await.unwrap();
        assert_eq!(
            wants,
            vec![
                "0123456789abcdef0123456789abcdef01234567".to_string(),
                "89abcdef0123456789abcdef0123456789abcdef".to_string(),
            ]
        );
    }
}
