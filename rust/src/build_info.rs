use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const TRAILER_MAGIC: &[u8; 16] = b"FGPXBUILDINFOv1!";
const TRAILER_FOOTER_LEN: usize = 32;
const UNKNOWN_GIT_REVISION: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct EmbeddedBuildInfo {
    git_revision: String,
}

#[derive(Debug, Clone)]
struct CachedBuildInfo {
    git_revision: String,
    long_version: String,
}

pub fn git_revision() -> &'static str {
    cached_build_info().git_revision.as_str()
}

pub fn long_version() -> &'static str {
    cached_build_info().long_version.as_str()
}

fn cached_build_info() -> &'static CachedBuildInfo {
    static BUILD_INFO: OnceLock<CachedBuildInfo> = OnceLock::new();
    BUILD_INFO.get_or_init(|| {
        let git_revision = std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| parse_embedded_build_info(&bytes))
            .map(|metadata| metadata.git_revision)
            .filter(|revision| !revision.trim().is_empty())
            .unwrap_or_else(|| UNKNOWN_GIT_REVISION.to_string());

        CachedBuildInfo {
            long_version: format!("{VERSION} ({git_revision})"),
            git_revision,
        }
    })
}

fn parse_embedded_build_info(bytes: &[u8]) -> Option<EmbeddedBuildInfo> {
    let footer = bytes.get(bytes.len().checked_sub(TRAILER_FOOTER_LEN)?..)?;
    let (raw_len, raw_magic) = footer.split_at(16);
    if raw_magic != TRAILER_MAGIC {
        return None;
    }

    let metadata_len = std::str::from_utf8(raw_len)
        .ok()
        .and_then(|text| usize::from_str_radix(text, 16).ok())?;
    let metadata_start = bytes
        .len()
        .checked_sub(TRAILER_FOOTER_LEN)?
        .checked_sub(metadata_len)?;
    let metadata_bytes = bytes.get(metadata_start..metadata_start + metadata_len)?;
    serde_json::from_slice(metadata_bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::{EmbeddedBuildInfo, TRAILER_FOOTER_LEN, TRAILER_MAGIC, parse_embedded_build_info};

    fn with_embedded_build_info(prefix: &[u8], git_revision: &str) -> Vec<u8> {
        let metadata_json = serde_json::to_string(&EmbeddedBuildInfo {
            git_revision: git_revision.to_string(),
        })
        .unwrap();
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(metadata_json.as_bytes());
        bytes.extend_from_slice(format!("{:016x}", metadata_json.len()).as_bytes());
        bytes.extend_from_slice(TRAILER_MAGIC);
        bytes
    }

    #[test]
    fn parses_embedded_build_info_trailer() {
        let bytes = with_embedded_build_info(b"\x7fELFpayload", "abc123def456");
        let metadata = parse_embedded_build_info(&bytes).unwrap();
        assert_eq!(metadata.git_revision, "abc123def456");
    }

    #[test]
    fn rejects_missing_magic() {
        let mut bytes = with_embedded_build_info(b"\x7fELFpayload", "abc123def456");
        let len = bytes.len();
        bytes[len - 1] = b'?';
        assert!(parse_embedded_build_info(&bytes).is_none());
    }

    #[test]
    fn rejects_invalid_metadata_length() {
        let mut bytes = with_embedded_build_info(b"\x7fELFpayload", "abc123def456");
        let len_field_start = bytes.len() - TRAILER_FOOTER_LEN;
        bytes[len_field_start..len_field_start + 16].copy_from_slice(b"ffffffffffffffff");
        assert!(parse_embedded_build_info(&bytes).is_none());
    }
}
