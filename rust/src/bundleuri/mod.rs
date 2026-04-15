//! Bundle-URI subsystem for the Caching Reverse Proxy.
//!
//! This module implements the Git bundle-URI protocol: pre-computing bundles
//! from freshly updated mirrors, publishing them to S3, generating bundle-list
//! manifests in the Git config INI format, and maintaining monotonic creation
//! tokens for incremental fetches.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod bundlelist;
pub mod creation_token;
pub mod generator;
pub mod lifecycle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedBundleMetadata {
    pub publisher_id: String,
    pub creation_token: u64,
    pub bundle_s3_key: String,
    #[serde(default)]
    pub filtered_bundle_s3_key: Option<String>,
    pub updated_at_unix_secs: i64,
    #[serde(default)]
    pub service_instance_id: Option<String>,
    #[serde(default)]
    pub service_machine_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundleManifest {
    pub version: u32,
    pub owner_repo: String,
    pub updated_at_unix_secs: i64,
    #[serde(default)]
    pub entries: Vec<BundleManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifestEntry {
    pub id: String,
    pub bundle_kind: BundleKind,
    pub creation_token: u64,
    pub bundle_s3_key: String,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub refs: HashMap<String, String>,
    pub updated_at_unix_secs: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    Base,
    Incremental,
    Filtered,
}

impl BundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Incremental => "incremental",
            Self::Filtered => "filtered",
        }
    }
}

fn join_s3_key(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_string()
    } else if prefix.ends_with('/') {
        format!("{prefix}{suffix}")
    } else {
        format!("{prefix}/{suffix}")
    }
}

pub fn bundle_counter_s3_key(prefix: &str, owner_repo: &str) -> String {
    join_s3_key(prefix, &format!("{owner_repo}/gen.counter"))
}

pub fn repo_bundle_object_s3_key(
    prefix: &str,
    owner_repo: &str,
    creation_token: u64,
    bundle_kind: BundleKind,
) -> String {
    join_s3_key(
        prefix,
        &format!(
            "{owner_repo}/bundle-generations/{creation_token:020}.{}.bundle",
            bundle_kind.as_str()
        ),
    )
}

pub fn bundle_metadata_s3_key(prefix: &str, owner_repo: &str, publisher_id: &str) -> String {
    join_s3_key(prefix, &format!("{owner_repo}/bundles/{publisher_id}.json"))
}

pub fn bundle_metadata_s3_prefix(prefix: &str, owner_repo: &str) -> String {
    join_s3_key(prefix, &format!("{owner_repo}/bundles/"))
}

pub fn repo_bundle_manifest_s3_key(prefix: &str, owner_repo: &str) -> String {
    join_s3_key(prefix, &format!("{owner_repo}/bundle-manifest.json"))
}
