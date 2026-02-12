//! Bundle-URI subsystem for the GHE Caching Reverse Proxy.
//!
//! This module implements the Git bundle-URI protocol: pre-computing bundles
//! on a schedule, managing their lifecycle (hourly -> daily -> weekly
//! consolidation), generating bundle-list manifests in the Git config INI
//! format, and maintaining monotonic creation tokens for incremental fetches.

pub mod bundlelist;
pub mod creation_token;
pub mod generator;
pub mod lifecycle;
