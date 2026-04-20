//! Local cache management for the Caching Reverse Proxy.
//!
//! Provides a [`CacheManager`] that owns the on-disk bare-repo cache backed by
//! gp3 EBS, an LFU eviction policy driven by clone-count data stored in Valkey,
//! and a hydrator that can reconstruct a local repo from S3 bundles.

pub mod archive;
pub(crate) mod capacity;
pub mod hydrator;
pub(crate) mod layout;
pub mod lfu;
pub mod lru;
pub mod manager;
pub mod telemetry;

pub use manager::CacheManager;
