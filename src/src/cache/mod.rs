//! Local cache management for the GHE Caching Reverse Proxy.
//!
//! Provides a [`CacheManager`] that owns the on-disk bare-repo cache backed by
//! gp3 EBS, an LFU eviction policy driven by clone-count data stored in KeyDB,
//! and a hydrator that can reconstruct a local repo from S3 bundles.

pub mod hydrator;
pub mod lfu;
pub mod lru;
pub mod manager;

pub use manager::CacheManager;
