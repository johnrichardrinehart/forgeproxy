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

#[allow(unused_imports)]
pub use bundlelist::{generate_bundle_list, parse_bundle_list, BundleEntry};
#[allow(unused_imports)]
pub use creation_token::{creation_token_for_bundle_type, next_creation_token, BundleType};
#[allow(unused_imports)]
pub use generator::{
    generate_filtered_bundle, generate_full_bundle, generate_incremental_bundle, get_refs,
    BundleResult,
};
#[allow(unused_imports)]
pub use lifecycle::{run_bundle_lifecycle, run_daily_consolidation, run_weekly_consolidation};
