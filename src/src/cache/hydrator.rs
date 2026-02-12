//! Hydrate local bare repos from S3 bundles.
//!
//! When a repo exists in S3 (warm cache) but not locally, the hydrator
//! downloads the bundle-list, fetches all referenced bundles in creation-token
//! order, initialises a bare repo, and unbundles them.
//!
//! Currently unused — will be wired in when the S3 hydration path is enabled.
