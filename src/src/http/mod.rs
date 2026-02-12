//! HTTP layer for the GHE Caching Reverse Proxy.
//!
//! This module provides the axum-based HTTP server that intercepts Git smart
//! HTTP protocol requests, validates authentication, injects bundle-uri
//! capabilities into protocol v2 responses, and serves pre-signed bundle
//! download URLs.

pub mod archive;
pub mod bundle_serve;
pub mod handler;
pub mod protocolv2;
