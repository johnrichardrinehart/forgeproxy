//! Bundle-list file parsing in Git config INI format.
//!
//! The bundle-list is a manifest document that tells `git clone --bundle-uri`
//! (or `git fetch --bundle-uri`) which bundles to download and in what order.
//! The format is defined by the Git bundle-URI specification and uses the Git
//! config INI syntax.
//!
//! Parsing is currently unused — will be wired in when the S3 hydration path
//! is enabled.
