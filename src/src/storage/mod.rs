//! S3 storage layer.
//!
//! Manages uploading and downloading bundles and bare repo archives to/from
//! S3, with pre-signed URL generation for client-side bundle downloads.

pub mod s3;
