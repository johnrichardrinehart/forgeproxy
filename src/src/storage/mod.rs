//! S3 storage layer.
//!
//! Manages uploading and downloading bundles and bare repo archives to/from
//! S3, with pre-signed URL generation for client-side bundle downloads.

pub mod s3;

pub use s3::{
    bundle_exists, delete_bundle, download_bundle, generate_presigned_url, list_bundles,
    upload_bundle, upload_bundle_list, S3Storage,
};
