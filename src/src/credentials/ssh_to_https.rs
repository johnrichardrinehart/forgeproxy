//! SSH-to-HTTPS URL translation.
//!
//! Translates `git@host:owner/repo.git` style SSH URLs to HTTPS URLs
//! with embedded PAT credentials for authentication.
//!
//! Currently unused — URL construction is done inline in the SSH upstream
//! proxy module.
