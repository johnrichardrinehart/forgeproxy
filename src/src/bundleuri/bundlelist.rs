//! Bundle-list file generation and parsing in Git config INI format.
//!
//! The bundle-list is a manifest document that tells `git clone --bundle-uri`
//! (or `git fetch --bundle-uri`) which bundles to download and in what order.
//! The format is defined by the Git bundle-URI specification and uses the Git
//! config INI syntax.
//!
//! Example output:
//!
//! ```ini
//! [bundle]
//!     version = 1
//!     mode = all
//!     heuristic = creationToken
//!
//! [bundle "base-20250101"]
//!     uri = https://cdn.example.com/bundles/base-20250101.bundle
//!     creationToken = 1000
//!
//! [bundle "hourly-2025010112"]
//!     uri = https://cdn.example.com/bundles/hourly-2025010112.bundle
//!     creationToken = 3012
//! ```

use std::fmt::Write;

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single entry in a bundle-list manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// Logical name of the bundle (used as the section key, e.g.
    /// `"base-20250101"`).
    pub name: String,
    /// Download URI (typically a pre-signed S3 URL or CDN URL).
    pub uri: String,
    /// Monotonic creation token.  Clients use this to determine which bundles
    /// they already have and which they still need.
    pub creation_token: u64,
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a bundle-list document from a slice of [`BundleEntry`] values.
///
/// The output is a valid Git config INI document that can be served directly
/// to clients requesting a bundle-list via the bundle-URI protocol.  Bundles
/// are emitted in the order provided; callers should sort by ascending
/// `creation_token` if deterministic ordering is desired.
pub fn generate_bundle_list(bundles: &[BundleEntry]) -> String {
    let mut output = String::new();

    // Header section.
    writeln!(output, "[bundle]").unwrap();
    writeln!(output, "\tversion = 1").unwrap();
    writeln!(output, "\tmode = all").unwrap();
    writeln!(output, "\theuristic = creationToken").unwrap();

    // Individual bundle sections.
    for entry in bundles {
        writeln!(output).unwrap();
        writeln!(output, "[bundle \"{}\"]", entry.name).unwrap();
        writeln!(output, "\turi = {}", entry.uri).unwrap();
        writeln!(output, "\tcreationToken = {}", entry.creation_token).unwrap();
    }

    output
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a bundle-list INI document back into a vector of [`BundleEntry`].
///
/// This is a simple line-by-line parser that understands the subset of Git
/// config syntax used by bundle-lists.  It does **not** handle the full
/// generality of Git config (e.g. multi-valued keys, includes, etc.).
pub fn parse_bundle_list(content: &str) -> Result<Vec<BundleEntry>> {
    let mut entries: Vec<BundleEntry> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_uri: Option<String> = None;
    let mut current_token: Option<u64> = None;

    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            // If we were accumulating an entry, the blank line signals the
            // end of the previous section.  However, we also handle the case
            // where fields span until the next section header.
            continue;
        }

        // Section header: `[bundle]` or `[bundle "name"]`.
        if line.starts_with('[') {
            // Flush any pending entry.
            flush_entry(
                &mut entries,
                &mut current_name,
                &mut current_uri,
                &mut current_token,
            );

            if let Some(name) = parse_bundle_section_name(line) {
                current_name = Some(name);
            }
            // The bare `[bundle]` header is the global section; we skip it.
            continue;
        }

        // Key-value pair: `key = value` or `\tkey = value`.
        if let Some((key, value)) = parse_key_value(line) {
            match key {
                "uri" => {
                    current_uri = Some(value.to_string());
                }
                "creationToken" | "creationtoken" => {
                    current_token = Some(value.parse::<u64>().with_context(|| {
                        format!("invalid creationToken on line {}: {:?}", line_no + 1, value)
                    })?);
                }
                // Ignore keys we don't care about (version, mode, heuristic).
                _ => {}
            }
        }
    }

    // Flush the last entry.
    flush_entry(
        &mut entries,
        &mut current_name,
        &mut current_uri,
        &mut current_token,
    );

    Ok(entries)
}

/// Flush accumulated fields into a [`BundleEntry`] if all required fields
/// are present.
fn flush_entry(
    entries: &mut Vec<BundleEntry>,
    name: &mut Option<String>,
    uri: &mut Option<String>,
    token: &mut Option<u64>,
) {
    if let (Some(n), Some(u), Some(t)) = (name.take(), uri.take(), token.take()) {
        entries.push(BundleEntry {
            name: n,
            uri: u,
            creation_token: t,
        });
    } else {
        // Discard incomplete entries; reset accumulators.
        *name = None;
        *uri = None;
        *token = None;
    }
}

/// Extract the bundle name from a section header like `[bundle "my-name"]`.
///
/// Returns `None` for the bare `[bundle]` header or non-bundle sections.
fn parse_bundle_section_name(line: &str) -> Option<String> {
    // Expected: [bundle "name"]
    let line = line.trim();
    if !line.starts_with("[bundle ") {
        return None;
    }

    let inner = line.strip_prefix("[bundle ")?.strip_suffix(']')?.trim();

    // Remove surrounding quotes.
    let name = inner.trim_matches('"');
    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
}

/// Parse a `key = value` line, tolerating leading whitespace/tabs.
fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let list = generate_bundle_list(&[]);
        let parsed = parse_bundle_list(&list).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn roundtrip_single_entry() {
        let entries = vec![BundleEntry {
            name: "base-20250101".to_string(),
            uri: "https://cdn.example.com/base.bundle".to_string(),
            creation_token: 1000,
        }];

        let list = generate_bundle_list(&entries);
        let parsed = parse_bundle_list(&list).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], entries[0]);
    }

    #[test]
    fn roundtrip_multiple_entries() {
        let entries = vec![
            BundleEntry {
                name: "base".to_string(),
                uri: "https://cdn.example.com/base.bundle".to_string(),
                creation_token: 1000,
            },
            BundleEntry {
                name: "daily-20250115".to_string(),
                uri: "https://cdn.example.com/daily.bundle".to_string(),
                creation_token: 2015,
            },
            BundleEntry {
                name: "hourly-2025011512".to_string(),
                uri: "https://cdn.example.com/hourly.bundle".to_string(),
                creation_token: 3372,
            },
        ];

        let list = generate_bundle_list(&entries);
        let parsed = parse_bundle_list(&list).unwrap();

        assert_eq!(parsed.len(), 3);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(&parsed[i], entry, "mismatch at index {i}");
        }
    }

    #[test]
    fn generate_format_is_correct() {
        let entries = vec![BundleEntry {
            name: "test".to_string(),
            uri: "https://example.com/test.bundle".to_string(),
            creation_token: 42,
        }];

        let output = generate_bundle_list(&entries);
        assert!(output.contains("[bundle]"));
        assert!(output.contains("\tversion = 1"));
        assert!(output.contains("\tmode = all"));
        assert!(output.contains("\theuristic = creationToken"));
        assert!(output.contains("[bundle \"test\"]"));
        assert!(output.contains("\turi = https://example.com/test.bundle"));
        assert!(output.contains("\tcreationToken = 42"));
    }

    #[test]
    fn parse_section_name() {
        assert_eq!(
            parse_bundle_section_name("[bundle \"my-bundle\"]"),
            Some("my-bundle".to_string()),
        );
        assert_eq!(parse_bundle_section_name("[bundle]"), None);
        assert_eq!(parse_bundle_section_name("[other \"x\"]"), None);
    }
}
