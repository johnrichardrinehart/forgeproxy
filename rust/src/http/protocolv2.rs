//! Git protocol v2 packet-line manipulation.
//!
//! This module parses and re-serialises the Git smart HTTP protocol v2
//! packet-line format so that we can inject the `bundle-uri` capability
//! advertisement into `info/refs` responses.
//!
//! # Packet-line format
//!
//! Each packet line is prefixed with a 4-character hex length that includes
//! itself:
//!
//! - `0000` -- flush packet (end of section)
//! - `0001` -- delimiter packet
//! - `0002` -- response-end packet
//! - `0004`+ -- data packet (length includes the 4 prefix bytes)

use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single Git protocol v2 packet line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine {
    /// A data packet containing arbitrary bytes.
    Data(Vec<u8>),
    /// Flush packet (`0000`) -- marks end of a message / section.
    Flush,
    /// Delimiter packet (`0001`) -- separates sections within a single
    /// message.
    Delimiter,
    /// Response-end packet (`0002`).
    ResponseEnd,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a byte slice as a Git packet-line (4-hex-digit length prefix + data).
///
/// The length includes the 4 prefix bytes themselves.  Callers are responsible
/// for including any trailing newline in `data` if the protocol requires it.
pub fn encode_pkt_line(data: &[u8]) -> Vec<u8> {
    let total_len = data.len() + 4;
    assert!(
        total_len <= 0xFFFF,
        "packet-line data too large ({total_len} bytes)"
    );
    let mut buf = Vec::with_capacity(total_len);
    // Write the 4-hex-digit length prefix.
    buf.extend_from_slice(format!("{total_len:04x}").as_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Encode a [`PktLine`] back into its wire representation.
pub fn encode_pkt(pkt: &PktLine) -> Vec<u8> {
    match pkt {
        PktLine::Data(data) => encode_pkt_line(data),
        PktLine::Flush => b"0000".to_vec(),
        PktLine::Delimiter => b"0001".to_vec(),
        PktLine::ResponseEnd => b"0002".to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a sequence of Git protocol v2 packet lines from raw bytes.
///
/// Returns all successfully parsed packets.  If the input is malformed the
/// parser stops at the first unparseable position and returns whatever was
/// decoded up to that point.
pub fn decode_pkt_lines(data: &[u8]) -> Vec<PktLine> {
    let mut packets = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let len_hex = match std::str::from_utf8(&data[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => {
                warn!(offset = pos, "non-UTF-8 packet-line length prefix");
                break;
            }
        };

        let pkt_len = match u16::from_str_radix(len_hex, 16) {
            Ok(n) => n as usize,
            Err(_) => {
                warn!(offset = pos, len_hex, "invalid packet-line length");
                break;
            }
        };

        match pkt_len {
            0 => {
                trace!(offset = pos, "flush packet");
                packets.push(PktLine::Flush);
                pos += 4;
            }
            1 => {
                trace!(offset = pos, "delimiter packet");
                packets.push(PktLine::Delimiter);
                pos += 4;
            }
            2 => {
                trace!(offset = pos, "response-end packet");
                packets.push(PktLine::ResponseEnd);
                pos += 4;
            }
            3 => {
                // Length 3 is invalid (would mean 3 total bytes but the prefix
                // itself is 4).
                warn!(offset = pos, "invalid packet-line length 0003");
                break;
            }
            n => {
                if pos + n > data.len() {
                    warn!(
                        offset = pos,
                        declared = n,
                        available = data.len() - pos,
                        "truncated packet-line"
                    );
                    break;
                }
                let payload = data[pos + 4..pos + n].to_vec();
                trace!(offset = pos, payload_len = payload.len(), "data packet");
                packets.push(PktLine::Data(payload));
                pos += n;
            }
        }
    }

    packets
}

// ---------------------------------------------------------------------------
// Bundle-URI injection
// ---------------------------------------------------------------------------

/// Inject the `bundle-uri` capability into a Git protocol v2 info/refs
/// response, pointing clients at `bundle_list_url`.
///
/// The info/refs response for protocol v2 has the structure:
///
/// ```text
/// PKT  "version 2\n"
/// PKT  "agent=...\n"
/// PKT  "ls-refs\n"
/// PKT  "fetch=...\n"
/// PKT  "server-option\n"
/// FLUSH
/// ```
///
/// We insert `PKT "bundle-uri\n"` into the capability list (before the
/// trailing flush) so that compliant Git clients know they can request a
/// bundle-list from our proxy.
///
/// If the response does not look like a protocol v2 capability advertisement
/// (e.g. protocol v0/v1), the data is returned unmodified.
pub fn inject_bundle_uri(response_body: &[u8], _bundle_list_url: &str) -> Vec<u8> {
    let packets = decode_pkt_lines(response_body);

    if packets.is_empty() {
        debug!("empty packet sequence; returning body unchanged");
        return response_body.to_vec();
    }

    // Quick sanity check: the first data packet should contain "version 2".
    let is_v2 = packets.iter().any(|p| match p {
        PktLine::Data(d) => {
            let s = String::from_utf8_lossy(d);
            s.contains("version 2")
        }
        _ => false,
    });

    if !is_v2 {
        debug!("response is not protocol v2; returning body unchanged");
        return response_body.to_vec();
    }

    // Check whether bundle-uri is already advertised.
    let already_present = packets.iter().any(|p| match p {
        PktLine::Data(d) => {
            let s = String::from_utf8_lossy(d);
            s.trim().starts_with("bundle-uri")
        }
        _ => false,
    });

    if already_present {
        debug!("bundle-uri capability already present; returning body unchanged");
        return response_body.to_vec();
    }

    // Rebuild the response, inserting the bundle-uri capability line just
    // before the first flush packet (end of capability advertisement).
    let bundle_uri_line = "bundle-uri\n".to_string();
    let bundle_uri_pkt = PktLine::Data(bundle_uri_line.into_bytes());

    let mut output = Vec::with_capacity(response_body.len() + 64);
    let mut injected = false;

    for pkt in &packets {
        if !injected && *pkt == PktLine::Flush {
            // Insert bundle-uri capability just before the flush.
            output.extend_from_slice(&encode_pkt(&bundle_uri_pkt));
            injected = true;
            debug!("injected bundle-uri capability into protocol v2 response");
        }
        output.extend_from_slice(&encode_pkt(pkt));
    }

    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_pkt_line() {
        let encoded = encode_pkt_line(b"hello\n");
        assert_eq!(&encoded, b"000ahello\n");
    }

    #[test]
    fn test_encode_pkt_line_empty() {
        let encoded = encode_pkt_line(b"");
        assert_eq!(&encoded, b"0004");
    }

    #[test]
    fn test_decode_flush() {
        let packets = decode_pkt_lines(b"0000");
        assert_eq!(packets, vec![PktLine::Flush]);
    }

    #[test]
    fn test_decode_delimiter() {
        let packets = decode_pkt_lines(b"0001");
        assert_eq!(packets, vec![PktLine::Delimiter]);
    }

    #[test]
    fn test_decode_response_end() {
        let packets = decode_pkt_lines(b"0002");
        assert_eq!(packets, vec![PktLine::ResponseEnd]);
    }

    #[test]
    fn test_roundtrip_data_packet() {
        let original = b"version 2\n";
        let encoded = encode_pkt_line(original);
        let decoded = decode_pkt_lines(&encoded);
        assert_eq!(decoded.len(), 1);
        match &decoded[0] {
            PktLine::Data(d) => assert_eq!(d.as_slice(), original),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_multiple_packets() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_pkt_line(b"version 2\n"));
        wire.extend_from_slice(&encode_pkt_line(b"agent=git/2.43\n"));
        wire.extend_from_slice(&encode_pkt_line(b"ls-refs\n"));
        wire.extend_from_slice(&encode_pkt_line(b"fetch=shallow\n"));
        wire.extend_from_slice(b"0000");

        let packets = decode_pkt_lines(&wire);
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[4], PktLine::Flush);
    }

    #[test]
    fn test_inject_bundle_uri() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_pkt_line(b"version 2\n"));
        wire.extend_from_slice(&encode_pkt_line(b"agent=git/2.43\n"));
        wire.extend_from_slice(&encode_pkt_line(b"ls-refs\n"));
        wire.extend_from_slice(&encode_pkt_line(b"fetch=shallow\n"));
        wire.extend_from_slice(&encode_pkt_line(b"server-option\n"));
        wire.extend_from_slice(b"0000");

        let result = inject_bundle_uri(&wire, "https://proxy.example.com/bundles/o/r/bundle-list");
        let packets = decode_pkt_lines(&result);

        // Should have the original 5 data packets + 1 injected + 1 flush = 7
        assert_eq!(packets.len(), 7);

        // The injected packet should be right before the flush (index 5).
        match &packets[5] {
            PktLine::Data(d) => {
                let s = String::from_utf8_lossy(d);
                assert_eq!(s.trim(), "bundle-uri");
            }
            other => panic!("expected bundle-uri Data packet, got {other:?}"),
        }
        assert_eq!(packets[6], PktLine::Flush);
    }

    #[test]
    fn test_inject_noop_when_already_present() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_pkt_line(b"version 2\n"));
        wire.extend_from_slice(&encode_pkt_line(b"bundle-uri\n"));
        wire.extend_from_slice(b"0000");

        let original_len = wire.len();
        let result = inject_bundle_uri(&wire, "https://proxy.example.com/bundles/o/r/bundle-list");
        assert_eq!(
            result.len(),
            original_len,
            "should not modify when already present"
        );
    }

    #[test]
    fn test_inject_noop_for_non_v2() {
        // Protocol v0/v1 style response -- no "version 2" line.
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_pkt_line(b"# service=git-upload-pack\n"));
        wire.extend_from_slice(b"0000");

        let original = wire.clone();
        let result = inject_bundle_uri(&wire, "https://proxy.example.com/bundles/o/r/bundle-list");
        assert_eq!(result, original, "should not modify non-v2 responses");
    }
}
