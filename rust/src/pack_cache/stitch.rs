use anyhow::{Context, Result, bail, ensure};
use sha1::{Digest, Sha1};

const MAX_PKT_LINE_LEN: usize = 0xffff;
const PKT_HEADER_LEN: usize = 4;
const SIDEBAND_PREFIX_LEN: usize = 1;
const MAX_SIDEBAND_PACK_CHUNK: usize = MAX_PKT_LINE_LEN - PKT_HEADER_LEN - SIDEBAND_PREFIX_LEN;
const SHA1_TRAILER_LEN: usize = 20;
const PACK_HEADER_LEN: usize = 12;

pub fn extract_raw_pack(response: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut pack = Vec::new();

    while offset < response.len() {
        let (packet_len, next_offset) = read_packet_len(response, offset)?;
        if packet_len <= PKT_HEADER_LEN {
            offset = next_offset;
            continue;
        }

        let payload = &response[offset + PKT_HEADER_LEN..next_offset];
        if let Some((&band, rest)) = payload.split_first()
            && band == 1
        {
            pack.extend_from_slice(rest);
        }
        offset = next_offset;
    }

    ensure!(
        !pack.is_empty(),
        "response contained no sideband-1 pack data"
    );
    ensure!(
        pack.len() >= PACK_HEADER_LEN + SHA1_TRAILER_LEN && &pack[..4] == b"PACK",
        "sideband-1 payload did not contain a raw pack"
    );
    Ok(pack)
}

pub fn replace_sideband1_in_response(
    base_response: &[u8],
    stitched_pack: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        stitched_pack.len() >= PACK_HEADER_LEN + SHA1_TRAILER_LEN && &stitched_pack[..4] == b"PACK",
        "stitched payload is not a raw pack"
    );

    let mut offset = 0usize;
    let mut out = Vec::with_capacity(base_response.len() + stitched_pack.len());
    let mut emitted_stitched_pack = false;
    let mut saw_sideband1 = false;

    while offset < base_response.len() {
        let (packet_len, next_offset) = read_packet_len(base_response, offset)?;
        if packet_len <= PKT_HEADER_LEN {
            out.extend_from_slice(&base_response[offset..next_offset]);
            offset = next_offset;
            continue;
        }

        let payload = &base_response[offset + PKT_HEADER_LEN..next_offset];
        if payload.first() == Some(&1) {
            saw_sideband1 = true;
            if !emitted_stitched_pack {
                write_sideband1_pack(&mut out, stitched_pack);
                emitted_stitched_pack = true;
            }
        } else {
            out.extend_from_slice(&base_response[offset..next_offset]);
        }
        offset = next_offset;
    }

    ensure!(
        saw_sideband1,
        "base response contained no sideband-1 pack data"
    );
    Ok(out)
}

pub fn stitch_raw_packs(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let (base_version, base_count) = pack_header(base, "base")?;
    let (delta_version, delta_count) = pack_header(delta, "delta")?;
    ensure!(
        base_version == delta_version,
        "cannot stitch pack versions {base_version} and {delta_version}"
    );
    let total_count = base_count
        .checked_add(delta_count)
        .context("pack object count overflow")?;

    let mut out = Vec::with_capacity(base.len() + delta.len() - PACK_HEADER_LEN - SHA1_TRAILER_LEN);
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&base_version.to_be_bytes());
    out.extend_from_slice(&total_count.to_be_bytes());
    out.extend_from_slice(&base[PACK_HEADER_LEN..base.len() - SHA1_TRAILER_LEN]);
    out.extend_from_slice(&delta[PACK_HEADER_LEN..delta.len() - SHA1_TRAILER_LEN]);

    let mut sha1 = Sha1::new();
    sha1.update(&out);
    out.extend_from_slice(&sha1.finalize());
    Ok(out)
}

pub fn stitch_response_with_delta_chain(
    base_response: &[u8],
    delta_packs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut stitched_pack = extract_raw_pack(base_response)?;
    for delta_pack in delta_packs {
        stitched_pack = stitch_raw_packs(&stitched_pack, delta_pack)?;
    }
    replace_sideband1_in_response(base_response, &stitched_pack)
}

fn read_packet_len(bytes: &[u8], offset: usize) -> Result<(usize, usize)> {
    ensure!(
        offset + PKT_HEADER_LEN <= bytes.len(),
        "truncated pkt-line header"
    );
    let header = &bytes[offset..offset + PKT_HEADER_LEN];
    let header = std::str::from_utf8(header).context("non-utf8 pkt-line header")?;
    let len = usize::from_str_radix(header, 16).context("invalid pkt-line length")?;
    match len {
        0..=2 => Ok((len, offset + PKT_HEADER_LEN)),
        3 => bail!("invalid pkt-line length 3"),
        _ => {
            ensure!(offset + len <= bytes.len(), "truncated pkt-line payload");
            Ok((len, offset + len))
        }
    }
}

fn write_sideband1_pack(out: &mut Vec<u8>, pack: &[u8]) {
    for chunk in pack.chunks(MAX_SIDEBAND_PACK_CHUNK) {
        let packet_len = PKT_HEADER_LEN + SIDEBAND_PREFIX_LEN + chunk.len();
        out.extend_from_slice(format!("{packet_len:04x}").as_bytes());
        out.push(1);
        out.extend_from_slice(chunk);
    }
}

fn pack_header(pack: &[u8], name: &str) -> Result<(u32, u32)> {
    ensure!(
        pack.len() >= PACK_HEADER_LEN + SHA1_TRAILER_LEN,
        "{name} pack is too short"
    );
    ensure!(&pack[..4] == b"PACK", "{name} pack has invalid magic");
    let version = u32::from_be_bytes(pack[4..8].try_into()?);
    ensure!(
        version == 2 || version == 3,
        "{name} pack version {version} is unsupported"
    );
    let count = u32::from_be_bytes(pack[8..12].try_into()?);
    Ok((version, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    fn raw_pack(count: u32, body: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&count.to_be_bytes());
        pack.extend_from_slice(body);
        let mut sha1 = Sha1::new();
        sha1.update(&pack);
        pack.extend_from_slice(&sha1.finalize());
        pack
    }

    fn sideband_packet(band: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 1);
        out.push(band);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn stitch_raw_packs_concatenates_bodies_and_updates_count() {
        let base = raw_pack(2, b"base-objects");
        let delta = raw_pack(3, b"delta-objects");

        let stitched = stitch_raw_packs(&base, &delta).unwrap();

        assert_eq!(&stitched[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(stitched[8..12].try_into().unwrap()), 5);
        assert_eq!(
            &stitched[12..stitched.len() - SHA1_TRAILER_LEN],
            b"base-objectsdelta-objects"
        );
    }

    #[test]
    fn extracts_and_replaces_sideband1_payloads() {
        let base_pack = raw_pack(1, b"base");
        let replacement = raw_pack(1, b"replacement");
        let mut response = Vec::new();
        response.extend_from_slice(&pkt(b"packfile\n"));
        response.extend_from_slice(&pkt(&sideband_packet(2, b"progress\n")));
        response.extend_from_slice(&pkt(&sideband_packet(1, &base_pack[..6])));
        response.extend_from_slice(&pkt(&sideband_packet(1, &base_pack[6..])));
        response.extend_from_slice(b"0000");

        assert_eq!(extract_raw_pack(&response).unwrap(), base_pack);

        let replaced = replace_sideband1_in_response(&response, &replacement).unwrap();
        assert_eq!(extract_raw_pack(&replaced).unwrap(), replacement);
        assert!(
            replaced
                .windows(b"progress\n".len())
                .any(|w| w == b"progress\n")
        );
    }
}
