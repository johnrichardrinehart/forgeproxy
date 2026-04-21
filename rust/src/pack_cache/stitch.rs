#[cfg(test)]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

const MAX_PKT_LINE_LEN: usize = 65520;
const PKT_HEADER_LEN: usize = 4;
const SIDEBAND_PREFIX_LEN: usize = 1;
const MAX_SIDEBAND_PACK_CHUNK: usize = MAX_PKT_LINE_LEN - PKT_HEADER_LEN - SIDEBAND_PREFIX_LEN;
const SHA1_TRAILER_LEN: usize = 20;
const PACK_HEADER_LEN: usize = 12;

#[cfg(test)]
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
        if payload == b"packfile\n" {
            offset = next_offset;
            continue;
        }
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

#[cfg(test)]
pub fn replace_sideband1_in_response(
    base_response: &[u8],
    replacement_pack: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        replacement_pack.len() >= PACK_HEADER_LEN + SHA1_TRAILER_LEN
            && &replacement_pack[..4] == b"PACK",
        "replacement payload is not a raw pack"
    );

    let mut offset = 0usize;
    let mut out = Vec::with_capacity(base_response.len() + replacement_pack.len());
    let mut emitted_replacement = false;
    let mut saw_sideband1 = false;

    while offset < base_response.len() {
        let (packet_len, next_offset) = read_packet_len(base_response, offset)?;
        if packet_len <= PKT_HEADER_LEN {
            out.extend_from_slice(&base_response[offset..next_offset]);
            offset = next_offset;
            continue;
        }

        let payload = &base_response[offset + PKT_HEADER_LEN..next_offset];
        if payload == b"packfile\n" {
            out.extend_from_slice(&base_response[offset..next_offset]);
        } else if payload.first() == Some(&1) {
            saw_sideband1 = true;
            if !emitted_replacement {
                for chunk in sideband1_chunks(replacement_pack) {
                    out.extend_from_slice(&chunk);
                }
                emitted_replacement = true;
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

#[cfg(test)]
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

pub(crate) struct OpenedPack {
    name: String,
    file: File,
    version: u32,
    count: u32,
    header: [u8; PACK_HEADER_LEN],
}

impl OpenedPack {
    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        let mut file = File::open(path).with_context(|| format!("open pack {}", path.display()))?;
        let mut header = [0u8; PACK_HEADER_LEN];
        file.read_exact(&mut header)
            .with_context(|| format!("read pack header {}", path.display()))?;
        let version = pack_header_version(&header, "pack")?;
        let count = u32::from_be_bytes(header[8..12].try_into()?);
        Ok(Self {
            name: path.display().to_string(),
            file,
            version,
            count,
            header,
        })
    }
}

#[cfg(test)]
pub fn stream_packfile_response_from_paths<F>(pack_paths: &[PathBuf], emit: F) -> Result<()>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    let pack_infos = pack_paths
        .iter()
        .map(|path| OpenedPack::from_path(path))
        .collect::<Result<Vec<_>>>()?;
    stream_packfile_response_from_open_files(pack_infos, emit)
}

pub(crate) fn stream_packfile_response_from_open_files<F>(
    mut pack_infos: Vec<OpenedPack>,
    mut emit: F,
) -> Result<()>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    ensure!(
        !pack_infos.is_empty(),
        "cannot stream response without packs"
    );

    emit(encode_data_pkt(b"packfile\n")).context("emit packfile section")?;

    let first_header = pack_infos[0].header;
    let total_count = pack_infos
        .iter()
        .fold(0u64, |total, info| total + u64::from(info.count));
    ensure!(
        total_count <= u64::from(u32::MAX),
        "pack object count overflow"
    );

    let mut streamer = PackStreamer::new(first_header, total_count as u32);
    streamer.emit_rewritten_header(&mut emit)?;
    for pack in &mut pack_infos {
        streamer.stream_pack_body(pack, &mut emit)?;
    }
    streamer.finish(&mut emit)?;
    emit(encode_control_pkt(0)?).context("emit packfile flush")?;
    Ok(())
}

#[cfg(test)]
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

fn encode_control_pkt(len: usize) -> Result<Vec<u8>> {
    ensure!(len <= 2, "invalid control pkt length {len}");
    Ok(format!("{len:04x}").into_bytes())
}

fn encode_data_pkt(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + PKT_HEADER_LEN).into_bytes();
    out.extend_from_slice(payload);
    out
}

fn sideband1_chunks(bytes: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    bytes.chunks(MAX_SIDEBAND_PACK_CHUNK).map(|chunk| {
        let packet_len = PKT_HEADER_LEN + SIDEBAND_PREFIX_LEN + chunk.len();
        let mut out = Vec::with_capacity(packet_len);
        out.extend_from_slice(format!("{packet_len:04x}").as_bytes());
        out.push(1);
        out.extend_from_slice(chunk);
        out
    })
}

#[cfg(test)]
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

struct PackStreamer {
    version: u32,
    total_count: u32,
    sha1: Sha1,
}

impl PackStreamer {
    fn new(first_header: [u8; PACK_HEADER_LEN], total_count: u32) -> Self {
        Self {
            version: pack_header_version(&first_header, "pack").unwrap_or(2),
            total_count,
            sha1: Sha1::new(),
        }
    }

    fn emit_rewritten_header<F>(&mut self, emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        let mut rewritten = Vec::with_capacity(PACK_HEADER_LEN);
        rewritten.extend_from_slice(b"PACK");
        rewritten.extend_from_slice(&self.version.to_be_bytes());
        rewritten.extend_from_slice(&self.total_count.to_be_bytes());
        self.sha1.update(&rewritten);
        self.emit_sideband1(&rewritten, emit)
    }

    fn stream_pack_body<F>(&mut self, info: &mut OpenedPack, emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        ensure!(
            info.version == self.version,
            "pack version {} does not match base pack version {}",
            info.version,
            self.version
        );

        let mut reader = BufReader::new(&mut info.file);
        let mut trailer_window = Vec::with_capacity(SHA1_TRAILER_LEN);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buf)
                .with_context(|| format!("read pack body {}", info.name))?;
            if read == 0 {
                break;
            }
            trailer_window.extend_from_slice(&buf[..read]);
            if trailer_window.len() <= SHA1_TRAILER_LEN {
                continue;
            }
            let emit_len = trailer_window.len() - SHA1_TRAILER_LEN;
            let emit_bytes = trailer_window[..emit_len].to_vec();
            trailer_window.drain(..emit_len);
            self.sha1.update(&emit_bytes);
            self.emit_sideband1(&emit_bytes, emit)?;
        }
        ensure!(
            trailer_window.len() == SHA1_TRAILER_LEN,
            "pack trailer was incomplete for {}",
            info.name
        );
        Ok(())
    }

    fn finish<F>(&mut self, emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        let trailer = self.sha1.clone().finalize();
        self.emit_sideband1(&trailer, emit)?;
        Ok(())
    }

    fn emit_sideband1<F>(&mut self, bytes: &[u8], emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        for chunk in sideband1_chunks(bytes) {
            emit(chunk).context("emit sideband-1 chunk")?;
        }
        Ok(())
    }
}

fn pack_header_version(header: &[u8], name: &str) -> Result<u32> {
    ensure!(
        header.len() >= PACK_HEADER_LEN,
        "{name} pack header too short"
    );
    ensure!(&header[..4] == b"PACK", "{name} pack has invalid magic");
    let version = u32::from_be_bytes(header[4..8].try_into()?);
    ensure!(
        version == 2 || version == 3,
        "{name} pack version {version} is unsupported"
    );
    Ok(version)
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

    #[test]
    fn streams_packfile_response_from_files() {
        let temp = tempfile::tempdir().unwrap();
        let base_pack = raw_pack(1, b"base");
        let delta_pack = raw_pack(2, b"delta");
        let base_path = temp.path().join("base.pack");
        let delta_path = temp.path().join("delta.pack");
        std::fs::write(&base_path, &base_pack).unwrap();
        std::fs::write(&delta_path, &delta_pack).unwrap();

        let mut streamed = Vec::new();
        stream_packfile_response_from_paths(&[base_path, delta_path], |chunk| {
            streamed.extend_from_slice(&chunk);
            Ok(())
        })
        .unwrap();

        let raw = extract_raw_pack(&streamed).unwrap();
        assert_eq!(u32::from_be_bytes(raw[8..12].try_into().unwrap()), 3);
        assert_eq!(&raw[12..raw.len() - SHA1_TRAILER_LEN], b"basedelta");
        assert!(
            streamed
                .windows(b"packfile\n".len())
                .any(|w| w == b"packfile\n")
        );
        assert!(streamed.ends_with(b"0000"));
    }
}
