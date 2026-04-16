use anyhow::{Context, Result, bail, ensure};
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

const MAX_PKT_LINE_LEN: usize = 0xffff;
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

pub fn stream_stitched_response_from_paths<F>(
    base_response_path: &Path,
    delta_pack_paths: &[PathBuf],
    emit: F,
) -> Result<()>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    let base_file = File::open(base_response_path)
        .with_context(|| format!("open base response {}", base_response_path.display()))?;
    let delta_infos = delta_pack_paths
        .iter()
        .map(|path| DeltaPackInfo::from_path(path))
        .collect::<Result<Vec<_>>>()?;
    let mut streamer = ResponseStreamer::new(delta_infos, emit);
    streamer.stream_response(BufReader::new(base_file))?;
    streamer.finish()
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

fn read_packet_header<R: Read>(reader: &mut R) -> Result<Option<usize>> {
    let mut header = [0u8; PKT_HEADER_LEN];
    let mut read = 0usize;
    while read < PKT_HEADER_LEN {
        match reader.read(&mut header[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => bail!("truncated pkt-line header"),
            Ok(n) => read += n,
            Err(error) => return Err(error).context("read pkt-line header"),
        }
    }
    let header_text = std::str::from_utf8(&header).context("non-utf8 pkt-line header")?;
    let len = usize::from_str_radix(header_text, 16).context("invalid pkt-line length")?;
    Ok(Some(len))
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

#[cfg(test)]
fn write_sideband1_pack(out: &mut Vec<u8>, pack: &[u8]) {
    for chunk in pack.chunks(MAX_SIDEBAND_PACK_CHUNK) {
        let packet_len = PKT_HEADER_LEN + SIDEBAND_PREFIX_LEN + chunk.len();
        out.extend_from_slice(format!("{packet_len:04x}").as_bytes());
        out.push(1);
        out.extend_from_slice(chunk);
    }
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

struct DeltaPackInfo {
    path: PathBuf,
    version: u32,
    count: u32,
}

impl DeltaPackInfo {
    fn from_path(path: &Path) -> Result<Self> {
        let mut file =
            File::open(path).with_context(|| format!("open delta pack {}", path.display()))?;
        let mut header = [0u8; PACK_HEADER_LEN];
        file.read_exact(&mut header)
            .with_context(|| format!("read delta pack header {}", path.display()))?;
        let version = pack_header_version(&header, "delta")?;
        let count = u32::from_be_bytes(header[8..12].try_into()?);
        Ok(Self {
            path: path.to_path_buf(),
            version,
            count,
        })
    }
}

struct ResponseStreamer<F>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    delta_infos: Vec<DeltaPackInfo>,
    emit: F,
    pack_streamer: Option<PackStreamer>,
    saw_sideband1: bool,
}

impl<F> ResponseStreamer<F>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    fn new(delta_infos: Vec<DeltaPackInfo>, emit: F) -> Self {
        Self {
            delta_infos,
            emit,
            pack_streamer: None,
            saw_sideband1: false,
        }
    }

    fn stream_response<R: Read>(&mut self, mut reader: R) -> Result<()> {
        while let Some(packet_len) = read_packet_header(&mut reader)? {
            if packet_len <= 2 {
                if self.saw_sideband1 {
                    self.finish_pack_streamer()?;
                }
                (self.emit)(encode_control_pkt(packet_len)?).context("emit control pkt-line")?;
                continue;
            }
            ensure!(
                packet_len >= PKT_HEADER_LEN,
                "invalid pkt-line length {packet_len}"
            );
            let payload_len = packet_len - PKT_HEADER_LEN;
            let mut payload = vec![0u8; payload_len];
            reader
                .read_exact(&mut payload)
                .context("read pkt-line payload")?;

            if payload.first() == Some(&1) {
                self.saw_sideband1 = true;
                self.pack_streamer
                    .get_or_insert_with(|| PackStreamer::new(&self.delta_infos))
                    .feed_base_pack_payload(&payload[1..], &mut self.emit)?;
            } else {
                (self.emit)(encode_data_pkt(&payload)).context("emit non-pack pkt-line")?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        ensure!(
            self.saw_sideband1,
            "base response contained no sideband-1 pack data"
        );
        self.finish_pack_streamer()
    }

    fn finish_pack_streamer(&mut self) -> Result<()> {
        if let Some(mut pack_streamer) = self.pack_streamer.take() {
            pack_streamer.finish(&self.delta_infos, &mut self.emit)?;
        }
        Ok(())
    }
}

struct PackStreamer {
    delta_count: u64,
    header: Vec<u8>,
    version: Option<u32>,
    trailer_window: Vec<u8>,
    sha1: Sha1,
}

impl PackStreamer {
    fn new(delta_infos: &[DeltaPackInfo]) -> Self {
        let delta_count = delta_infos
            .iter()
            .fold(0u64, |total, info| total + u64::from(info.count));
        Self {
            delta_count,
            header: Vec::with_capacity(PACK_HEADER_LEN),
            version: None,
            trailer_window: Vec::with_capacity(SHA1_TRAILER_LEN),
            sha1: Sha1::new(),
        }
    }

    fn feed_base_pack_payload<F>(&mut self, mut bytes: &[u8], emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        if self.header.len() < PACK_HEADER_LEN {
            let needed = PACK_HEADER_LEN - self.header.len();
            let take = needed.min(bytes.len());
            self.header.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.header.len() == PACK_HEADER_LEN {
                self.emit_rewritten_header(emit)?;
            }
        }
        if !bytes.is_empty() {
            self.feed_body_bytes(bytes, emit)?;
        }
        Ok(())
    }

    fn finish<F>(&mut self, delta_infos: &[DeltaPackInfo], emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        ensure!(self.version.is_some(), "base pack header was incomplete");
        ensure!(
            self.trailer_window.len() == SHA1_TRAILER_LEN,
            "base pack trailer was incomplete"
        );
        self.trailer_window.clear();

        for info in delta_infos {
            self.stream_delta_body(info, emit)?;
        }

        let trailer = self.sha1.clone().finalize();
        self.emit_sideband1(&trailer, emit)?;
        Ok(())
    }

    fn emit_rewritten_header<F>(&mut self, emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        ensure!(&self.header[..4] == b"PACK", "base pack has invalid magic");
        let version = pack_header_version(&self.header, "base")?;
        let base_count = u32::from_be_bytes(self.header[8..12].try_into()?);
        let total_count = u64::from(base_count) + self.delta_count;
        ensure!(
            total_count <= u64::from(u32::MAX),
            "pack object count overflow"
        );

        let mut rewritten = Vec::with_capacity(PACK_HEADER_LEN);
        rewritten.extend_from_slice(b"PACK");
        rewritten.extend_from_slice(&version.to_be_bytes());
        rewritten.extend_from_slice(&(total_count as u32).to_be_bytes());
        self.sha1.update(&rewritten);
        self.emit_sideband1(&rewritten, emit)?;
        self.version = Some(version);
        Ok(())
    }

    fn feed_body_bytes<F>(&mut self, bytes: &[u8], emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        self.trailer_window.extend_from_slice(bytes);
        if self.trailer_window.len() <= SHA1_TRAILER_LEN {
            return Ok(());
        }

        let emit_len = self.trailer_window.len() - SHA1_TRAILER_LEN;
        let emit_bytes = self.trailer_window[..emit_len].to_vec();
        self.trailer_window.drain(..emit_len);
        self.sha1.update(&emit_bytes);
        self.emit_sideband1(&emit_bytes, emit)
    }

    fn stream_delta_body<F>(&mut self, info: &DeltaPackInfo, emit: &mut F) -> Result<()>
    where
        F: FnMut(Vec<u8>) -> io::Result<()>,
    {
        let mut file = BufReader::new(
            File::open(&info.path)
                .with_context(|| format!("open delta pack {}", info.path.display()))?,
        );
        let mut header = [0u8; PACK_HEADER_LEN];
        file.read_exact(&mut header)
            .with_context(|| format!("read delta pack header {}", info.path.display()))?;
        ensure!(
            Some(info.version) == self.version,
            "delta pack version {} does not match base pack version {:?}",
            info.version,
            self.version
        );

        let mut trailer_window = Vec::with_capacity(SHA1_TRAILER_LEN);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buf)
                .with_context(|| format!("read delta pack {}", info.path.display()))?;
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
            "delta pack trailer was incomplete"
        );
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
    fn streams_stitched_response_from_files() {
        let temp = tempfile::tempdir().unwrap();
        let base_pack = raw_pack(1, b"base");
        let delta_pack = raw_pack(2, b"delta");
        let base_response_path = temp.path().join("base.pack-response");
        let delta_path = temp.path().join("delta.pack");
        let mut response = Vec::new();
        response.extend_from_slice(&pkt(b"packfile\n"));
        response.extend_from_slice(&pkt(&sideband_packet(2, b"progress\n")));
        response.extend_from_slice(&pkt(&sideband_packet(1, &base_pack[..6])));
        response.extend_from_slice(&pkt(&sideband_packet(1, &base_pack[6..])));
        response.extend_from_slice(b"0000");
        std::fs::write(&base_response_path, response).unwrap();
        std::fs::write(&delta_path, &delta_pack).unwrap();

        let mut streamed = Vec::new();
        stream_stitched_response_from_paths(&base_response_path, &[delta_path], |chunk| {
            streamed.extend_from_slice(&chunk);
            Ok(())
        })
        .unwrap();

        let raw = extract_raw_pack(&streamed).unwrap();
        assert_eq!(u32::from_be_bytes(raw[8..12].try_into().unwrap()), 3);
        assert_eq!(&raw[12..raw.len() - SHA1_TRAILER_LEN], b"basedelta");
        assert!(
            streamed
                .windows(b"progress\n".len())
                .any(|w| w == b"progress\n")
        );
    }
}
