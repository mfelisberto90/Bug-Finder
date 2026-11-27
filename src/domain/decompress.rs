use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompressError {
    TooLarge { limit: usize },
    UnsupportedEncoding(String),
    CorruptStream(String),
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => write!(f, "Decompressed payload exceeds {limit} bytes"),
            Self::UnsupportedEncoding(enc) => write!(f, "Unsupported Content-Encoding: {enc}"),
            Self::CorruptStream(msg) => write!(f, "Malformed compressed stream: {msg}"),
        }
    }
}

/// Bounded streaming decompression defending against zip bombs on public ingestion endpoints.
/// Aborts the moment decompressed output crosses `max_bytes` without buffering the remainder.
pub fn decompress_bounded(
    raw: &[u8],
    encoding: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>, DecompressError> {
    let enc = encoding
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "identity");

    let Some(enc_name) = enc else {
        if raw.len() > max_bytes {
            return Err(DecompressError::TooLarge { limit: max_bytes });
        }
        return Ok(raw.to_vec());
    };

    match enc_name.as_str() {
        "gzip" | "x-gzip" => {
            let dec = flate2::read::GzDecoder::new(raw);
            read_with_limit(dec, max_bytes)
        }
        "deflate" => {
            let dec = flate2::read::ZlibDecoder::new(raw);
            match read_with_limit(dec, max_bytes) {
                Ok(v) => Ok(v),
                Err(DecompressError::TooLarge { limit }) => {
                    Err(DecompressError::TooLarge { limit })
                }
                Err(_) => {
                    // Fallback to raw deflate stream (RFC 1951) if no zlib header
                    let raw_dec = flate2::read::DeflateDecoder::new(raw);
                    read_with_limit(raw_dec, max_bytes)
                }
            }
        }
        "br" => {
            let dec = brotli::Decompressor::new(raw, 4096);
            read_with_limit(dec, max_bytes)
        }
        "zstd" => {
            // Pre-validate RFC 8878 Zstandard frame header window size before decoder init
            // (defense-in-depth alongside ruzstd >= 0.9.1 against RUSTSEC-2026-0344 OOM bombs).
            let max_window = (max_bytes as u64).clamp(64 * 1024, 8 * 1024 * 1024);
            if zstd_frame_window_exceeds(raw, max_window) {
                return Err(DecompressError::TooLarge { limit: max_bytes });
            }
            let dec = ruzstd::decoding::StreamingDecoder::new(raw)
                .map_err(|e| DecompressError::CorruptStream(e.to_string()))?;
            read_with_limit(dec, max_bytes)
        }
        other => Err(DecompressError::UnsupportedEncoding(other.to_string())),
    }
}

/// Inspects RFC 8878 Zstandard frame magic + Frame_Header_Descriptor to reject giant
/// Window_Size allocations before `ruzstd` initializes its scratch buffer.
fn zstd_frame_window_exceeds(raw: &[u8], max_window: u64) -> bool {
    if raw.len() < 6 || raw[0..4] != [0x28, 0xB5, 0x2F, 0xFD] {
        return false;
    }
    let fhd = raw[4];
    let single_segment = (fhd & 0x20) != 0;
    if single_segment {
        // Window size equals Frame_Content_Size when Single_Segment_Flag = 1
        let fcs_flag = fhd >> 6;
        let dict_len = match fhd & 0x03 {
            0 => 0usize,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let fcs_offset = 5 + dict_len;
        let fcs_opt = match fcs_flag {
            0 => raw.get(fcs_offset).map(|&b| b as u64),
            1 => raw
                .get(fcs_offset..fcs_offset + 2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]) as u64 + 256),
            2 => raw
                .get(fcs_offset..fcs_offset + 4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64),
            _ => raw
                .get(fcs_offset..fcs_offset + 8)
                .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])),
        };
        return fcs_opt.is_some_and(|fcs| fcs > max_window);
    }
    let wd = raw[5];
    let exponent = (wd >> 3) as u32;
    let mantissa = (wd & 0x07) as u64;
    if exponent >= 50 {
        return true;
    }
    let base = 1u64 << (10 + exponent);
    let step = base >> 3;
    let window_size = base.saturating_add(step.saturating_mul(mantissa));
    window_size > max_window
}

fn read_with_limit<R: Read>(reader: R, max_bytes: usize) -> Result<Vec<u8>, DecompressError> {
    let mut out = Vec::new();
    let cap = (max_bytes as u64).saturating_add(1);
    reader
        .take(cap)
        .read_to_end(&mut out)
        .map_err(|e| DecompressError::CorruptStream(e.to_string()))?;
    if out.len() > max_bytes {
        return Err(DecompressError::TooLarge { limit: max_bytes });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_roundtrip_and_zip_bomb_rejection() {
        let small = b"{\"event_id\":\"abc\"}";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(small).unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(decompress_bounded(&gz, Some("gzip"), 1024).unwrap(), small);

        // 2 MiB of zeros compresses into ~2 KiB -> must fail at 64 KiB cap
        let bomb_raw = vec![0u8; 2 * 1024 * 1024];
        let mut enc2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc2.write_all(&bomb_raw).unwrap();
        let bomb_gz = enc2.finish().unwrap();
        assert!(bomb_gz.len() < 16 * 1024);
        assert_eq!(
            decompress_bounded(&bomb_gz, Some("gzip"), 64 * 1024),
            Err(DecompressError::TooLarge { limit: 64 * 1024 })
        );
    }

    #[test]
    fn brotli_roundtrip() {
        let input = br#"{"type":"event"}\n{"message":"ok"}"#;
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(input).unwrap();
        }
        assert_eq!(
            decompress_bounded(&compressed, Some("br"), 4096).unwrap(),
            input
        );
    }

    #[test]
    fn rejects_zstd_giant_window_header_before_decoder_alloc() {
        // RFC 8878 Zstandard magic + FHD(0x00, single_segment=0) + WD(0xF8 => exponent=31 => >2 TiB window)
        let bomb_hdr = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xF8, 0x00, 0x00];
        assert_eq!(
            decompress_bounded(&bomb_hdr, Some("zstd"), 64 * 1024),
            Err(DecompressError::TooLarge { limit: 64 * 1024 })
        );
    }
}
