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
            let dec = ruzstd::StreamingDecoder::new(raw)
                .map_err(|e| DecompressError::CorruptStream(e.to_string()))?;
            read_with_limit(dec, max_bytes)
        }
        other => Err(DecompressError::UnsupportedEncoding(other.to_string())),
    }
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
}
