use crate::runtime::trim_heap;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MappedLocation {
    pub source: String,
    pub line: u32,   // 1-based
    pub column: u32, // 0-based
    pub name: Option<String>,
    pub pre_context: Vec<String>,
    pub context_line: Option<String>,
    pub post_context: Vec<String>,
}

#[derive(Debug, Clone)]
struct MappingSeg {
    gen_col: i64,
    src_idx: Option<usize>,
    orig_line: Option<i64>,
    orig_col: Option<i64>,
    name_idx: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SourceMapV3 {
    pub sources: Vec<String>,
    pub names: Vec<String>,
    pub sources_content: Vec<Option<String>>,
    lines: Vec<Vec<MappingSeg>>,
    pub approx_bytes: usize,
}

#[derive(Deserialize)]
struct RawSourceMap {
    version: u32,
    sources: Option<Vec<String>>,
    names: Option<Vec<String>>,
    #[serde(rename = "sourcesContent")]
    sources_content: Option<Vec<Option<String>>>,
    mappings: String,
}

fn b64_digit(b: u8) -> Option<i64> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as i64),
        b'a'..=b'z' => Some((b - b'a' + 26) as i64),
        b'0'..=b'9' => Some((b - b'0' + 52) as i64),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_vlq(bytes: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        if *pos >= bytes.len() || shift > 30 {
            return None;
        }
        let digit = b64_digit(bytes[*pos])?;
        *pos += 1;
        let cont = (digit & 32) != 0;
        result += (digit & 31) << shift;
        shift += 5;
        if !cont {
            break;
        }
    }
    let neg = (result & 1) == 1;
    let mag = result >> 1;
    Some(if neg { -mag } else { mag })
}

impl SourceMapV3 {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let parsed: RawSourceMap =
            serde_json::from_slice(raw).map_err(|e| format!("Invalid SourceMap JSON: {e}"))?;
        if parsed.version != 3 {
            return Err(format!("Unsupported SourceMap version {}", parsed.version));
        }

        let sources = parsed.sources.unwrap_or_default();
        let names = parsed.names.unwrap_or_default();
        let sources_content = parsed.sources_content.unwrap_or_default();

        let mut lines = Vec::new();
        let mut src_idx = 0i64;
        let mut orig_line = 0i64;
        let mut orig_col = 0i64;
        let mut name_idx = 0i64;

        for raw_line in parsed.mappings.split(';') {
            let mut gen_col = 0i64;
            let mut segs = Vec::new();
            if !raw_line.is_empty() {
                for raw_seg in raw_line.split(',') {
                    if raw_seg.is_empty() {
                        continue;
                    }
                    let b = raw_seg.as_bytes();
                    let mut p = 0;
                    let Some(dc) = decode_vlq(b, &mut p) else {
                        continue;
                    };
                    gen_col += dc;
                    let mut seg = MappingSeg {
                        gen_col,
                        src_idx: None,
                        orig_line: None,
                        orig_col: None,
                        name_idx: None,
                    };
                    if p < b.len() {
                        if let (Some(ds), Some(dl), Some(dcol)) = (
                            decode_vlq(b, &mut p),
                            decode_vlq(b, &mut p),
                            decode_vlq(b, &mut p),
                        ) {
                            src_idx += ds;
                            orig_line += dl;
                            orig_col += dcol;
                            if src_idx >= 0 {
                                seg.src_idx = Some(src_idx as usize);
                                seg.orig_line = Some(orig_line);
                                seg.orig_col = Some(orig_col);
                            }
                            if p < b.len() {
                                if let Some(dn) = decode_vlq(b, &mut p) {
                                    name_idx += dn;
                                    if name_idx >= 0 {
                                        seg.name_idx = Some(name_idx as usize);
                                    }
                                }
                            }
                        }
                    }
                    segs.push(seg);
                }
            }
            lines.push(segs);
        }

        Ok(Self {
            sources,
            names,
            sources_content,
            lines,
            approx_bytes: raw.len(),
        })
    }

    pub fn lookup(&self, gen_line_1based: u32, gen_col_0based: u32) -> Option<MappedLocation> {
        let line_idx = gen_line_1based.checked_sub(1)? as usize;
        let segs = self.lines.get(line_idx)?;
        if segs.is_empty() {
            return None;
        }
        let target_col = gen_col_0based as i64;
        let pos = segs.partition_point(|s| s.gen_col <= target_col);
        let seg = if pos == 0 { &segs[0] } else { &segs[pos - 1] };

        let s_idx = seg.src_idx?;
        let source = self.sources.get(s_idx)?.clone();
        let orig_line = seg.orig_line?.max(0) as u32 + 1;
        let orig_col = seg.orig_col.unwrap_or(0).max(0) as u32;
        let name = seg.name_idx.and_then(|i| self.names.get(i).cloned());

        let (pre_context, context_line, post_context) =
            extract_context(self.sources_content.get(s_idx).and_then(|o| o.as_deref()), orig_line);

        Some(MappedLocation {
            source,
            line: orig_line,
            column: orig_col,
            name,
            pre_context,
            context_line,
            post_context,
        })
    }
}

fn extract_context(
    content: Option<&str>,
    line_1based: u32,
) -> (Vec<String>, Option<String>, Vec<String>) {
    let Some(text) = content else {
        return (Vec::new(), None, Vec::new());
    };
    let lines: Vec<&str> = text.lines().collect();
    let idx = line_1based.saturating_sub(1) as usize;
    if idx >= lines.len() {
        return (Vec::new(), None, Vec::new());
    }
    let start = idx.saturating_sub(5);
    let end = (idx + 6).min(lines.len());
    let pre = lines[start..idx].iter().map(|s| (*s).to_string()).collect();
    let ctx = Some(lines[idx].to_string());
    let post = lines[idx + 1..end].iter().map(|s| (*s).to_string()).collect();
    (pre, ctx, post)
}

/// Byte-bounded LRU cache for parsed Source Maps (cap 2 MiB / 8 entries)
/// so decoding large JS maps never balloons resident RAM.
pub struct SourceMapCache {
    max_bytes: usize,
    max_entries: usize,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<String, SourceMapV3>,
    order: VecDeque<String>,
    total_bytes: usize,
}

impl SourceMapCache {
    pub fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                total_bytes: 0,
            }),
        }
    }

    pub fn get_or_parse(&self, key: &str, raw_bytes: &[u8]) -> Option<SourceMapV3> {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(found) = guard.map.get(key).cloned() {
                guard.order.retain(|k| k != key);
                guard.order.push_back(key.to_string());
                return Some(found);
            }
        }

        let parsed = SourceMapV3::parse(raw_bytes).ok()?;
        let mut evicted = false;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            while (guard.total_bytes + parsed.approx_bytes > self.max_bytes
                || guard.map.len() >= self.max_entries)
                && !guard.order.is_empty()
            {
                if let Some(oldest) = guard.order.pop_front() {
                    if let Some(removed) = guard.map.remove(&oldest) {
                        guard.total_bytes = guard.total_bytes.saturating_sub(removed.approx_bytes);
                        evicted = true;
                    }
                }
            }
            if parsed.approx_bytes <= self.max_bytes {
                guard.total_bytes += parsed.approx_bytes;
                guard.map.insert(key.to_string(), parsed.clone());
                guard.order.push_back(key.to_string());
            }
        }
        if evicted {
            trim_heap();
        }
        Some(parsed)
    }
}

pub fn strip_url_basename(raw: &str) -> &str {
    let without_query = raw.split(&['?', '#'][..]).next().unwrap_or(raw);
    without_query.rsplit('/').next().unwrap_or(without_query)
}

pub fn demangle_event_with_maps<F>(ev: &mut Value, mut fetch_map: F) -> bool
where
    F: FnMut(Option<&str>, &str) -> Option<SourceMapV3>,
{
    let debug_id_by_file: HashMap<String, String> = ev
        .get("debug_meta")
        .and_then(|dm| dm.get("images"))
        .and_then(|imgs| imgs.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|img| {
                    let code_file = img.get("code_file")?.as_str()?;
                    let debug_id = img.get("debug_id")?.as_str()?;
                    Some((code_file.to_string(), debug_id.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut any_mapped = false;
    let Some(exc_vals) = ev
        .get_mut("exception")
        .and_then(|e| e.get_mut("values"))
        .and_then(|v| v.as_array_mut())
    else {
        return false;
    };

    for exc in exc_vals.iter_mut() {
        let Some(frames) = exc
            .get_mut("stacktrace")
            .and_then(|s| s.get_mut("frames"))
            .and_then(|f| f.as_array_mut())
        else {
            continue;
        };
        for frame in frames.iter_mut() {
            let Some(obj) = frame.as_object_mut() else {
                continue;
            };
            let filename = obj
                .get("filename")
                .or_else(|| obj.get("abs_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let lineno = obj.get("lineno").and_then(|v| v.as_u64()).map(|n| n as u32);
            let colno = obj.get("colno").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let Some(line) = lineno else {
                continue;
            };

            let basename = strip_url_basename(&filename);
            let debug_id = debug_id_by_file
                .get(&filename)
                .or_else(|| debug_id_by_file.get(basename))
                .map(|s| s.as_str());

            if let Some(sm) = fetch_map(debug_id, basename) {
                if let Some(loc) = sm.lookup(line, colno) {
                    any_mapped = true;
                    obj.insert("abs_path".into(), Value::String(filename.clone()));
                    obj.insert("filename".into(), Value::String(loc.source));
                    obj.insert("lineno".into(), Value::Number(loc.line.into()));
                    obj.insert("colno".into(), Value::Number(loc.column.into()));
                    if let Some(name) = loc.name {
                        obj.insert("function".into(), Value::String(name));
                    }
                    if let Some(ctx) = loc.context_line {
                        obj.insert("context_line".into(), Value::String(ctx));
                        obj.insert(
                            "pre_context".into(),
                            Value::Array(loc.pre_context.into_iter().map(Value::String).collect()),
                        );
                        obj.insert(
                            "post_context".into(),
                            Value::Array(loc.post_context.into_iter().map(Value::String).collect()),
                        );
                    }
                    obj.insert("source_mapped".into(), Value::Bool(true));
                }
            }
        }
    }
    any_mapped
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_vlq_sourcemap_and_demangles_frame() {
        // Minimal valid SourceMap v3 mapping gen(1,0) -> src[0] line 2, col 4, name[0]
        // VLQ deltas: 0(A), 0(A), +2(E), +4(I), 0(A) => "AAEIA"
        let sm_bytes = br#"{
            "version": 3,
            "sources": ["src/checkout.ts"],
            "names": ["submitOrder"],
            "sourcesContent": ["const a = 1;\nfunction submitOrder() {\n  throw new Error('boom');\n}\n"],
            "mappings": "AAEIA"
        }"#;
        let sm = SourceMapV3::parse(sm_bytes).unwrap();
        let loc = sm.lookup(1, 0).unwrap();
        assert_eq!(loc.source, "src/checkout.ts");
        assert_eq!(loc.line, 3); // 0-based 2 => 1-based 3
        assert_eq!(loc.column, 4);
        assert_eq!(loc.name.as_deref(), Some("submitOrder"));
        assert_eq!(
            loc.context_line.as_deref(),
            Some("  throw new Error('boom');")
        );

        let mut ev = json!({
            "exception": {
                "values": [{
                    "type": "Error",
                    "value": "boom",
                    "stacktrace": {
                        "frames": [{ "filename": "https://cdn.example.com/app.min.js?v=99#top", "lineno": 1, "colno": 0 }]
                    }
                }]
            }
        });
        assert_eq!(strip_url_basename("https://cdn.example.com/app.min.js?v=99#top"), "app.min.js");
        let mapped = demangle_event_with_maps(&mut ev, |_, fname| {
            if fname == "app.min.js" { Some(sm.clone()) } else { None }
        });
        assert!(mapped);
        let fr = &ev["exception"]["values"][0]["stacktrace"]["frames"][0];
        assert_eq!(fr["filename"], "src/checkout.ts");
        assert_eq!(fr["function"], "submitOrder");
        assert_eq!(fr["source_mapped"], true);
    }
}
