use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn collect_files(root: &Path, current: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    let mut items: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    items.sort_by_key(|e| e.path());
    for entry in items {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                out.push((rel_str, path));
            }
        }
    }
}

fn content_type_for(rel: &str) -> &'static str {
    if rel.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if rel.ends_with(".js") || rel.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if rel.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if rel.ends_with(".svg") {
        "image/svg+xml"
    } else if rel.ends_with(".png") {
        "image/png"
    } else if rel.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if rel.ends_with(".woff2") {
        "font/woff2"
    } else if rel.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}

fn main() {
    println!("cargo:rerun-if-changed=ui/dist");
    println!("cargo:rerun-if-changed=sdks/browser/bugfinder-mini.js");
    println!("cargo:rerun-if-changed=sdks/browser/bugfinder-shield.js");
    println!("cargo:rerun-if-changed=migrations/sqlite/001_init.sql");
    println!("cargo:rerun-if-changed=migrations/postgres/001_init_rls.sql");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ui_dist = manifest_dir.join("ui").join("dist");
    let dest = out_dir.join("embedded_ui.rs");

    let mut files = Vec::new();
    if ui_dist.join("index.html").is_file() {
        collect_files(&ui_dist, &ui_dist, &mut files);
    }

    let mut file = fs::File::create(&dest).expect("create embedded_ui.rs");

    if files.is_empty() {
        let fallback_html = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Bug-Finder</title>
</head>
<body>
  <main><h1>Bug-Finder</h1><p>UI bundle not built yet. Run ui build.</p></main>
</body>
</html>"#;
        let etag = fnv1a_hex(fallback_html);
        writeln!(file, "pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str, &'static str)> {{").unwrap();
        writeln!(file, "    match path {{").unwrap();
        writeln!(
            file,
            "        \"index.html\" => Some((&{:?}, \"text/html; charset=utf-8\", \"{}\")),",
            fallback_html, etag
        ).unwrap();
        writeln!(file, "        _ => None,").unwrap();
        writeln!(file, "    }}").unwrap();
        writeln!(file, "}}").unwrap();
    } else {
        writeln!(file, "pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str, &'static str)> {{").unwrap();
        writeln!(file, "    match path {{").unwrap();
        for (rel, abs) in &files {
            let bytes = fs::read(abs).expect("read ui dist asset");
            let etag = fnv1a_hex(&bytes);
            let ct = content_type_for(rel);
            let abs_str = abs.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(
                file,
                "        {:?} => Some((include_bytes!(\"{}\"), {:?}, {:?})),",
                rel, abs_str, ct, etag
            ).unwrap();
        }
        writeln!(file, "        _ => None,").unwrap();
        writeln!(file, "    }}").unwrap();
        writeln!(file, "}}").unwrap();
    }

    let mini_sdk_path = manifest_dir.join("sdks").join("browser").join("bugfinder-mini.js");
    if mini_sdk_path.is_file() {
        let abs_str = mini_sdk_path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
        writeln!(file, "pub const MINI_SDK_JS: &[u8] = include_bytes!(\"{}\");", abs_str).unwrap();
    } else {
        writeln!(file, "pub const MINI_SDK_JS: &[u8] = b\"/* BugFinder Mini SDK placeholder */\";").unwrap();
    }

    let shield_sdk_path = manifest_dir.join("sdks").join("browser").join("bugfinder-shield.js");
    if shield_sdk_path.is_file() {
        let abs_str = shield_sdk_path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
        writeln!(file, "pub const SHIELD_SDK_JS: &[u8] = include_bytes!(\"{}\");", abs_str).unwrap();
    } else {
        writeln!(file, "pub const SHIELD_SDK_JS: &[u8] = b\"/* BugFinder Shield SDK placeholder */\";").unwrap();
    }
}
