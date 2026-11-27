use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Pure-Rust validator for HTML `<input pattern="...">` attributes compiled under
/// Chromium's ECMAScript `/v` (`unicodeSets`) mode.
pub fn validate_ecmascript_v_pattern(pat: &str) -> Result<(), String> {
    if pat.is_empty() {
        return Err("Empty pattern".into());
    }
    let bytes = pat.as_bytes();
    let mut i = 0usize;
    let mut class_depth = 0usize;
    let mut paren_depth = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return Err("Trailing backslash in pattern".into());
            }
            let next = bytes[i];
            if class_depth == 0 {
                // Outside [...], ECMAScript /v forbids unnecessary identity escapes such as \- or \_.
                let allowed_outside = matches!(
                    next,
                    b'd' | b'D'
                        | b'w'
                        | b'W'
                        | b's'
                        | b'S'
                        | b'b'
                        | b'B'
                        | b'n'
                        | b'r'
                        | b't'
                        | b'f'
                        | b'v'
                        | b'0'
                        | b'p'
                        | b'P'
                        | b'u'
                        | b'x'
                        | b'k'
                        | b'^'
                        | b'$'
                        | b'\\'
                        | b'.'
                        | b'*'
                        | b'+'
                        | b'?'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'|'
                        | b'/'
                ) || next.is_ascii_digit();
                if !allowed_outside {
                    return Err(format!(
                        "Invalid escape '\\{}' outside character class under ECMAScript /v",
                        next as char
                    ));
                }
            }
            if (next == b'u' || next == b'p' || next == b'P') && bytes.get(i + 1) == Some(&b'{') {
                let close = bytes[i + 2..]
                    .iter()
                    .position(|&c| c == b'}')
                    .ok_or_else(|| "Unclosed \\u{...} or \\p{...} escape".to_string())?;
                i += 2 + close + 1;
                continue;
            }
            i += 1;
            continue;
        }

        if class_depth > 0 {
            if b == b'[' {
                class_depth += 1;
                i += 1;
                if bytes.get(i) == Some(&b'^') {
                    i += 1;
                }
                continue;
            }
            if b == b']' {
                class_depth -= 1;
                i += 1;
                continue;
            }
            // Reserved ClassSetSyntaxCharacter inside [...]: ( ) { } / (unless escaped)
            if matches!(b, b'(' | b')' | b'{' | b'}' | b'/') {
                return Err(format!(
                    "Unescaped reserved character '{}' inside [...] under ECMAScript /v",
                    b as char
                ));
            }
            // ClassSetReservedDoublePunctuator inside [...] under /v
            if i + 1 < bytes.len()
                && bytes[i + 1] == b
                && matches!(
                    b,
                    b'&' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'*'
                        | b'+'
                        | b','
                        | b'.'
                        | b':'
                        | b';'
                        | b'<'
                        | b'='
                        | b'>'
                        | b'?'
                        | b'@'
                        | b'^'
                        | b'`'
                        | b'~'
                        | b'-'
                )
            {
                return Err(format!(
                    "Unescaped reserved double punctuator '{}{}' inside [...] under /v",
                    b as char, b as char
                ));
            }
            i += 1;
            continue;
        }

        match b {
            b'[' => {
                class_depth += 1;
                i += 1;
                if bytes.get(i) == Some(&b'^') {
                    i += 1;
                }
            }
            b']' => {
                i += 1;
            }
            b'(' => {
                paren_depth += 1;
                i += 1;
            }
            b')' => {
                if paren_depth == 0 {
                    return Err("Unmatched ')' in pattern".into());
                }
                paren_depth -= 1;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if class_depth != 0 {
        return Err("Unclosed '[' character class in pattern".into());
    }
    if paren_depth != 0 {
        return Err("Unclosed '(' group in pattern".into());
    }
    Ok(())
}

fn collect_files_with_exts(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut sorted: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    sorted.sort();
    for path in sorted {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "node_modules" || name == "dist" || name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_files_with_exts(&path, exts, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if exts.iter().any(|wanted| wanted.eq_ignore_ascii_case(ext)) {
                out.push(path);
            }
        }
    }
}

/// Strip `-- ...` line comments and `/* ... */` block comments from SQL while ignoring SQL strings.
pub fn strip_sql_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;
    let mut in_single_quote = false;

    while i < bytes.len() {
        let b = bytes[i];
        if in_single_quote {
            out.push(b as char);
            if b == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                in_single_quote = false;
            }
            i += 1;
            continue;
        }

        if b == b'\'' {
            in_single_quote = true;
            out.push('\'');
            i += 1;
            continue;
        }

        if b == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            out.push(' ');
            continue;
        }

        out.push(b as char);
        i += 1;
    }
    out
}

fn contains_word_ascii(haystack: &str, word: &str) -> bool {
    let h = haystack.as_bytes();
    let w = word.as_bytes();
    if w.is_empty() || h.len() < w.len() {
        return false;
    }
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(word) {
        let abs = start + pos;
        let left_ok = abs == 0 || !(h[abs - 1].is_ascii_alphanumeric() || h[abs - 1] == b'_');
        let end = abs + w.len();
        let right_ok = end == h.len() || !(h[end].is_ascii_alphanumeric() || h[end] == b'_');
        if left_ok && right_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

fn extract_pattern_attrs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let needle = "pattern=\"";
    let mut idx = 0usize;
    while let Some(pos) = text[idx..].find(needle) {
        let val_start = idx + pos + needle.len();
        if let Some(end_rel) = text[val_start..].find('"') {
            out.push(&text[val_start..val_start + end_rel]);
            idx = val_start + end_rel + 1;
        } else {
            break;
        }
    }
    out
}

fn extract_create_table_blocks(sql: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let needle = "CREATE TABLE IF NOT EXISTS ";
    let mut idx = 0usize;
    while let Some(pos) = sql[idx..].find(needle) {
        let name_start = idx + pos + needle.len();
        let rest = &sql[name_start..];
        let Some(open_paren) = rest.find('(') else {
            break;
        };
        let tbl_name = rest[..open_paren].trim().to_string();
        let mut depth = 0usize;
        let mut body_end = None;
        for (off, b) in rest.bytes().enumerate().skip(open_paren) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        body_end = Some(off);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = body_end {
            out.push((tbl_name, rest[open_paren + 1..end].to_string()));
            idx = name_start + end + 1;
        } else {
            break;
        }
    }
    out
}

fn strip_rust_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Run all security, performance, supply-chain, and public-hygiene invariant checks on `root`.
pub fn run_lint(root: &Path) -> Result<usize, Vec<String>> {
    let mut errors = Vec::new();
    let mut checked_files = 0usize;

    // 1. UI CSP inline style ban & ECMAScript /v input pattern checks
    let mut ui_files = Vec::new();
    collect_files_with_exts(&root.join("ui"), &["ts", "html"], &mut ui_files);
    for p in &ui_files {
        checked_files += 1;
        let rel = p.strip_prefix(root).unwrap_or(p).display();
        let Ok(text) = fs::read_to_string(p) else {
            errors.push(format!("Failed reading {rel}"));
            continue;
        };
        let style_eq_dq = concat!("style=", "\"");
        let style_eq_sq = concat!("style=", "'");
        let style_dot = concat!(".style", ".");
        if text.contains(style_eq_dq) || text.contains(style_eq_sq) {
            errors.push(format!(
                "CSP violation: inline style attribute found in {rel}"
            ));
        }
        if text.contains(style_dot) {
            errors.push(format!(
                "CSP violation: DOM .style. mutation found in {rel}"
            ));
        }
        if p.extension().and_then(|e| e.to_str()) == Some("ts") && text.contains("style =") {
            errors.push(format!(
                "CSP violation: inline style assignment found in {rel}"
            ));
        }

        let is_ts = p.extension().and_then(|e| e.to_str()) == Some("ts");
        for raw_pat in extract_pattern_attrs(&text) {
            let pat = if is_ts {
                raw_pat.replace("\\\\", "\\")
            } else {
                raw_pat.to_string()
            };
            if let Err(err) = validate_ecmascript_v_pattern(&pat) {
                errors.push(format!(
                    "Invalid ECMAScript /v pattern '{pat}' in {rel}: {err}"
                ));
            }
        }
    }

    // 2. Rust source security invariants
    let mut rs_files = Vec::new();
    collect_files_with_exts(&root.join("src"), &["rs"], &mut rs_files);
    let lock_unwrap = concat!(".lock()", ".unwrap()");
    let unsafe_inline = concat!("'unsafe-", "inline'");
    let unsafe_eval = concat!("'unsafe-", "eval'");
    let disallow_tok = concat!("Dis", "allow:");
    let rng_fn_a = concat!("thread_", "rng");
    let rng_fn_b = concat!("rand::", "random");
    let get_cookie_tok = concat!(".get(", "header::COOKIE)");
    let get_xff_tok = concat!(".get(\"x-forwarded-", "for\")");

    for p in &rs_files {
        checked_files += 1;
        let rel_path = p.strip_prefix(root).unwrap_or(p);
        let rel = rel_path.to_string_lossy().replace('\\', "/");
        let Ok(text) = fs::read_to_string(p) else {
            errors.push(format!("Failed reading {rel}"));
            continue;
        };
        let code_no_line_comments = strip_rust_comments(&text);

        if text.contains(lock_unwrap) {
            errors.push(format!("Poison-unsafe lock/unwrap found in {rel}"));
        }
        if text.contains(unsafe_inline) || text.contains(unsafe_eval) {
            errors.push(format!("Forbidden unsafe CSP directive found in {rel}"));
        }
        if text.contains(disallow_tok) {
            errors.push(format!(
                "Anti-recon violation: robots exclusion rule found in {rel}"
            ));
        }
        if code_no_line_comments.contains(rng_fn_a) || code_no_line_comments.contains(rng_fn_b) {
            errors.push(format!(
                "CSPRNG violation: non-OS RNG call detected in {rel}"
            ));
        }
        let gitleaks_bypass = concat!("gitleaks", ":allow");
        if text.contains(gitleaks_bypass) {
            errors.push(format!(
                "Secret-scanner bypass comment is forbidden in {rel}; construct synthetic test strings dynamically"
            ));
        }
        if text.contains("unicode(false)") {
            let rx_builder_tok = concat!("RegexBuilder", "::new");
            let neg_class_tok = concat!("[", "^");
            for (idx, line) in text.lines().enumerate() {
                if line.contains(rx_builder_tok) && line.contains(neg_class_tok) {
                    errors.push(format!(
                        "UTF-8 panic risk: negated character class with unicode(false) at {rel}:{}",
                        idx + 1
                    ));
                }
            }
        }
        if rel == "src/http/auth_routes.rs" && code_no_line_comments.contains(get_cookie_tok) {
            errors.push(format!(
                "HTTP/2 multi-header bug: use headers.get_all(header::COOKIE) in {rel}"
            ));
        }
        if rel == "src/security/headers.rs" {
            if code_no_line_comments.contains(get_xff_tok)
                || code_no_line_comments.contains(get_cookie_tok)
            {
                errors.push(format!(
                    "Multi-header parser bug: use headers.get_all(...) in {rel}"
                ));
            }
            if !text.contains("style-src-attr 'none'") {
                errors.push(format!(
                    "CSP invariant missing style-src-attr 'none' in {rel}"
                ));
            }
        }
        if matches!(
            rel.as_str(),
            "src/http/auth_routes.rs" | "src/storage/sqlite.rs" | "src/storage/postgres.rs"
        ) && !text.contains("seal_secret")
            && !text.contains("seal_webhook_secret")
        {
            errors.push(format!("AEAD invariant missing seal_secret call in {rel}"));
        }
    }

    // 3. PostgreSQL FORCE RLS + SQLite/PG audit_logs immutability invariants
    let pg_path = root.join("migrations/postgres/001_init_rls.sql");
    if let Ok(pg_raw) = fs::read_to_string(&pg_path) {
        checked_files += 1;
        let pg_sql = strip_sql_comments(&pg_raw);
        let bypass_tok = concat!("BYPASS", "RLS");
        if contains_word_ascii(&pg_sql, bypass_tok) {
            errors.push("Postgres security violation: literal BYPASSRLS token found".into());
        }
        let has_tenant_loop = pg_sql.contains("FOREACH tbl IN ARRAY tenant_tables");
        for (tbl_name, body) in extract_create_table_blocks(&pg_sql) {
            if body.contains("organization_id") || body.contains("target_org_id") {
                let explicit_enable =
                    pg_sql.contains(&format!("ALTER TABLE {tbl_name} ENABLE ROW LEVEL SECURITY"));
                let explicit_force =
                    pg_sql.contains(&format!("ALTER TABLE {tbl_name} FORCE ROW LEVEL SECURITY"));
                let in_array = has_tenant_loop && pg_sql.contains(&format!("'{tbl_name}'"));
                if !(in_array || (explicit_enable && explicit_force)) {
                    errors.push(format!(
                        "Table {tbl_name} has org scoping without ENABLE + FORCE RLS"
                    ));
                }
            }
        }
        for cap in [
            "dsn_key_lookup",
            "api_token_lookup",
            "session_lookup",
            "tunnel_lookup",
            "invitation_lookup",
            "mfa_challenges",
            "user_mfa",
            "user_mfa_recovery_codes",
            "webauthn_credentials",
            "webauthn_challenges",
        ] {
            if !pg_sql.contains(&format!("ALTER TABLE {cap} ENABLE ROW LEVEL SECURITY"))
                || !pg_sql.contains(&format!("ALTER TABLE {cap} FORCE ROW LEVEL SECURITY"))
            {
                errors.push(format!(
                    "Security/capability table {cap} missing explicit ENABLE + FORCE RLS"
                ));
            }
        }
        if !pg_sql.contains("REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM bugfinder_app") {
            errors.push(
                "Postgres security violation: audit_logs must revoke UPDATE, DELETE, TRUNCATE from bugfinder_app"
                    .into(),
            );
        }
        if !pg_sql.contains("trg_audit_logs_immutable_update")
            || !pg_sql.contains("trg_audit_logs_immutable_delete")
        {
            errors.push(
                "Postgres security violation: audit_logs missing append-only immutability triggers"
                    .into(),
            );
        }
    } else {
        errors.push("Missing migrations/postgres/001_init_rls.sql".into());
    }

    let sqlite_path = root.join("migrations/sqlite/001_init.sql");
    if let Ok(sq_raw) = fs::read_to_string(&sqlite_path) {
        checked_files += 1;
        let sq_sql = strip_sql_comments(&sq_raw);
        if !sq_sql.contains("trg_audit_logs_immutable_update")
            || !sq_sql.contains("trg_audit_logs_immutable_delete")
        {
            errors.push(
                "SQLite security violation: audit_logs missing append-only immutability triggers"
                    .into(),
            );
        }
    } else {
        errors.push("Missing migrations/sqlite/001_init.sql".into());
    }

    // 4. GitHub Actions SHA pinning (40-char commit SHA required)
    let wf_dir = root.join(".github/workflows");
    if wf_dir.is_dir() {
        let mut wf_files = Vec::new();
        collect_files_with_exts(&wf_dir, &["yml", "yaml"], &mut wf_files);
        for p in wf_files {
            checked_files += 1;
            let rel = p.strip_prefix(root).unwrap_or(&p).display();
            if let Ok(txt) = fs::read_to_string(&p) {
                for (idx, line) in txt.lines().enumerate() {
                    let trimmed = line.trim();
                    let cleaned = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
                    if let Some(after_uses) = cleaned.strip_prefix("uses:") {
                        let spec = after_uses.split('#').next().unwrap_or("").trim();
                        if spec.starts_with("./") {
                            continue;
                        }
                        let Some((_, ref_part)) = spec.split_once('@') else {
                            errors.push(format!(
                                "CI supply-chain violation: unpinned action '{spec}' in {rel}:{}",
                                idx + 1
                            ));
                            continue;
                        };
                        let sha = ref_part.trim();
                        let valid_sha = sha.len() == 40
                            && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                        if !valid_sha {
                            errors.push(format!(
                                "CI supply-chain violation: GitHub Action '{spec}' must pin a 40-char commit SHA in {rel}:{}",
                                idx + 1
                            ));
                        }
                    }
                }
            }
        }
    }

    // 5. Zero Python scripts invariant
    let mut py_files = Vec::new();
    collect_files_with_exts(root, &["py"], &mut py_files);
    for p in py_files {
        let rel = p.strip_prefix(root).unwrap_or(&p).display();
        errors.push(format!(
            "Zero-Python invariant violation: remove Python file {rel}"
        ));
    }

    // 6. Public repo path hygiene across docs/scripts/ui (no hardcoded /home/ developer paths)
    for sub in ["docs", "scripts", "ui/src", "sdks"] {
        let mut doc_files = Vec::new();
        collect_files_with_exts(
            &root.join(sub),
            &["md", "sh", "ts", "js", "html"],
            &mut doc_files,
        );
        for p in doc_files {
            checked_files += 1;
            if let Ok(txt) = fs::read_to_string(&p) {
                if txt.contains("/home/") || txt.contains("C:\\Users\\") {
                    let rel = p.strip_prefix(root).unwrap_or(&p).display();
                    errors.push(format!(
                        "Public hygiene violation: hardcoded local user path in {rel}"
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(checked_files)
    } else {
        Err(errors)
    }
}

pub fn run_lint_cli(root: &Path) -> u8 {
    let started = Instant::now();
    match run_lint(root) {
        Ok(count) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            println!(
                "[SECURITY-LINT PASS] 0 violations across {count} checked file(s) in {ms:.2} ms."
            );
            0
        }
        Err(errs) => {
            for e in &errs {
                eprintln!("[SECURITY-LINT FAIL] {e}");
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_minimal_clean_tree() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join("ui/src")).unwrap();
        fs::create_dir_all(r.join("src/http")).unwrap();
        fs::create_dir_all(r.join("src/security")).unwrap();
        fs::create_dir_all(r.join("src/storage")).unwrap();
        fs::create_dir_all(r.join("migrations/postgres")).unwrap();
        fs::create_dir_all(r.join("migrations/sqlite")).unwrap();
        fs::create_dir_all(r.join(".github/workflows")).unwrap();

        fs::write(
            r.join("ui/src/app.ts"),
            r#"const html = `<input pattern="[a-z0-9_\\-]{2,40}">`;"#,
        )
        .unwrap();
        fs::write(
            r.join("src/http/auth_routes.rs"),
            "pub fn f(h: &HeaderMap) { let _ = h.get_all(header::COOKIE); }\nfn s() { seal_secret(); }",
        )
        .unwrap();
        fs::write(
            r.join("src/security/headers.rs"),
            r#"pub fn f(h: &HeaderMap) { let _ = h.get_all(header::COOKIE); let _ = h.get_all("x-forwarded-for"); let _ = "style-src-attr 'none'"; }"#,
        )
        .unwrap();
        fs::write(r.join("src/storage/sqlite.rs"), "fn s() { seal_secret(); }").unwrap();
        fs::write(
            r.join("src/storage/postgres.rs"),
            "fn s() { seal_secret(); }",
        )
        .unwrap();

        let mut pg = String::from(
            "CREATE TABLE IF NOT EXISTS org_items (id BIGINT, organization_id BIGINT);\n\
             ALTER TABLE org_items ENABLE ROW LEVEL SECURITY;\n\
             ALTER TABLE org_items FORCE ROW LEVEL SECURITY;\n\
             REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM bugfinder_app;\n\
             trg_audit_logs_immutable_update trg_audit_logs_immutable_delete\n",
        );
        for cap in [
            "dsn_key_lookup",
            "api_token_lookup",
            "session_lookup",
            "tunnel_lookup",
            "invitation_lookup",
            "mfa_challenges",
            "user_mfa",
            "user_mfa_recovery_codes",
            "webauthn_credentials",
            "webauthn_challenges",
        ] {
            pg.push_str(&format!(
                "ALTER TABLE {cap} ENABLE ROW LEVEL SECURITY;\nALTER TABLE {cap} FORCE ROW LEVEL SECURITY;\n"
            ));
        }
        fs::write(r.join("migrations/postgres/001_init_rls.sql"), pg).unwrap();
        fs::write(
            r.join("migrations/sqlite/001_init.sql"),
            "CREATE TRIGGER trg_audit_logs_immutable_update BEGIN SELECT 1; END;\n\
             CREATE TRIGGER trg_audit_logs_immutable_delete BEGIN SELECT 1; END;\n",
        )
        .unwrap();
        fs::write(
            r.join(".github/workflows/ci.yml"),
            "steps:\n  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn clean_minimal_tree_passes_and_negative_mutations_fail() {
        let dir = write_minimal_clean_tree();
        assert!(run_lint(dir.path()).is_ok());

        // 1. Negative: ECMAScript /v invalid pattern escape \- outside [...]
        assert!(validate_ecmascript_v_pattern(r"a\-b").is_err());
        assert!(validate_ecmascript_v_pattern(r"[a-z/b]").is_err());
        assert!(validate_ecmascript_v_pattern(r"[a--z]").is_err());
        assert!(
            validate_ecmascript_v_pattern(r"^(@[A-Za-z][A-Za-z0-9_]{4,31}|-?[0-9]{5,20})$").is_ok()
        );
        assert!(validate_ecmascript_v_pattern(r"[a-z0-9_\-]{2,40}").is_ok());

        // 2. Negative: inline style in UI
        fs::write(dir.path().join("ui/src/bad.ts"), "el.style.color = 'red';").unwrap();
        let errs = run_lint(dir.path()).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("DOM .style. mutation")));
        let _ = fs::remove_file(dir.path().join("ui/src/bad.ts"));

        // 3. Negative: non-OS RNG in Rust source
        let bad_rng = concat!("fn bad() { rand::", "thread_", "rng(); }");
        fs::write(dir.path().join("src/bad_rng.rs"), bad_rng).unwrap();
        let errs = run_lint(dir.path()).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("CSPRNG violation")));
        let _ = fs::remove_file(dir.path().join("src/bad_rng.rs"));

        // 4. Negative: commented-out FORCE ROW LEVEL SECURITY bypass attempt
        let pg_path = dir.path().join("migrations/postgres/001_init_rls.sql");
        let orig_pg = fs::read_to_string(&pg_path).unwrap();
        let commented_pg = orig_pg.replace(
            "ALTER TABLE org_items FORCE ROW LEVEL SECURITY;",
            "-- ALTER TABLE org_items FORCE ROW LEVEL SECURITY;",
        );
        fs::write(&pg_path, commented_pg).unwrap();
        let errs = run_lint(dir.path()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.contains("org_items has org scoping without ENABLE + FORCE RLS")));
        fs::write(&pg_path, orig_pg).unwrap();

        // 5. Negative: unpinned GitHub Action tag
        let ci_path = dir.path().join(".github/workflows/ci.yml");
        fs::write(&ci_path, "steps:\n  - uses: actions/checkout@v4\n").unwrap();
        let errs = run_lint(dir.path()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.contains("must pin a 40-char commit SHA")));
        fs::write(
            &ci_path,
            "steps:\n  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        )
        .unwrap();

        // 6. Negative: leftover Python file
        fs::write(dir.path().join("helper.py"), "print('hi')").unwrap();
        let errs = run_lint(dir.path()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.contains("Zero-Python invariant violation")));
    }
}
