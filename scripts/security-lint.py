#!/usr/bin/env python3
"""CI Security Invariant Linter for Bug-Finder (Enterprise Security Blueprint)."""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def check_files() -> list[str]:
    errors: list[str] = []

    # 1. Zero inline styles or element.style.* mutations in ui/src & ui/index.html
    ui_files = list((ROOT / "ui").rglob("*.ts")) + list((ROOT / "ui").rglob("*.html"))
    for p in ui_files:
        if "node_modules" in p.parts or "dist" in p.parts:
            continue
        text = p.read_text(encoding="utf-8")
        if 'style="' in text or "style='" in text:
            errors.append(f"CSP violation: inline style attribute found in {p.relative_to(ROOT)}")
        if ".style." in text:
            errors.append(f"CSP violation: DOM .style. mutation found in {p.relative_to(ROOT)}")

        # Validate HTML <input pattern="..."> under ECMAScript /v (unicodeSets)
        for m in re.finditer(r'pattern="([^"]+)"', text):
            raw_pat = m.group(1)
            pat = raw_pat.replace("\\\\", "\\") if p.suffix == ".ts" else raw_pat
            res = subprocess.run(
                ["node", "-e", "new RegExp('^(?:' + process.argv[1] + ')$', 'v')", pat],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                errors.append(f"Invalid ECMAScript /v pattern '{pat}' in {p.relative_to(ROOT)}: {res.stderr.strip()}")

    # 2. Rust source security invariants
    for p in (ROOT / "src").rglob("*.rs"):
        text = p.read_text(encoding="utf-8")
        rel = p.relative_to(ROOT)

        if ".lock().unwrap()" in text:
            errors.append(f"Poison-unsafe .lock().unwrap() found in {rel}")
        if "'unsafe-inline'" in text or "'unsafe-eval'" in text:
            errors.append(f"Forbidden unsafe CSP directive found in {rel}")
        if "Disallow:" in text:
            errors.append(f"Anti-recon violation: Disallow: found in {rel}")

        # Ensure unicode(false) regexes never contain [^...] negated classes
        if "unicode(false)" in text:
            for line_no, line in enumerate(text.splitlines(), 1):
                if "RegexBuilder::new" in line and "[^" in line:
                    errors.append(f"UTF-8 panic risk: negated class [^ with unicode(false) at {rel}:{line_no}")

    # 3. PostgreSQL FORCE RLS + zero BYPASSRLS invariants
    pg_sql = (ROOT / "migrations" / "postgres" / "001_init_rls.sql").read_text(encoding="utf-8")
    if "BYPASSRLS" in pg_sql and "NOBYPASSRLS" not in pg_sql:
        errors.append("Postgres security violation: BYPASSRLS must never be granted")
    if re.search(r"\bBYPASSRLS\b", pg_sql):
        errors.append("Postgres security violation: literal BYPASSRLS token found")

    # Verify every table with organization_id has ENABLE + FORCE ROW LEVEL SECURITY
    cap_tables = (
        "dsn_key_lookup",
        "api_token_lookup",
        "session_lookup",
        "tunnel_lookup",
        "invitation_lookup",
    )
    create_blocks = re.findall(
        r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\);", pg_sql, flags=re.DOTALL
    )
    for tbl_name, body in create_blocks:
        if "organization_id" in body:
            explicit_enable = f"ALTER TABLE {tbl_name} ENABLE ROW LEVEL SECURITY" in pg_sql
            explicit_force = f"ALTER TABLE {tbl_name} FORCE ROW LEVEL SECURITY" in pg_sql
            in_array = f"'{tbl_name}'" in pg_sql and "FOREACH tbl IN ARRAY tenant_tables" in pg_sql
            if not (in_array or (explicit_enable and explicit_force)):
                errors.append(f"Table {tbl_name} has organization_id without ENABLE + FORCE RLS")
    for cap in cap_tables:
        if f"ALTER TABLE {cap} ENABLE ROW LEVEL SECURITY" not in pg_sql or f"ALTER TABLE {cap} FORCE ROW LEVEL SECURITY" not in pg_sql:
            errors.append(f"Capability lookup table {cap} missing explicit ENABLE + FORCE RLS")

    # Verify AEAD encryption at rest invariant (seal_secret used in MFA & persistence)
    for req_file in ("src/http/auth_routes.rs", "src/storage/sqlite.rs", "src/storage/postgres.rs"):
        fpath = ROOT / req_file
        if fpath.exists():
            txt = fpath.read_text(encoding="utf-8", errors="ignore")
            if "seal_secret" not in txt:
                errors.append(f"AEAD invariant missing seal_secret call in {req_file}")

    # Verify zero inline styles in frontend TS sources
    ui_dir = ROOT / "ui" / "src"
    if ui_dir.is_dir():
        for ts_file in ui_dir.glob("*.ts"):
            txt = ts_file.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'style\s*=|\.style\.', txt):
                errors.append(f"CSP inline style violation found in ui/src/{ts_file.name}")

    return errors


if __name__ == "__main__":
    found = check_files()
    if found:
        for err in found:
            print(f"[SECURITY-LINT FAIL] {err}", file=sys.stderr)
        sys.exit(1)
    print("[SECURITY-LINT PASS] 0 security invariant violations found.")
