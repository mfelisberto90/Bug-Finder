#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Bug-Finder End-to-End Verification Shell

Usage:
  ./scripts/check.sh [--url URL] [--dsn DSN] [--app-url APP_URL] [--org SLUG] [--project SLUG] [--token TOKEN] [--json]

Reads BUGFINDER_URL, BUGFINDER_PUBLIC_URL, BUGFINDER_DSN, BUGFINDER_APP_URL,
BUGFINDER_ORG, BUGFINDER_PROJECT, and BUGFINDER_TOKEN from .env or environment
when not passed as flags.
EOF
  exit 0
fi

# Safely load .env KEY=VALUE pairs without shell evaluation
if [[ -f "${ROOT_DIR}/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    if [[ "$line" =~ ^(BUGFINDER_[A-Z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="${val#\"}"
      val="${val%\"}"
      val="${val#\'}"
      val="${val%\'}"
      if [[ -z "${!key:-}" && -n "$val" ]]; then
        export "${key}=${val}"
      fi
    fi
  done < "${ROOT_DIR}/.env"
fi

if [[ -x "${ROOT_DIR}/target/release/bugfinder" ]]; then
  exec "${ROOT_DIR}/target/release/bugfinder" check "$@"
fi

if command -v bugfinder >/dev/null 2>&1; then
  exec bugfinder check "$@"
fi

if command -v cargo >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/Cargo.toml" ]]; then
  exec cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -- check "$@"
fi

# Pure POSIX/curl remote fallback when binary/cargo are not present
command -v curl >/dev/null 2>&1 || {
  echo "[FAIL] Neither bugfinder binary, cargo, nor curl is installed." >&2
  exit 1
}

URL="${BUGFINDER_URL:-${BUGFINDER_PUBLIC_URL:-http://127.0.0.1:8080}}"
DSN="${BUGFINDER_DSN:-}"
APP_URL="${BUGFINDER_APP_URL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      [[ $# -ge 2 ]] || { echo "[FAIL] --url requires a value" >&2; exit 1; }
      URL="$2"; shift 2 ;;
    --dsn)
      [[ $# -ge 2 ]] || { echo "[FAIL] --dsn requires a value" >&2; exit 1; }
      DSN="$2"; shift 2 ;;
    --app-url)
      [[ $# -ge 2 ]] || { echo "[FAIL] --app-url requires a value" >&2; exit 1; }
      APP_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done

FAILS=0
URL="${URL%/}"
DSN="${DSN%/}"
echo "Bug-Finder Fallback Curl Check Shell (server=${URL})"

if curl -fsS --max-time 3 "${URL}/api/health" >/dev/null && curl -fsS --max-time 3 "${URL}/llms.txt" >/dev/null; then
  echo "[PASS] Bug-Finder /api/health & /llms.txt reachable"
else
  echo "[FAIL] Bug-Finder /api/health or /llms.txt unreachable at ${URL}"
  FAILS=$((FAILS + 1))
fi

if [[ -n "$DSN" ]]; then
  if [[ "$DSN" =~ ^https?://([^@]+)@([^/]+)/([0-9]+)$ ]]; then
    KEY="${BASH_REMATCH[1]}"
    PID="${BASH_REMATCH[3]}"
    CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -X POST \
      -H 'Content-Type: text/plain;charset=utf-8' \
      -H 'X-BugFinder-Check: dry-probe' \
      --data $'{"sdk":{"name":"check.sh","version":"2.0.0"}}\n{"type":"event"}\n{"message":"dry-probe"}\n' \
      "${URL}/api/${PID}/envelope/?sentry_key=${KEY}" || echo 000)"
    if [[ "$CODE" == "200" ]]; then
      echo "[PASS] Envelope dry-probe HTTP 200 on project ${PID}"
    else
      echo "[FAIL] Envelope dry-probe returned HTTP ${CODE} on project ${PID}"
      FAILS=$((FAILS + 1))
    fi
  else
    echo "[FAIL] Malformed --dsn value"
    FAILS=$((FAILS + 1))
  fi
fi

if [[ -n "$APP_URL" ]]; then
  APP_URL="${APP_URL%/}"
  HTML="$(curl -fsS --max-time 3 "${APP_URL}" || true)"
  if [[ "$HTML" == *"/_obs/m.js"* || "$HTML" == *"bugfinder-mini.js"* ]]; then
    echo "[PASS] App HTML contains Bug-Finder SDK tag"
  else
    echo "[FAIL] App HTML missing /_obs/m.js or bugfinder-mini.js at ${APP_URL}"
    FAILS=$((FAILS + 1))
  fi
  ENV_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "${APP_URL}/.env" || echo 000)"
  if [[ "$ENV_CODE" == "403" || "$ENV_CODE" == "404" || "$ENV_CODE" == "429" ]]; then
    echo "[PASS] App Edge WAF blocked /.env with HTTP ${ENV_CODE}"
  else
    echo "[FAIL] App /.env returned HTTP ${ENV_CODE} (expected 403/404/429)"
    FAILS=$((FAILS + 1))
  fi
fi

exit "$FAILS"
