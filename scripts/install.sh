#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="bugfinder-install"
DEFAULT_REPO_SSH="${BUGFINDER_REPO:-git@github.com:mfelisberto90/Bug-Finder.git}"
DEFAULT_REPO_HTTPS="https://github.com/mfelisberto90/Bug-Finder.git"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  PREFIX="/usr/local/bin"
else
  PREFIX="${HOME}/.local/bin"
fi

DATA_DIR="${HOME}/.local/share/bugfinder"
CONFIG_DIR="${HOME}/.config/bugfinder"
BIND_ADDR="127.0.0.1:8080"
INSTALL_SERVICE=0
DOCKER_MODE=0
SKIP_BUILD=0
UNINSTALL_MODE=0
CHECK_ONLY=0

usage() {
  cat <<'EOF'
Bug-Finder One-Command Installer

Usage:
  ./scripts/install.sh [OPTIONS]

Options:
  --prefix DIR       Binary install directory (default: ~/.local/bin, or /usr/local/bin if root)
  --data-dir DIR     Persistent SQLite & crash data dir (default: ~/.local/share/bugfinder)
  --config-dir DIR   Env/config directory (default: ~/.config/bugfinder)
  --bind ADDR        Bind address for generated config (default: 127.0.0.1:8080)
  --service          Install, enable, and start systemd --user unit (bugfinder.service)
  --docker           Generate .env if missing and run docker compose up -d --build
  --skip-build       Skip building UI/Rust and install existing target/release/bugfinder
  --check            Verify local prerequisites and run diagnostics without installing
  --uninstall        Remove installed binary and user systemd unit (preserves data by default)
  --help, -h         Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -lt 2 ]] && { echo "Missing value for --prefix" >&2; exit 2; }
      PREFIX="$2"
      shift 2
      ;;
    --data-dir)
      [[ $# -lt 2 ]] && { echo "Missing value for --data-dir" >&2; exit 2; }
      DATA_DIR="$2"
      shift 2
      ;;
    --config-dir)
      [[ $# -lt 2 ]] && { echo "Missing value for --config-dir" >&2; exit 2; }
      CONFIG_DIR="$2"
      shift 2
      ;;
    --bind)
      [[ $# -lt 2 ]] && { echo "Missing value for --bind" >&2; exit 2; }
      BIND_ADDR="$2"
      shift 2
      ;;
    --service)
      INSTALL_SERVICE=1
      shift
      ;;
    --docker)
      DOCKER_MODE=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --uninstall)
      UNINSTALL_MODE=1
      shift
      ;;
    --check)
      CHECK_ONLY=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*"
}

fail_missing() {
  local tool="$1"
  local hint="$2"
  echo "ERROR: Required tool '$tool' is not installed." >&2
  echo "  Install hint: $hint" >&2
  exit 1
}

generate_app_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  elif [[ -r /dev/urandom ]]; then
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    printf '\n'
  else
    fail_missing "openssl or python3" "Install openssl or python3 to generate cryptographic BUGFINDER_APP_KEY."
  fi
}

write_secure_env_if_missing() {
  local env_path="$1"
  local target_data="$2"
  if [[ -f "$env_path" ]]; then
    chmod 600 "$env_path" || true
    log "Keeping existing config: $env_path"
    return 0
  fi

  local key_hex
  key_hex="$(generate_app_key | tr -d '\n\r')"
  mkdir -p "$(dirname "$env_path")"
  (
    umask 077
    cat > "$env_path" <<EOF
BUGFINDER_BIND=${BIND_ADDR}
BUGFINDER_DATA_DIR=${target_data}
BUGFINDER_APP_KEY=${key_hex}
BUGFINDER_MAX_DB_MB=512
BUGFINDER_RETENTION_DAYS=30
EOF
  )
  chmod 600 "$env_path"
  log "Generated locked-down config (0600): $env_path"
}

if [[ "$UNINSTALL_MODE" -eq 1 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now bugfinder.service 2>/dev/null || true
    rm -f "${HOME}/.config/systemd/user/bugfinder.service"
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  rm -f "${PREFIX}/bugfinder"
  log "Removed ${PREFIX}/bugfinder and user systemd service (data kept in ${DATA_DIR})."
  exit 0
fi

# Locate source directory or clone if invoked standalone
REPO_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  CANDIDATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [[ -f "${CANDIDATE_ROOT}/Cargo.toml" && -f "${CANDIDATE_ROOT}/scripts/build-release.sh" ]]; then
    REPO_DIR="$CANDIDATE_ROOT"
  fi
fi

if [[ -z "$REPO_DIR" ]]; then
  if [[ -f "$(pwd)/Cargo.toml" && -f "$(pwd)/scripts/build-release.sh" ]]; then
    REPO_DIR="$(pwd)"
  else
    command -v git >/dev/null 2>&1 || fail_missing "git" "sudo apt-get install -y git"
    REPO_DIR="${DATA_DIR}/src"
    mkdir -p "$(dirname "$REPO_DIR")"
    if [[ -d "${REPO_DIR}/.git" ]]; then
      log "Updating existing source checkout in ${REPO_DIR}..."
      git -C "$REPO_DIR" pull --ff-only
    else
      log "Cloning Bug-Finder repository into ${REPO_DIR}..."
      if ! git clone --depth 1 "$DEFAULT_REPO_SSH" "$REPO_DIR" 2>/dev/null; then
        git clone --depth 1 "$DEFAULT_REPO_HTTPS" "$REPO_DIR"
      fi
    fi
  fi
fi

cd "$REPO_DIR"

if [[ "$DOCKER_MODE" -eq 1 ]]; then
  command -v docker >/dev/null 2>&1 || fail_missing "docker" "Install Docker Engine & Compose plugin (https://docs.docker.com/engine/install/)"
  docker compose version >/dev/null 2>&1 || fail_missing "docker compose" "Install docker-compose-plugin"

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log "[OK] Docker & docker compose found in ${REPO_DIR}."
    exit 0
  fi

  write_secure_env_if_missing "${REPO_DIR}/.env" "/data"
  log "Starting Bug-Finder via Docker Compose..."
  docker compose up -d --build
  log "Container running. Check status with: docker compose ps && curl -fsS http://${BIND_ADDR}/api/health"
  exit 0
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  [[ -d "${HOME}/.cargo/bin" ]] && export PATH="${HOME}/.cargo/bin:${PATH}"
  command -v cargo >/dev/null 2>&1 || fail_missing "cargo (Rust toolchain)" "curl https://sh.rustup.rs -sSf | sh"
  command -v node >/dev/null 2>&1 || fail_missing "node" "Install Node.js 20+ (e.g. nvm install --lts)"
  command -v npm >/dev/null 2>&1 || fail_missing "npm" "Install Node.js + npm"
  command -v python3 >/dev/null 2>&1 || fail_missing "python3" "sudo apt-get install -y python3"
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  log "[OK] Prerequisites verified for native install in ${REPO_DIR}."
  if [[ -x "${PREFIX}/bugfinder" ]]; then
    "${PREFIX}/bugfinder" doctor --data "$DATA_DIR"
  elif [[ -x "${REPO_DIR}/target/release/bugfinder" ]]; then
    "${REPO_DIR}/target/release/bugfinder" doctor --data "$DATA_DIR"
  fi
  exit 0
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  log "Building hardened Bug-Finder release binary + embedded SPA..."
  "${REPO_DIR}/scripts/build-release.sh"
fi

RELEASE_BIN="${REPO_DIR}/target/release/bugfinder"
if [[ ! -x "$RELEASE_BIN" ]]; then
  echo "ERROR: Expected release binary at ${RELEASE_BIN}, run without --skip-build first." >&2
  exit 1
fi

mkdir -p "$PREFIX" "$DATA_DIR" "$CONFIG_DIR"
chmod 700 "$DATA_DIR" "$CONFIG_DIR" || true

install -m 0755 "$RELEASE_BIN" "${PREFIX}/bugfinder"
log "Installed binary: ${PREFIX}/bugfinder"

ENV_FILE="${CONFIG_DIR}/bugfinder.env"
write_secure_env_if_missing "$ENV_FILE" "$DATA_DIR"

if [[ "$INSTALL_SERVICE" -eq 1 ]]; then
  SYSTEMD_DIR="${HOME}/.config/systemd/user"
  UNIT_FILE="${SYSTEMD_DIR}/bugfinder.service"
  mkdir -p "$SYSTEMD_DIR"
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Bug-Finder Error Tracking & Logs Service
After=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${PREFIX}/bugfinder --headless
Restart=on-failure
RestartSec=3
MemoryMax=64M
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF
  if command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null; then
    systemctl --user enable --now bugfinder.service
    log "systemd --user service active: bugfinder.service"
  else
    log "Wrote unit file ${UNIT_FILE}; run 'systemctl --user daemon-reload && systemctl --user enable --now bugfinder.service' in a user session."
  fi
fi

log "Running self-diagnostics (bugfinder doctor)..."
"${PREFIX}/bugfinder" doctor --data "$DATA_DIR"

echo ""
echo "Installation complete!"
echo "  Binary: ${PREFIX}/bugfinder"
echo "  Data:   ${DATA_DIR}"
echo "  Config: ${ENV_FILE}"
echo "  Start:  ${PREFIX}/bugfinder --headless --bind ${BIND_ADDR} --data ${DATA_DIR}"
echo "  App UI: ${PREFIX}/bugfinder --app --data ${DATA_DIR}"
if [[ ":${PATH}:" != *":${PREFIX}:"* ]]; then
  echo "  Note:   Add ${PREFIX} to your PATH: export PATH=\"${PREFIX}:\$PATH\""
fi
