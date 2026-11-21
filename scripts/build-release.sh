#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/3] Building embedded UI bundle..."
pushd "$ROOT_DIR/ui" >/dev/null
if [[ ! -d node_modules ]]; then
  npm install --no-audit --no-fund
fi
npm run build
popd >/dev/null

if [[ ! -f "$ROOT_DIR/ui/dist/index.html" ]]; then
  echo "ERROR: ui/dist/index.html missing after frontend build" >&2
  exit 1
fi

echo "[2/3] Running security invariant linter..."
python3 "$ROOT_DIR/scripts/security-lint.py"

echo "[3/3] Building hardened single-binary Rust release with cargo-auditable..."
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
[[ -d "${CARGO_HOME_DIR}/bin" ]] && export PATH="${CARGO_HOME_DIR}/bin:${PATH}"

EXTRA_FLAGS=(
  "-C" "force-unwind-tables=no"
  "-C" "link-arg=-Wl,-z,pack-relative-relocs"
  "-C" "link-arg=-Wl,--as-needed"
  "--remap-path-prefix=${ROOT_DIR}=/src"
  "--remap-path-prefix=${CARGO_HOME_DIR}=/cargo"
  "--remap-path-prefix=${RUSTUP_HOME_DIR}=/rustup"
  "--remap-path-prefix=${HOME}=/build"
)
export RUSTFLAGS="${RUSTFLAGS:-} ${EXTRA_FLAGS[*]}"

if command -v cargo-auditable >/dev/null 2>&1; then
  cargo auditable build --release "$@"
else
  cargo build --release "$@"
fi

echo "Release binary built at: $ROOT_DIR/target/release/bugfinder"
ls -lh "$ROOT_DIR/target/release/bugfinder"
