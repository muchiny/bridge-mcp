#!/usr/bin/env bash
# Bridge MCP binary bootstrap.
#
# Installs the `bridge-mcp` binary that the plugin drives. Strategy:
#   1. already on PATH        -> nothing to do
#   2. prebuilt release asset -> download + extract (fast, no Rust toolchain)
#   3. cargo install --git    -> build from source (fallback; needs Rust)
#
# Safe to re-run (idempotent). Installs to ~/.local/bin.
set -euo pipefail

REPO="muchiny/bridge-mcp"
BIN="bridge-mcp"
DEST="${HOME}/.local/bin"
# When set (e.g. auto-run from the SessionStart hook), never block on a
# multi-minute `cargo` build — print the manual command instead.
AUTO="${BRIDGE_MCP_BOOTSTRAP_AUTO:-}"

if command -v "${BIN}" >/dev/null 2>&1; then
  echo "✔ ${BIN} already installed: $("${BIN}" --version 2>/dev/null || echo present)"
  exit 0
fi

mkdir -p "${DEST}"

# Map the current platform to a release asset name.
os="$(uname -s)"
arch="$(uname -m)"
asset=""
case "${os}" in
  Linux)
    case "${arch}" in
      x86_64 | amd64) asset="${BIN}-linux-x86_64.tar.gz" ;;
      aarch64 | arm64) asset="${BIN}-linux-arm64.tar.gz" ;;
    esac
    ;;
  Darwin)
    case "${arch}" in
      arm64) asset="${BIN}-macos-arm64.tar.gz" ;;
    esac
    ;;
esac

install_prebuilt() {
  [ -n "${asset}" ] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  local url="https://github.com/${REPO}/releases/latest/download/${asset}"
  local tmp
  tmp="$(mktemp -d)"
  echo "↓ Downloading prebuilt binary: ${url}"
  if ! curl -fsSL "${url}" -o "${tmp}/bin.tar.gz"; then
    rm -rf "${tmp}"
    return 1
  fi
  # Verify the checksum when available (and sha256sum exists).
  if command -v sha256sum >/dev/null 2>&1 &&
    curl -fsSL "${url}.sha256" -o "${tmp}/bin.sha256" 2>/dev/null; then
    local want got
    want="$(awk '{print $1}' "${tmp}/bin.sha256")"
    got="$(sha256sum "${tmp}/bin.tar.gz" | awk '{print $1}')"
    if [ "${want}" != "${got}" ]; then
      echo "✗ checksum mismatch (expected ${want}, got ${got})"
      rm -rf "${tmp}"
      return 1
    fi
  fi
  tar -xzf "${tmp}/bin.tar.gz" -C "${tmp}"
  install -m 0755 "${tmp}/${BIN}" "${DEST}/${BIN}"
  rm -rf "${tmp}"
}

install_cargo() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "✗ No prebuilt for ${os}/${arch} and cargo is not installed."
    echo "  Install Rust (https://rustup.rs) or grab a binary from:"
    echo "  https://github.com/${REPO}/releases/latest"
    return 1
  fi
  echo "⚙ No prebuilt for ${os}/${arch}; building from source (a few minutes)…"
  cargo install --git "https://github.com/${REPO}" --features full
}

if install_prebuilt; then
  echo "✔ Installed ${BIN} -> ${DEST}/${BIN}"
elif [ -n "${AUTO}" ]; then
  # Auto mode (hook): no prebuilt for this platform — don't block on a build.
  echo "ℹ No prebuilt binary for ${os}/${arch}. Build it manually (needs Rust):"
  echo "  cargo install --git https://github.com/${REPO} --features full"
  exit 0
elif install_cargo; then
  echo "✔ Installed ${BIN} via cargo"
else
  echo "✗ bridge-mcp install failed. See https://github.com/${REPO}#install"
  exit 1
fi

case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) echo "⚠ ${DEST} is not on your PATH — add: export PATH=\"${DEST}:\$PATH\"" ;;
esac

"${DEST}/${BIN}" --version 2>/dev/null || "${BIN}" --version 2>/dev/null || true
