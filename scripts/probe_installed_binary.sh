#!/usr/bin/env bash
# Behavioural fingerprint probes for an installed bridge-mcp binary.
#
# `bridge-mcp --version` CANNOT answer "is this binary current?": it prints
# CARGO_PKG_VERSION (src/mcp/protocol.rs:897), which is identical for every
# build of a given release. The binary installed on 2026-08-02 printed
# "bridge-mcp 1.20.0"; every build of the current 2.2.0 tree prints
# "bridge-mcp 2.2.0", whether it is the cut commit or twenty commits later.
# These probes exercise behaviour that only exists after specific commits, so
# a stale binary cannot pass them.
#
# Usage: scripts/probe_installed_binary.sh [path-to-binary]
set -uo pipefail

BIN="${1:-$HOME/.local/bin/bridge-mcp}"
fail=0

if [ ! -x "$BIN" ]; then
    echo "probe: no executable at $BIN" >&2
    exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# --- Probes 1 and 2: ssh_upload schema -------------------------------------
# Uses the operator's real config (default path) because describe-tool only
# resolves tools whose group is enabled; file_transfer is enabled there.
schema="$("$BIN" --json describe-tool ssh_upload 2>/dev/null)"

# Probe 1 — chunk_size clamp bounds (src/mcp/tool_handlers/ssh_upload.rs:67-68).
if printf '%s' "$schema" | grep -q '"minimum": *4096'; then
    echo "probe 1 (ssh_upload chunk_size minimum 4096): PASS"
else
    echo "probe 1 (ssh_upload chunk_size minimum 4096): FAIL - binary predates the chunk_size clamp"
    fail=1
fi

# Probe 2 — verify_checksum wording (src/mcp/tool_handlers/ssh_upload.rs:74).
if printf '%s' "$schema" | grep -q 'This is not a verification'; then
    echo "probe 2 (ssh_upload verify_checksum wording): PASS"
else
    echo "probe 2 (ssh_upload verify_checksum wording): FAIL - binary still claims verify_checksum verifies"
    fail=1
fi

# --- Probe 3: rbac.enabled must be rejected at config load -----------------
# src/config/loader.rs:226-235
cfg="$tmpdir/rbac_probe.yaml"
cat > "$cfg" <<'YAML'
hosts:
  probe:
    hostname: 127.0.0.1
    user: probe
    auth:
      type: agent
rbac:
  enabled: true
YAML
# The loader refuses any config readable by group/other (max 0640).
chmod 600 "$cfg"

if "$BIN" --config "$cfg" validate > "$tmpdir/rbac.out" 2>&1; then
    echo "probe 3 (rbac.enabled rejected): FAIL - config loaded, binary predates the rejection"
    fail=1
elif grep -q 'rbac.enabled' "$tmpdir/rbac.out"; then
    echo "probe 3 (rbac.enabled rejected): PASS"
else
    echo "probe 3 (rbac.enabled rejected): FAIL - load failed for an unrelated reason:"
    cat "$tmpdir/rbac.out"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "all probes passed: $BIN carries the 2.2.0 behaviour"
else
    echo "STALE BINARY at $BIN - rebuild with: CARGO_BUILD_JOBS=2 make install" >&2
fi
exit "$fail"
