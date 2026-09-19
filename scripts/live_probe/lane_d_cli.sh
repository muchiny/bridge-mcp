#!/usr/bin/env bash
# Lane D — CLI/HTTP driver for P6b (concurrency, CLI half), P7 (non-tool CLI
# surface) and P8 (daemon). P1-P6a live in lane_d_proto.py against one long
# BIN serve. See task-6-brief.md for the exact case table this implements.
#
# Usage: lane_d_cli.sh BIN HOST SBX D_DIR [--only p6b,p7,p8]
set -u
BIN="$1"; HOST="$2"; SBX="$3"; D="$4"; shift 4
ONLY="p6b,p7,p8"
if [ "${1:-}" = "--only" ]; then ONLY="$2"; fi

mkdir -p "$D"
PASS=0; FAIL=0; NOTES=0
declare -a RESULTS

record() {
  local id="$1" verdict="$2" detail="$3"
  RESULTS+=("$id|$verdict|$detail")
  echo "$id $verdict — ${detail:0:200}"
  case "$verdict" in
    PASS) PASS=$((PASS+1));;
    FAIL) FAIL=$((FAIL+1));;
    NOTE) NOTES=$((NOTES+1));;
  esac
}

has() { [ "${ONLY/,/}" != "${ONLY/$1/}" ] || [[ ",$ONLY," == *",$1,"* ]]; }
run_lane() { [[ ",$ONLY," == *",$1,"* ]]; }

# =========================== P6b — concurrency, CLI half ===========================
if run_lane p6b; then
  echo "=== P6b — concurrency (CLI half) ==="
  start=$(date +%s)
  for i in $(seq 6); do
    ( RUST_LOG=error "$BIN" tool ssh_pty_exec host="$HOST" command="sleep 6" >/dev/null 2>&1 ) &
  done
  wait
  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge 6 ] && [ "$elapsed" -le 9 ]; then v=PASS; else v=FAIL; fi
  record "P6-06" "$v" "6 concurrent CLI processes, elapsed=${elapsed}s (expect 6-9s, never ~12s)"
  record "P6-07" "NOTE" "MCP half: 5 commands gated by max_concurrent_commands=5 (see P6-02/03 in lane_d_proto.py output), 6th waits >3s. CLI half: elapsed=${elapsed}s -- each CLI invocation is its own process/own semaphore, so max_concurrent_commands does NOT apply across processes. Both halves of the sentence measured, not cited."
fi

# =========================== P7 — non-tool CLI surface ===========================
if run_lane p7; then
  echo "=== P7 — non-tool CLI surface ==="

  # P7-01: serve starts/stops cleanly on EOF
  printf '' | RUST_LOG=error "$BIN" serve </dev/null >"$D/P7-01.out" 2>"$D/P7-01.err"
  rc=$?
  if [ "$rc" -eq 0 ] && [ ! -s "$D/P7-01.out" ]; then v=PASS; else v=FAIL; fi
  record "P7-01" "$v" "serve on empty stdin -> rc=$rc stdout_bytes=$(wc -c <"$D/P7-01.out")"

  # P7-02..P7-08: serve-http
  # DISCOVERED CONTRACT, not in the brief's table: EVERY request (including
  # GET /health) is also gated by an anti-DNS-rebinding Origin-header guard
  # (origin_guard, src/mcp/transport/http.rs:136-155), independent of the
  # three Modern MCP headers the brief describes. Loopback bind does NOT
  # exempt requests from this guard -- it only removes the need for
  # `--insecure-bind`. A bare curl (no Origin header) gets 403 "Missing
  # Origin header (anti-DNS-rebinding)" on every route, /health included.
  # default_allowed_origins() (http.rs:65-73) accepts http(s)://localhost,
  # 127.0.0.1 or [::1] with an optional :<port> suffix, so all P7-02..07
  # calls carry -H 'Origin: http://127.0.0.1:18080'.
  ORIGIN='http://127.0.0.1:18080'
  RUST_LOG=error "$BIN" serve-http --bind 127.0.0.1:18080 >"$D/P7-http.log" 2>&1 &
  HTTP_PID=$!
  sleep 1
  health=$(curl -sf http://127.0.0.1:18080/health -H "Origin: $ORIGIN" 2>/dev/null)
  if [ "$health" = '{"status":"ok"}' ]; then v=PASS; else v=FAIL; fi
  record "P7-02" "$v" "GET /health (with Origin) -> ${health:-<no response>}"

  code_405=$(curl -s -o /dev/null -w '%{http_code}' -X GET http://127.0.0.1:18080/mcp -H "Origin: $ORIGIN")
  allow_hdr=$(curl -s -D - -o /dev/null -X GET http://127.0.0.1:18080/mcp -H "Origin: $ORIGIN" | grep -i '^allow:')
  if [ "$code_405" = "405" ] && [ -n "$allow_hdr" ]; then v=PASS; else v=FAIL; fi
  record "P7-03" "$v" "GET /mcp -> $code_405, Allow: ${allow_hdr:-<absent>}"

  META_BODY='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
  resp=$(curl -s -w '\n%{http_code}' -X POST http://127.0.0.1:18080/mcp -H 'content-type: application/json' -H "Origin: $ORIGIN" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META_BODY}}")
  code=$(echo "$resp" | tail -1); body=$(echo "$resp" | sed '$d')
  if [ "$code" = "400" ] && echo "$body" | grep -q '\-32020' && echo "$body" | grep -q 'MCP-Protocol-Version'; then v=PASS; else v=FAIL; fi
  record "P7-04" "$v" "POST /mcp no MCP headers (Origin present) -> $code $body"

  resp=$(curl -s -w '\n%{http_code}' -X POST http://127.0.0.1:18080/mcp -H 'content-type: application/json' -H "Origin: $ORIGIN" \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/list' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META_BODY}}")
  code=$(echo "$resp" | tail -1); body=$(echo "$resp" | sed '$d')
  ntools=$(echo "$body" | grep -o 'mcp_[a-z_]*' | sort -u | wc -l)
  if [ "$code" = "200" ] && [ "$ntools" -eq 4 ]; then v=PASS; else v=FAIL; fi
  record "P7-05" "$v" "POST /mcp correct headers -> $code, distinct mcp_* names=$ntools"

  resp=$(curl -s -w '\n%{http_code}' -X POST http://127.0.0.1:18080/mcp -H 'content-type: application/json' -H "Origin: $ORIGIN" \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: prompts/list' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META_BODY}}")
  code=$(echo "$resp" | tail -1); body=$(echo "$resp" | sed '$d')
  if [ "$code" = "400" ] && echo "$body" | grep -q '\-32020' && echo "$body" | grep -q "does not match the body's method"; then v=PASS; else v=FAIL; fi
  record "P7-06" "$v" "Mcp-Method disagrees with body -> $code $body"

  wk=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/.well-known/mcp.json -H "Origin: $ORIGIN")
  if [ "$wk" = "200" ]; then v=PASS; else v=FAIL; fi
  record "P7-07" "$v" "/.well-known/mcp.json -> $wk"

  kill "$HTTP_PID" 2>/dev/null
  wait "$HTTP_PID" 2>/dev/null
  sleep 1
  residual=$(pgrep -f "serve-http" || true)
  port_free=$(ss -ltn 2>/dev/null | grep -c ':18080' || true)
  if [ -z "$residual" ] && [ "${port_free:-0}" -eq 0 ]; then v=PASS; else v=FAIL; fi
  record "P7-08" "$v" "after kill: residual_pids='${residual:-none}' port18080_listeners=${port_free:-0}"

  # P7-09..P7-14: exec
  RUST_LOG=error "$BIN" exec "$HOST" "true" </dev/null >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then v=PASS; else v=FAIL; fi
  record "P7-09" "$v" "exec true -> rc=$rc"

  RUST_LOG=error "$BIN" exec "$HOST" "exit 7" </dev/null >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 1 ]; then v=PASS; else v=FAIL; fi
  record "P7-10" "$v" "exec 'exit 7' -> rc=$rc (expect 1, run_exec propagates remote failure)"

  out=$(RUST_LOG=error "$BIN" exec "$HOST" "true" --json </dev/null 2>&1)
  if echo "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then v=PASS; else v=FAIL; fi
  record "P7-11" "$v" "exec --json -> valid_json=$?"

  out=$(RUST_LOG=error "$BIN" --dry-run exec "$HOST" "true" </dev/null 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ] && echo "$out" | grep -q "Would execute on host '$HOST': true" && echo "$out" | grep -q '\[dry-run\] Timeout: 120s'; then v=PASS; else v=FAIL; fi
  record "P7-12" "$v" "--dry-run exec -> rc=$rc out=${out:0:150}"

  off_before=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  RUST_LOG=error "$BIN" exec "$HOST" "true" </dev/null >/dev/null 2>&1
  off_after=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  new_lines=$(tail -n $((off_after - off_before)) /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null)
  if echo "$new_lines" | grep -q '"event_type":"ssh_exec"'; then v=PASS; else v=FAIL; fi
  record "P7-13" "$v" "exec is audited -> new_lines_with_ssh_exec=$(echo "$new_lines" | grep -c '"event_type":"ssh_exec"')"

  RUST_LOG=error "$BIN" exec "$HOST" "true" </dev/null >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then v=PASS; else v=FAIL; fi
  record "P7-14" "$v" "exec bypasses NO destructive gate (rc=$rc, no prompt, no --yes) -- discovered-contract asymmetry vs ssh_exec tool (see P7-23)"

  # P7-15..P7-18
  out=$(RUST_LOG=error "$BIN" status </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && echo "$out" | grep -qi "Permissive" && [ "$(echo "$out" | grep -c 'raspberry\|win2012\|win2025')" -ge 1 ]; then v=PASS; else v=FAIL; fi
  record "P7-15" "$v" "status -> rc=$rc"

  out=$(RUST_LOG=error "$BIN" status --json </dev/null 2>&1)
  if echo "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then v=PASS; else v=FAIL; fi
  record "P7-16" "$v" "status --json valid"

  out=$(RUST_LOG=error "$BIN" history --limit 20 </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && echo "$out" | grep -q "No command history available." && echo "$out" | grep -q "only available during a CLI session"; then v=PASS; else v=FAIL; fi
  record "P7-17" "$v" "history (no daemon) -> $out"

  out=$(RUST_LOG=error "$BIN" history --limit 20 --json </dev/null 2>&1)
  if echo "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then v=PASS; else v=FAIL; fi
  record "P7-18" "$v" "history --json -> $out"

  # P7-19..P7-22: upload/download in $SBX
  printf lane-d-upload > "$D/lane-d-up.txt"
  RUST_LOG=error "$BIN" upload "$HOST" "$D/lane-d-up.txt" "$SBX/lane-d-up.txt" </dev/null >"$D/P7-19.out" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then v=PASS; else v=FAIL; fi
  record "P7-19" "$v" "upload -> rc=$rc $(cat "$D/P7-19.out" | head -c150)"

  RUST_LOG=error "$BIN" download "$HOST" "$SBX/lane-d-up.txt" "$D/lane-d-down.txt" </dev/null >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && cmp -s "$D/lane-d-up.txt" "$D/lane-d-down.txt"; then v=PASS; else v=FAIL; fi
  record "P7-20" "$v" "download roundtrip -> rc=$rc identical=$(cmp -s "$D/lane-d-up.txt" "$D/lane-d-down.txt" && echo yes || echo no)"

  RUST_LOG=error "$BIN" upload "$HOST" "$D/lane-d-up.txt" "$SBX/lane-d-up.txt" --mode fail-if-exists </dev/null >"$D/P7-21.out" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] && grep -qi "exist" "$D/P7-21.out"; then v=PASS; else v=FAIL; fi
  record "P7-21" "$v" "upload fail-if-exists on existing target -> rc=$rc $(cat "$D/P7-21.out" | head -c150)"

  RUST_LOG=error "$BIN" upload "$HOST" "$D/lane-d-up.txt" "$SBX/lane-d-up2.txt" --verify-checksum </dev/null >"$D/P7-22.out" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && grep -qE '[0-9a-f]{64}' "$D/P7-22.out"; then v=PASS; else v=FAIL; fi
  record "P7-22" "$v" "upload --verify-checksum prints sha256 -> rc=$rc $(cat "$D/P7-22.out" | head -c150)"

  # P7-23..P7-27: destructive gate (tool ssh_exec)
  out=$(RUST_LOG=error "$BIN" tool ssh_exec host="$HOST" command=true </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 4 ] && echo "$out" | grep -q "is annotated destructive and stdin is not a terminal"; then v=PASS; else v=FAIL; fi
  record "P7-23" "$v" "tool ssh_exec no --yes, no tty -> rc=$rc $(echo "$out" | head -c150)"

  # CASE edit (§3.8 category 1, harness-only substitution, property
  # unchanged: "the TTY branch of the destructive gate, answered 'n'"). The
  # brief's own driver is `script -qec ... /dev/null`; `script` (bsdutils)
  # is not installed on THIS bridge/WSL host (an ENV gap on the harness
  # machine, not the Pi) -- neither is `unbuffer`. Python's stdlib `pty`
  # module allocates a real pty and is always available, so it stands in
  # for `script` with the same effect: a real TTY on stdin, 'n\n' written
  # to it after the prompt appears.
  out=$(timeout 15 python3 -c "
import pty, os, time
pid, fd = pty.fork()
if pid == 0:
    os.environ['RUST_LOG'] = 'error'
    os.execvp('$BIN', ['$BIN', 'tool', 'ssh_exec', 'host=$HOST', 'command=true'])
else:
    time.sleep(0.5)
    os.write(fd, b'n\n')
    out = b''
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    print(out.decode(errors='replace'))
    raise SystemExit(rc)
" 2>&1); rc=$?
  if [ "$rc" -eq 4 ] && echo "$out" | grep -q "DESTRUCTIVE: ssh_exec" && echo "$out" | grep -q "was not confirmed"; then v=PASS; else v=FAIL; fi
  record "P7-24" "$v" "TTY branch (pty.fork, script(1) absent on this host), negative answer -> rc=$rc $(echo "$out" | tr -d '\r' | head -c200)"

  off_before=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  out=$(RUST_LOG=error "$BIN" --yes tool ssh_exec host="$HOST" command="echo lane-d-yes" </dev/null 2>&1); rc=$?
  off_after=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  new_lines=$(tail -n $((off_after - off_before)) /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null)
  if [ "$rc" -eq 0 ] && echo "$out" | grep -q "lane-d-yes" && echo "$new_lines" | grep -q '"event_type":"ssh_exec"'; then v=PASS; else v=FAIL; fi
  record "P7-25" "$v" "--yes tool ssh_exec -> rc=$rc out=${out:0:80} audited=$(echo "$new_lines" | grep -c '"event_type":"ssh_exec"')"

  if echo "$new_lines" | grep -qi -- '--yes\|confirmed by'; then v=FAIL; else v=PASS; fi
  record "P7-26" "$v" "audit delta around P7-25 has NO --yes/confirmed-by trace (contract contradicted: --yes help claims it records the choice, confirm_destructive only tracing::warn!s to stderr) -- delta_lines_checked=$(echo "$new_lines" | wc -l)"

  off_before=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  out=$(RUST_LOG=error "$BIN" --yes tool ssh_exec host="$HOST" command="rm -rf $SBX/blacklist-probe" </dev/null 2>&1); rc=$?
  off_after=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null || echo 0)
  new_lines=$(tail -n $((off_after - off_before)) /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null)
  if [ "$rc" -eq 4 ] && echo "$new_lines" | grep -q '"event_type":"command_denied"'; then v=PASS; else v=FAIL; fi
  record "P7-27" "$v" "--yes then blacklist refuses anyway -> rc=$rc denied_lines=$(echo "$new_lines" | grep -c '"event_type":"command_denied"')"

  # P7-28/29: completions
  out=$(RUST_LOG=error "$BIN" completions bash 2>&1 | head -1); rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ] && [ -n "$out" ]; then v=PASS; else v=FAIL; fi
  record "P7-28" "$v" "completions bash -> rc=$rc first_line=${out:0:60}"

  ok29=1
  for shell in zsh fish; do
    out=$(RUST_LOG=error "$BIN" completions "$shell" 2>&1 | head -1); rc=${PIPESTATUS[0]}
    [ "$rc" -eq 0 ] || ok29=0
  done
  if [ "$ok29" -eq 1 ]; then v=PASS; else v=FAIL; fi
  record "P7-29" "$v" "completions zsh & fish -> both rc=0: $([ "$ok29" -eq 1 ] && echo yes || echo no)"

  # P7-30..P7-38: exit code contract
  out=$(RUST_LOG=error "$BIN" validate </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && echo "$out" | grep -q "Hosts: 7" && echo "$out" | grep -q "Tools: 353" && echo "$out" | grep -qi "Permissive"; then v=PASS; else v=FAIL; fi
  record "P7-30" "$v" "validate -> rc=$rc (README documents 0)"

  RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path=/nexiste-pas-lane-d </dev/null >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 1 ]; then v=PASS; else v=FAIL; fi
  record "P7-31" "$v" "tool ssh_ls on nonexistent path -> rc=$rc (README documents 1: tool execution error)"

  out=$(RUST_LOG=error "$BIN" tool ssh_nexiste_pas_du_tout host="$HOST" </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 2 ] && echo "$out" | grep -qi "MCP unknown tool"; then v=PASS; else v=FAIL; fi
  record "P7-32" "$v" "unknown tool -> rc=$rc (README documents 2) $(echo "$out"|head -c100)"

  RUST_LOG=error "$BIN" tool ssh_ls host=pas-un-host path=/tmp </dev/null >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 3 ]; then v=PASS; else v=FAIL; fi
  record "P7-33" "$v" "unknown host -> rc=$rc (README documents 3)"

  RUST_LOG=error "$BIN" tool ssh_exec host="$HOST" command=true </dev/null >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 4 ]; then v=PASS; else v=FAIL; fi
  record "P7-34" "$v" "=P7-23, destructive denial -> rc=$rc (README documents 4)"

  out=$(RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" pas-un-kv </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 5 ] && echo "$out" | grep -q "Invalid argument 'pas-un-kv': expected key=value format"; then v=PASS; else v=FAIL; fi
  record "P7-35" "$v" "malformed positional arg -> rc=$rc (README documents 5) $(echo "$out"|head -c120)"

  # CASE edit (§3.8 category 1, verified via describe-tool): the brief's own
  # probe is `ssh_status limite=3`, but `describe-tool ssh_status` shows an
  # EMPTY Input Schema -- ssh_status takes NO parameters at all. Measured:
  # that exact command exits 0 and silently runs ssh_status, ignoring
  # `limite=3` entirely -- reject_unknown_args is never reached for a
  # zero-parameter tool, a further undocumented contract distinct from D3.
  # Substituting `ssh_ls ... bogus_arg=3` (a tool WITH declared parameters)
  # reproduces the property D3 actually names: an unknown argument on a tool
  # that HAS a schema to violate.
  out0=$(RUST_LOG=error "$BIN" tool ssh_status limite=3 </dev/null 2>&1); rc0=$?
  record "P7-36-zeroparam" "NOTE" "DISCOVERED CONTRACT: ssh_status has an EMPTY input schema (describe-tool confirms); limite=3 is silently ignored, rc=$rc0 (not rejected -- reject_unknown_args isn't reached for zero-param tools)"

  out=$(RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path=/tmp bogus_arg=3 </dev/null 2>&1); rc=$?
  record "P7-36" "NOTE" "three-way disagreement resolved by proof (on a tool WITH declared params): binary=rc$rc, README.md~762 says 2, CLAUDE.md says 5. Cause: reject_unknown_args returns McpInvalidRequest, unlisted in map_exit_code, falls to catch-all 1 (src/main.rs:301-310). out=${out:0:150}"
  if [ "$rc" -eq 1 ]; then v=PASS; else v=FAIL; fi
  record "P7-36-verify" "$v" "unknown tool argument on a real-schema tool -> rc=$rc (expected 1 per source read)"

  out=$(RUST_LOG=error "$BIN" describe-tool ssh_podman_ps </dev/null 2>&1); rc=$?
  if [ "$rc" -eq 1 ] && echo "$out" | grep -qi "MCP unknown tool: ssh_podman_ps"; then v=PASS; else v=FAIL; fi
  record "P7-37" "$v" "describe-tool on registered-but-disabled-group tool -> rc=$rc (differs from P7-32's rc=2 for the SAME underlying McpUnknownTool error -- map_exit_code only wired on the Tool arm) out=${out:0:150}"

  out1=$(RUST_LOG=error "$BIN" --config /nexiste-pas.yaml validate </dev/null 2>&1); rc1=$?
  out2=$(RUST_LOG=error "$BIN" --pas-un-flag </dev/null 2>&1); rc2=$?
  out3=$(RUST_LOG=error "$BIN" tool ssh_status --json-args '{invalide' </dev/null 2>&1); rc3=$?
  if [ "$rc1" -eq 1 ] && [ "$rc2" -eq 2 ] && [ "$rc3" -eq 5 ]; then v=PASS; else v=FAIL; fi
  record "P7-38" "$v" "three more error paths -> config_missing=$rc1(README says 5) clap_parse=$rc2 bad_json_args=$rc3"
fi

# =========================== P8 — daemon ===========================
if run_lane p8; then
  echo "=== P8 — daemon (exclusive) ==="
  SOCK="/run/user/1000/bridge-mcp.sock"
  if ls "${SOCK}"* >/dev/null 2>&1; then
    record "P8-BLOCK" "FAIL" "socket already present before P8 started -- ABANDONING P8, will not touch a daemon we do not own: $(ls "${SOCK}"* 2>&1)"
  else
    record "P8-01" "PASS" "no pre-existing daemon socket at $SOCK"

    out=$(RUST_LOG=error "$BIN" daemon status </dev/null 2>&1); rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -q "Daemon is not running." && echo "$out" | grep -q "Socket path: $SOCK"; then v=PASS; else v=FAIL; fi
    record "P8-02" "$v" "daemon status (stopped) -> rc=$rc $(echo "$out"|head -c150)"

    for i in 1 2 3; do RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path="$SBX" </dev/null >/dev/null 2>&1; done
    h=$(RUST_LOG=error "$BIN" tool ssh_health </dev/null 2>&1)
    if echo "$h" | grep -q "Total pooled connections: 0" && echo "$h" | grep -q "(no connections in pool)"; then v=PASS; else v=FAIL; fi
    record "P8-03" "$v" "no-daemon baseline: fresh process per call -> $(echo "$h"|head -c150)"

    times=()
    for i in $(seq 10); do
      t0=$(date +%s%N)
      RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path="$SBX" </dev/null >/dev/null 2>&1
      t1=$(date +%s%N)
      times+=($(( (t1-t0)/1000000 )))
    done
    sorted=($(printf '%s\n' "${times[@]}" | sort -n))
    T_SANS=${sorted[4]}
    record "P8-04" "NOTE" "T_sans (median of 10, no daemon) = ${T_SANS}ms, samples=${times[*]}"

    RUST_LOG=error "$BIN" daemon start >"$D/P8-daemon.log" 2>&1 &
    sleep 2
    out=$(RUST_LOG=error "$BIN" daemon status </dev/null 2>&1); rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -q "Daemon is running." && echo "$out" | grep -q "PID:" && echo "$out" | grep -q "Socket:"; then v=PASS; else v=FAIL; fi
    record "P8-05" "$v" "daemon start -> rc=$rc $(echo "$out"|head -c150)"

    for i in 1 2 3; do RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path="$SBX" </dev/null >/dev/null 2>&1; done
    h=$(RUST_LOG=error "$BIN" tool ssh_health </dev/null 2>&1)
    pooled_line=$(echo "$h" | grep -E "^\s*$HOST: [0-9]+ connection")
    if echo "$h" | grep -qv "Total pooled connections: 0" && [ -n "$pooled_line" ]; then v=PASS; else v=FAIL; fi
    record "P8-06" "$v" "pool reuse signal via ssh_health (daemon) -> $(echo "$h"|head -c250)"

    times2=()
    for i in $(seq 10); do
      t0=$(date +%s%N)
      RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path="$SBX" </dev/null >/dev/null 2>&1
      t1=$(date +%s%N)
      times2+=($(( (t1-t0)/1000000 )))
    done
    sorted2=($(printf '%s\n' "${times2[@]}" | sort -n))
    T_AVEC=${sorted2[4]}
    delta=$(( T_SANS - T_AVEC ))
    if [ "$delta" -ge 50 ]; then v=PASS; else v=FAIL; fi
    record "P8-07" "$v" "T_avec (median, daemon) = ${T_AVEC}ms vs T_sans=${T_SANS}ms, delta=${delta}ms (expect >=~50ms), samples=${times2[*]}"

    h=$(RUST_LOG=error "$BIN" tool ssh_health </dev/null 2>&1)
    hist_line=$(echo "$h" | grep "Commands in history:")
    hist_n=$(echo "$hist_line" | grep -o '[0-9]\+')
    if [ -n "$hist_n" ] && [ "$hist_n" -ge 13 ]; then v=PASS; else v=FAIL; fi
    record "P8-08" "$v" "history accumulates in daemon -> $hist_line (expect >=13)"

    RUST_LOG=error "$BIN" tool ssh_exec host="$HOST" command=true </dev/null >/dev/null 2>&1; rc=$?
    if [ "$rc" -eq 4 ]; then v=PASS; else v=FAIL; fi
    record "P8-09" "$v" "destructive gate runs before daemon forward -> rc=$rc (expect 4, no accidental bypass)"

    out=$(RUST_LOG=error "$BIN" tool ssh_nexiste_pas_du_tout host="$HOST" </dev/null 2>&1); rc=$?
    if [ "$rc" -eq 2 ]; then v=PASS; else v=FAIL; fi
    record "P8-10" "$v" "unknown tool with daemon active -> rc=$rc, daemon's own JSON-RPC error propagated (not silently re-run in-process)"

    RUST_LOG=error "$BIN" --dry-run upload "$HOST" "$D/lane-d-up.txt" "$SBX/lane-d-dryrun.txt" </dev/null >/dev/null 2>&1
    out=$(RUST_LOG=error "$BIN" tool ssh_ls host="$HOST" path="$SBX" </dev/null 2>&1)
    # Table's own "attendu" is that the file EXISTS -- that IS the defect being
    # reproduced (--dry-run silently ignored by the upload arm). PASS here means
    # the probe reproduced the known defect; it is reported under DEFECT in D.md.
    if echo "$out" | grep -q "lane-d-dryrun.txt"; then v=PASS; else v=FAIL; fi
    record "P8-11" "$v" "DEFECT check: --dry-run upload actually WROTE the file (dry-run only wired on Exec/Tool arms) -- file_present=$(echo "$out" | grep -q 'lane-d-dryrun.txt' && echo yes || echo no)"

    out=$(RUST_LOG=error "$BIN" daemon stop </dev/null 2>&1); rc=$?
    sleep 1
    out2=$(RUST_LOG=error "$BIN" daemon status </dev/null 2>&1)
    residual=$(pgrep -af "$BIN daemon" || true)
    sock_gone=1; ls "${SOCK}"* >/dev/null 2>&1 && sock_gone=0
    if echo "$out" | grep -qi "stopped" && echo "$out2" | grep -q "Daemon is not running." && [ -z "$residual" ] && [ "$sock_gone" -eq 1 ]; then v=PASS; else v=FAIL; fi
    record "P8-12" "$v" "daemon stop -> $out / $out2 / residual='${residual:-none}' sock_gone=$sock_gone"
  fi
fi

echo
echo "$PASS PASS(es), $FAIL FAIL(s), $NOTES NOTE(s)"
printf '%s\n' "${RESULTS[@]}" > "$D/cli-results.tsv"
exit "$FAIL"
