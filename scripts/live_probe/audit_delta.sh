#!/usr/bin/env bash
# Lane C, sous-lane 5 — delta d'audit, hors `run.py`.
#
# `run.py` exécute tout un fichier de cas puis écrit UN rapport : il n'y a
# aucun point d'accroche par cas où intercaler un `wc -l`. Le delta d'audit
# n'est donc mesurable qu'à ce prix : un script shell autonome, strictement
# séquentiel (un seul processus écrivant à la fois sur le journal).
set -u
W=/home/muchini/bmcp-test-0909
D=$W/.superpowers/campaign/2026-09-09
BIN=$W/target/release/bridge-mcp
A=/home/muchini/.local/share/bridge-mcp/audit.log
SBX=/tmp/bridge-test-0909/lane-c

run_case() {   # $1 = id, reste = commande complète
  local id="$1"; shift
  local before after rc
  before=$(wc -l < "$A")
  RUST_LOG=error "$@" </dev/null >/dev/null 2>&1; rc=$?
  sleep 1                 # le writer d'audit est une tâche asynchrone, drainée par finish_audit
  after=$(wc -l < "$A")
  echo "$id rc=$rc delta=$((after-before))"
}

echo "--- Contrôle positif obligatoire ---"
c501=$(run_case C501 "$BIN" --yes tool ssh_exec --json-args '{"host":"raspberry","command":"echo audit-c501"}')
echo "$c501"
if ! echo "$c501" | grep -q 'delta=1'; then
  echo "ABORT: C501 ne rend pas delta=1 — la mesure est cassée, le +0 de C503 ne prouverait rien" >&2
  echo "(défaut de harnais, pas une régression D5 — sous-lane arrêtée)" >&2
  exit 1
fi
tail -1 "$A" | grep -o '"event_type":"[^"]*"\|"result":"[^"]*"'

echo "--- C502 : refus blacklist (doit journaliser) ---"
run_case C502 "$BIN" --yes tool ssh_exec --json-args '{"host":"raspberry","command":"echo shutdown"}'
tail -1 "$A" | grep -o '"event_type":"[^"]*"\|"result":"[^"]*"\|"command":"[^"]*"'

echo "--- C503 : refus du gate destructif, SANS --yes (régression D5 attendue : +0) ---"
run_case C503 "$BIN" tool ssh_exec --json-args '{"host":"raspberry","command":"echo audit-c503"}'

echo "--- C504 : builtin destructif --yes dans le bac à sable ---"
run_case C504 "$BIN" --yes tool ssh_file_write --json-args "{\"host\":\"raspberry\",\"path\":\"$SBX/c504.txt\",\"content\":\"audit-c504\\n\"}"

echo "--- C505 : le --yes n'écrit-il rien dans le journal ? ---"
before505=$(wc -l < "$A")
RUST_LOG=error "$BIN" --yes tool ssh_exec --json-args '{"host":"raspberry","command":"echo audit-c505"}' </dev/null >/dev/null 2>&1
sleep 1
after505=$(wc -l < "$A")
n_confirmed=$(tail -n $((after505-before505)) "$A" | grep -c 'confirmed by --yes')
echo "C505 delta=$((after505-before505)) confirmed_by_yes_lines=$n_confirmed"

echo "--- C506 : session exec réussi (trou connu : jamais journalisé) ---"
# `bridge-mcp tool ssh_session_create` puis `ssh_session_exec` en deux appels
# CLI séparés ne partagent RIEN : chaque invocation CLI est son propre
# processus, la table de sessions est en mémoire de PROCESSUS
# (mcp_probe.py le dit déjà : "Sessions, tunnels and the output cache live
# inside ONE server process"). Mesuré ci-dessous en CLI d'abord (pour montrer
# l'échec), PUIS dans un seul process MCP long-vécu (seule forme correcte).
before506cli=$(wc -l < "$A")
sid_cli=$(RUST_LOG=error "$BIN" tool ssh_session_create --json-args '{"host":"raspberry"}' </dev/null 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)
RUST_LOG=error "$BIN" tool ssh_session_exec --json-args "{\"session_id\":\"$sid_cli\",\"command\":\"echo audit-c506-cli\"}" </dev/null >/tmp/c506cli.out 2>&1
sleep 1
after506cli=$(wc -l < "$A")
echo "C506-cli-form (WRONG, kept for the record) session_id=$sid_cli delta=$((after506cli-before506cli)) out=$(cat /tmp/c506cli.out | tr '\n' ' ' | cut -c1-120)"

before506=$(wc -l < "$A")
python3 - "$BIN" "$A" <<'PY'
import json, subprocess, sys, time
binary, audit_path = sys.argv[1], sys.argv[2]
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "audit-delta-c506", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}}
p = subprocess.Popen([binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, text=True, bufsize=1,
                      env={**__import__("os").environ, "RUST_LOG": "error"})

def call(n, method, params):
    req = {"jsonrpc": "2.0", "id": n, "method": method, "params": {**params, "_meta": META}}
    p.stdin.write(json.dumps(req) + "\n"); p.stdin.flush()
    for _ in range(100):
        line = p.stdout.readline()
        if not line:
            return {}
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == n:
            return msg
    return {}

def text_of(msg):
    r = msg.get("result", {})
    return "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")

r1 = call(1, "tools/call", {"name": "ssh_session_create", "arguments": {"host": "raspberry"}})
sid = None
try:
    sid = json.loads(text_of(r1)).get("id")
except Exception:
    pass
print(f"MCP_SESSION_ID={sid}", file=sys.stderr)
if sid:
    before = sum(1 for _ in open(audit_path))
    r2 = call(2, "tools/call", {"name": "ssh_session_exec", "arguments": {"session_id": sid, "command": "echo audit-c506-mcp"}})
    time.sleep(1)
    after = sum(1 for _ in open(audit_path))
    print(f"C506-mcp-form delta={after-before} text={text_of(r2)!r}")
    call(3, "tools/call", {"name": "ssh_session_close", "arguments": {"session_id": sid}})
else:
    print(f"C506-mcp-form BLOCKED: session_create -> {json.dumps(r1)[:200]}")
p.stdin.close()
try:
    p.wait(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
PY

echo "--- C507 : ssh_runbook_validate avec un contenu contenant 'shutdown' (validate_builtin sans log_denied ?) ---"
before507=$(wc -l < "$A")
out507=$(RUST_LOG=error "$BIN" tool ssh_runbook_validate --json-args '{"yaml_content":"name: bad\ndescription: probe\nsteps:\n  - name: bad\n    command: \"echo shutdown\"\n"}' </dev/null 2>&1)
rc507=$?
sleep 1
after507=$(wc -l < "$A")
echo "C507 rc=$rc507 delta=$((after507-before507)) out=${out507:0:200}"

echo "--- C508 : ssh_fleet_diff (orchestration) sur une entrée refusée ---"
before508=$(wc -l < "$A")
out508=$(RUST_LOG=error "$BIN" tool ssh_fleet_diff --json-args '{"host":"raspberry","command":"echo shutdown"}' </dev/null 2>&1)
rc508=$?
sleep 1
after508=$(wc -l < "$A")
echo "C508 rc=$rc508 delta=$((after508-before508)) out=${out508:0:200}"

echo "--- Réconciliation globale de fin de lane ---"
end=$(wc -l < "$A")
start=$(cat "$D/audit-offset-start.txt" | awk '{print $1}')
echo "lane C: $((end-start)) lignes d'audit gagnées" | tee "$D/audit-delta.txt"
{
  echo "--- ventilation par event_type sur la tranche [start=$start, end=$end) ---"
  tail -n $((end-start)) "$A" | grep -o '"event_type":"[^"]*"' | sort | uniq -c | sort -rn
  echo "--- lignes command_denied sur la tranche ---"
  n_denied=$(tail -n $((end-start)) "$A" | grep -c '"event_type":"command_denied"')
  # Refus attendus mesurés dans cette lane : 16 (blacklist C201-C208+b) +
  # 13 évasions refusées (C222,C224,C230,C232,C233,C234,C235,C237 = 8 sur 13
  # exécutables, cf. rapport C.md pour le compte exact des KO documentés) +
  # C302/C305/C308/C330 (config matrix) + C161/C203-C208 doublons déjà comptés
  # ci-dessus. Le chiffre exact et son écart sont recalculés et expliqués
  # dans C.md ; ici on n'écrit que le compte brut mesuré.
  echo "command_denied lines counted: $n_denied"
} | tee -a "$D/audit-delta.txt"
