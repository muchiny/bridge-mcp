#!/usr/bin/env bash
# Lane C, sous-lane 3 — variantes de configuration.
#
# `run.py` ne sait pas passer `-c` : ce script est autonome, hors `run.py`.
# Chaque variante est une COPIE patchée sous $D/configs/, jamais la config
# vivante en place. Refuse de démarrer si le sha256 de la config vivante a
# bougé depuis le Step 1 de la lane.
set -u
W=/home/muchini/bmcp-test-0909
D=$W/.superpowers/campaign/2026-09-09
BIN=$W/target/release/bridge-mcp
SRC=/home/muchini/.config/mcp-ssh-bridge/config.yaml
EXPECT_SHA=3817558666520493701d78b4741190d8e4453ece2ac4f90b2df5f5fb4556408f

actual_sha=$(sha256sum "$SRC" | awk '{print $1}')
if [ "$actual_sha" != "$EXPECT_SHA" ]; then
  echo "ABORT: config vivante modifiée depuis le Step 1 (sha256=$actual_sha) — la lane C s'arrête" >&2
  exit 1
fi

mkdir -p "$D/configs"

mk() { cp "$SRC" "$D/configs/$1"; }

# --- Génération des 13 copies patchées ------------------------------------
mk cfg-strict-empty.yaml
sed -i 's/^  mode: permissive$/  mode: strict/' "$D/configs/cfg-strict-empty.yaml"
grep -q '^  mode: strict$' "$D/configs/cfg-strict-empty.yaml" && echo "grep-ok cfg-strict-empty.yaml" || echo "grep-FAIL cfg-strict-empty.yaml"

mk cfg-strict-allow.yaml
python3 - "$D/configs/cfg-strict-allow.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
s = open(p).read()
s = s.replace("  mode: permissive\n", "  mode: strict\n", 1)
# .replace(), not re.sub(): re.sub's `repl` argument runs its OWN backslash
# escaping pass (backreferences), which silently halves a literal backslash
# (measured: 4 backslashes in the Python source collapsed to 1 in the file,
# not 2 — the whitelist regex never matched anything as a result).
s = s.replace('  whitelist:\n    []\n',
              '  whitelist:\n    - "^echo\\\\b"\n    - "^uname\\\\b"\n', 1)
open(p, "w").write(s)
# Verify by loading the YAML and matching the regex for real, not by
# counting backslashes in a grep pattern (that check was ALSO wrong once).
d = yaml.safe_load(open(p))
import re as relib
wl = d["security"]["whitelist"]
ok = d["security"]["mode"] == "strict" and any(relib.search(pat, "echo ok") for pat in wl)
print("PATCH_OK" if ok else f"PATCH_FAIL wl={wl!r}")
PY

mk cfg-standard-allow.yaml
python3 - "$D/configs/cfg-standard-allow.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
s = open(p).read()
s = s.replace("  mode: permissive\n", "  mode: standard\n", 1)
s = s.replace('  whitelist:\n    []\n',
              '  whitelist:\n    - "^echo\\\\b"\n    - "^uname\\\\b"\n', 1)
open(p, "w").write(s)
d = yaml.safe_load(open(p))
import re as relib
wl = d["security"]["whitelist"]
ok = d["security"]["mode"] == "standard" and any(relib.search(pat, "echo ok") for pat in wl)
print("PATCH_OK" if ok else f"PATCH_FAIL wl={wl!r}")
PY

mk cfg-nosanitize.yaml
sed -i '/^security:$/a\  sanitize:\n    enabled: false' "$D/configs/cfg-nosanitize.yaml"
grep -q '^  sanitize:$' "$D/configs/cfg-nosanitize.yaml" && grep -q '^    enabled: false$' "$D/configs/cfg-nosanitize.yaml" \
  && echo "grep-ok cfg-nosanitize.yaml" || echo "grep-FAIL cfg-nosanitize.yaml"

mk cfg-listing-full.yaml
sed -i 's/^  listing: progressive$/  listing: full/' "$D/configs/cfg-listing-full.yaml"
grep -q '^  listing: full$' "$D/configs/cfg-listing-full.yaml" && echo "grep-ok cfg-listing-full.yaml" || echo "grep-FAIL cfg-listing-full.yaml"

mk cfg-nodocker.yaml
sed -i 's/^    docker: true$/    docker: false/' "$D/configs/cfg-nodocker.yaml"
grep -q '^    docker: false$' "$D/configs/cfg-nodocker.yaml" && echo "grep-ok cfg-nodocker.yaml" || echo "grep-FAIL cfg-nodocker.yaml"

mk cfg-nocore.yaml
sed -i '/^  groups:$/a\    core: false' "$D/configs/cfg-nocore.yaml"
grep -q '^    core: false$' "$D/configs/cfg-nocore.yaml" && echo "grep-ok cfg-nocore.yaml" || echo "grep-FAIL cfg-nocore.yaml"

mk cfg-rbac.yaml
printf '\nrbac:\n  enabled: true\n' >> "$D/configs/cfg-rbac.yaml"
grep -q '^  enabled: true$' "$D/configs/cfg-rbac.yaml" && echo "grep-ok cfg-rbac.yaml" || echo "grep-FAIL cfg-rbac.yaml"

mk cfg-httpsession.yaml
printf '\nhttp:\n  session_timeout_seconds: 60\n' >> "$D/configs/cfg-httpsession.yaml"
grep -q '^  session_timeout_seconds: 60$' "$D/configs/cfg-httpsession.yaml" && echo "grep-ok cfg-httpsession.yaml" || echo "grep-FAIL cfg-httpsession.yaml"

mk cfg-noaudit.yaml
sed -i '0,/^  enabled: true$/{s/^  enabled: true$/  enabled: false/}' "$D/configs/cfg-noaudit.yaml"
# Le premier "  enabled: true" du fichier est celui d'audit: (security: n'a pas
# cette clé à ce niveau d'indentation) ; on revérifie que c'est bien celui-là.
awk '/^audit:$/{f=1} f&&/^  enabled: false$/{print;exit}' "$D/configs/cfg-noaudit.yaml" | grep -q 'enabled: false' \
  && echo "grep-ok cfg-noaudit.yaml" || echo "grep-FAIL cfg-noaudit.yaml"

mk cfg-timeout2.yaml
sed -i 's/^  command_timeout_seconds: 60$/  command_timeout_seconds: 2/' "$D/configs/cfg-timeout2.yaml"
grep -q '^  command_timeout_seconds: 2$' "$D/configs/cfg-timeout2.yaml" && echo "grep-ok cfg-timeout2.yaml" || echo "grep-FAIL cfg-timeout2.yaml"

mk cfg-maxout2k.yaml
sed -i 's/^  max_output_bytes: 1048576$/  max_output_bytes: 2048/' "$D/configs/cfg-maxout2k.yaml"
grep -q '^  max_output_bytes: 2048$' "$D/configs/cfg-maxout2k.yaml" && echo "grep-ok cfg-maxout2k.yaml" || echo "grep-FAIL cfg-maxout2k.yaml"

mk cfg-tildeaudit.yaml
sed -i 's#^  path: /home/muchini/.local/share/bridge-mcp/audit.log$#  path: "~/bmcp-tilde-0909/audit.log"#' "$D/configs/cfg-tildeaudit.yaml"
grep -q '^  path: "~/bmcp-tilde-0909/audit.log"$' "$D/configs/cfg-tildeaudit.yaml" && echo "grep-ok cfg-tildeaudit.yaml" || echo "grep-FAIL cfg-tildeaudit.yaml"

echo "--- 13 fichiers produits sous $D/configs ---"

run() { # id, description, cmd...
  local id="$1" desc="$2"; shift 2
  local out rc
  out=$("$@" 2>&1 </dev/null)
  rc=$?
  echo "$id OK rc=$rc $desc :: ${out:0:200}"
}

# --- C301-C330 -------------------------------------------------------------
run C301 "strict-empty validate" $BIN -c "$D/configs/cfg-strict-empty.yaml" validate
run C302 "strict-empty ssh_exec --yes echo x" $BIN --yes -c "$D/configs/cfg-strict-empty.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo x"}'
run C303 "strict-empty ssh_file_read /etc/os-release" $BIN -c "$D/configs/cfg-strict-empty.yaml" tool ssh_file_read --json-args '{"host":"raspberry","path":"/etc/os-release"}'
run C304 "strict-allow ssh_exec --yes echo ok" $BIN --yes -c "$D/configs/cfg-strict-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo ok"}'
run C305 "strict-allow ssh_exec --yes id" $BIN --yes -c "$D/configs/cfg-strict-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"id"}'
run C306 "strict-allow ssh_exec --yes ' echo ok' (leading space)" $BIN --yes -c "$D/configs/cfg-strict-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":" echo ok"}'
run C307 "strict-allow ssh_exec --yes echo\${IFS}ok" $BIN --yes -c "$D/configs/cfg-strict-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo${IFS}ok"}'
run C308 "standard-allow ssh_exec --yes id" $BIN --yes -c "$D/configs/cfg-standard-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"id"}'
run C309 "strict-allow ssh_exec --yes echo shutdown" $BIN --yes -c "$D/configs/cfg-strict-allow.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo shutdown"}'
run C310 "nosanitize ssh_exec --yes SF01 decode" $BIN --yes -c "$D/configs/cfg-nosanitize.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo eyJtZXRhZGF0YSI6eyJuYW1lIjoiZGVtbyJ9LCJzZWNyZXQiOnsicGFzc3dvcmQiOiJTM2NyM3QtVmExdWUteDlRMiJ9LCJvdGhlciI6ImtlZXAifQ== | base64 -d"}'
run C311 "live-config (no -c) ssh_exec --yes SF01 decode" $BIN --yes tool ssh_exec --json-args '{"host":"raspberry","command":"echo eyJtZXRhZGF0YSI6eyJuYW1lIjoiZGVtbyJ9LCJzZWNyZXQiOnsicGFzc3dvcmQiOiJTM2NyM3QtVmExdWUteDlRMiJ9LCJvdGhlciI6ImtlZXAifQ== | base64 -d"}'
run C312 "listing-full validate" $BIN -c "$D/configs/cfg-listing-full.yaml" validate
echo "C313 $(printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"cfg","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}\n' | RUST_LOG=error $BIN -c "$D/configs/cfg-listing-full.yaml" serve 2>/dev/null | head -1 | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["result"]["tools"]))' 2>&1)"
echo "C314 $(printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"cfg","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}\n' | RUST_LOG=error $BIN serve 2>/dev/null | head -1 | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["result"]["tools"]))' 2>&1)"
run C315 "nodocker list-tools -g docker" $BIN -c "$D/configs/cfg-nodocker.yaml" list-tools -g docker
run C316 "nodocker ssh_docker_ps call-by-name" $BIN -c "$D/configs/cfg-nodocker.yaml" tool ssh_docker_ps --json-args '{"host":"raspberry"}'
run C317 "nodocker validate (Tools: count)" $BIN -c "$D/configs/cfg-nodocker.yaml" validate
run C318 "nocore ssh_exec call-by-name" $BIN -c "$D/configs/cfg-nocore.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"true"}'
run C319 "rbac validate" $BIN -c "$D/configs/cfg-rbac.yaml" validate
run C320 "rbac list-tools" $BIN -c "$D/configs/cfg-rbac.yaml" list-tools
run C321 "httpsession validate" $BIN -c "$D/configs/cfg-httpsession.yaml" validate
run C322 "timeout2 ssh_exec --yes sleep 5" $BIN --yes -c "$D/configs/cfg-timeout2.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"sleep 5"}'
run C323 "timeout2 ssh_exec --yes sleep 5 timeout_seconds=20" $BIN --yes -c "$D/configs/cfg-timeout2.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"sleep 5","timeout_seconds":20}'
run C324 "timeout2 ssh_exec --yes echo fast" $BIN --yes -c "$D/configs/cfg-timeout2.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo fast"}'
run C325 "maxout2k ssh_exec --yes seq 1 20000" $BIN --yes -c "$D/configs/cfg-maxout2k.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"seq 1 20000"}'
run C326 "maxout2k ssh_exec --yes seq 1 20000 max_output=0" $BIN --yes -c "$D/configs/cfg-maxout2k.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"seq 1 20000","max_output":0}'
run C327 "maxout2k ssh_k8s_get pods all_namespaces max_output=200" $BIN -c "$D/configs/cfg-maxout2k.yaml" tool ssh_k8s_get --json-args '{"host":"raspberry","resource":"pods","all_namespaces":true,"max_output":200}'
( cd "$D/configs" && "$BIN" --yes -c "$D/configs/cfg-tildeaudit.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo tilde"}' >/tmp/c328.out 2>&1 </dev/null
  rc=$?
  ls -d "$D/configs/~" >/tmp/c328.ls 2>&1
  echo "C328 OK rc=$rc :: $(cat /tmp/c328.out | tr '\n' ' ' | cut -c1-150) :: tilde-dir=$(cat /tmp/c328.ls)" )
before=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log)
run C329 "noaudit ssh_exec --yes echo noaudit" $BIN --yes -c "$D/configs/cfg-noaudit.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo noaudit"}'
after=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log)
echo "C329-audit before=$before after=$after delta=$((after-before))"
before2=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log)
run C330 "strict-empty ssh_exec --yes echo x (whitelist refusal, again)" $BIN --yes -c "$D/configs/cfg-strict-empty.yaml" tool ssh_exec --json-args '{"host":"raspberry","command":"echo x"}'
after2=$(wc -l < /home/muchini/.local/share/bridge-mcp/audit.log)
echo "C330-audit before=$before2 after=$after2 delta=$((after2-before2))"
tail -n $((after2-before2)) /home/muchini/.local/share/bridge-mcp/audit.log 2>/dev/null | grep -o '"event_type":"[^"]*"' | tail -3
