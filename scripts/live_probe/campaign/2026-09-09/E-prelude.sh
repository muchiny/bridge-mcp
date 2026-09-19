#!/usr/bin/env bash
#
# E-prelude.sh — campaign 2026-09-09, lane E, Step 1.
#
# Read-only host preflight + LOCAL fixture creation + rewrite of the `vars` block of
# every E*.json case file.  It writes NOTHING on the Pi: every probe below is a read
# (findmnt, command -v, crontab -l, crictl images/ps, k3s etcd status, kubectl get
# nodes).  The only files it creates are on the bridge machine (WSL), under
# $SANDBOX_LOCAL.
#
# Usage:  BIN=/abs/path/to/bridge-mcp HOST=raspberry ./E-prelude.sh
# Output: a `measure: <key> = <value>` line per derived variable, then the list of
#         case files whose `vars` block was rewritten.
#
# WHY THE LOCAL FIXTURES ARE HERE AND NOT IN A CASE
#   E121/E122/E124/E125 (ssh_upload) and E127/E128 (ssh_sync direction=upload) consume
#   files that live on the BRIDGE machine.  No tool of the campaign creates them, and
#   run.py has no "local setup" hook.  Without them E121 fails on "local file not
#   found", E122/E125 cascade, and E128 reports a FALSE DEFECT (an empty source
#   directory syncs successfully and produces nothing to list).
#
# WHY PAUSE_IMAGE IS DERIVED AND NOT HARD-CODED
#   The plan calls it "the exact reference of the `pause` image of the containerd
#   cache".  Its FUNCTION is: an image already present on the node, so that a
#   Deployment referencing it never attempts a pull (decision B: install nothing).
#   This script picks, in order: a `pause` image if the node has one, else a
#   `busybox` image, else empty.  Empty means E225-E229, E245b, E246, E509b, E509c
#   and E510 are BLOCKED — never fallen back onto a real workload container.
#
# BUSYBOX_OK is SEPARATE and much narrower: it is `yes` only when the node already
#   holds busybox in tag **1.36**, the tag `ssh_k8s_dns_check` hard-codes
#   (kubernetes.rs:3828).  Any other tag cannot unblock E602-E604.
#
# BT_CID is deliberately left empty here: the container of the campaign's own
#   `bt-pause` pod does not exist yet at Step 1.  It is measured by E509c, inside
#   the E5 sub-batch, and patched in then.  `ssh_crictl_exec` (E510) uses BT_CID and
#   never CID — CID names a REAL user workload and is reserved for the read-only
#   `ssh_crictl_inspect` of E615.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-/home/muchini/bmcp-test-0909/target/release/bridge-mcp}"
HOST="${HOST:-raspberry}"
SANDBOX_LOCAL=/tmp/bridge-test-0909-local

if [ ! -x "$BIN" ]; then
  echo "error: '$BIN' is not an executable bridge-mcp binary" >&2
  exit 2
fi

export RUST_LOG=error

ro()  { "$BIN" tool "$@" 2>&1; }
# ssh_exec carries destructiveHint even for a read-only payload, so the probes need
# --yes.  Every payload below is provably read-only: findmnt, command -v, crontab -l,
# crictl, grep, head.  None writes anywhere.
mut() { "$BIN" --yes tool "$@" 2>&1; }

# ------------------------------------------------------------ local fixtures
# The trailing newline is load-bearing.  The plan spelled the fixture
# `printf 'uploaded'` (no newline) yet asks E125 for `eq=uploaded\nuploaded` after an
# `mode=append` upload — without a newline the append yields `uploadeduploaded` and
# E125 can never pass.  With it, BOTH expectations hold: run.py's `eq=` rstrips the
# trailing newline, so E122 still reads `uploaded`.
mkdir -p "$SANDBOX_LOCAL/synced"
printf 'uploaded\n' > "$SANDBOX_LOCAL/up.txt"
printf 's1\n'       > "$SANDBOX_LOCAL/synced/s1.txt"
echo "fixture: $SANDBOX_LOCAL/up.txt ($(wc -c < "$SANDBOX_LOCAL/up.txt") bytes)"
echo "fixture: $SANDBOX_LOCAL/synced/s1.txt ($(wc -c < "$SANDBOX_LOCAL/synced/s1.txt") bytes)"

# ------------------------------------------------------------ the seven probes
# Probes 4 and 5 deliberately go through `ssh_exec sudo=true 'crictl …'` and NOT through
# ssh_crictl_images / ssh_crictl_ps: those two tools return JSON, and the PAUSE_IMAGE /
# CID derivations below parse the `repository tag …` TABLE that raw crictl prints. The
# two tools themselves are exercised as real tool calls elsewhere in the lane —
# ssh_crictl_images by E601 (the D11 image lock) and ssh_crictl_ps by E509c — so nothing
# is lost. The echoed labels say what actually ran.
P1=$(mut ssh_exec host="$HOST" command='findmnt -n -o FSTYPE /tmp' | grep -E '^[a-z0-9]+$' | head -1)
echo "probe 1: findmnt -n -o FSTYPE /tmp            -> ${P1:-<empty>}"

P2=$(mut ssh_exec host="$HOST" command='command -v ufw || echo none' | tail -2 | grep -E '^(/|none)' | head -1)
echo "probe 2: command -v ufw                       -> ${P2:-<empty>}"

P3=$(mut ssh_exec host="$HOST" command='crontab -l >/dev/null 2>&1 && echo has-crontab || echo no-crontab' | grep -E '^(has|no)-crontab$' | head -1)
echo "probe 3: crontab -l                           -> ${P3:-<empty>}"

IMAGES=$(mut ssh_exec host="$HOST" sudo=true command='crictl images 2>/dev/null')
echo "probe 4: ssh_exec sudo=true 'crictl images'      -> $(printf '%s\n' "$IMAGES" | grep -c . ) line(s)"

PS_OUT=$(mut ssh_exec host="$HOST" sudo=true command='crictl ps 2>/dev/null')
echo "probe 5: ssh_exec sudo=true 'crictl ps'          -> $(printf '%s\n' "$PS_OUT" | grep -c . ) line(s)"

ETCD=$(ro ssh_k3s_etcd_status host="$HOST" | grep -A1 '== datastore ==' | tail -1)
echo "probe 6: ssh_k3s_etcd_status (datastore)      -> ${ETCD:-<empty>}"

NODES=$(ro ssh_k8s_get host="$HOST" resource=nodes | tail -1)
echo "probe 7: ssh_k8s_get resource=nodes           -> ${NODES:-<empty>}"

# ------------------------------------------------------------ derivations
# PAUSE_IMAGE: `repository tag ...` columns; prefer a pause image, else busybox.
pick_image() {
  printf '%s\n' "$IMAGES" | awk -v pat="$1" '
    $1 ~ pat && $2 != "<none>" && $2 != "" { printf "%s:%s\n", $1, $2; exit }'
}
PAUSE_IMAGE=$(pick_image 'pause')
PAUSE_SRC=pause
if [ -z "$PAUSE_IMAGE" ]; then
  PAUSE_IMAGE=$(pick_image 'busybox')
  PAUSE_SRC=busybox-fallback
fi
[ -n "$PAUSE_IMAGE" ] || PAUSE_SRC=absent

# BUSYBOX_OK: strictly tag 1.36, the tag dns_check hard-codes.
if printf '%s\n' "$IMAGES" | awk '$1 ~ /busybox/ && $2 == "1.36" { found=1 } END { exit !found }'; then
  BUSYBOX_OK=yes
else
  BUSYBOX_OK=no
fi

# CID: a REAL container, for the read-only ssh_crictl_inspect of E615 ONLY.
CID=$(printf '%s\n' "$PS_OUT" | awk 'NR>1 && $1 ~ /^[0-9a-f]{12,}$/ { print $1; exit }')

case "$P2" in none|'') UFW_ABSENT=yes ;; *) UFW_ABSENT=no ;; esac
case "$P3" in has-crontab) HAD_CRONTAB=yes ;; *) HAD_CRONTAB=no ;; esac

echo "measure: PAUSE_IMAGE = ${PAUSE_IMAGE:-<absent>}  (source: $PAUSE_SRC)"
echo "measure: BUSYBOX_OK  = $BUSYBOX_OK  (strictly tag 1.36)"
echo "measure: CID         = ${CID:-<absent>}  (REAL container — read-only E615 only)"
echo "measure: BT_CID      = <deferred to E509c>"
echo "measure: UFW_ABSENT  = $UFW_ABSENT"
echo "measure: HAD_CRONTAB = $HAD_CRONTAB"
echo "measure: TMP_FSTYPE  = ${P1:-<unknown>}"

# ------------------------------------------------------------ rewrite vars blocks
python3 - "$HERE" "$PAUSE_IMAGE" "$BUSYBOX_OK" "$CID" "$UFW_ABSENT" "$HAD_CRONTAB" <<'PY'
import glob, json, os, sys

here, pause, busybox, cid, ufw, hadcron = sys.argv[1:7]
updates = {"PAUSE_IMAGE": pause, "BUSYBOX_OK": busybox, "CID": cid,
           "UFW_ABSENT": ufw, "HAD_CRONTAB": hadcron}
# E9-teardown-proof.json is Task 1bis's artefact.  Ruling R4: lane E VERIFIES it, it
# never rewrites it — and none of the five keys below appears in any of its cases, so
# it has nothing to gain from a rewrite and everything to lose from a reformat.
for path in sorted(glob.glob(os.path.join(here, "E[1-6]-*.json"))):
    doc = json.load(open(path))
    v = doc.get("vars")
    if not isinstance(v, dict):
        print(f"{path}: no vars block, skipped")
        continue
    changed = [k for k, val in updates.items() if k in v and v[k] != val]
    for k, val in updates.items():
        if k in v:
            v[k] = val
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"{os.path.basename(path)}: vars rewritten ({', '.join(changed) if changed else 'no change'})")
PY
