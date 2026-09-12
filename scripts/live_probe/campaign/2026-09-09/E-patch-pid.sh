#!/usr/bin/env bash
#
# E-patch-pid.sh — campaign 2026-09-09, lane E.
#
# Rewrites the `pid` argument of every ssh_process_kill case in a case file.
#
# WHY A SCRIPT AND NOT A ${SLEEPPID} SUBSTITUTION
#   `pid` is an integer in the schema (ssh_process_kill req=['host','pid'], pid: integer)
#   and run.py's substitute() (run.py:132-136) only replaces ${VAR} INSIDE A STRING.
#   `"pid": ${SLEEPPID}` is not valid JSON; `"pid": "${SLEEPPID}"` makes serde answer
#   `invalid type: string "12345", expected u32`.  Both forms fail.  So the case files
#   carry `"pid": 0` and this script rewrites it just before the run.
#
# !!! TASK 7 MUST RE-MEASURE THE PID AND RE-RUN THIS SCRIPT IMMEDIATELY BEFORE E505 !!!
#   Global constraints §3.2: ssh_process_kill may only target a PID returned by E505a
#   AND re-confirmed by the identity guard E505b in the SAME sub-batch — never a PID
#   measured in another task.  The Pi creates processes continuously (K3s, the
#   media-backup CronJob), PIDs are recycled, and ssh_process_kill guards nothing but
#   PID 0 and 1 (process.rs:73).  The SLEEPPID published by Task 1bis in
#   sandbox-vars.{sh,json} is PLUMBING PROOF that the mechanism works — it is NOT a
#   licence to kill a PID measured hours earlier.
#   If E505b's identity guard does not confirm the process, RE-CREATE the sleep and
#   re-run this script; do not execute E506.
#   Task 1bis created its sleep as `sleep 86400` (not `sleep 600`) so it outlives the
#   campaign; an identity guard must match the argv of whichever sleep it targets.
#
# The script is idempotent and re-runnable: it rewrites the pid whatever its current
# value, so a second run with a freshly measured PID overwrites the first.  The single
# exception is the sentinel 2147483647 ("inexistent by construction", the fallback the
# safety whitelist allows): that case is deliberately left untouched.
#
# Usage:
#   E-patch-pid.sh <pid | /path/to/pidfile> [case-file.json ...]
# Default case file:
#   scripts/live_probe/campaign/2026-09-09/E5-storage-process-env.json

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SENTINEL=2147483647

if [ "$#" -lt 1 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "usage: $0 <pid | /path/to/pidfile> [case-file.json ...]" >&2
  exit 2
fi

SRC="$1"
shift

if [ -f "$SRC" ]; then
  PID="$(tr -cd '0-9' < "$SRC")"
else
  PID="$SRC"
fi

case "$PID" in
  ''|*[!0-9]*) echo "error: '$SRC' did not yield a numeric pid" >&2; exit 2 ;;
esac
if [ "$PID" -le 1 ]; then
  echo "error: refusing pid $PID (0 and 1 are never valid targets)" >&2
  exit 2
fi

if [ "$#" -eq 0 ]; then
  set -- "$HERE/E5-storage-process-env.json"
fi

rc=0
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "error: case file not found: $f" >&2
    rc=1
    continue
  fi
  python3 - "$f" "$PID" "$SENTINEL" <<'PY'
import json, sys

path, pid, sentinel = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
doc = json.load(open(path))
touched = []
for case in doc.get("cases", []):
    if case.get("tool") != "ssh_process_kill":
        continue
    old = case.get("args", {}).get("pid")
    if old == sentinel:
        continue
    if old == pid:
        touched.append((case["id"], old, pid, "unchanged"))
        continue
    case["args"]["pid"] = pid
    touched.append((case["id"], old, pid, "rewritten"))
if any(t[3] == "rewritten" for t in touched):
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
if not touched:
    print(f"{path}: no ssh_process_kill case to patch (sentinel cases are skipped)")
for cid, old, new, what in touched:
    print(f"{path}: {cid} pid {old} -> {new} ({what})")
remaining = sum(1 for line in open(path) if '"pid": 0' in line)
print(f'{path}: lines still carrying \'"pid": 0\': {remaining}')
PY
  [ $? -ne 0 ] && rc=1
done
exit "$rc"
