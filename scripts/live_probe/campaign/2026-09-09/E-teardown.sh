#!/usr/bin/env bash
#
# E-teardown.sh — campaign 2026-09-09, lane E sandbox teardown.
#
# Written and PROVEN by Task 1bis (Step 0 writes it, Step 5 runs it for real on a
# sandbox that genuinely existed).  Task 7 Step 3 only VERIFIES it and must not
# rewrite it.  Its single real execution point in the campaign is Task 9 Step 0.
#
# Usage:   E-teardown.sh /abs/path/to/bridge-mcp [host]        (host defaults to raspberry)
#
# Contract:
#   * `set -u` but deliberately NOT `set -e`: every section must run even if the
#     previous one failed, otherwise one stuck object strands all the others.
#   * Nine sections, §0 .. §8, in this order.  §0 unmounts the tmpfs BEFORE §1
#     deletes files, or the delete fails on a busy mount point.
#   * Each section prints exactly one line, `SECTION n: cleaned`,
#     `SECTION n: already absent`, or `SECTION n: FAILED`.
#   * Idempotent: running it twice is safe; the second run prints `already absent`.
#   * Exit 0 when there was nothing to clean or everything was cleaned;
#     exit 1 if any section reports FAILED.
#
# Two commands are FORBIDDEN in this script and anywhere in this campaign:
#   * `rm` with the -rf flag spelling.  The pattern rm\s+-rf is the first entry of
#     the live blacklist (config.yaml:92): the command crosses the destructive gate
#     with --yes and is then REFUSED (exit 4), leaving the sandbox on the host under
#     a "host unchanged" verdict.  Use `rm -r --` / `rm -f --` / `find … -exec rm -- {} +`.
#   * `crontab` with the -r flag.  It would erase the ENTIRE crontab of the SSH
#     account, not just the campaign's entries.  §6 removes by pattern only.
#     A leftover empty crontab file is an ADMITTED residual trace (§7.1), never removed.
#
# Cross-task constraint §6 depends on: the cron entries created by E317 and E137
# MUST carry the literal marker BRIDGE_TEST_0909, because the only removal pattern
# the safety whitelist allows is `pattern=BRIDGE_TEST_0909` exactly.  An entry that
# carries only the lowercase `bridge-test-0909` spelling is detected by §6 but
# cannot be removed by it, and §6 will report FAILED.

set -u

BIN="${1:-}"
HOST="${2:-raspberry}"

if [ -z "$BIN" ] || [ "$BIN" = "-h" ] || [ "$BIN" = "--help" ]; then
  echo "usage: $0 /abs/path/to/bridge-mcp [host]" >&2
  exit 2
fi
if [ ! -x "$BIN" ]; then
  echo "error: '$BIN' is not an executable bridge-mcp binary" >&2
  exit 2
fi

SANDBOX=/tmp/bridge-test-0909
SANDBOX_LOCAL=/tmp/bridge-test-0909-local
NS=bridge-test
SBXUSER=btest0909
SBXGROUP=btestgrp0909
CRON_MARK=BRIDGE_TEST_0909
NODE=server

FAILURES=0

# Read-only invocation.  Global flags go BEFORE the `tool` subcommand: `args` is
# declared trailing_var_arg, so a flag placed after a key=value positional is
# swallowed as a positional (src/cli/mod.rs:220-231).
ro()  { "$BIN" tool "$@" 2>&1; }
# Destructive-gated invocation.  ssh_exec is annotated destructiveHint even for a
# read-only payload, so the presence probes below also need --yes; their payloads
# are provably read-only (ls / findmnt / grep / echo) and write nothing anywhere.
mut() { "$BIN" --yes tool "$@" 2>&1; }

# --------------------------------------------------------------------------- §0
# Unmount the tmpfs first.  A tmpfs mounted as root survives an interrupted lane
# (E501 done, E504 never reached) and makes the §1 delete fail on a busy mount.
section_0() {
  local probe out
  probe=$(mut ssh_exec host="$HOST" command='findmnt -n /tmp/bridge-test-0909/mnt >/dev/null 2>&1 && echo mounted || echo unmounted')
  if ! printf '%s\n' "$probe" | grep -qx 'mounted'; then
    echo "SECTION 0: already absent"
    return 0
  fi
  out=$(mut ssh_exec host="$HOST" sudo=true command='umount /tmp/bridge-test-0909/mnt 2>/dev/null; findmnt -n /tmp/bridge-test-0909/mnt >/dev/null 2>&1 && echo still-mounted || echo now-unmounted')
  if printf '%s\n' "$out" | grep -qx 'now-unmounted'; then
    echo "SECTION 0: cleaned"
  else
    echo "SECTION 0: FAILED"
    printf '  umount output: %s\n' "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §1
# Files: the sandbox tree on the Pi, the timestamped snapshot archives dropped in
# /tmp by ssh_backup_snapshot, and the bridge-side sandbox.
section_1() {
  local probe out local_present=0
  [ -e "$SANDBOX_LOCAL" ] && local_present=1
  probe=$(mut ssh_exec host="$HOST" command='r=0; [ -e /tmp/bridge-test-0909 ] && r=1; c=$(ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l); [ "$c" -gt 0 ] && r=1; echo fileprobe:$r')
  if ! printf '%s\n' "$probe" | grep -q 'fileprobe:1' && [ "$local_present" -eq 0 ]; then
    echo "SECTION 1: already absent"
    return 0
  fi
  out=$(mut ssh_exec host="$HOST" command='rm -r -- /tmp/bridge-test-0909 2>/dev/null; find /tmp -maxdepth 1 -name "snapshot_bridge-test-0909*" -exec rm -- {} + 2>/dev/null; c=$(ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l); if [ ! -e /tmp/bridge-test-0909 ] && [ "$c" -eq 0 ]; then echo files-gone; else echo files-left; fi')
  if ! printf '%s\n' "$out" | grep -qx 'files-gone'; then
    out=$(mut ssh_exec host="$HOST" sudo=true command='rm -r -- /tmp/bridge-test-0909 2>/dev/null; find /tmp -maxdepth 1 -name "snapshot_bridge-test-0909*" -exec rm -- {} + 2>/dev/null; c=$(ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l); if [ ! -e /tmp/bridge-test-0909 ] && [ "$c" -eq 0 ]; then echo files-gone; else echo files-left; fi')
  fi
  # Bridge-side sandbox.  </dev/null so a write-protected file can never turn the
  # delete into an interactive prompt that would hang the script.
  rm -r -- "$SANDBOX_LOCAL" </dev/null 2>/dev/null
  if printf '%s\n' "$out" | grep -qx 'files-gone' && [ ! -e "$SANDBOX_LOCAL" ]; then
    echo "SECTION 1: cleaned"
  else
    echo "SECTION 1: FAILED"
    printf '  remote: %s / local %s still present: %s\n' "$out" "$SANDBOX_LOCAL" "$([ -e "$SANDBOX_LOCAL" ] && echo yes || echo no)" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §2
# Namespace bridge-test.  Deleting it takes the ten namespaced objects of 7.1 #4
# (configmap, secret, serviceaccount, roles, rolebinding, deployment, netpol,
# ingress, pvc) with it; the cluster-scoped PV is §3's job.
section_2() {
  local i
  if ro ssh_k8s_get host="$HOST" resource=namespace name="$NS" | grep -q 'NotFound'; then
    echo "SECTION 2: already absent"
    return 0
  fi
  mut ssh_k8s_delete host="$HOST" resource=namespace name="$NS" >/dev/null 2>&1
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
    if ro ssh_k8s_get host="$HOST" resource=namespace name="$NS" | grep -q 'NotFound'; then
      echo "SECTION 2: cleaned"
      return 0
    fi
    sleep 5
  done
  echo "SECTION 2: FAILED"
  printf '  namespace %s still present after 90s (finalizer stuck?)\n' "$NS" >&2
  FAILURES=$((FAILURES + 1))
}

# --------------------------------------------------------------------------- §3
# PersistentVolume bt-pv is cluster-scoped: removing the namespace does NOT
# remove it.  It has to be named explicitly, after §2 so its PVC is gone first.
section_3() {
  local i
  if ro ssh_k8s_get host="$HOST" resource=pv name=bt-pv | grep -q 'NotFound'; then
    echo "SECTION 3: already absent"
    return 0
  fi
  mut ssh_k8s_delete host="$HOST" resource=pv name=bt-pv >/dev/null 2>&1
  for i in 1 2 3 4 5 6; do
    if ro ssh_k8s_get host="$HOST" resource=pv name=bt-pv | grep -q 'NotFound'; then
      echo "SECTION 3: cleaned"
      return 0
    fi
    sleep 5
  done
  echo "SECTION 3: FAILED"
  printf '  pv bt-pv still present after 30s\n' >&2
  FAILURES=$((FAILURES + 1))
}

# --------------------------------------------------------------------------- §4
# Helm repo bridge-test — an entry in the SSH account's ~/.config/helm/repositories.yaml.
section_4() {
  if ! ro ssh_helm_repo_list host="$HOST" | grep -q '^bridge-test[[:space:]]'; then
    echo "SECTION 4: already absent"
    return 0
  fi
  mut ssh_helm_repo_remove host="$HOST" names='["bridge-test"]' >/dev/null 2>&1
  if ro ssh_helm_repo_list host="$HOST" | grep -q '^bridge-test[[:space:]]'; then
    echo "SECTION 4: FAILED"
    printf '  helm repo bridge-test still listed\n' >&2
    FAILURES=$((FAILURES + 1))
  else
    echo "SECTION 4: cleaned"
  fi
}

# --------------------------------------------------------------------------- §5
# Throwaway identity: the user first (it is a member of the group), then the group.
section_5() {
  local user_present=0 group_present=0 acted=0 left=0
  ro ssh_user_info host="$HOST" username="$SBXUSER" | grep -q 'no such user' || user_present=1
  ro ssh_group_list host="$HOST" | grep -q -E "^(${SBXGROUP}|${SBXUSER})[[:space:]]" && group_present=1
  if [ "$user_present" -eq 0 ] && [ "$group_present" -eq 0 ]; then
    echo "SECTION 5: already absent"
    return 0
  fi
  if [ "$user_present" -eq 1 ]; then
    mut ssh_user_delete host="$HOST" username="$SBXUSER" remove_home=true sudo=true >/dev/null 2>&1
    acted=1
    ro ssh_user_info host="$HOST" username="$SBXUSER" | grep -q 'no such user' || left=1
  fi
  if [ "$group_present" -eq 1 ]; then
    mut ssh_group_delete host="$HOST" name="$SBXGROUP" sudo=true >/dev/null 2>&1
    acted=1
    ro ssh_group_list host="$HOST" | grep -q "^${SBXGROUP}[[:space:]]" && left=1
  fi
  # useradd silently creates a private primary group named after the user
  # (btest0909, gid 987).  It is a campaign-created object that the 7.1 inventory
  # does not name; userdel normally removes it with the account.  Verify, and remove
  # it only if it survived — leaving it would be a permanent /etc/group change.
  if ro ssh_group_list host="$HOST" | grep -q "^${SBXUSER}[[:space:]]"; then
    mut ssh_group_delete host="$HOST" name="$SBXUSER" sudo=true >/dev/null 2>&1
    acted=1
    ro ssh_group_list host="$HOST" | grep -q "^${SBXUSER}[[:space:]]" && left=1
  fi
  if [ "$left" -eq 0 ] && [ "$acted" -eq 1 ]; then
    echo "SECTION 5: cleaned"
  else
    echo "SECTION 5: FAILED"
    printf '  user %s or group %s survived the delete\n' "$SBXUSER" "$SBXGROUP" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §6
# Cron entries carrying the campaign marker.  Removal is BY PATTERN ONLY, with
# the exact marker; never the whole crontab (see the header).  An empty crontab
# file left behind is an admitted residual trace and is not removed.
section_6() {
  local before after
  before=$(ro ssh_cron_list host="$HOST" | grep -c -E "${CRON_MARK}|bridge-test-0909")
  if [ "$before" -eq 0 ]; then
    echo "SECTION 6: already absent"
    return 0
  fi
  mut ssh_cron_remove host="$HOST" pattern="$CRON_MARK" >/dev/null 2>&1
  after=$(ro ssh_cron_list host="$HOST" | grep -c -E "${CRON_MARK}|bridge-test-0909")
  if [ "$after" -eq 0 ]; then
    echo "SECTION 6: cleaned"
  else
    echo "SECTION 6: FAILED"
    printf '  %s cron line(s) still carry the campaign marker\n' "$after" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §7
# Transient systemd units in /run/systemd/system (a tmpfs), plus the enable
# symlinks that systemctl enable drops under /etc/systemd/system/*.wants/.
# The presence probe runs FIRST and unprivileged: when nothing is there this
# section performs no privileged write at all.
section_7() {
  local probe out
  probe=$(mut ssh_exec host="$HOST" command='a=$(ls /run/systemd/system/bridge-test-0909.* 2>/dev/null | wc -l); b=$(ls /etc/systemd/system/*.wants/bridge-test-0909.* 2>/dev/null | wc -l); echo unitprobe:$((a+b))')
  if printf '%s\n' "$probe" | grep -q 'unitprobe:0'; then
    echo "SECTION 7: already absent"
    return 0
  fi
  out=$(mut ssh_exec host="$HOST" sudo=true command='systemctl disable --now bridge-test-0909.timer bridge-test-0909.service >/dev/null 2>&1; rm -f -- /run/systemd/system/bridge-test-0909.*; rm -f -- /etc/systemd/system/*.wants/bridge-test-0909.*; systemctl daemon-reload >/dev/null 2>&1; a=$(ls /run/systemd/system/bridge-test-0909.* 2>/dev/null | wc -l); b=$(ls /etc/systemd/system/*.wants/bridge-test-0909.* 2>/dev/null | wc -l); echo unitprobe:$((a+b))')
  if printf '%s\n' "$out" | grep -q 'unitprobe:0'; then
    echo "SECTION 7: cleaned"
  else
    echo "SECTION 7: FAILED"
    printf '  unit files survived: %s\n' "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §8
# Unconditional uncordon.  Single-node cluster: if any lane left the node
# cordoned, nothing schedules until this runs.  kubectl is idempotent here and
# answers "already uncordoned" on a node that was never cordoned.
section_8() {
  local out
  out=$(ro ssh_k8s_uncordon host="$HOST" node="$NODE")
  if printf '%s\n' "$out" | grep -q 'uncordoned'; then
    echo "SECTION 8: cleaned"
  else
    echo "SECTION 8: FAILED"
    printf '  uncordon output: %s\n' "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

section_0
section_1
section_2
section_3
section_4
section_5
section_6
section_7
section_8

if [ "$FAILURES" -eq 0 ]; then
  exit 0
fi
echo "teardown: $FAILURES section(s) FAILED" >&2
exit 1
