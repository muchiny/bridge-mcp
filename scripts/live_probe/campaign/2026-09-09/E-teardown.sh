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
#   * Nine sections from the reference spec, §0 .. §8, in this order.  §0 unmounts
#     the tmpfs BEFORE §1 deletes files, or the delete fails on a busy mount point.
#     §9 is an ADDITION beyond the reference spec — see its own header.
#   * Each section prints exactly one line, `SECTION n: cleaned`,
#     `SECTION n: already absent`, or `SECTION n: FAILED`.
#   * Idempotent: running it twice is safe; the second run prints `already absent`.
#   * Exit 0 when there was nothing to clean or everything was cleaned;
#     exit 1 if any section reports FAILED.
#
# ABSENCE IS PROVED POSITIVELY, NEVER INFERRED FROM A MISSING MATCH.
#   Every presence probe ends in an explicit token — `fileprobe:0` for absent,
#   `fileprobe:1` for present — and a section takes the `already absent` exit ONLY
#   on `grep -qx '<token>:0'`.  Anything else — no output at all, a dropped SSH
#   call, a refusal by the destructive gate, a mangled reduction — falls through to
#   the removal and then demands a positive token before reporting `cleaned`.
#   A probe written the other way round (`if ! grep -q present`) turns silence into
#   proof of cleanliness: the script would print `already absent`, exit 0, and leave
#   the sandbox on the Pi under a "host unchanged" verdict.  That is the one outcome
#   this script exists to make impossible.
#
# NO SECTION INFERS SUCCESS FROM AN EXIT CODE.  The CLI exits 0 even when the remote
# command failed and reports the failure in the body prefixed `[exit:N]` (defect D1);
# a teardown that trusted `$?` would call `[exit:127] userdel: command not found` a
# success.  Every section re-reads the state instead.
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
# ONE privileged write outside $SANDBOX is authorized by the plan (global constraints
# §3.1): /run/systemd/system/bridge-test-0909.*, handled by §7.  Everything else that
# runs elevated in this script targets $SANDBOX itself.  §1 deliberately splits its
# elevated retry so that the `find /tmp …` half, which reaches outside $SANDBOX,
# always runs unprivileged — the snapshot archives belong to the SSH account, which
# can delete them without root.
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
SLEEP_ARGV='sleep 86400'

FAILURES=0
SLEEP_PID_RECORDED=""

# Read-only invocation.  Global flags go BEFORE the `tool` subcommand: `args` is
# declared trailing_var_arg, so a flag placed after a key=value positional is
# swallowed as a positional (src/cli/mod.rs:220-231).
ro()  { "$BIN" tool "$@" 2>&1; }
# Destructive-gated invocation.  ssh_exec is annotated destructiveHint even for a
# read-only payload, so the presence probes below also need --yes; their payloads
# are provably read-only (ls / findmnt / grep / ps / echo) and write nothing anywhere.
mut() { "$BIN" --yes tool "$@" 2>&1; }

# --------------------------------------------------------------- pre-flight
# §1 deletes the sandbox tree, and $SANDBOX/sleep.pid with it.  §9 needs that PID,
# so it is read here, before any section runs.  Only a positive integer above 1 is
# accepted; anything else leaves SLEEP_PID_RECORDED empty and §9 refuses to guess.
preflight_read_sleep_pid() {
  local raw pid
  raw=$(mut ssh_exec host="$HOST" command='if [ -r /tmp/bridge-test-0909/sleep.pid ]; then printf "sleeppid:"; tr -cd "0-9" < /tmp/bridge-test-0909/sleep.pid; echo; else echo sleeppid:none; fi')
  pid=$(printf '%s\n' "$raw" | sed -n 's/^sleeppid:\([0-9][0-9]*\)$/\1/p' | head -1)
  if [ -n "$pid" ] && [ "$pid" -gt 1 ] 2>/dev/null; then
    SLEEP_PID_RECORDED="$pid"
  fi
}

# --------------------------------------------------------------------------- §0
# Unmount the tmpfs first.  A tmpfs mounted as root survives an interrupted lane
# (E501 done, E504 never reached) and makes the §1 delete fail on a busy mount.
section_0() {
  local probe out
  probe=$(mut ssh_exec host="$HOST" command='findmnt -n /tmp/bridge-test-0909/mnt >/dev/null 2>&1 && echo mountprobe:1 || echo mountprobe:0')
  if printf '%s\n' "$probe" | grep -qx 'mountprobe:0'; then
    echo "SECTION 0: already absent"
    return 0
  fi
  # Either mounted, or the probe proved nothing.  Attempt the unmount either way:
  # umount on a path that is not a mount point is a harmless no-op.
  out=$(mut ssh_exec host="$HOST" sudo=true command='umount /tmp/bridge-test-0909/mnt 2>/dev/null; findmnt -n /tmp/bridge-test-0909/mnt >/dev/null 2>&1 && echo mountprobe:1 || echo mountprobe:0')
  if printf '%s\n' "$out" | grep -qx 'mountprobe:0'; then
    echo "SECTION 0: cleaned"
  else
    echo "SECTION 0: FAILED"
    printf '  probe: %s / after umount: %s\n' "$probe" "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §1
# Files: the sandbox tree on the Pi, the timestamped snapshot archives dropped in
# /tmp by ssh_backup_snapshot, and the bridge-side sandbox.
section_1() {
  local probe out local_present=0 probe_cmd del_cmd
  [ -e "$SANDBOX_LOCAL" ] && local_present=1
  probe_cmd='r=0; [ -e /tmp/bridge-test-0909 ] && r=1; c=$(ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l); [ "$c" -gt 0 ] && r=1; echo fileprobe:$r'
  probe=$(mut ssh_exec host="$HOST" command="$probe_cmd")
  if printf '%s\n' "$probe" | grep -qx 'fileprobe:0' && [ "$local_present" -eq 0 ]; then
    echo "SECTION 1: already absent"
    return 0
  fi
  # Either something is there, or the probe proved nothing.  Delete unconditionally:
  # `rm -r --` on an absent path is a no-op, and silence must never read as clean.
  del_cmd='rm -r -- /tmp/bridge-test-0909 2>/dev/null; find /tmp -maxdepth 1 -name "snapshot_bridge-test-0909*" -exec rm -- {} + 2>/dev/null; '"$probe_cmd"
  out=$(mut ssh_exec host="$HOST" command="$del_cmd")
  if ! printf '%s\n' "$out" | grep -qx 'fileprobe:0'; then
    # Elevated retry, restricted to the sandbox tree — a subdirectory written as
    # root by an interrupted lane is the only thing that needs it.  The `find /tmp`
    # half reaches OUTSIDE $SANDBOX and therefore never runs elevated: global
    # constraints §3.1 names /run/systemd/system/bridge-test-0909.* as the only
    # authorized root write outside the sandbox.  The snapshot archives are created
    # by the SSH account, so the unprivileged pass above already removes them.
    mut ssh_exec host="$HOST" sudo=true command='rm -r -- /tmp/bridge-test-0909 2>/dev/null; echo elevated-retry-done' >/dev/null 2>&1
    out=$(mut ssh_exec host="$HOST" command="$del_cmd")
  fi
  # Bridge-side sandbox.  </dev/null so a write-protected file can never turn the
  # delete into an interactive prompt that would hang the script.
  rm -r -- "$SANDBOX_LOCAL" </dev/null 2>/dev/null
  if printf '%s\n' "$out" | grep -qx 'fileprobe:0' && [ ! -e "$SANDBOX_LOCAL" ]; then
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
# `NotFound` is kubectl's own positive statement that the object is gone, so this
# probe is already a positive proof and needs no token.
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
# A listing that shows neither the repo nor a recognisable shape proves nothing:
# helm's own `NAME` header, or its "no repositories to show" error, is the positive
# evidence that the listing really ran.
section_4() {
  local repos
  repos=$(ro ssh_helm_repo_list host="$HOST")
  if ! printf '%s\n' "$repos" | grep -q '^bridge-test[[:space:]]'; then
    if printf '%s\n' "$repos" | grep -qE '^NAME[[:space:]]|no repositories to show'; then
      echo "SECTION 4: already absent"
      return 0
    fi
    echo "SECTION 4: FAILED"
    printf '  helm repo listing is inconclusive, absence cannot be proved: %s\n' "$repos" >&2
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  mut ssh_helm_repo_remove host="$HOST" names='["bridge-test"]' >/dev/null 2>&1
  repos=$(ro ssh_helm_repo_list host="$HOST")
  if ! printf '%s\n' "$repos" | grep -q '^bridge-test[[:space:]]' &&
     printf '%s\n' "$repos" | grep -qE '^NAME[[:space:]]|no repositories to show'; then
    echo "SECTION 4: cleaned"
  else
    echo "SECTION 4: FAILED"
    printf '  helm repo bridge-test still listed, or listing inconclusive: %s\n' "$repos" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §5
# Throwaway identity: the user first (it is a member of the group), then the group.
# `no such user` is getent's positive statement of absence.  For groups there is no
# such message, so the `GROUP` header of the listing is the positive evidence that
# the listing really ran — without it, a missing match proves nothing.
section_5() {
  local user_present=0 group_present=0 acted=0 left=0 groups
  ro ssh_user_info host="$HOST" username="$SBXUSER" | grep -q 'no such user' || user_present=1
  groups=$(ro ssh_group_list host="$HOST")
  if ! printf '%s\n' "$groups" | grep -q '^GROUP[[:space:]]'; then
    echo "SECTION 5: FAILED"
    printf '  group listing has no GROUP header, absence cannot be proved: %s\n' "$groups" >&2
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  printf '%s\n' "$groups" | grep -q -E "^(${SBXGROUP}|${SBXUSER})[[:space:]]" && group_present=1
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
  fi
  # useradd silently creates a private primary group named after the user
  # (btest0909, gid 987).  It is a campaign-created object that the 7.1 inventory
  # does not name; userdel normally removes it with the account.  Verify, and remove
  # it only if it survived — leaving it would be a permanent /etc/group change.
  groups=$(ro ssh_group_list host="$HOST")
  if printf '%s\n' "$groups" | grep -q "^${SBXUSER}[[:space:]]"; then
    mut ssh_group_delete host="$HOST" name="$SBXUSER" sudo=true >/dev/null 2>&1
    acted=1
  fi
  groups=$(ro ssh_group_list host="$HOST")
  if ! printf '%s\n' "$groups" | grep -q '^GROUP[[:space:]]'; then
    left=1
  elif printf '%s\n' "$groups" | grep -q -E "^(${SBXGROUP}|${SBXUSER})[[:space:]]"; then
    left=1
  fi
  if [ "$left" -eq 0 ] && [ "$acted" -eq 1 ]; then
    echo "SECTION 5: cleaned"
  else
    echo "SECTION 5: FAILED"
    printf '  user %s or group %s survived the delete, or the re-read proved nothing\n' "$SBXUSER" "$SBXGROUP" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §6
# Cron entries carrying the campaign marker.  Removal is BY PATTERN ONLY, with
# the exact marker; never the whole crontab (see the header).  An empty crontab
# file left behind is an admitted residual trace and is not removed.
#
# The probe counts through ssh_exec rather than ssh_cron_list because an empty
# crontab and a failed call both render as empty output: only an explicit token
# distinguishes "no campaign entry" from "the listing never happened".
section_6() {
  local probe out probe_cmd
  probe_cmd='n=$(crontab -l 2>/dev/null | grep -c -E "BRIDGE_TEST_0909|bridge-test-0909"); echo cronprobe:$n'
  probe=$(mut ssh_exec host="$HOST" command="$probe_cmd")
  if printf '%s\n' "$probe" | grep -qx 'cronprobe:0'; then
    echo "SECTION 6: already absent"
    return 0
  fi
  mut ssh_cron_remove host="$HOST" pattern="$CRON_MARK" >/dev/null 2>&1
  out=$(mut ssh_exec host="$HOST" command="$probe_cmd")
  if printf '%s\n' "$out" | grep -qx 'cronprobe:0'; then
    echo "SECTION 6: cleaned"
  else
    echo "SECTION 6: FAILED"
    printf '  probe: %s / after removal: %s\n' "$probe" "$out" >&2
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
  if printf '%s\n' "$probe" | grep -qx 'unitprobe:0'; then
    echo "SECTION 7: already absent"
    return 0
  fi
  out=$(mut ssh_exec host="$HOST" sudo=true command='systemctl disable --now bridge-test-0909.timer bridge-test-0909.service >/dev/null 2>&1; rm -f -- /run/systemd/system/bridge-test-0909.*; rm -f -- /etc/systemd/system/*.wants/bridge-test-0909.*; systemctl daemon-reload >/dev/null 2>&1; a=$(ls /run/systemd/system/bridge-test-0909.* 2>/dev/null | wc -l); b=$(ls /etc/systemd/system/*.wants/bridge-test-0909.* 2>/dev/null | wc -l); echo unitprobe:$((a+b))')
  if printf '%s\n' "$out" | grep -qx 'unitprobe:0'; then
    echo "SECTION 7: cleaned"
  else
    echo "SECTION 7: FAILED"
    printf '  probe: %s / unit files survived: %s\n' "$probe" "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §8
# Unconditional uncordon.  Single-node cluster: if any lane left the node
# cordoned, nothing schedules until this runs.  kubectl is idempotent here and
# answers `node/server already uncordoned` on a node that was never cordoned —
# which is `already absent` in this script's vocabulary, not `cleaned`.
section_8() {
  local out
  out=$(ro ssh_k8s_uncordon host="$HOST" node="$NODE")
  if printf '%s\n' "$out" | grep -q 'already uncordoned'; then
    echo "SECTION 8: already absent"
  elif printf '%s\n' "$out" | grep -q 'uncordoned'; then
    echo "SECTION 8: cleaned"
  else
    echo "SECTION 8: FAILED"
    printf '  uncordon output: %s\n' "$out" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# --------------------------------------------------------------------------- §9
# BEYOND THE REFERENCE SPEC, which stops at §8.
#
# The reference teardown has no section for a process because the original plan
# created a `sleep 600`, which self-terminates in ten minutes and therefore needs no
# owner.  Ruling R11 changed it to `sleep 86400` so that it would outlive the
# campaign — and that turned it into a residual with nobody to reclaim it.  §9 is
# that owner.  It is numbered 9 so that Task 7's `grep -c 'SECTION [0-8]:'` check on
# the reference sections keeps measuring exactly what it was written to measure.
#
# IDENTITY GUARD, NON-NEGOTIABLE.  A PID is killed only when BOTH hold: it was
# recorded by the campaign in $SANDBOX/sleep.pid (read in the pre-flight, before §1
# deletes that file), AND its argv right now is exactly `sleep 86400`.  PIDs are
# recycled and the Pi creates processes continuously (K3s, the media-backup
# CronJob); ssh_process_kill guards nothing but PID 0 and 1 (process.rs:73).  An
# unrecorded `sleep 86400` may well belong to the user and is NEVER killed — it is
# reported so a human can decide.
section_9() {
  local probe out cmd i
  if [ -z "$SLEEP_PID_RECORDED" ]; then
    probe=$(mut ssh_exec host="$HOST" command='p=$(pgrep -f "^sleep 86400$" | tr "\n" " "); if [ -z "$p" ]; then echo sleepprobe:0; else echo "sleepprobe:unattributed $p"; fi')
    if printf '%s\n' "$probe" | grep -qx 'sleepprobe:0'; then
      echo "SECTION 9: already absent"
      return 0
    fi
    echo "SECTION 9: FAILED"
    printf '  no pid recorded in %s/sleep.pid and the probe did not prove absence: %s\n' "$SANDBOX" "$probe" >&2
    printf '  refusing to kill a pid this campaign cannot attribute to itself\n' >&2
    FAILURES=$((FAILURES + 1))
    return 0
  fi

  cmd='a=$(ps -p PIDHERE -o args= 2>/dev/null); if [ -z "$a" ]; then echo sleepprobe:0; elif [ "$a" = "ARGVHERE" ]; then echo sleepprobe:1; else echo sleepprobe:recycled; fi'
  cmd=${cmd//PIDHERE/$SLEEP_PID_RECORDED}
  cmd=${cmd//ARGVHERE/$SLEEP_ARGV}
  probe=$(mut ssh_exec host="$HOST" command="$cmd")

  if printf '%s\n' "$probe" | grep -qx 'sleepprobe:0'; then
    echo "SECTION 9: already absent"
    return 0
  fi
  if printf '%s\n' "$probe" | grep -qx 'sleepprobe:recycled'; then
    # A process keeps its pid for life, so a pid now running something else proves
    # the campaign's sleep exited.  Absent — and emphatically not a kill target.
    echo "SECTION 9: already absent"
    printf '  note: pid %s now runs a different process; the campaign sleep is gone, nothing was signalled\n' "$SLEEP_PID_RECORDED" >&2
    return 0
  fi
  if ! printf '%s\n' "$probe" | grep -qx 'sleepprobe:1'; then
    echo "SECTION 9: FAILED"
    printf '  identity guard proved nothing for pid %s: %s\n' "$SLEEP_PID_RECORDED" "$probe" >&2
    FAILURES=$((FAILURES + 1))
    return 0
  fi

  mut ssh_process_kill host="$HOST" pid="$SLEEP_PID_RECORDED" signal=TERM >/dev/null 2>&1
  for i in 1 2 3; do
    out=$(mut ssh_exec host="$HOST" command="$cmd")
    if printf '%s\n' "$out" | grep -qxE 'sleepprobe:(0|recycled)'; then
      echo "SECTION 9: cleaned"
      return 0
    fi
    sleep 2
  done
  echo "SECTION 9: FAILED"
  printf '  pid %s still runs %s after TERM: %s\n' "$SLEEP_PID_RECORDED" "$SLEEP_ARGV" "$out" >&2
  FAILURES=$((FAILURES + 1))
}

preflight_read_sleep_pid
section_0
section_1
section_2
section_3
section_4
section_5
section_6
section_7
section_8
section_9

if [ "$FAILURES" -eq 0 ]; then
  exit 0
fi
echo "teardown: $FAILURES section(s) FAILED" >&2
exit 1
