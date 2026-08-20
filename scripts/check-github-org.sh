#!/usr/bin/env bash
# Fail if any GitHub URL in the tree uses the dead `muchini` org spelling.
#
# G-27 (audit 2026-08-19): `serverInfo.icons[0].src` shipped a hard 404 because
# src/mcp/protocol.rs used `muchini` while every other repository URL used
# `muchiny`. CHANGELOG.md:206 records an EARLIER sweep of the same typo that
# missed two constants — this guard makes a third occurrence impossible.
#
# Only URL contexts are matched: `muchini` is also the maintainer's unix
# username and appears legitimately in `ps` output fixtures
# (src/mcp/tool_handlers/ssh_process_list.rs, src/mcp/tool_handlers/utils.rs)
# and in the CHANGELOG prose that documents the fix. Those must NOT be flagged.
#
# MINOR (fix round 1, audit 2026-08-19): two problems fixed here.
# 1. Scanned `.` -- every file on disk, including untracked local scratch
#    (e.g. planning notes under .superpowers/sdd/) that CI never checks
#    out. A dev with local notes mentioning the old org spelling got a
#    false failure this script would never produce in CI. Scans
#    `git ls-files` instead, matching exactly what CI sees.
# 2. `grep`'s exit code 2 means an ERROR (an unreadable file, a bad
#    pattern), not "no match" -- but `if hits=$(grep ...); then ... else
#    echo OK; fi` treated ANY non-zero exit (1 *or* 2) as "clean". A real
#    grep failure would have silently printed OK and exited 0. Exit codes
#    are now checked explicitly. (Deliberately not piped through `xargs`:
#    xargs collapses grep's distinct 0/1/2 exits into its own 0/123/1
#    scheme once it might split the file list across multiple invocations,
#    which would reintroduce the same ambiguity. A single `grep -- "${files[@]}"`
#    call keeps grep's real exit code intact.)
set -euo pipefail

pattern='(github\.com|githubusercontent\.com|ghcr\.io)/muchini'

mapfile -d '' -t files < <(git ls-files -z)

if [ "${#files[@]}" -eq 0 ]; then
    echo "OK: every GitHub URL uses the 'muchiny' org (no tracked files)."
    exit 0
fi

set +e
hits=$(grep -InE "$pattern" -- "${files[@]}" 2>&1)
status=$?
set -e

case "$status" in
    0)
        echo "ERROR: GitHub URLs using the dead 'muchini' org (canonical: muchiny):" >&2
        echo "$hits" >&2
        exit 1
        ;;
    1)
        echo "OK: every GitHub URL uses the 'muchiny' org."
        ;;
    *)
        echo "ERROR: failed to scan the repo for the dead 'muchini' org (grep exit $status):" >&2
        echo "$hits" >&2
        exit 1
        ;;
esac
