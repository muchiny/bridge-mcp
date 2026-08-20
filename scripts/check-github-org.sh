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
set -euo pipefail

pattern='(github\.com|githubusercontent\.com|ghcr\.io)/muchini'

if hits=$(grep -rIn -E "$pattern" --exclude-dir=target --exclude-dir=.git .); then
    echo "ERROR: GitHub URLs using the dead 'muchini' org (canonical: muchiny):" >&2
    echo "$hits" >&2
    exit 1
fi

echo "OK: every GitHub URL uses the 'muchiny' org."
