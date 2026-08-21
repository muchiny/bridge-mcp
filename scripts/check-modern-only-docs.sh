#!/usr/bin/env bash
# Gate: the shipped prose describes a Modern-only (2026-07-28) server.
# Not a spell-checker — it looks for the specific claims that became false
# when the legacy handshake and the GET-SSE stream were deleted.
set -euo pipefail

fail=0

must_have() {  # file, literal
  if grep -qF -- "$2" "$1"; then
    printf 'ok    %s :: %s\n' "$1" "$2"
  else
    printf 'MISS  %s :: %s\n' "$1" "$2"
    fail=1
  fi
}

must_not_have() {  # file, literal
  if grep -qF -- "$2" "$1"; then
    printf 'STALE %s :: %s\n' "$1" "$2"
    fail=1
  else
    printf 'ok    %s :: (absent) %s\n' "$1" "$2"
  fi
}

must_have    README.md 'MCP-2026--07--28'
must_have    README.md '2026-07-28'
must_have    README.md 'server/discover'
must_have    README.md 'subscriptions/listen'
must_have    README.md '-32022'
must_not_have README.md '2025-11-25'
# The plan asked for `must_not_have README.md 'Mcp-Session-Id'`. That check is
# unsatisfiable alongside the same task's own required prose, which must say
# "There is no `Mcp-Session-Id`..." to document the removal: a substring search
# cannot tell "documented as removed" from "documented as still supported".
# Asserting the NEGATION SENTENCE instead keeps a real guard — it fails if the
# removal stops being documented, and it cannot be satisfied by a stale claim
# that the header still works.
must_have     README.md 'There is no `Mcp-Session-Id`'

must_have     .well-known/mcp/server-card.json '"modern_only"'
must_have     .well-known/mcp/server-card.json 'server/discover'
must_have     .well-known/mcp/server-card.json 'subscriptions/listen'
must_not_have .well-known/mcp/server-card.json '"tasks": true'
must_have     dxt/manifest.json 'MCP 2026-07-28'
must_have     dxt/README.md '2026-07-28'
must_not_have dxt/README.md '"version": "2.2.0"'
must_have     CLAUDE.md '2026-07-28'
must_have     CLAUDE.md 'server/discover'
must_not_have CLAUDE.md 'PROTOCOL_VERSION = "2025-11-25"'

exit "$fail"
