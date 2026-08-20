#!/usr/bin/env bash
# Gate: the 3.0.0 CHANGELOG entry exists, carries a MIGRATION section, and
# names every method removed by the Modern-only cut. Run from the repo root.
set -euo pipefail

fail=0
check() {
  if grep -qF -- "$1" CHANGELOG.md; then
    printf 'ok   %s\n' "$1"
  else
    printf 'MISS %s\n' "$1"
    fail=1
  fi
}

check '## [3.0.0]'
check '### MIGRATION — read this before upgrading'
check '-32022'
check 'server/discover'
check 'subscriptions/listen'
check 'io.modelcontextprotocol/protocolVersion'
check '`initialize`'
check '`notifications/initialized`'
check '`ping`'
check '`logging/setLevel`'
check '`resources/subscribe`'
check '`resources/unsubscribe`'
check '`notifications/roots/list_changed`'
check 'Mcp-Session-Id'
check 'Last-Event-ID'
check 'Mcp-Method'
check 'Mcp-Name'
check '[3.0.0]: https://github.com/muchiny/bridge-mcp/compare/v2.2.0...v3.0.0'

exit "$fail"
