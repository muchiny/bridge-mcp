#!/usr/bin/env bash
# Gate: the 3.0.0 CHANGELOG entry exists, carries a MIGRATION section, and
# names every method removed by the Modern-only cut. Run from the repo root.
#
# WHAT THIS IS NOT: it greps CHANGELOG.md for literals. It reads no .rs file,
# builds nothing, and starts no server. It therefore passes on a CHANGELOG
# that describes behaviour the code does not have -- and it DID, for a whole
# cycle, while the HTTP transport contradicted every line it checked here.
#
# It is a regression guard on the PROSE: it stops a rewrite from silently
# dropping a documented removal. What proves the behaviour is the test suite,
# and specifically `src/mcp/transport/http.rs`'s tests for the 405s, the
# required headers and the listen stream. Do not read a green run here as
# evidence about the server.
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
# v2.2.0 was never tagged, so 3.0.0 compares against v1.20.0, the last tag
# that exists. See the note under the 2.2.0 heading in CHANGELOG.md.
check '[3.0.0]: https://github.com/muchiny/bridge-mcp/compare/v1.20.0...v3.0.0'

exit "$fail"
