# CLAUDE.md

## Project Overview

Bridge MCP (binary `bridge-mcp`, formerly MCP SSH Bridge / `mcp-ssh-bridge`) is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **476 tools** across **77 groups** (62 Linux, 13 Windows, 2 cross-platform). Count source of truth: `.migration-baseline.json` (`python3 scripts/validate_baseline.py`).

## CLI-as-Tool Mode (Alternative to MCP)

All 476 MCP tools are reachable from the CLI (`bridge-mcp tool <name> key=value`), for
**10-32x token savings** over MCP mode. CLI for dev workflows, MCP for enterprise
integration and for anything needing persistent sessions or the output cache.

**Full reference — progressive discovery, the per-`OutputKind` reduction strategies,
pagination, global flags — is in the `bridge` skill (`/bridge`).** Load it before
invoking tools; do not re-derive it here.

## Build Commands

`make ci` before every commit (fmt-check, lint, test, audit, typos). `make help` lists
every target.

## Tool Groups Reference

77 groups, 476 tools (62 Linux, 13 Windows, 2 cross-platform). Full reference loaded automatically when editing registry or handlers (see `.claude/rules/tool-groups-reference.md`). Quick overview: `bridge-mcp list-tools --groups-only`.

## Feature Flags

Full matrix in `Cargo.toml`. The one thing the matrix does not say: **`cloud` (SSM +
Azure + GCP) is NOT air-gapped** — it requires connectivity to the AWS/Azure/GCP APIs,
and GCP wraps the `gcloud` CLI, which must be installed on the bridge host.

## Configuration

YAML config at `~/.config/bridge-mcp/config.yaml`, falling back to the legacy
`~/.config/mcp-ssh-bridge/config.yaml` when the current path is absent
(`src/config/loader.rs`). **On this machine only the legacy path exists — that is the
file actually loaded.** Schema is `Config` in
`src/config/types.rs` (`deny_unknown_fields`). Conventions, validation flow and the
non-obvious gotchas (`rbac.enabled` rejected at load, session recording is not a YAML
section) live in
`.claude/rules/config.md`, loaded when you touch config code.

## Known Advisories

7 advisories ignored in `deny.toml` + `.cargo/audit.toml` (keep both in sync). Details
and removal conditions in `.claude/rules/advisories.md`, loaded when you touch those
files.

## Recent Changes

Full history is in CHANGELOG.md. Only the current-state entries live here.

- **Live-host sweep (2026-08-31)** — ten fixes found by running 3.0.0 against a
  Raspberry Pi K3s host, not by reading it. Two are breaking:
  **`bridge-mcp tool` rejects arguments the tool does not declare** (exit 5;
  `jq_fitler=…` used to return the full unreduced output, indistinguishable from
  a working call), and **destructive tools are now gated in the CLI too** —
  prompt on a terminal, exit 4 without one, `--yes` for scripts. So
  `require_elicitation_on_destructive` is **no longer MCP-only**; before this,
  the direct path ran destructive tools unchallenged while the daemon path
  refused them, and the default was the unguarded one.

  **`sudo` / `sudo_user` now work on every standard tool**, not the three that
  had them — without it the whole `cri` group, `firewall`, and every systemd
  write were unreachable on a K3s host. Elevation runs before the blacklist, so
  it cannot launder a denied command.

  Also: the daemon refused all 279 tools (`_meta` envelope); the direct CLI path
  printed MCP Apps blobs (85% of the payload); `--json` was ignored by five of
  seven commands; a timed-out command was replayed three times; output over
  `max_output_bytes` failed outright instead of truncating; and 43 builders used
  a bash-only `&>/dev/null` — with the default blacklist's `>\s*/dev/` denying
  both that and the POSIX form, so those tools were denied under a default
  config either way. That pattern now names device families.

  **Not fixed, known:** the destructive gate runs before the blacklist, so a
  blacklisted command asks for confirmation and is then refused anyway (fails
  closed). The output cache is MCP-only, so CLI truncation is unrecoverable.
  `max_concurrent_commands` does not apply to one-process-per-call CLI runs.

- **Conformance sweep (2026-08-22, on top of 3.0.0)** — found by probing the
  reference client (Claude Code 2.1.239 with `MCP_PROTOCOL_NEGOTIATION=auto`,
  which negotiates Modern over stdio), not by reading. Before it, that client
  connected and then refused `tools/list`, so a Modern client saw ZERO tools.
  Emitted the result members that were missing (`resultType` everywhere,
  `ttlMs`/`cacheScope` on five of six cacheable methods, `serverInfo` on every
  result); made `_meta.protocolVersion` required (`-32602` when absent);
  decoded the `Mcp-Name` Base64 sentinel; served RFC 9728 and put
  `WWW-Authenticate` on the 401 plus a 403 for insufficient scope.
  **The destructive-confirmation gate is now MRTR** — `resultType:
  "input_required"` plus an HMAC-signed `requestState` binding the request
  digest, a 5-minute TTL and the principal (`src/mcp/request_state.rs`; set
  `MCP_REQUEST_STATE_KEY` if more than one process serves one address).
  `inputResponses` count only alongside a state this server signed for that
  exact call. Nineteen handlers that confirmed a SECOND time are gone, so
  `security.require_elicitation_on_destructive` is now the whole confirmation
  policy — **turn it on if you had it off**. `client_requester`, `sampling`,
  `pending_requests`, `ElicitationService` and `WriterMessage::Request` are
  deleted. **All three callers are MRTR now**: the gate, client roots
  (`ROOT_SCOPED_TOOLS`, asked at the gate because `validate_root_scope` runs
  too late to ask from), and `summarize=true` sampling — the last carries the
  finished result inside the `requestState` so the remote command runs once and
  the summary describes the output actually shown (`ToolContext::
  request_summary`, cap `MAX_SEALED_RESULT_BYTES`). Remaining gaps, both
  documented: `notifications/progress` is unreachable over HTTP, and
  `Mcp-Param-*` headers are unvalidated (nothing emits the annotation yet).
  See CHANGELOG.md "Conformance sweep".

- **v3.0.0 (2026-08-20, not yet tagged)** — **Modern-only.** `PROTOCOL_VERSION = "2026-07-28"`,
  `SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28"]`
  (`src/mcp/protocol.rs`, `PROTOCOL_VERSION` and `SUPPORTED_PROTOCOL_VERSIONS`).
  Named rather than cited by line: the previous citation pointed at lines
  894-895, which is unrelated code, and a stale line number in the file agents
  load first is worse than no citation.
  `server/discover` replaces the `initialize` handshake; the only remaining
  `initialize` arm answers `-32022` with the supported-version list, because a
  legacy client cannot fall forward on its own. Protocol revision, client
  identity and client capabilities now arrive in a per-request `_meta`
  envelope (`io.modelcontextprotocol/protocolVersion` / `…/clientInfo` /
  `…/clientCapabilities`) — that is what feeds the fail-closed
  destructive-elicitation gate, so `SessionCapabilities` is gone. Notifications
  are opt-in through `subscriptions/listen` and carry
  `_meta["io.modelcontextprotocol/subscriptionId"]`. Removed: `ping`,
  `logging/setLevel`, `notifications/roots/list_changed`,
  `resources/subscribe`/`unsubscribe`, `notifications/initialized`, the HTTP
  `Mcp-Session-Id` session lifecycle, the `GET /mcp` SSE handler (405 now) and
  `Last-Event-ID` resumption. Tasks moved out of core into the
  `io.modelcontextprotocol/tasks` extension under `capabilities.extensions`.
  Four 2.2.0 fixes are superseded — see the "2.2.0 fixes that 3.0.0
  supersedes" section in CHANGELOG.md before re-applying anything from them.

- **v2.2.0 (2026-08-19)** — 21 breaking changes, ten in the public lib API. Two
  land-mines worth carrying forward: **`audit.retain_days` starts DELETING archives**
  on the first event after upgrade (`retain_days: 0` opts out), and `rbac.enabled:
  true` is now rejected at load because it was never enforced and granted full access.
  Everything else — the wire/config list and the lib-API signature changes — is in
  CHANGELOG.md.
