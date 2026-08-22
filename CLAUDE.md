# CLAUDE.md

## Project Overview

Bridge MCP (binary `bridge-mcp`, formerly MCP SSH Bridge / `mcp-ssh-bridge`) is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **476 tools** across **77 groups** (62 Linux, 13 Windows, 2 cross-platform). Count source of truth: `.migration-baseline.json` (`python3 scripts/validate_baseline.py`).

## CLI-as-Tool Mode (Alternative to MCP)

All 476 MCP tools are accessible directly via CLI, enabling **10-32x token savings** compared to MCP mode. Use CLI for dev workflows, MCP for enterprise integration.

### Quick Reference

```bash
# Invoke any tool directly (same as MCP, but via CLI)
bridge-mcp tool ssh_docker_ps host=prod
bridge-mcp tool ssh_exec host=prod command="df -h" --json
bridge-mcp tool ssh_k8s_get --json-args '{"host":"k8s","resource":"pods","namespace":"default"}'

# Progressive discovery (token-efficient for AI agents)
bridge-mcp list-tools --groups-only          # 77 groups (~2K tokens)
bridge-mcp list-tools --group docker          # tools in group (~500 tokens)
bridge-mcp list-tools --search kubernetes     # keyword search
bridge-mcp describe-tool ssh_docker_ps        # full schema + Reduction Strategy (~200 tokens)
bridge-mcp describe-tool ssh_exec --json      # schema as JSON

# Global --json flag works on all commands
bridge-mcp --json status
bridge-mcp --json tool ssh_service_status host=web1 service=nginx
```

### Token-efficient patterns (IMPORTANT for AI agents)

**Always call `describe-tool` before invoking an unknown tool** — its top-of-output
**Reduction Strategy** line tells you which params apply. Server-side filtering
runs BEFORE truncation, so you never lose data to the output cap.

| Output kind | Strategy | Example |
|---|---|---|
| **Tabular** (`docker_ps`, `service_list`) | `columns` + `limit` | `columns='["NAME","STATUS"]' limit=20` |
| **Json** (`k8s_get`, `docker_inspect`, `awx_*`) | `jq_filter` + `output_format=tsv` | `jq_filter='.items[] \| [.name, .status]' output_format=tsv` (60-80% savings) |
| **Yaml** | `yq_filter` + `output_format=tsv` | same shape as jq |
| **Auto** | Any of the above | tool auto-detects |
| **RawText** (logs, `ssh_exec`) | `save_output=/tmp/out.txt` | read file locally afterwards |

Ergonomic global flags (equivalent to `jq_filter=`, `columns=`, `limit=`, `output_format=`):

```bash
bridge-mcp --jq '.items[] | {name, phase}' --output-format=tsv tool ssh_k8s_get host=k8s resource=pods
bridge-mcp --columns name,status --limit 10 tool ssh_docker_ps host=prod
```

Pagination cycle for truncated output: `[output_id: abc123]` → `bridge-mcp tool ssh_output_fetch output_id=abc123 offset=N`.

Common params on every tool: `host`, `timeout_seconds`, `max_output`, `save_output`.

### When to Use CLI vs MCP

| Use Case | CLI | MCP |
|----------|-----|-----|
| Dev workflows, scripting | Preferred (token-efficient) | Works |
| AI agent integration (Claude Code Bash) | Preferred (progressive discovery) | Works (dumps all schemas) |
| Enterprise (auth, audit, multi-user) | Works | Preferred |
| Claude Desktop / DXT extension | N/A | Required |
| Persistent sessions, output cache | Limited | Full support |

## Build Commands

```bash
make build              # Debug build
make release            # Optimized release build with LTO
make test               # Run tests (uses nextest if available)
make lint               # Run clippy with strict warnings
make ci                 # Quick CI (fmt-check, lint, test, audit, typos)
make ci-full            # Full CI (ci + hack + geiger)
make release-pipeline   # Full release (ci-full + release-all + docker-scan)
make dxt                # Build DXT package (Claude Desktop extension)
make deps-check         # Check outdated/unused deps
make help               # Show all available targets
```

## Architecture Hexagonale (Ports & Adapters)

```
+-------------------------------------------------------------+
|                    ADAPTERS (Externe)                        |
|  +-----------+  +-----------+  +---------------------+      |
|  |MCP Adapter|  |SSH Adapter|  | Config YAML Adapter |      |
|  |(JSON-RPC) |  | (russh)   |  |  (serde-saphyr)     |      |
|  +-----+-----+  +-----+-----+  +----------+----------+      |
+---------+--------------+------------------+-----------------+
          |              |                  |
          v              v                  v
+-------------------------------------------------------------+
|                      PORTS (Traits)                          |
|  +-----------+  +-----------+  +---------------------+      |
|  |ToolHandler|  |SshExecutor|  |  ConfigProvider     |      |
|  |   trait   |  |   trait   |  |      trait          |      |
|  +-----+-----+  +-----+-----+  +----------+----------+      |
+---------+--------------+------------------+-----------------+
          |              |                  |
          v              v                  v
+-------------------------------------------------------------+
|                    DOMAIN (Core Logic)                       |
|  +-----------------------------------------------------+    |
|  |                    Use Cases                         |    |
|  |  ExecuteCommand | ValidateCommand | SanitizeOutput  |    |
|  |  Diagnostics | Runbooks | Orchestration | Drift     |    |
|  +-----------------------------------------------------+    |
|  +-----------------------------------------------------+    |
|  |                    Entities                          |    |
|  |   Command | CommandResult | SecurityPolicy | Host    |    |
|  +-----------------------------------------------------+    |
+-------------------------------------------------------------+
```

## Project Structure

```
src/
├── main.rs, lib.rs, error.rs    # Entry point, exports, errors
├── cli/                          # CLI (feature-gated: clap)
├── config/                       # YAML config loading
├── domain/                       # Pure business logic (use cases, builders)
│   ├── runbook.rs                # Runbook engine (YAML workflows)
│   └── use_cases/                # Command builders (65 modules)
├── ports/                        # Traits (SshExecutor, ToolHandler, ConfigProvider)
├── mcp/                          # MCP protocol adapter + tool_handlers/
├── ssh/                          # SSH client adapter (russh)
└── security/                     # Validation, sanitization, rate limiting
config/
├── config.example.yaml           # Configuration reference
└── runbooks/                     # Built-in runbook YAML definitions
.well-known/mcp/server-card.json  # MCP ecosystem discovery
dxt/                              # DXT packaging (Claude Desktop extension)
```

## Tool Groups Reference

77 groups, 476 tools (62 Linux, 13 Windows, 2 cross-platform). Full reference loaded automatically when editing registry or handlers (see `.claude/rules/tool-groups-reference.md`). Quick overview: `bridge-mcp list-tools --groups-only`.

## Feature Flags

- `default = ["cli"]` — CLI binary (disable for lib-only)
- `full` — CLI + mimalloc + HTTP transport
- `air-gapped` — WinRM + Telnet (no outbound internet required)
- `cloud` — SSM + Azure + GCP (**NOT air-gapped** — requires connectivity to AWS/Azure/GCP APIs; GCP wraps the `gcloud` CLI which must be installed on the bridge host)
- `all-protocols` — All 7 non-SSH adapters (WinRM, Telnet, K8s, Serial, SSM, Azure, GCP)
- See `Cargo.toml` for full feature matrix

## Key Principles

1. **Ports (Traits)**: Define interfaces (`SshExecutor`, `ToolHandler`)
2. **Adapters**: Implement ports (russh, JSON-RPC, YAML)
3. **Domain**: Pure business logic, no external dependencies
4. **Use Cases**: Orchestrate: validation -> execution -> sanitization -> audit
5. **Tool Registry**: Open/Closed pattern for adding tools

## Code Quality

- `#![forbid(unsafe_code)]`
- Clippy with `-D warnings` (all lint groups enabled)
- rustfmt 100 char line width
- cargo-deny for security/license checks
- 6300+ tests (unit, integration, fuzz, mutation)

## Configuration

YAML config at `~/.config/bridge-mcp/config.yaml`. See `config/config.example.yaml`.
Key sections: `hosts`, `security`, `limits`, `audit`, `sessions`, `tool_groups`,
`ssh_config`, `http`, `awx` (full schema: `Config` in `src/config/types.rs`,
`deny_unknown_fields`). Session recording is not a YAML section — it is runtime/
tool-driven (`ssh_recording_*` + `MCP_RECORDING_KEY`). `rbac` still parses (it is
a real `Config` field) but `rbac.enabled: true` is rejected at load time —
nothing in the request path enforces it yet (`src/config/loader.rs`,
`src/security/rbac.rs`). `security.require_elicitation_on_destructive` reads
the elicitation flag from the calling request's
`_meta["io.modelcontextprotocol/clientCapabilities"]` and is **MCP-only** —
`bridge-mcp tool …` on the CLI has no elicitation channel and never prompts.

## Known Advisories

7 advisories actively ignored in `deny.toml` + `.cargo/audit.toml` (keep both files in sync):

- RUSTSEC-2023-0071 — Marvin Attack on RSA (transitive via russh, no upstream fix)
- RUSTSEC-2026-0098 / 0099 / 0104 — rustls-webpki 0.101, pinned by the aws-smithy
  stack (re-triggered by the v1.19.0 dep bumps; `ssm`/`cloud` features only)
- RUSTSEC-2026-0194 / 0195 — quick-xml 0.36 DoS (transitive via psrp-rs;
  `psrp`/`all-protocols` features only). Remove once psrp-rs bumps quick-xml >=0.41.
- RUSTSEC-2026-0258 — h2 unbounded empty DATA frames. Patched in h2 >=0.4.16 only,
  and the lockfile is there; the ignore covers the remaining h2 0.3.27, pulled by
  aws-smithy-http-client with no patched 0.3 release (`ssm`/`cloud` features only).
  cargo-deny cannot scope an advisory ignore to a version, so dropping this entry is
  the test that aws-smithy has left h2 0.3.

Previously ignored (resolved after dep-updates-2026-05-30):
RUSTSEC-2025-0134, RUSTSEC-2026-0049, RUSTSEC-2026-0074

## Path-Scoped Rules

Detailed guidance is loaded automatically via `.claude/rules/`:

- `tool-handlers.md` — Adding tools, handler pattern, clippy pitfalls
- `domain-builders.md` — Domain layer purity, builder conventions
- `security.md` — Security model, blacklist, sanitization
- `registry.md` — Test count assertions, clippy attributes
- `ssh-adapter.md` — Host keys, auth, connection pool, retry
- `testing.md` — Standard tests, fuzz, coverage, mutation
- `config.md` — YAML config, serde conventions, validation, permissions
- `mcp-protocol.md` — JSON-RPC, McpServer, protocol versioning
- `ports.md` — Traits, mock patterns, ToolContext, ExecutorRouter
- `cli.md` — Clap derive, global flags, runner pattern, exit codes
- `tool-groups-reference.md` — Full 77-group tool reference table

## Active Technologies

- Rust 2024 edition, MSRV 1.94 + winrm-rs 1.1, psrp-rs 1.0, russh 0.62, tokio, serde, clap 4

## Recent Changes

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

- **v2.2.0 (2026-08-19)** — major bump for **21 breaking changes, ten in the
  public lib API**. (Two earlier drafts of this line were wrong: "seven, four"
  never reconciled against the CHANGELOG's own numbered list, and "23, nine"
  came from counting `grep -c BREAKING` LINES instead of distinct changes. The
  CHANGELOG now prints the arithmetic — 14 marked bullets + 10 table rows − 3
  in both.) Config/wire: `rbac.enabled: true` is rejected at load (it was
  never enforced and granted full access); `verify_checksum` refuses
  `resume`/`append` instead of returning a checksum-free success; no-`jq` builds
  error on reduction params; `ssh_history` redacts the command itself, so
  entropy detection now masks opaque 16+ char arguments; `chunk_size` is clamped
  to 4 KB..=64 MB; `tools/call` rejects an unlisted name; `resources/subscribe`
  AND `unsubscribe` both return `-32601`; templates publish `{+path}`; a
  notification-only HTTP POST returns `202`, and a cancelled stdio request gets
  no response at all. **`audit.retain_days` starts DELETING archives for the
  first time in any release** — it was documented in every release and executed
  in none, and it fires on the first event after upgrade; `retain_days: 0` opts
  out. Lib: `DataReductionArgs::extract` and `build_log_aggregate_command`
  return `Result`, `truncate_output_with_cache` and
  `Metrics::record_pipeline_stats` gained a parameter, `BridgeError` is
  `#[non_exhaustive]` with a new `RateLimitExceeded` variant,
  `AuditLogger::needs_rotation`/`::rotate` left the public API, `ServerInfo`
  gained `meta`, and `TaskStore::list_tasks` returns `Result` with a new public
  `InvalidCursor`. Also fixes a permanent hang in `TaskStore::wait_for_result`
  on TTL eviction, five command-injection sites, an audit retention sweep that
  deleted files outside its own lineage, an unbounded rename-retry loop, and a
  mutation sweep whose flags cargo-mutants silently ignored. Full migration
  notes in CHANGELOG.md.

- ci-hardening-2026-08: **`rust-toolchain.toml` outranks `rustup default`** — every
  workflow now sets `RUSTUP_TOOLCHAIN` explicitly, because until now every CI job
  silently ran 1.94.0 (MSRV job = duplicate of Tests; the stable/beta/nightly matrix
  tested one compiler three times). Real stable exposed 48 style lints, all fixed.
  Weekly mutation sweep re-scoped (8→24 shards, `--baseline skip`, budget enforced by
  `timeout` inside the step so artifacts always upload — the old 8×300min matrix hit
  the job timeout every week and produced nothing). Doctests now run (`cargo test
  --doc`, 6 of them, never executed before: nextest skips doctests). Release attests
  provenance AFTER the .dxt/.mcpb/SBOM exist, gates tag vs `Cargo.toml` version, and
  ships `.dxt.sha256`. `mcp-publisher` pinned + checksum-verified. Scheduled Security
  / Nightly failures now open a tracking issue. zizmor clean at `--persona=auditor
  --min-severity low` (was 3 high + 29 artipacked).
- token-efficiency-2026-07: truncation messages now suggest jq_filter/columns/limit per OutputKind; no-jq builds reject (and no longer advertise) jq params; per-param reduction adoption metrics; `tool_groups.listing: progressive` lists only 4 meta-schemas (vs ~140K tokens for the full registry) with `mcp_call_tool` dispatch; handler schemas say 40000 (real default), not 20000.
- v1.20.0: russh 0.61->0.62 (channel-open callbacks take a `ChannelOpenHandle`), K3s/CRI/K8s-triage tool expansion (476 tools / 77 groups), CI hardening (least-privilege permissions, MSRV job, test-gated release/docker), `audit.path` tilde expansion, `df -hT` column-parse fix, session/tunnel `close` re-annotated non-destructive.
- 001-winrm-psrp-integration: Added winrm-rs + psrp-rs protocol adapters (russh 0.58->0.60 originally; now 0.62).
- 2026-roadmap-alignment: opt-in `security.require_elicitation_on_destructive` (MCP `elicitation/create` confirmation before any `destructive_hint: true` tool runs); three progressive-discovery meta-tools (`mcp_list_tool_groups`, `mcp_search_tools`, `mcp_describe_tool`) surfaced at the top of `tools/list`; `SessionStore` async trait + `InMemorySessionStore` behind the HTTP session hashmap so a future Redis/Valkey store drops in without touching the handlers.
