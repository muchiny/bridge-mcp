# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.19.0] - 2026-06-19

### Added

- **Claude Code plugin marketplace** — `.claude-plugin/marketplace.json` lets the
  plugin install via `claude plugin marketplace add muchiny/bridge-mcp` then
  `claude plugin install bridge-mcp@muchiny`. The `SessionStart` hook now detects a
  missing `bridge-mcp` binary and prints the `cargo install --git` bootstrap.

### Fixed

- **Structured output for tabular tools** — `ssh_process_list`, `ssh_service_list`
  and `ssh_net_connections` returned empty or garbled structured rows on real host
  output: the space-gutter parser merged columns on tight `ps aux` spacing (8-char
  user + 7-digit PID), lost the header on `systemctl --no-legend`, and sliced the
  `ss` header mid-word (Process packed onto Peer). These known-schema tools are now
  parsed positionally via `utils::parse_fixed_columns`; `net_connections` adapts to
  the `Netid` column only emitted by `ss -tunap`. `docker_ps`/`docker_stats` gain a
  positional name fallback. Verified live across all variants.
- Corrected the GitHub handle typo `muchini` → `muchiny` in every repository URL,
  manifest, and `CODEOWNERS` entry (the unix username `muchini` is unchanged).

### Changed

- Bumped `kube` 3.1→4.0, `k8s-openapi` 0.27→0.28, `tower-http` 0.6→0.7, plus 73
  semver-compatible lockfile updates (all compile with no code changes).
- Rebranded user-facing display strings `"MCP SSH Bridge"` → `"Bridge MCP"`.
- Added +79 targeted unit tests (session capabilities, telemetry, known_hosts,
  pidfile, and several tool handlers).

## [1.18.0] - 2026-05-31

### Added

- **`RedactedSecret` newtype** (`src/config/secret.rs`) — a leak-proof,
  zeroize-on-drop string secret whose `Debug`, `Display`, and `Serialize`
  impls emit `"[REDACTED]"` by construction, with transparent `Deserialize`
  and a `Deref<Target = str>` / `as_str()` audited escape hatch. Intentionally
  omits `PartialEq`/`Hash` (timing-side-channel rationale documented).

### Security

- Migrated **every in-memory secret** to `RedactedSecret`: SSH password, key
  passphrase, NTLM password, `sudo_password`, SOCKS proxy password, AWX OAuth
  token, the three DB-handler `db_password` args, and vault `data` pairs.
  - **F1** — closes a `Debug` cleartext leak (`zeroize::Zeroizing` forwards
    `Debug`, so any `{:?}` on a credential-bearing struct printed the secret).
  - **F2** — closes the matching `Serialize` cleartext leak.
  - **F3** — the AWX OAuth token (previously a bare `String`) is now zeroized
    and redacted.
- **F4** — added an `Authorization: Bearer` sanitizer pattern that redacts
  opaque (non-JWT) bearer tokens from command output/audit even when the
  entropy detector is disabled; ordered after the JWT pattern so JWTs keep
  their `[JWT_TOKEN_REDACTED]` marker.

### Changed

- Dependency bumps: `russh` 0.60 → 0.61, `serde-saphyr` 0.0.21 → 0.0.27,
  `jsonwebtoken` 9 → 10, `sha2` 0.10 → 0.11, `similar` 2 → 3, OpenTelemetry
  stack 0.31 → 0.32, `winrm-rs` 1.0 → 1.1.2 (drops the git-fork patch).

## [1.17.0] - 2026-05-10

### Summary

**Full security audit (2026-05-09) — 30+ findings remediated across YAML
parsing, JWT validation, transport defaults, session isolation, secret
zeroization, and tool-group exposure.** Two BREAKING default flips
(FIND-022 elicitation + FIND-024 tool_groups) plus per-session isolation
hardening (FIND-033/034/035/036/037/038), Zeroizing on every cred-bearing
struct (FIND-014/028/029/030), saphyr Budget on every YAML parse site
(FIND-001/002/004/032), OAuth/JWT spec compliance (FIND-006/007),
russh algo pinning + rekey limits (FIND-008), HTTP middleware hardening
(FIND-005), SSH error sanitization (FIND-016), `deny_unknown_fields`
on every config struct (FIND-017), and supply-chain cleanup
(FIND-018/025/026/027). Test suite: ~6,973 → 7,200+ tests (new
integration suites: `cross_session_cancel`, `multisession_isolation`,
`per_session_state`, `per_session_log_level`, `oauth_keys_loaded`,
`saphyr_budget`, `deny_unknown_fields`, `destructive_default`,
`http_middleware`, `ssh_config_discovery_default`, `ssh_preferred_algos`,
`sudo_password_zeroizing`, `security_audit_redaction`).

### Changed (BREAKING)

- **Security: `tool_groups` default-disabled, ships an 8-group minimal
  profile** (FIND-024). The pre-FIND-024 behaviour was "unlisted =
  enabled": `tool_groups: { groups: {} }` registered all 75 groups /
  357 handlers out of the box. An operator who only needed `docker` +
  `service` was also exposed to AD/LDAP/Vault/K8s/AWS/ESXi/HyperV /
  Windows-only handlers. Unlisted groups now resolve via membership in
  the new `MINIMAL_DEFAULT_GROUPS` const: `[core, file_ops, directory,
  process, monitoring, network, systemd, sessions]` — everything else
  requires explicit opt-in via `tool_groups.groups: { groupname: true }`.
  Operators who relied on the old all-enabled behaviour must enumerate
  the groups they need (or set every group they want to `true`).
  Migration documented in `config/config.example.yaml`.

- **Security: `security.require_elicitation_on_destructive` now defaults to
  `true`** (was `false`). Destructive tools annotated `destructive_hint: true`
  (e.g., `ssh_process_kill`, `ssh_file_write`, `ssh_k8s_delete`,
  `ssh_terraform_apply`, …) now require MCP `elicitation/create`
  confirmation by default. Operators who relied on the old permissive
  behaviour must explicitly set
  `security.require_elicitation_on_destructive: false` in their config
  (NOT RECOMMENDED in production — a compromised MCP client could
  otherwise mass-execute destructive tools without surfacing to a human).

- **Security: `SshConfigDiscovery` default off** (FIND-023). `~/.ssh/config`
  is no longer parsed unless the operator explicitly opts in. Eliminates
  the implicit on-disk attack surface for hosts not declared in
  `config.yaml`.

### Security

- **YAML parser: enforce saphyr `Budget` on every parse site**
  (FIND-001/002/004/032). Caps node count + alias depth + recursion to
  prevent resource-exhaustion via crafted runbooks/configs.
- **HTTP transport: defaults to loopback; refuses anonymous public bind.**
  Public bind requires explicit auth + origin allowlist.
- **HTTP middleware: timeout + body-limit + request-id + sensitive-header
  redaction** (FIND-005).
- **JWT: signature verification via `jsonwebtoken` (Vuln 2)** + require
  `sub`/`iss`/`aud` spec claims (FIND-007).
- **OAuth: load keys at boot, share `Arc<OAuthValidator>`** (FIND-006).
- **russh: pin `Preferred` algorithms + rekey limits** (FIND-008).
- **SSH errors: sanitize at every connect-phase site** (FIND-016) —
  no more leaking key paths/host details on auth failure.
- **Path traversal: canonicalize in `validate_root_scope` (Vuln 11).**
- **Audit log: sanitize commands before write** — no plaintext secrets.
- **Heredoc: randomize terminator in `template_apply`** — defeats
  attacker-supplied terminator injection.
- **Env vars: validate names in `file_template` builder.**
- **LDAP: RFC 4515-escape values in filters.**
- **systemd: allowlist `unit_type` in `list_command`.**
- **Firewall: allowlist protocol values.**
- **Blacklist matcher: normalize `${IFS}` / `$'\t'` / line-continuation
  before match** (defeats common bypass tricks).
- **Per-session isolation:**
  - `PendingRequests` (Vuln 8 part 2) + UUID-based unguessable IDs
    (Vuln 8 part 1)
  - `SessionCapabilities` (Vuln 9)
  - `active_requests` map (FIND-038)
  - `runtime` / `notification` / `resource_subs` / `roots` (FIND-033/034/036/037)
  - `log_level` (FIND-035)
- **Secret zeroization:**
  - `HostConfig.sudo_password` (FIND-028)
  - `db_password` Args (FIND-029)
  - vault `Args.data` (FIND-030)
  - `SocksProxyConfig.password` (FIND-014)
  - vault/db secrets piped via stdin/tempfile (FIND-031)
- **`deny_unknown_fields` on every config + runbook struct** (FIND-017) —
  unknown keys are now hard errors, not silent ignores.

### Changed

- **Reliability: replace `expect`/`unwrap` with `?`/`Err` on Result-returning
  functions** (FIND-010/011/012/013).
- **Clippy clean across `--workspace --all-targets --all-features`**
  (FIND-019/020).
- **CI: `cargo-geiger` fallback + baseline** (FIND-021).
- **Domain layer: move YAML helper into domain/** (hexagonal compliance).

### Removed / Deps

- **Drop archived `shellexpand`, use `dirs::home_dir`** (FIND-025).
- **Patch `winrm-rs` to drop obsolete `reqwest` feature** (FIND-018).
- **Supply-chain monitoring entries for `saphyr` + `tokio-socks`**
  (FIND-026/027).

## [1.16.0] - 2026-05-03

### Summary

**MCP interactive integration: Phase D/E/F/G across 38 handlers + mutation
testing harden across 27 modules.** Long-running tools now stream
per-step progress, destructive tools confirm via elicitation, diagnostic
tools optionally enrich output via LLM sampling, and multi-step tools
emit structured logs through `notifications/message`. Test suite grew
from 6,934 to 6,973 tests; mutation kill rate is now 99 %+ on the
testable surface across 27 hot files.

### Added

- **Phase D — Per-step progress notifications.** Long-running multi-host
  tools (`ssh_exec_multi`, `ssh_metrics_multi`, `ssh_runbook_execute`,
  `ssh_log_search_multi`, `ssh_log_tail_multi`) now emit
  `notifications/progress` for each host or step, so clients with a
  progress UI can render real-time completion instead of a single
  black-box wait.
- **Phase E — Elicitation on destructive tools.** 18 destructive
  handlers gain a `security.require_elicitation_on_destructive`
  opt-in: when enabled and the client advertises the elicitation
  capability, the server sends `elicitation/create` and short-circuits
  with a structured error if the user declines. Affected tools include
  `ssh_cron_remove`, `ssh_file_patch`, `ssh_file_write`,
  `ssh_files_write`, `ssh_firewall_deny`, `ssh_group_delete`,
  `ssh_helm_uninstall`, `ssh_hyperv_vm_stop`, `ssh_k8s_delete`,
  `ssh_net_equip_config`, `ssh_process_kill`, `ssh_reg_delete`,
  `ssh_service_stop`, `ssh_template_apply`, `ssh_win_feature_remove`,
  `ssh_win_firewall_remove`, `ssh_win_process_kill`,
  `ssh_win_service_stop`.
- **Phase F — Optional LLM sampling on diagnostic tools.** 13
  diagnostic handlers add a `summarize=true` flag (with
  `summary_max_tokens` cap) that asks the client's LLM to analyse the
  raw output via `sampling/createMessage` and appends the summary
  alongside the raw data. Falls through to raw-only when the client
  doesn't advertise sampling. Tools: `ssh_diagnose`,
  `ssh_security_audit`, `ssh_log_aggregate`, `ssh_compliance_check`,
  `ssh_compliance_score`, `ssh_compliance_report`, `ssh_vuln_scan`,
  `ssh_journal_query`, `ssh_compare_state`, `ssh_env_diff`,
  `ssh_env_drift`, `ssh_incident_correlate`, `ssh_incident_triage`.
- **Phase G — MCP-side structured logging.** 8 long-running tools
  (`ssh_runbook_execute`, `ssh_ansible_playbook`, `ssh_helm_install`,
  `ssh_helm_upgrade`, `ssh_helm_rollback`, `ssh_terraform_apply`,
  `ssh_k8s_rollout`, `ssh_security_audit`) emit per-step
  `notifications/message` so clients can stream the playbook /
  rollout / audit log to their UI instead of waiting for the bulk
  result.
- **Async pre-execute and enrich hooks** on `StandardTool` so handlers
  can drive elicitation / sampling / logging without re-implementing
  the 16-step pipeline.

### Changed

- **Tool count: 338 → 357 across 75 groups** (was 74). The
  `total_tools` and `total_groups` fields on the `mcp_list_tool_groups`
  response, the DXT manifest, and the `.well-known/mcp/server-card.json`
  all reflect the new totals.
- **`Metrics::render_token_summary` arithmetic refactor.** The two
  inner `if before > 0 { saved * 100 / before } else { 0 }` and
  `if total_kind > 0 { *count * 100 / total_kind } else { 0 }` checks
  are now removed — the outer guards already prove both denominators
  positive, so the dead branches are inlined as direct divisions.
  Behaviour identical, surface for arithmetic mutations reduced.

### Tests

- **Mutation testing: 27 modules, ~99 % kill rate on viable mutants.**
  Files now at 100 % kill rate (excluding provably-equivalent or
  feature-gated mutants): `mcp/{elicitation, sampling, progress,
  logger, meta_tools, pending_requests, client_requester,
  instructions, protocol}.rs`, `domain/{output_kind, output_cache,
  diff, output_truncator, runbook, history, task_store,
  data_reduction}.rs`, `metrics.rs`, `security/{rbac, validator,
  audit, rate_limiter}.rs`, `ports/{tools, executor, protocol}.rs`.
  Two mutants on `mcp/standard_tool.rs` (audit-log content + warn
  tracing) remain — killing them needs a tracing-subscriber and
  audit-log file harness, deferred.
- **Test count: 6 934 → 6 973 lib tests** (+39 net new). New tests
  include `tokio::time::timeout`-bounded shortcuts on
  `ToolContext::elicit_confirm` / `sample`, async-cache twins of the
  truncator arithmetic invariants, two-kind percentage assertions on
  `render_token_summary`, single-field `is_empty` cases on
  `ToolAnnotations`, exact-byte 160/161-char truncation cases, and a
  threaded `floor_char_boundary` / `ceil_char_boundary` termination
  check that catches `i /= 1` / `i *= 1` infinite-loop mutants.
- **`.cargo/mutants.toml` `exclude_re`** now lists ten classes of
  provably equivalent or untestable-without-Clock-injection
  mutations: `ToolHandler::output_kind` defaults, empty-vec
  `scoped_paths`, jq-feature-gated bodies, OutputCache TTL
  boundaries, `floor`/`ceil` short-circuit equivalents, infinite-loop
  arithmetic on the boundary scanners, ConfigWatcher fs-timing /
  filter mutations, AuditLogger TTL boundary, and the `> -> <`
  `u64`-zero comparison family in `render_token_summary`.

## [1.15.1] - 2026-04-30

### Summary

**Stdio transport silent-exit regression fix** — `bridge-mcp serve` now actually responds to JSON-RPC requests. Affects every client that spawns the binary in stdio mode (Claude Desktop, DXT, Claude Code via `.mcp.json`).

### Fixed

- **Stdio MCP server died before reading any client message** (regression introduced in 1.13.0 by commit `927f278`, "feat(transport): factor run() into serve<T: Transport> + serve_session()"). The refactor moved the per-session reader loop into a detached `tokio::spawn`, but the `JoinHandle` was discarded. For the single-session stdio transport, `accept()` returned `Some(Session)` once and then `None` on the next call, the accept loop exited, `serve()` returned, `main()` exited, and tokio aborted the still-warming-up `serve_session` task before it had read a single byte from stdin. Symptom: `MCP SSH Bridge server starting...` immediately followed by `Transport accept loop ended, shutting down` on stderr, empty stdout, exit 0. Versions 1.13.0 / 1.14.0 / 1.15.0 are all affected — 1.11.0 and earlier are fine because the reader loop was inlined in `run()`.
- **Daemon mode shutdown now drains in-flight Unix-socket sessions** instead of abandoning them when the listener stops.

### Internal

- **`McpServer::serve<T: Transport>`** now collects spawned session tasks in a `tokio::task::JoinSet` and drains the set after the accept loop exits, before tearing down `session_manager`, `connection_pool`, and the transport. New log lines `Transport accept loop ended, draining in-flight sessions` and `All sessions drained, shutting down` make the lifecycle explicit.
- **New regression test `tests/stdio_transport_e2e.rs`** spawns the real binary, pipes a JSON-RPC `initialize` request to its stdin, and asserts that a well-formed response comes back on stdout within 5 seconds. The pre-existing 6857-test suite missed this regression because `accept()` and `serve_session()` were tested in isolation but never their composition via `serve<T>()`.

## [1.15.0] - 2026-04-27

### Summary

**`jq_filter` no-longer silently no-ops** | **DNS-1123 namespace validation across all 16 k8s/helm handlers** | **`ssh_k8s_top` gains `--all-namespaces`** | **`parse_columnar_output` handles tab-separated and ss-style headers**

### Added

- **`KubernetesCommandBuilder::validate_namespace`** — DNS-1123 label validator (`[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`) wired into all 16 k8s/helm handlers' `build_command`. Rejects flag-like values such as `namespace=--all-namespaces` (previously accepted as a literal name and silently producing "No resources found"), uppercase, and oversized inputs at the boundary, before the command reaches kubectl/helm. Returns `BridgeError::CommandDenied` with a descriptive reason.
- **`ssh_k8s_top` `all_namespaces` flag** — `SshK8sTopArgs` and the JSON schema gain a boolean field; `build_top_command` propagates `-A` to kubectl. Users no longer need to fall back to `ssh_exec command="kubectl top pods -A"`.
- **Tab-separated branch in `parse_columnar_output`** — when the header line contains `\t` (e.g. `helm list -A`), columns are split on tab. The space-aligned algorithm previously emitted a single concatenated header cell (`"name   namespace  revision …"`) that broke `--columns` filtering.
- **JSON-shape guard in `parse_columnar_output`** — input whose first non-empty char is `{` or `[` is rejected. Without the `jq` feature, raw kubectl JSON used to fall through to `post_process` and produce mangled TSV with tab-padded JSON lines.
- **Runtime warning when `jq_filter` is requested without the feature** — `DataReductionArgs::extract` now strips `jq_filter`/`yq_filter`/`output_format` from the JSON args and emits a `tracing::warn!` pointing the user at `--features jq` (or `full`). Previously these keys silently survived into the handler args and were dropped without trace.
- **15+ tests** — 4 `validate_namespace` cases, 1 handler-level rejection (`test_build_command_rejects_flag_like_namespace`), 1 builder test for `top -A`, 4 parser tests (tab-separated helm, ss `tunap`, JSON object/array rejection), 1 CLI-flag rejection test under `cfg(not(feature = "jq"))`.

### Changed

- **CLI flags `--jq` and `--output-format` are feature-gated** — clap only registers them when `cfg(feature = "jq")`. A binary built without the feature now rejects them as unknown arguments instead of silently no-op'ing the filter. The `DataReductionFlags` runner struct mirrors the gating.
- **`parse_columnar_output` uses data-only gap detection** — phase 1 previously required `header has space AND all data rows have space`, which collapsed the column boundaries on tools like `ss -tunap` whose header packs single-space gaps even though the data is multi-space aligned. The relaxed rule (data-only + the existing `≥ 2` run-width filter) keeps multi-word values like `Up 2 hours` and multi-word headers like `CONTAINER ID` intact, and now produces meaningful columns on `ss` output (4 detected columns instead of an empty `columns: []` envelope).
- **`KubernetesCommandBuilder::build_top_command` signature** — gains a `all_namespaces: bool` parameter. Library consumers calling it directly need to thread the flag (false preserves prior behavior).
- **`Makefile install`** — `release` now passes `--features full` (cli + mimalloc + http + jq + otel) and `install` lands the binary in `~/.local/bin` (with `mkdir -p`), matching where most users have it on PATH.

### Fixed

- **Silent `jq_filter` no-op when binary lacks the `jq` feature** — three layered guards (clap-level rejection, runner-side struct gating, runtime warn in `extract`) close the trap that previously let `--jq '.items'` succeed-but-do-nothing on a `default = ["cli"]` build.
- **Mangled JSON TSV on `ssh_k8s_get output=json`** without the `jq` feature — the JSON-shape guard in `parse_columnar_output` blocks the columnar fallback that produced tab-padded raw JSON lines.
- **`namespace=--all-namespaces` accepted as a literal** — `validate_namespace` rejects flag-like values across all k8s/helm handlers with a clear error.
- **`ssh_helm_list` `App.columns` returned the whole header line as a single concatenated cell** — fixed by the tab-separated branch in `parse_columnar_output`.

### Internal

- **All 16 k8s/helm handlers** (`ssh_k8s_*`, `ssh_helm_*`) call `KubernetesCommandBuilder::validate_namespace(ns)?` at the top of `build_command` when a namespace is supplied. Helm handlers gained a `KubernetesCommandBuilder` import alongside `HelmCommandBuilder`.

## [1.14.0] - 2026-04-26

### Summary

**SEP-973 Icons on `Tool` / `ServerInfo`** | **MCP 2025-11-25 anti-DNS-rebinding Origin guard** | **SEP-1686 `notifications/tasks/status` on task creation** | **CORS allowlist replaces `permissive()`**

### Added

- **SEP-973 Icons support** — new `Icon { src, mime_type, sizes, theme }` struct in `src/mcp/protocol.rs`, surfaced on `Tool` and `ServerInfo`. Lets MCP clients render per-tool / per-server visual affordances. All fields optional; serialization stays byte-identical when `icons = None`.
- **Anti-DNS-rebinding Origin guard** (`origin_guard` axum middleware in `src/mcp/transport/http.rs`) — closes the hole called out in MCP 2025-11-25 §"Streamable HTTP / Security Warning". Requests with no `Origin` (non-browser clients like Claude Desktop) are forwarded; an `Origin` not in the allowlist returns HTTP 403 with a JSON-RPC error body. Covers the MCP routes and the `/health` + `.well-known` endpoints so attackers cannot fingerprint the server cross-origin.
- **`http.allowed_origins`** — new YAML config field on `HttpTransportConfig`. Default is the localhost set (`http://localhost`, `http://127.0.0.1`, `http://[::1]` + HTTPS variants). Operators with a public origin must add it explicitly.
- **CORS allowlist** — explicit origin list (built from `allowed_origins`) replaces `CorsLayer::permissive()`. Browsers receive `Access-Control-Allow-Origin` only for allowlisted origins; the origin guard is the actual MUST-comply spec hook layered underneath.
- **SEP-1686 task-status notification on creation** — `handle_tools_call` emits `notifications/tasks/status` (`status: "working"`) synchronously when an async task is registered, so clients see the non-existent → working transition without polling. The worker still fires the matching terminal-status notification on completion / failure / cancellation.
- **12 new tests** — 8 unit tests on `is_allowed_origin` (exact match, port suffix, lookalike rejection like `http://localhost.evil.com`); 4 end-to-end full-router tests covering invalid origin (403), localhost allowed, no Origin header (forwarded), `/health` cross-origin probe (403); 1 server-level test asserting `notifications/tasks/status` on task creation; round-trip + minimal-form tests for `Icon`, `Tool { icons }`, `ServerInfo { icons }`.

### Changed

- **`CorsLayer::permissive()` → explicit allowlist** — browsers no longer receive `*` for `Access-Control-Allow-Origin`. Aligns with the server-side `origin_guard`.
- **`HttpTransportConfig.allowed_origins`** is the single source of truth — `default_http_allowed_origins()` provides the localhost set used by both the YAML config layer (`src/config/types.rs`) and the transport layer (`src/mcp/transport/http.rs`).
- **`McpServer::initialize`** sets `serverInfo.icons = None` explicitly so downstream renderers see the field.
- **`config_watcher` integration test** — added a 200 ms grace period after `ConfigWatcher::new()` so the first event isn't lost under instrumented (llvm-cov) builds where the inotify watcher thread is slow to come online.
- **`mcp_search_tools` test assertion** — relaxed to compare against the registry's full description rather than the truncated search-entry text, fixing a flake when a match's description exceeds the truncation limit.
- **README** — top-of-file counts updated to reflect the current registry (357 tools / 75 groups) and protocol surface (9 adapters: SSH, WinRM, PSRP, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP). Mentions daemon mode and the WinRM/K8s pools shipped in 1.12.0.

### Security

- **Spec compliance** — `origin_guard` closes the DNS-rebinding hole flagged by MCP 2025-11-25. Operators upgrading from 1.13.0 with browser clients on a non-localhost origin **must** add their origin to `http.allowed_origins` or the gate will reject them with HTTP 403.
- **CORS does not opt into `allow_credentials`** — preserves the previous (safe) behavior.

## [1.13.0] - 2026-04-23

### Summary

**Destructive-op confirmation via MCP elicitation** | **Progressive discovery meta-tools** | **`SessionStore` trait for future stateless HTTP transport**

### Added

- **`security.require_elicitation_on_destructive`** (opt-in, default `false`) — when enabled, the server sends `elicitation/create` to the client before executing any tool annotated `destructive_hint: true` (`ssh_terraform_apply`, `ssh_k8s_delete`, `ssh_cron_remove`, `ssh_win_update_reboot`, `ssh_helm_uninstall`, and ~30 more). The tool call is rejected on decline, cancel, or when the client does not advertise the `elicitation` capability (fail-closed). Addresses Anthropic's 2026 MCP roadmap "destructive-op confirmation" recommendation.
- **`ElicitationService::confirm_destructive(tool_name, summary)`** — builds a boolean `{confirm: bool}` schema, parses the client's reply, propagates `Declined`/`Cancelled` as user-facing errors.
- **`McpServer.client_supports_elicitation`** — captures `InitializeParams.capabilities.elicitation` during the handshake so the gate can fail fast without a round-trip.
- **Progressive discovery meta-tools** — three read-only MCP tools let clients browse the registry on demand instead of loading all 338 schemas up front (~100 K tokens):
  - `mcp_list_tool_groups` — 74 groups with tool counts (~2 K tokens).
  - `mcp_search_tools(query, group?, limit=20)` — case-insensitive substring search over name + description, compact entries without the full schema.
  - `mcp_describe_tool(name)` — full input schema + output_kind + Reduction Strategy for one tool.
  - All three populate `structuredContent` (MCP 2025-06-18+) and advertise `task_support: "optional"` to preserve the registry invariant.
- **`mcp::meta_tools` module** — pure logic that consumes a `ToolRegistry` reference; dispatched specially from `handle_tools_call` before the elicitation gate and before the task/progress plumbing.
- **`SessionStore` async trait** in `src/mcp/transport/session_store.rs` — pluggable backing store for the streamable HTTP transport with `insert`, `get_tx`, `update_tx`, `remove`, `count`. Default impl `InMemorySessionStore` preserves current behavior.
- **`build_router_with_store(server, config, store)`** — variant of `build_router` that accepts a caller-provided `Arc<dyn SessionStore>`. Drop-in extension point for a future `RedisSessionStore` / `ValkeySessionStore` once the 2026 stateless-transport SEP lands.
- **`.well-known/mcp/server-card.json`** — new `extensions.progressive_discovery` entry listing the three meta-tools so crawlers and registries can detect the capability without connecting.
- **17 new tests** — 3 for the elicitation gate (unit + integration via `handle_tools_call`), 12 for meta-tools (8 unit + 4 dispatch round-trip), 4 for `InMemorySessionStore`.

### Changed

- **`handle_tools_call` dispatch order** — progressive-discovery meta-tools are intercepted right after params parsing; the elicitation gate runs next, covering both the synchronous path and the task-augmented async path.
- **`HttpTransportState.sessions`** goes from owning a `RwLock<HashMap<String, HttpSession>>` to holding an `Arc<dyn SessionStore>`; the four HTTP handlers (POST init, GET SSE, DELETE, /health) route through the trait methods.
- **`tools/list` response** — the three meta-tools are surfaced at the front of the list so clients find them before paginating through the 338 real tools.
- **`config/config.example.yaml`** — documents the new `require_elicitation_on_destructive` flag.

### Removed

- **`HttpSession::is_expired`** and the two tests that exercised it — dead code; the transport never called the expiry helper.

## [1.12.0] - 2026-04-12

### Summary — Sprint 3 (complete)

**Transport unified** | **Daemon inherits stdio features** | **WinRM + K8sExec pools** | **Multi-host output diffing** | **`#[mcp_tool]` auto-registration — 357/357 handlers migrated** | **Server-side data-reduction for custom handlers**

### Added

- **Unified `Transport` trait** with session-based `accept() -> Option<Session>` API in `src/mcp/transport/mod.rs`. One trait drives both stdio and the daemon's Unix socket listener; each session gets its own reader/writer halves that can be moved into independent tokio tasks.
- **`McpServer::serve<T: Transport>`** — generic accept loop that replaces the stdio-hardcoded `run()`. `run()` now delegates to `serve(StdioTransport::new(), …)`. `run_daemon()` plugs in a new `UnixSocketTransport` and gets every feature the stdio loop has (batch requests, parse_error responses, elicitation/sampling/logging via per-session `notification_tx`, config hot-reload) for free.
- **`UnixSocketTransport`** — multi-session Transport impl backed by `tokio::net::UnixListener` with a `CancellationToken` for graceful shutdown on SIGINT.
- **Per-session `notification_tx` in `ToolContext`** — tool handlers running inside a live MCP session now reach the originating client directly via their session's writer channel, instead of racing against a global `McpServer::notification_tx` slot. Multi-session daemon clients no longer step on each other's server-initiated messages.
- **`WinRmPool`** (`src/winrm/pool.rs`) — caches `reqwest::Client` instances per host for 120 seconds so back-to-back WinRM calls reuse the existing HTTPS connection pool instead of paying a fresh TLS handshake on every invocation.
- **`K8sExecPool`** (`src/k8s_exec/pool.rs`) — same pattern for `kube::Client`, 300-second idle TTL. Cold cost (kubeconfig walk + auth plugin refresh + TLS stack) is amortized across subsequent calls.
- **Multi-host output diffing** in `ssh_exec_multi` — new `diff`, `diff_baseline`, `normalize` args add a structured diff section to the response comparing the output of the same command across every host against a baseline. Useful for detecting config drift on a fleet. Backed by a new pure-domain module `src/domain/diff.rs` using the `similar` crate. Large outputs (>100 KB) skip the unified-diff generation and fall back to a hash-based match/differ comparison to keep per-call cost bounded.
- **Sanitizer YAML custom patterns** — explicit end-to-end tests proving that `SanitizeConfig.custom_patterns` compose with builtin patterns and that invalid regexes in YAML are skipped rather than fatal.
- **New daemon integration tests**: batch request dispatch + parse_error response for malformed JSON, both proving that behaviors `daemon/connection.rs` used to reject are now inherited from the shared `serve_session` path.
- **Server-side data-reduction for custom (non-`StandardTool`) handlers.** `apply_typed_reduction` is renamed to `apply_reduction` and made `pub` in `src/mcp/standard_tool.rs` so handlers that opt out of the `StandardTool` pipeline can still consume `jq_filter`, `yq_filter`, `columns`, `limit`, and `output_format`. 12 AWX handlers (`ssh_awx_*`), `ssh_ls`, and `ssh_metrics` now participate in the reduction pipeline.
- **`OutputKind::short_marker()` + `strategy_hint()`** — new helpers on the domain enum used by the CLI to surface per-tool reduction metadata without leaking enum details.
- **CLI `list-tools`** — text table gains a `REDUCE` column; JSON output adds a `reduce` field per tool. A legend at the bottom explains the markers (`jq+tsv`, `yq+tsv`, `cols`, `*`, `—`).
- **CLI `describe-tool`** — text mode prints `Output Kind` and `Reduction Strategy`; JSON mode adds `output_kind` + `reduction_strategy` fields.
- **CLI `--output-format` flag** on `DataReductionFlags` maps to the `output_format` tool parameter. Explicit tool args still win over the flag.

### Changed

- **`McpServer::handle_request_with_cancel`** signature gains a `notification_tx` parameter propagated through `handle_tools_call` and `create_tool_context` so the per-session sender reaches every handler.
- **`ExecutorRouter`** stores `WinRmPool` + `K8sExecPool` (feature-gated) and delegates `Protocol::WinRm` / `Protocol::K8sExec` routing to them instead of constructing a fresh connection on every call. `cleanup()` and `close_all()` forward to every pool so the shared cleanup tasks clear stale entries.

- **`crates/bridge-mcp-macros/`** — new proc-macro crate providing `#[mcp_tool(name, group, annotation)]` and `#[mcp_standard_tool(...)]` attributes. Both emit an `inventory::submit!` that populates a static `ToolRegistryEntry` table at compile time; the main crate walks that table to build the registry, map names to groups, and map names to annotation kinds.
- **`ToolRegistryEntry`, `ToolAnnotationKind`** public types in `src/mcp/registry.rs` backing the inventory entries. Two `OnceLock<HashMap>` caches (`inventory_group_map` / `inventory_annotation_map`) are built on first call and reused for the life of the process.
- **`Cargo.toml`** is now a workspace (`[workspace] members = [".", "crates/bridge-mcp-macros"]`) and depends on `inventory = "0.3"` + the local macro crate + `similar = "2.6"` (multi-host diff).
- **`src/lib.rs`** adds `extern crate self as mcp_ssh_bridge;` so the proc-macro-generated fully-qualified paths (`::mcp_ssh_bridge::mcp::registry::…`) resolve both when building the main crate and from downstream consumers.
- **All 357 tool handlers migrated to `#[mcp_tool]` / `#[mcp_standard_tool]`.** Each handler file gained a single-line attribute (329 `#[mcp_standard_tool]` markers + 28 `#[mcp_tool]` direct-impl structs). Migration done by a dedicated Python tooling suite (`scripts/extract_tool_metadata.py`, `scripts/migrate_handler.py`, `scripts/validate_baseline.py`) in 18 group-at-a-time waves, each with its own atomic commit and a full `cargo test --lib` + `cargo clippy -D warnings` + baseline-count gate.
- **`src/mcp/registry.rs`: 4312 → ~2700 lines (-37 %).** The legacy `all_handlers: Vec<Arc<dyn ToolHandler>>` (309 entries + 309 `use` imports), the 340-arm `tool_group()` match table, and the 340-arm `tool_annotations()` match table all collapse into ~4-line inventory lookups. The function that used to require `#[allow(clippy::too_many_lines, clippy::large_stack_arrays)]` annotations is now a trivial 5-line for-loop.
- **78 static test-count assertions → dynamic.** Assertions like `assert_eq!(registry.len(), 357)` were rewritten to `assert_eq!(registry.len(), all_tools_count())` using two helper functions (`all_tools_count()`, `group_size(group)`) that read the inventory at runtime. Adding a new tool no longer requires touching any test file.
- **`.migration-baseline.json`** committed at repo root — a frozen snapshot of `(total, groups_count, groups[])` that `scripts/validate_baseline.py` checks against at every migration wave and that any future tool addition must update intentionally via `--force-baseline`.

### Removed

- `src/daemon/connection.rs` — the per-connection handler is now replaced by `McpServer::serve_session`, which already has cancellation plumbing, the request registry, and the full dispatch surface.
- **`/sync-counts` skill** (`.claude/skills/sync-counts/`) and every reference to it in `.claude/` docs, rules, settings, and agent memory. The "manually update 78 test count assertions after adding a tool" maintenance chore is dead code since commit D.
- The "Adding a tool = 8 steps" procedure. The new procedure is **3 steps**: annotate the struct, add the `mod` + `pub use` line, and (only if introducing a new group) update `ToolGroupsConfig`.

### Fixed

- **Clippy `--all-features`** — `ExecutorRouter` tagged with `#[allow(clippy::struct_field_names)]` (all three fields legitimately end in `_pool`), and `doc_markdown` violations on `host_name` / `WinRM` in `k8s_exec/pool.rs` + `winrm/pool.rs` module docs. Local `cargo clippy` without `--all-features` masked these; CI now validates `--all-features` on every push.
- **Markdownlint MD024** — two sibling `### Changed` headings in the Unreleased block collapsed into one.
- **Coverage job `test_docker_file_write_and_read`** — the shell path of `ssh_file_write` returns raw stdout which is empty on success, so the "Write should return confirmation" assertion always failed under CI's `sftp_write_threshold_bytes` default. Assertion dropped; the read-back in the same test is the real semantic check.
- **Coverage job `e2e_raspberry` leakage** — tests in `tests/e2e_raspberry.rs` are now wrapped in `mod rpi { ... }` so the CI filter `--skip rpi::` (previously `--skip e2e_raspberry`, which never matched since libtest `--skip` filters test function names, not file/binary names) correctly excludes them under `--include-ignored`.

## [1.11.0] - 2026-04-10

### Summary

**Remove 5 unused protocols** | **Rewrite Telnet (zero deps)** | **CLI data-reduction** | **GCP runtime check** | **-7 dependencies**

### Removed

- **5 protocol adapters** — MQTT (`rumqttc`), NATS (`async-nats`), NETCONF (`netconf-rs`), SNMP (`snmp`), ZeroMQ (`zeromq`). These were non-functional stubs with no real-world usage. Removing them eliminates 7 transitive dependencies and simplifies the feature matrix.
- **`messaging` feature bundle** — was `zeromq + nats + mqtt`, no longer exists.
- **`RemoteExecutor::supports_structured_config()`** — only used by NETCONF/SNMP, removed from the port trait.

### Changed

- **Telnet adapter rewritten** — replaced `mini-telnet` crate with an in-house minimal RFC 854 client using raw `tokio::net::TcpStream`. Zero unmaintained transitive dependencies. Negotiation policy: refuse all options (`DONT`/`WONT`), drop subnegotiation blocks. Sufficient for command-line network gear.
- **`air-gapped` feature** — now `winrm + telnet` (was `winrm + telnet + netconf`).
- **`all-protocols` feature** — now 7 adapters (was 12): SSH, WinRM, Telnet, K8s Exec, Serial, SSM, Azure, GCP.
- **CLI `describe-tool`** — now shows data-reduction parameters (`jq_filter`, `yq_filter`, `columns`, `output_format`, `limit`) based on the tool's `OutputKind`. Previously these were only visible in MCP mode.
- **CLI `tool` invocation** — type coercion now uses the enriched schema including data-reduction parameters for correct auto-detection of argument types.
- **README CLI section** — expanded with data-reduction examples, exit codes, shell completions, and Claude Code integration instructions.

### Added

- **GCP `gcloud` runtime check** — `warn_if_gcloud_missing()` logs a warning on first use when `gcloud` CLI is not in `$PATH`. Uses `OnceLock` for one-shot check.
- **`config/claude-code/`** — Claude Code rule (`cli-bridge.md`) and skill (`/bridge`) for CLI-aware AI assistance. Copy to `.claude/` to enable.
- **`inject_reduction_schema()` is now `pub`** — allows CLI runner to reuse the same schema enrichment as MCP mode.

## [1.10.0] - 2026-04-08

### Summary

**TSV output for jq/yq filters** | **YAML filtering via yq_filter** | **0 new dependencies**

Adds two complementary features to the data reduction pipeline:

1. **`output_format=tsv`** parameter on all `Json`/`Auto`/`Yaml` tools to serialize jq/yq results as tab-separated values instead of JSON. Reduces token consumption by 60-80% on tabular data.
2. **`yq_filter`** parameter for tools producing YAML output. Uses the existing jaq-core engine on a YAML→JSON converted value tree (via the existing `serde-saphyr` dependency, no new crates).

### Added

- **`apply_jq_filter_tsv()`** in `src/domain/jq_filter.rs` — TSV serializer for jq results. Arrays are joined with tabs, rows with newlines. Strings are unquoted. Null becomes empty string. Object iteration order is alphabetical (use array filters `[.foo, .bar]` for predictable column order).
- **`apply_yq_filter()` and `apply_yq_filter_tsv()`** in new `src/domain/yq_filter.rs` — jq-syntax filtering on YAML inputs. Parses YAML to `serde_json::Value` via `serde-saphyr` then runs the existing jaq pipeline.
- **`OutputKind::Yaml`** — new variant in `src/domain/output_kind.rs` for tools producing YAML output. Supports `yq_filter` + `limit` + `output_format`.
- **`DataReductionArgs::yq_filter`** and **`DataReductionArgs::output_format`** — new fields with `wants_tsv()` helper.
- **Schema injection** in `src/mcp/registry.rs` `inject_reduction_schema()` exposes `output_format` (json/tsv enum) on all `Json`/`Yaml`/`Auto` tools and `yq_filter` on `Yaml` tools.
- **30+ new tests** covering TSV serialization (arrays, objects, nulls, scalars, token efficiency) and yq filtering (nested access, arrays, TSV combo, invalid YAML).

### Why

- `jaq-core 3.0.0` does **not** support the `@tsv` jq builtin (verified by direct test). The previous `join("\t")` workaround produces literal `\t` strings, not real tabs. Server-side post-conversion was the only way to get true TSV from jq filters.
- For YAML-first technologies (kubectl/helm `-o yaml`, ansible-navigator), there was no way to filter server-side. Now the same jq-syntax expressions work on both JSON and YAML inputs.

### Token efficiency example

```
ssh_awx_job_summary(job_id=123)
  → 600 chars JSON (per-host fields)

ssh_awx_job_summary(
  job_id=123,
  jq_filter=".results[] | [.host_name, .ok, .changed, .failures]",
  output_format="tsv"
)
  → 50 chars TSV (web01\t12\t2\t0\nweb02\t8\t0\t1)
```

## [1.9.1] - 2026-04-07

### Fixed

- **Docker workflow Trivy scan** — fix `MANIFEST_UNKNOWN` error by scanning the local image tag instead of trying to pull from `ghcr.io` before the push step
- **Pre-existing CI lint failures** — resolve all `cargo fmt`, `cargo clippy --all-features`, `typos`, and `markdownlint` errors that were failing CI before this release

## [1.9.0] - 2026-04-07

### Summary

**338 → 357 tools** | **74 → 75 groups** | 19 new tools, 1 new group (`awx`)

### Added

- **AWX REST API integration** (`awx` group, 13 tools): Full AWX lifecycle management via SSH-relayed curl commands for air-gapped environments. Includes `awx_status`, `awx_templates`, `awx_template_detail`, `awx_job_launch`, `awx_job_status`, `awx_job_events`, `awx_job_summary`, `awx_job_stdout`, `awx_job_cancel`, `awx_inventories`, `awx_inventory_hosts`, `awx_project_sync`, `awx_job_follow`
- **AWX config** (`AwxConfig` in config.yaml): `ssh_host`, `url`, `token`, `api_timeout`, `verify_ssl` for air-gapped AWX relay
- **Ansible enhanced tools** (6 new tools in `ansible` group): `ansible_recap` (compact PLAY RECAP extraction), `ansible_facts` (targeted fact gathering with filter), `ansible_lint` (playbook validation), `ansible_config` (active config dump), `ansible_run_background` (nohup + JSON callback), `ansible_events` (background run event parser)
- **Ansible playbook callback support**: New `callback` parameter on `ssh_ansible_playbook` to force `json`, `yaml`, `dense`, or `minimal` stdout callback plugins
- **Ansible OutputKind::Auto**: `ssh_ansible_playbook` now supports `jq_filter`, `columns`, and `limit` data reduction parameters for token-efficient output
- **AWX job follow**: `ssh_awx_job_follow` launches a job and polls until completion, returning a structured per-host summary (~500 tokens vs ~5000+ for raw stdout)
- **Background Ansible runs**: `ssh_ansible_run_background` + `ssh_ansible_events` for non-blocking playbook execution with incremental event monitoring
- **All AWX tools support jq_filter**: `OutputKind::Json` enables server-side jq filtering on all AWX API responses

## [1.6.1] - 2026-03-24

### Fixed

- **Revert serde-saphyr to 0.0.21** — v0.0.22 generates invalid YAML for empty arrays, breaking config hot-reload (`load_config` fails on re-serialized files)
- **Config watcher reliability** — replace `std::thread::spawn` + mini tokio runtime with `blocking_write()` for config updates in the file watcher callback; the previous approach was unreliable (spawned thread could fail to propagate writes back to the shared config)

## [1.6.0] - 2026-03-22

### Summary

**281 → 337 tools** | **55 → 57 groups** | **5697 tests** | 56 new tools across 21 new groups

### Added

- **Performance profiling** (`performance` group, 4 tools): perf_trace, io_trace, latency_test, benchmark
- **Container log analysis** (`container_logs` group, 4 tools): container_log_search, container_log_stats, container_events, container_health_history
- **Cron analysis** (`cron_analysis` group, 3 tools): cron_analyze, cron_history, at_jobs
- **Network security** (`network_security` group, 4 tools): port_scan, ssl_audit, network_capture, fail2ban_status
- **Compliance** (`compliance` group, 4 tools): cis_benchmark, stig_check, compliance_score, compliance_report
- **Cloud** (`cloud` group, 4 tools): aws_cli, cloud_metadata, cloud_tags, cloud_cost
- **Inventory** (`inventory` group, 3 tools): discover_hosts, inventory_sync, host_tags
- **Multi-cloud** (`multicloud` group, 3 tools): multicloud_list, multicloud_sync, multicloud_compare
- **Alerting** (`alerting` group, 3 tools): alert_check, alert_list, alert_set
- **Capacity** (`capacity` group, 3 tools): capacity_collect, capacity_trend, capacity_predict
- **Incident** (`incident` group, 2 tools): incident_timeline, incident_correlate
- **Log aggregation** (`log_aggregation` group, 3 tools): log_aggregate, log_search_multi, log_tail_multi
- **Key management** (`key_management` group, 3 tools): key_generate, key_distribute, key_audit
- **ChatOps** (`chatops` group, 2 tools): webhook_send, notify
- **Config templates** (`templates` group, 5 tools): template_list, template_show, template_apply, template_validate, template_diff
- **Interactive PTY** (`pty` group, 3 tools): pty_exec, pty_interact, pty_resize
- **Backup extensions**: backup_snapshot, backup_verify, backup_schedule (3 tools added to existing `backup` group)
- **TSV post_process** on 5 tools (port_scan, log_aggregate, discover_hosts, sbom_generate, runbook_list) for ~30-40% token savings
- **DXT packaging** for Claude Desktop extension
- **MCP server card** (`.well-known/mcp/server-card.json`)

### Changed

- **Tool Count**: 281 → 337 tools
- **Group Count**: 55 → 57 groups (42 Linux + 13 Windows + 2 cross-platform)
- **Test Count**: 4782 → 5697 tests
- Updated all documentation (README.md, CLAUDE.md, config.example.yaml, dxt/, server-card.json)
- Log aggregation output now uses TSV format instead of key=value

## [1.5.0] - 2026-03-21

### 🎯 Summary

**262 → 281 tools** | **47 → 55 groups** | **4782 tests** | 10 major features implemented from the research roadmap

### Added

#### 🔒 Security

- **Session Recording & Replay** (`recording` group, 5 tools): `ssh_recording_start`, `ssh_recording_stop`, `ssh_recording_list`, `ssh_recording_replay`, `ssh_recording_export` — Compliance-grade session recording with tamper-proof hash-chain integrity, asciinema v2 / JSON export, and automatic secret masking (SOC2, HIPAA, PCI-DSS)
- **SBOM & Vulnerability Scanning** (`security_scan` group, 3 tools): `ssh_sbom_generate`, `ssh_vuln_scan`, `ssh_compliance_check` — Software Bill of Materials generation, CVE scanning against installed packages, and CIS/STIG compliance verification
- **Advanced Secrets Detection**: Entropy-based detection (Shannon entropy) alongside regex patterns for catching unknown secret formats; configurable threshold, min-length, and whitelist

#### 🏥 SRE Platform

- **Intelligent Diagnostics** (`diagnostics` group, 3 tools): `ssh_diagnose`, `ssh_incident_triage`, `ssh_compare_state` — Single-call comprehensive host diagnostics (CPU, RAM, disk, load, top processes, failed services, recent errors, OOM kills), automated incident triage with log/metric/service correlation, and baseline state comparison
- **Runbook Engine** (`runbooks` group, 4 tools): `ssh_runbook_list`, `ssh_runbook_execute`, `ssh_runbook_status`, `ssh_runbook_validate` — YAML-based runbook definitions with conditions, loops, rollback; built-in templates for common incidents (disk full, OOM, service crash, cert expiry); async execution via MCP Tasks

#### 🚀 Orchestration

- **Multi-Host Orchestration** (`orchestration` group, 4 tools): `ssh_orchestrate`, `ssh_fleet_diff`, `ssh_rolling_exec`, `ssh_canary_exec` — Advanced fan-out/fan-in workflows with serial/parallel/canary strategies, rolling execution with automatic rollback on failure, and cross-host result diffing

#### 🔄 DevOps

- **Environment Drift Detection** (`drift` group, 3 tools): `ssh_env_snapshot`, `ssh_env_diff`, `ssh_env_drift` — Full environment snapshots (packages, configs, services, users), cross-environment comparison, and desired-state drift detection
- **File Diff & Patch**: `ssh_file_diff`, `ssh_file_patch`, `ssh_file_template`, `ssh_file_search` — Cross-host file comparison, patch application, Jinja2/Handlebars template rendering, and remote ripgrep with context

#### 📦 Distribution

- **MCP Server Cards**: `.well-known/mcp/server-card.json` for automated server discovery
- **DXT Packaging**: One-click Claude Desktop installation package

#### 🏗️ Infrastructure

- **`session_recorder` field** added to `ToolContext` (`Option<Arc<SessionRecorder>>`) for optional recording integration across all tool handlers
- **5 new domain builders**: `RecordingCommandBuilder`, `DiagnosticsCommandBuilder`, `RunbookCommandBuilder`, `OrchestrationCommandBuilder`, `DriftCommandBuilder`
- **Recording configuration section** in `config.yaml`: `enabled`, `path`, `format`, `hash_chain`, `hash_key_env`, `max_duration_seconds`, `auto_mask_secrets`

### Changed

- **Tool Count**: 262 → 281 tools
- **Group Count**: 47 → 55 groups (42 Linux + 13 Windows)
- **Test Count**: ~4200 → 4782 tests
- Updated `config.example.yaml` with recording configuration and 6 new tool groups
- Updated all documentation to reflect new tool counts and features

## [2.1.0] - 2026-03-21

### Added

- **53 new SSH tools** across 9 new groups, bringing total from 197 to **250 tools** across **47 groups**:
  - **File Operations** (`file_ops`, 5 tools): `ssh_file_read`, `ssh_file_write`, `ssh_file_chmod`, `ssh_file_chown`, `ssh_file_stat`
  - **User Management** (`user_management`, 8 tools): `ssh_user_list`, `ssh_user_info`, `ssh_user_add`, `ssh_user_modify`, `ssh_user_delete`, `ssh_group_list`, `ssh_group_add`, `ssh_group_delete`
  - **Storage** (`storage`, 7 tools): `ssh_storage_lsblk`, `ssh_storage_df`, `ssh_storage_mount`, `ssh_storage_umount`, `ssh_storage_lvm`, `ssh_storage_fdisk`, `ssh_storage_fstab`
  - **Journald** (`journald`, 4 tools): `ssh_journal_query`, `ssh_journal_follow`, `ssh_journal_boots`, `ssh_journal_disk_usage`
  - **Systemd Timers** (`systemd_timers`, 5 tools): `ssh_timer_list`, `ssh_timer_info`, `ssh_timer_enable`, `ssh_timer_disable`, `ssh_timer_trigger`
  - **Security Modules** (`security_modules`, 5 tools): `ssh_selinux_status`, `ssh_selinux_booleans`, `ssh_apparmor_status`, `ssh_apparmor_profiles`, `ssh_security_audit`
  - **Network Equipment** (`network_equipment`, 8 tools): `ssh_net_equip_show_run`, `ssh_net_equip_show_interfaces`, `ssh_net_equip_show_routes`, `ssh_net_equip_show_arp`, `ssh_net_equip_show_version`, `ssh_net_equip_show_vlans`, `ssh_net_equip_config`, `ssh_net_equip_save`
  - **Podman** (`podman`, 6 tools): `ssh_podman_ps`, `ssh_podman_logs`, `ssh_podman_inspect`, `ssh_podman_exec`, `ssh_podman_images`, `ssh_podman_compose`
  - **LDAP** (`ldap`, 5 tools): `ssh_ldap_search`, `ssh_ldap_user_info`, `ssh_ldap_group_members`, `ssh_ldap_add`, `ssh_ldap_modify`
- **6 new MCP protocol features**: batches, roots, app management, HTTP streaming, OAuth, and discovery
- **AI discoverability**: improved tool descriptions for better LLM understanding
- **9 new domain builders**: `FileOpsCommandBuilder`, `UserManagementCommandBuilder`, `StorageCommandBuilder`, `JournaldCommandBuilder`, `SystemdTimerCommandBuilder`, `SecurityModulesCommandBuilder`, `NetworkEquipmentCommandBuilder`, `PodmanCommandBuilder`, `LdapCommandBuilder`

### Changed

- **Tool Count**: 197 → 250 tools
- **Group Count**: 38 → 47 groups (34 Linux + 13 Windows)
- README rewritten to focus on installation, purpose, and configuration
- Documentation cleaned up across all modules

## [1.1.0] - 2026-02-19

### Added

- **MCP Tasks Support (MCP 2025-11-25)**: Async request primitive for long-running tool executions
  - `tools/call` with `"task": true` returns `CreateTaskResult` immediately, background worker executes
  - **Task lifecycle**: Working → Completed | Failed | Cancelled, with `CancellationToken` and `Notify` for blocking wait
  - **4 new MCP methods**: `tasks/get`, `tasks/cancel`, `tasks/result`, `tasks/list`
  - **`TaskStore`**: In-memory async task store with `RwLock<HashMap>`, TTL-based expiry, capacity limits, cursor-based pagination
  - **Task configuration**: `tasks.max_tasks` (default: 100), `tasks.default_ttl_ms` (default: 3600000) in `config.yaml`
  - All **197 tools** advertise `taskSupport: "optional"` via `execution` field
- **27 new fuzz targets** (53 total, was 26):
  - **Protocol/Domain** (6): `fuzz_task_params`, `fuzz_initialize_params`, `fuzz_prompts_get_params`, `fuzz_resource_uri`, `fuzz_task_store`, `fuzz_output_cache`
  - **Linux Builders** (13): `fuzz_docker_command_builder`, `fuzz_terraform_command_builder`, `fuzz_vault_command_builder`, `fuzz_redis_command_builder`, `fuzz_nginx_command_builder`, `fuzz_firewall_command_builder`, `fuzz_cron_command_builder`, `fuzz_certificate_command_builder`, `fuzz_git_command_builder`, `fuzz_systemd_command_builder`, `fuzz_network_command_builder`, `fuzz_process_command_builder`, `fuzz_package_command_builder`
  - **Windows Builders** (8): `fuzz_windows_service_builder`, `fuzz_windows_event_builder`, `fuzz_active_directory_builder`, `fuzz_scheduled_task_builder`, `fuzz_windows_firewall_builder`, `fuzz_iis_builder`, `fuzz_hyperv_builder`, `fuzz_windows_registry_builder`
- **26 new tests** for MCP Tasks:
  - `task_store.rs`: 15 tests (state transitions, get_result edges, wait_for_result, pagination, TTL capping, is_empty)
  - `server.rs`: 10 tests (cancel completed/cancelled, get completed, result cancelled/already-completed, missing params, dispatch)
  - `tool_filtering.rs`: 1 test (`test_every_tool_has_execution_task_support`)

### Fixed

- **TTL capping bug** in `TaskStore`: Expression `t.min(self.default_ttl_ms.max(t))` simplified to just `t` — custom TTLs were not actually capped at the configured default. Fixed to `t.min(self.default_ttl_ms)`

### Changed

- **Fuzz Targets**: 26 → 53 targets (100% coverage of all command builders + protocol types)
- **Test Count**: ~3788 → ~3888 tests
- **MCP Protocol**: `2025-11-25` Tasks support (experimental)

## [2.0.1] - 2026-02-16

### Changed

- Deduplicate 17 local `shell_escape` functions into centralized `shell::escape(s, ShellType::Posix)`
- Integrate `validate_terraform_dir` into all `TerraformCommandBuilder` methods
- Integrate `validate_vault_path` into `VaultCommandBuilder` read/list/write methods
- Integrate `validate_network_target` into `NetworkCommandBuilder` and `WindowsNetworkCommandBuilder`
- Add 8 missing Windows groups to `config.example.yaml` documentation
- Fix `ssh_win_disk_usage` group placement in `config.example.yaml`
- Update handler count comment in `lib.rs` (111 → 197)

## [2.0.0] - 2026-02-15

### Added

- **Windows Support**: 74 new tools across 13 groups for Windows Server management via PowerShell:
  - **Windows Services** (`windows_services`, 8 tools): `ssh_win_service_status`, `ssh_win_service_start`, `ssh_win_service_stop`, `ssh_win_service_restart`, `ssh_win_service_list`, `ssh_win_service_enable`, `ssh_win_service_disable`, `ssh_win_service_config`
  - **Windows Events** (`windows_events`, 5 tools): `ssh_win_event_logs`, `ssh_win_event_query`, `ssh_win_event_sources`, `ssh_win_event_tail`, `ssh_win_event_export`
  - **Active Directory** (`active_directory`, 6 tools): `ssh_ad_user_list`, `ssh_ad_user_info`, `ssh_ad_group_list`, `ssh_ad_group_members`, `ssh_ad_computer_list`, `ssh_ad_domain_info`
  - **Scheduled Tasks** (`scheduled_tasks`, 5 tools): `ssh_schtask_list`, `ssh_schtask_info`, `ssh_schtask_run`, `ssh_schtask_enable`, `ssh_schtask_disable`
  - **Windows Firewall** (`windows_firewall`, 5 tools): `ssh_win_firewall_status`, `ssh_win_firewall_list`, `ssh_win_firewall_allow`, `ssh_win_firewall_deny`, `ssh_win_firewall_remove`
  - **IIS** (`iis`, 6 tools): `ssh_iis_status`, `ssh_iis_list_sites`, `ssh_iis_list_pools`, `ssh_iis_start`, `ssh_iis_stop`, `ssh_iis_restart`
  - **Windows Updates** (`windows_updates`, 5 tools): `ssh_win_update_list`, `ssh_win_update_history`, `ssh_win_update_install`, `ssh_win_update_search`, `ssh_win_update_reboot`
  - **Windows Performance** (`windows_perf`, 6 tools): `ssh_win_perf_cpu`, `ssh_win_perf_memory`, `ssh_win_perf_disk`, `ssh_win_perf_network`, `ssh_win_perf_overview`, `ssh_win_disk_usage`
  - **Hyper-V** (`hyperv`, 8 tools): `ssh_hyperv_vm_list`, `ssh_hyperv_vm_info`, `ssh_hyperv_vm_start`, `ssh_hyperv_vm_stop`, `ssh_hyperv_snapshot_list`, `ssh_hyperv_snapshot_create`, `ssh_hyperv_host_info`, `ssh_hyperv_switch_list`
  - **Windows Registry** (`windows_registry`, 5 tools): `ssh_reg_query`, `ssh_reg_set`, `ssh_reg_list`, `ssh_reg_export`, `ssh_reg_delete`
  - **Windows Features** (`windows_features`, 4 tools): `ssh_win_feature_list`, `ssh_win_feature_info`, `ssh_win_feature_install`, `ssh_win_feature_remove`
  - **Windows Network** (`windows_network`, 6 tools): `ssh_win_net_adapters`, `ssh_win_net_ip`, `ssh_win_net_routes`, `ssh_win_net_connections`, `ssh_win_net_ping`, `ssh_win_net_dns`
  - **Windows Process** (`windows_process`, 5 tools): `ssh_win_process_list`, `ssh_win_process_info`, `ssh_win_process_kill`, `ssh_win_process_top`, `ssh_win_process_by_name`
- **OS Detection**: `OsType` (Linux/Windows) and `ShellType` (Posix/Cmd/PowerShell) for per-host OS routing
- **Shell Utilities**: `shell::escape()` with PowerShell-aware quoting (`shell.rs`)
- **13 Windows Domain Command Builders**: `WindowsServiceCommandBuilder`, `WindowsEventCommandBuilder`, `ActiveDirectoryCommandBuilder`, `ScheduledTaskCommandBuilder`, `WindowsFirewallCommandBuilder`, `IisCommandBuilder`, `WindowsUpdateCommandBuilder`, `WindowsPerfCommandBuilder`, `HyperVCommandBuilder`, `WindowsRegistryCommandBuilder`, `WindowsFeatureCommandBuilder`, `WindowsNetworkCommandBuilder`, `WindowsProcessCommandBuilder`
- **New Linux Tools**:
  - `ssh_disk_usage` (monitoring group): Disk usage analysis
  - `ssh_find` (directory group): File search with filters
  - `ssh_pkg_remove` (package group): Package removal
  - `ssh_service_enable`, `ssh_service_disable`, `ssh_service_daemon_reload` (systemd group): Service management
  - `ssh_docker_volume_ls`, `ssh_docker_volume_inspect`, `ssh_docker_network_ls`, `ssh_docker_network_inspect` (docker group): Docker volume and network management
- **SOCKS Proxy Support**: Connect through SOCKS5 proxies
- **SSH Config Auto-Discovery**: Enabled by default

### Changed

- **MCP Protocol**: Upgraded to `2025-11-25` (from `2025-06-18`)
- **Tool Count**: 113 → 197 tools across 38 groups (was 25 groups)
- **Tool Groups**: 25 → 38 groups (25 Linux + 13 Windows)
- **Test Count**: ~3788 tests

## [1.9.0] - 2026-02-14

### Added

- **Tool Annotations (MCP 2025-06-18)**: All 113 tools now have behavioral hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`) enabling Claude Code to optimize tool selection and confirm dangerous operations
- **New Config Tools** (`config` group, 2 tools):
  - `ssh_config_get`: Query runtime configuration (max_output_chars, timeouts)
  - `ssh_config_set`: Modify max_output_chars dynamically per session
- **Prompts** (4 new MCP prompts):
  - `backup-verify`: Backup verification workflow
  - `docker-health`: Docker health diagnostics
  - `k8s-overview`: Kubernetes cluster overview
  - `troubleshoot`: Troubleshooting assistant
- **Resources** (2 new MCP resources):
  - `history://recent`: Command execution history
  - `services://list`: System services listing
- **Security Documentation**:
  - `SECURITY.md`: Vulnerability reporting policy
  - `docs/THREAT_MODEL.md`: Comprehensive threat analysis
- **Security Audit**: CI workflow + test suite for security validation
- **Per-client output limits**: `ClientOverride` config, `runtime_max_output_chars` in server
- **Output management**: `OutputCache` for pagination, `save_output` parameter, configurable `max_output_chars`

### Changed

- **MCP Protocol**: Upgraded to `2025-06-18` (from `2024-11-05`)
- **Content types**: `ToolContent` now supports Text, Image, Audio, Resource variants
- **Structured content**: `ToolCallResult.structured_content` field for machine-readable data
- **Instructions**: `InitializeResult` includes server guidance for LLM tool selection
- **Tool Groups**: 24 → 25 groups (added `config`)
- **Tool Count**: 111 → 113 tools

## [1.8.3] - 2026-02-12

### Added

- **11 new tool groups** (45 tools) for system administration:
  - **Systemd** (`systemd` group, 6 tools): `ssh_service_status`, `ssh_service_start`, `ssh_service_stop`, `ssh_service_restart`, `ssh_service_list`, `ssh_service_logs`
  - **Network** (`network` group, 6 tools): `ssh_net_connections`, `ssh_net_interfaces`, `ssh_net_routes`, `ssh_net_ping`, `ssh_net_traceroute`, `ssh_net_dns`
  - **Process** (`process` group, 3 tools): `ssh_process_list`, `ssh_process_kill`, `ssh_process_top`
  - **Package** (`package` group, 4 tools): `ssh_pkg_list`, `ssh_pkg_search`, `ssh_pkg_install`, `ssh_pkg_update`
  - **Firewall** (`firewall` group, 4 tools): `ssh_firewall_status`, `ssh_firewall_list`, `ssh_firewall_allow`, `ssh_firewall_deny`
  - **Cron** (`cron` group, 3 tools): `ssh_cron_list`, `ssh_cron_add`, `ssh_cron_remove`
  - **Certificates** (`certificates` group, 3 tools): `ssh_cert_check`, `ssh_cert_info`, `ssh_cert_expiry`
  - **Nginx** (`nginx` group, 4 tools): `ssh_nginx_status`, `ssh_nginx_test`, `ssh_nginx_reload`, `ssh_nginx_list_sites`
  - **Redis** (`redis` group, 3 tools): `ssh_redis_info`, `ssh_redis_cli`, `ssh_redis_keys`
  - **Terraform** (`terraform` group, 5 tools): `ssh_terraform_init`, `ssh_terraform_plan`, `ssh_terraform_apply`, `ssh_terraform_state`, `ssh_terraform_output`
  - **Vault** (`vault` group, 4 tools): `ssh_vault_status`, `ssh_vault_read`, `ssh_vault_list`, `ssh_vault_write`
- **11 domain command builders**: `SystemdCommandBuilder`, `NetworkCommandBuilder`, `ProcessCommandBuilder`, `PackageCommandBuilder`, `FirewallCommandBuilder`, `CronCommandBuilder`, `CertificateCommandBuilder`, `NginxCommandBuilder`, `RedisCommandBuilder`, `TerraformCommandBuilder`, `VaultCommandBuilder`
- **28 new E2E tests** on Raspberry Pi (phases 11-20): systemd, network, process, package, cron, certificates, firewall, nginx, redis, and security validation tests
- **Input validation hardening**: 18 security findings fixed across command builders (shell injection prevention, empty input rejection, path traversal protection)

### Changed

- **Tool Count**: From 66 to 111 tools across 24 groups (was 13 groups)
- **E2E Test Count**: From 28 to 56 tests (20 phases)

## [1.8.2] - 2026-02-10

### Added

- **Docker Tools** (`docker` group): 7 new tools for Docker container management
  - `ssh_docker_ps`: List containers (all or running, with optional filters)
  - `ssh_docker_logs`: View container logs (with tail, since, timestamps)
  - `ssh_docker_inspect`: Inspect container/image details (JSON output)
  - `ssh_docker_exec`: Execute commands inside running containers
  - `ssh_docker_compose`: Run docker-compose commands (up, down, restart, ps, logs, build, pull)
  - `ssh_docker_images`: List Docker images (with optional repository filter)
  - `ssh_docker_stats`: Show container resource usage (CPU, memory, network)
- **ESXi Tools** (`esxi` group): 7 new tools for VMware ESXi host management
  - `ssh_esxi_vm_list`: List virtual machines on ESXi host
  - `ssh_esxi_vm_info`: Get detailed VM information (CPU, memory, disks, NICs)
  - `ssh_esxi_vm_power`: Power on/off/reset/suspend VMs
  - `ssh_esxi_snapshot`: Create, list, remove, or revert VM snapshots
  - `ssh_esxi_host_info`: Get ESXi host hardware and version info
  - `ssh_esxi_datastore_list`: List datastores with capacity info
  - `ssh_esxi_network_list`: List virtual switches and port groups
- **Git Tools** (`git` group): 7 new tools for remote Git repository management
  - `ssh_git_status`: Show working tree status (with optional short format)
  - `ssh_git_log`: View commit history (with filters: max_count, oneline, author, since, format)
  - `ssh_git_diff`: Show changes between commits or working tree (staged, file, commit)
  - `ssh_git_pull`: Fetch and integrate remote changes (with rebase, ff-only options)
  - `ssh_git_clone`: Clone a repository (with branch, depth, single-branch options)
  - `ssh_git_branch`: Manage branches (list, create, delete)
  - `ssh_git_checkout`: Switch branches or restore files (with create -b flag)
- **Tool Groups**: 10 → 13 groups, 44 → 66 tools
- Domain command builders: `DockerCommandBuilder`, `EsxiCommandBuilder`, `GitCommandBuilder`

## [1.8.1] - 2026-02-09

### Improved

- **LLM-optimized tool descriptions**: Rewritten all 44 tool descriptions for better LLM comprehension
  - Added output format guidance (e.g., "Returns JSON", "Returns stdout, stderr, exit code")
  - Added discovery workflow hints (e.g., "Use ssh_status first to discover host aliases")
  - Added tool alternatives (e.g., "For single files, prefer ssh_upload instead of ssh_sync")
  - Added inter-tool workflow guidance (e.g., "Use ssh_k8s_rollout after ssh_k8s_apply")
  - Added error handling hints (e.g., "If command denied, the security whitelist may need updating")
  - Kubernetes tools: ssh_k8s_get identified as entry point, tools cross-reference each other
  - Helm tools: ssh_helm_list as entry point, history→rollback workflow documented
  - Ansible tools: ssh_ansible_inventory as entry point, playbook vs adhoc distinction clarified
  - Database tools: workflow guidance (query→dump→download, upload→restore)
  - Backup tools: workflow guidance (create→list→restore)

## [1.8.0] - 2026-02-09

### Added

- **Kubernetes Tools** (`kubernetes` group): 9 new tools for kubectl management
  - `ssh_k8s_get`: List and inspect Kubernetes resources
  - `ssh_k8s_logs`: View pod logs with container/tail/since filters
  - `ssh_k8s_describe`: Describe resources in detail
  - `ssh_k8s_apply`: Apply manifests (file or inline YAML)
  - `ssh_k8s_delete`: Delete resources with namespace protection (blocks kube-system, kube-public, default, kube-node-lease)
  - `ssh_k8s_rollout`: Manage rollouts (status, restart, undo, history)
  - `ssh_k8s_scale`: Scale deployments/statefulsets
  - `ssh_k8s_exec`: Execute commands inside pods
  - `ssh_k8s_top`: View resource usage (pods/nodes)
- **Helm Tools** (`kubernetes` group): 7 new tools for Helm chart management
  - `ssh_helm_list`: List Helm releases
  - `ssh_helm_status`: Show release status
  - `ssh_helm_upgrade`: Upgrade releases with set values, values files
  - `ssh_helm_install`: Install new releases
  - `ssh_helm_rollback`: Rollback to previous revisions
  - `ssh_helm_history`: View release history
  - `ssh_helm_uninstall`: Uninstall releases
- **Ansible Tools** (`ansible` group): 3 new tools for Ansible automation
  - `ssh_ansible_playbook`: Run playbooks with inventory, tags, extra vars, check/diff modes
  - `ssh_ansible_inventory`: Query inventory (list, graph, host)
  - `ssh_ansible_adhoc`: Run ad-hoc commands with dangerous module/pattern blocking
- **Domain Command Builders**: `KubernetesCommandBuilder`, `HelmCommandBuilder`, `AnsibleCommandBuilder` with security validation
- **5 new fuzz targets**: `fuzz_k8s_command_builder`, `fuzz_k8s_validation`, `fuzz_helm_command_builder`, `fuzz_ansible_command_builder`, `fuzz_ansible_validation`
- **Architecture refactoring**:
  - Moved `CommandHistory` to domain layer (was in mcp adapter)
  - Moved `RealSshConnector` to ssh adapter (was in ports layer)
  - Moved protocol contract types (`ToolCallResult`, `PromptMessage`, etc.) to `ports/protocol.rs`
  - Centralized test context creation across all 37 handler files
- **Tool Groups**: 8 → 10 groups, 25 → 44 tools

## [1.7.0] - 2026-02-05

### Added

- **Database Tools** (`database` group): 3 new tools for MySQL/PostgreSQL management
  - `ssh_db_query`: Execute SQL queries with automatic dangerous query blocking
    (DROP DATABASE, DROP TABLE, TRUNCATE, DELETE FROM, GRANT, REVOKE)
  - `ssh_db_dump`: Database dump with optional compression (gzip/bzip2/xz)
  - `ssh_db_restore`: Restore database from dump files
  - `DatabaseCommandBuilder` domain service for safe command construction
  - Password handling via environment variables (MYSQL_PWD/PGPASSWORD)

- **Backup & Restore** (`backup` group): 3 new tools for tar archive management
  - `ssh_backup_create`: Create tar archives with optional compression and exclude patterns
  - `ssh_backup_list`: List archive contents with verbose mode
  - `ssh_backup_restore`: Extract archives with destination and strip_components support

- **SSH Tunnels** (`tunnels` group): 3 new tools for port forwarding
  - `ssh_tunnel_create`: Create local port forwarding tunnels
  - `ssh_tunnel_list`: List active tunnels with metadata
  - `ssh_tunnel_close`: Close tunnels by ID
  - `TunnelManager` domain service for tunnel lifecycle management

- **Directory Operations** (`directory` group):
  - `ssh_ls`: Structured directory listing with recursive, sort, and hidden file support

- **Recursive Directory Transfer**:
  - `ssh_sync`: Upload/download entire directories via SFTP with exclude patterns

- **SSH Config Auto-Discovery**: Parse `~/.ssh/config` to auto-discover hosts
  - Supports Host, HostName, Port, User, IdentityFile, ProxyJump, Include directives
  - Configurable exclude list and custom path
  - Discovered hosts use `AcceptNew` host key verification

- **Sudo Support**: Execute commands with sudo on ssh_exec, ssh_exec_multi, ssh_session_exec
  - Per-host `sudo_password` configuration
  - `sudo` and `sudo_user` parameters on execution tools

- **Tool Groups System**: Enable/disable tool groups to reduce LLM context
  - 8 groups: core, file_transfer, sessions, monitoring, tunnels, directory, database, backup
  - Hot-reload aware (restart required for tool group changes)

- **Docker Distribution**: Multi-stage Dockerfile (~15MB Alpine image)
  - docker-compose.yml with read-only volume mounts
  - Non-root container user

- **Fuzz Testing**: 5 new fuzz targets (21 total)
  - `fuzz_db_command_builder`, `fuzz_db_query_validation`, `fuzz_db_type_parse`
  - `fuzz_ssh_config_parser`, `fuzz_tunnel_manager`

- **Mutation Testing**: New `make mutants-db` target for database/domain module

### Changed

- **Tool Count**: From 15 to 25 tools across 8 groups
- **Test Count**: From 945 to 1113 tests
- **Fuzz Targets**: From 16 to 21 targets

## [1.6.0] - 2026-02-05

### Fixed

- **Hot-Reload for Whitelist/Blacklist/Mode**: Fixed `ConfigWatcher` not detecting
  configuration changes made by editors (vim, nano, VS Code) that use atomic saves
  (write temp file, rename over original):
  - **Root cause**: inotify watches file inodes, not paths. Atomic saves create a new
    inode, causing the watcher to lose track of the file
  - **Watch parent directory**: Now watches the config directory instead of the file
    directly, so rename events are captured
  - **Accept Create events**: In addition to Modify events, the watcher now reacts to
    Create events generated by atomic saves
  - **Debounce (500ms)**: Prevents duplicate reloads when editors generate multiple
    filesystem events per save

### Changed

- **Test Count**: From 929 to 945+ tests (25 new `ConfigWatcher` hot-reload tests)
- **Hot-Reload Test Coverage**: Comprehensive tests for whitelist add/remove/replace,
  blacklist add/remove/override, mode switching (strict/permissive), multiple
  consecutive reloads, debounce, invalid YAML resilience, and both atomic and
  direct write scenarios

## [1.5.0] - 2026-02-01

### Added

- **Claude Agent Pipeline**: TypeScript-based local CI/CD pipeline in `agents/`:
  - 7 orchestrated agents: lint, test, coverage, audit, fuzz, mutant, summary
  - Blocking/non-blocking execution modes
  - AI-powered summary generation (requires `ANTHROPIC_API_KEY`)
  - Configurable via CLI arguments (`--agent`, `-s/--skip`)

- **Mutation Testing Infrastructure**: cargo-mutants configuration in `.cargo/mutants.toml`:
  - Security module achieves ~88% mutation score
  - Makefile targets: `make mutants`, `make mutants-full`
  - Configured to skip logging calls and use nextest

- **Code Coverage**: cargo-tarpaulin integration:
  - LLVM engine for ptrace compatibility
  - Current coverage: ~54% (SSH modules require real server)

- **Documentation Updates**: Enhanced CLAUDE.md with:
  - Agent pipeline documentation
  - Testing tools section (mutation, coverage, fuzz)
  - Known advisories section

### Changed

- Updated fuzz target count from 9 to 16 in documentation

### Security

- Added `.cargo/audit.toml` to ignore RUSTSEC-2023-0071 (Marvin Attack on RSA):
  - Transitive dependency from russh -> rsa crate
  - No upstream fix available
  - Medium severity (5.9), timing attack requires network observation

## [1.4.0] - 2026-02-01

### Added

- **Comprehensive Fuzzing Infrastructure**: 16 fuzz targets covering all security-critical functions:
  - `fuzz_shell_escape`: Shell command escaping (149M+ executions)
  - `fuzz_validate_path`: Path traversal protection (82M+ executions)
  - `fuzz_sanitizer`: Password/secret masking (optimized: 12,800/s)
  - `fuzz_command_validator`: Whitelist/blacklist validation (optimized: 61,400/s)
  - `fuzz_parse_metrics`: System metrics parsing
  - `fuzz_truncate_output`: UTF-8 boundary-safe truncation
  - `fuzz_jsonrpc_parse`: MCP JSON-RPC protocol parsing
  - `fuzz_yaml_config`: Configuration file parsing
  - `fuzz_regex_redos`: ReDoS vulnerability detection
  - `fuzz_transfer_mode`: SFTP transfer mode parsing
  - `fuzz_tool_params`: MCP tool parameter parsing
  - `fuzz_host_config`: Host configuration parsing
  - `fuzz_rate_limiter`: Rate limiting logic
  - `fuzz_char_boundary`: UTF-8 character boundary functions
  - `fuzz_audit_serialize`: Audit event serialization
  - `fuzz_security_config`: Security configuration parsing

- **Corpus Seeds**: 67 seed files across all 16 fuzz targets for guided fuzzing

- **New Fuzzing Exports**: Exposed internal functions for fuzzing via `#[doc(hidden)]`:
  - `floor_char_boundary`, `ceil_char_boundary` from output truncator
  - `RateLimiter`, `CommandValidator`, `AuditEvent`, `CommandResult`
  - `TransferMode`, `SecurityConfig`, `HostConfig`

### Changed

- **Fuzz Harness Optimization**: Used `lazy_static!` to pre-compile regex patterns once:
  - `fuzz_sanitizer`: 4/s → 12,856/s (**3,214x faster**)
  - `fuzz_command_validator`: 39/s → 61,410/s (**1,574x faster**)

### Fixed

- **Fuzz Assertion**: Removed overly strict password masking assertion that caused
  false positives on edge cases like "Aassword=secret" (not a password pattern)

## [1.3.0] - 2026-01-31

### Added

- **Comprehensive Test Suite Expansion**: Added 72 new tests across multiple modules:
  - `mcp/protocol.rs`: JSON-RPC serialization/deserialization tests
  - `mcp/prompts/*.rs`: Tests for system-health, deploy, and security-audit prompts
  - `config/watcher.rs`: Config hot-reload and file watching tests
  - `mcp/tool_handlers/*.rs`: Schema validation, error handling, and description tests

### Fixed

- **JSON-RPC Null ID Handling**: Corrected test expectation for `"id": null` in JSON-RPC
  requests. Per serde_json behavior, `null` is correctly deserialized as `None` for
  `Option<Value>` fields, which aligns with JSON-RPC 2.0 spec (null id = notification).

### Changed

- **Test Count**: From 626 to 698 tests (+72 tests, +11.5% coverage)

## [1.2.0] - 2026-01-31

### Fixed

- **SFTP Division by Zero**: Fixed potential division by zero when calculating
  progress percentage for empty files (0 bytes). Now returns 100% correctly.

- **SFTP Checksum in Resume/Append Mode**: Disabled checksum calculation for
  Resume and Append transfer modes. Previously, the checksum only covered the
  transferred portion, not the complete file, which was misleading. Checksum
  is now only returned for Overwrite and FailIfExists modes where it represents
  the complete file.

- **SSH History JSON Parsing**: Changed from silent fallback to explicit error
  reporting when JSON arguments are malformed. Now consistent with other tool
  handlers that return `McpInvalidRequest` errors.

- **Parallel Sanitization Data Loss**: Fixed a subtle bug in the parallel
  sanitization code path where regex replacements that changed text length
  could cause data loss or duplication at chunk boundaries. The sanitizer now
  falls back to sequential processing when secrets are detected, ensuring
  correct output in all cases.

### Changed

- **Sanitizer Simplification**: Removed unused parallel chunk processing code
  (`create_chunks`, `apply_patterns_to_chunk`, `merge_chunks`) since the
  sanitizer now uses sequential processing when patterns match. Parallel
  detection via `RegexSet` is still used for fast-path rejection.

## [1.1.0-dev] - 2026-01-30

### Added

- **Configurable Sanitizer** with fine-grained control:
  - `security.sanitize.enabled`: Enable/disable sanitization entirely
  - `security.sanitize.disable_builtin`: Disable specific pattern categories
  - `security.sanitize.custom_patterns`: Add custom patterns with custom replacements
  - 17 pattern categories: `github`, `gitlab`, `slack`, `discord`, `openai`, `aws`, `k3s`, `jwt`, `certificates`, `kubeconfig`, `docker`, `database`, `ansible`, `azure`, `gcp`, `hashicorp`, `generic`

- **New Sanitizer APIs**:
  - `Sanitizer::from_config()`: Create from `SanitizeConfig`
  - `Sanitizer::from_config_with_legacy()`: Support legacy `sanitize_patterns` field
  - `Sanitizer::disabled()`: Create a pass-through sanitizer
  - `Sanitizer::is_enabled()`: Check if sanitization is active

- **New Config Types**:
  - `SanitizeConfig`: Advanced sanitizer configuration
  - `CustomSanitizePattern`: Custom pattern with replacement and description

### Changed

- **SFTP Documentation**: Removed artificial 50GB limit mentions - streaming supports unlimited file sizes
- **Pattern Categories**: All ~50 builtin patterns now have a category for filtering
- **Backward Compatibility**: Legacy `sanitize_patterns` field still works alongside new `sanitize` config

### Fixed

- Integration test for default security config now validates new `SanitizeConfig` fields

## [1.0.0] - 2026-01-30

### 🎉 First Stable Release

This release marks the first stable version of MCP SSH Bridge with a completely rewritten, high-performance output sanitizer.

### Added

- **High-Performance Sanitizer** (complete rewrite):
  - **~50 secret patterns** covering: GitHub, GitLab, Slack, OpenAI, AWS, K3s, Kubernetes, Docker, Ansible, databases, and more
  - **5-tier pattern architecture**: Specific patterns first (unique markers), generic patterns last
  - **Aho-Corasick pre-filter**: O(n) keyword detection for fast-path rejection
  - **RegexSet detection**: Single-pass to identify which patterns match
  - **Zero-copy optimization**: `Cow<str>` returns borrowed reference when no secrets found
  - **Parallel processing**: Rayon-based chunked processing for outputs >512KB
  - **New pattern categories**:
    - CI/CD: `ghp_*`, `gho_*`, `glpat-*`, GitLab CI tokens
    - AI APIs: OpenAI (`sk-*`), Anthropic, NVIDIA
    - Messaging: Slack (`xoxb-*`), Discord webhooks
    - Kubernetes: K3s tokens (`K10*`), kubeconfig certificates, JWT service account tokens
    - Docker: Registry auth, compose passwords
    - Ansible: Vault passwords, encrypted content, SSH passwords
    - Cloud: AWS, Azure, GCP, DigitalOcean credentials
    - Certificates: RSA, OpenSSH, EC, PGP private keys

- **New dependency**: `aho-corasick` 1.x for multi-pattern literal matching

### Changed

- `Sanitizer::sanitize()` now returns `Cow<'a, str>` instead of `String` for zero-copy optimization
- Added `Sanitizer::sanitize_to_string()` for backward compatibility
- Added `Sanitizer::pattern_count()` method
- Patterns are now ordered by specificity (specific markers like `[GITHUB_PAT_REDACTED]` before generic `[REDACTED]`)

### Performance

| Scenario | Before (v0.9) | After (v1.0) |
|----------|---------------|--------------|
| No secrets detected | O(n × 7 patterns) | **Zero-copy** (borrowed) |
| With secrets (<512KB) | O(n × 7) | O(n × matched patterns only) |
| Large output (>512KB) | Sequential | **Parallel (Rayon chunks)** |

## [0.9.0] - 2026-01-29

### Added

- **New MCP Tool**:
  - `ssh_metrics_multi`: Collect system metrics from multiple hosts in parallel
    - Uses rayon for parallel parsing of results
    - Same metrics as `ssh_metrics`: cpu, memory, disk, network, load
    - Supports `fail_fast` option to stop on first failure
    - Returns aggregated results with per-host success/failure status

### Changed

- **Dependencies**:
  - Added `rayon` 1.10 for data parallelism in multi-host metrics parsing
  - Updated `clap` to 4.5.56

- **Documentation Updates**:
  - Updated tool count from 13 to 14 tools
  - Added `ssh_metrics_multi` documentation to README

## [0.8.0] - 2026-01-29

### Added

- **New MCP Tool**:
  - `ssh_health`: Diagnostic tool providing internal state information (connection pool stats, active sessions, command history, configuration summary)

- **Code Quality Improvements**:
  - Added `#[must_use]` attributes to important functions returning values that should be used
  - Added `# Errors` documentation sections to all public functions returning `Result`
  - Made appropriate functions `const fn` for compile-time evaluation
  - Used `mul_add` for floating-point multiply-add operations (rate limiter)

### Changed

- **Documentation Updates**:
  - Updated feature flags documentation (removed deprecated `audit`, added `mimalloc`)
  - Updated tool count from 12 to 13 tools
  - Added `ssh_health` documentation to tool handlers README
  - Added hot-reload documentation to security module README

### Fixed

- **Config Watcher Panic Risk**: Replaced `.expect()` with proper error handling when creating tokio runtime for config reload
- **Clippy Pedantic/Nursery Compliance**: Fixed all warnings from `clippy::pedantic` and `clippy::nursery` lints:
  - Replaced `match` with `map_or`/`map_or_else` idioms
  - Fixed `future_not_send` warnings by adding `+ Send` to callback types
  - Added `#[allow]` attributes for `significant_drop_tightening` where appropriate
  - Fixed `option_if_let_else` warnings in test code

## [0.7.0] - 2026-01-28

### Added

- **New MCP Tools**:
  - `ssh_tail`: Read last N lines of remote files with optional grep filtering
  - `ssh_metrics`: Collect system metrics (CPU, memory, disk, network, load) as structured JSON
  - `ssh_exec_multi`: Execute commands in parallel across multiple hosts with fail-fast option

- **Persistent Shell Sessions**:
  - `ssh_session_create`: Create persistent interactive shell with cwd/env state
  - `ssh_session_exec`: Execute commands in existing session (maintains state)
  - `ssh_session_list`: List active sessions with metadata (age, idle time)
  - `ssh_session_close`: Close and cleanup sessions
  - Configurable max sessions, idle timeout, and max age
  - Automatic zombie session cleanup on channel failure

- **MCP Resources**:
  - Resource registry with URI-based resolution
  - `hosts://list` and `hosts://{name}/config`: Host configuration resources
  - `security://policy` and `security://blacklist`: Security policy resources

### Fixed

- **Session Zombie Cleanup**: Dead sessions are now removed from the session
  manager when the shell channel fails (exit, crash, or timeout)
- **Empty Command Validation**: Empty or whitespace-only commands are now
  rejected with `CommandDenied` error instead of being sent to the remote host
- **Blacklist Pattern Improvement**: `rm` blacklist pattern now catches all
  dangerous variants (`rm -r`, `rm -fr`, `rm --recursive`, `rm --force`)
  instead of only `rm -rf`

## [0.6.0] - 2026-01-27

### Added

- **Smart Output Truncation**: Head+tail truncation for large command outputs
  - New `output_truncator` module in domain layer (`src/domain/output_truncator.rs`)
  - Keeps 20% from start (context) + 80% from end (results), cuts at line boundaries
  - Default limit: 20,000 characters (configurable via `max_output_chars`)
  - `max_output` parameter on `ssh_exec` tool (0 = disabled)
  - Truncation message: `[truncated: X lines total, Y lines omitted, A → B chars]`

## [0.5.0] - 2026-01-27

### Fixed

- **SFTP Jump Host Support**: Upload and download handlers now correctly route
  through bastion/proxy hosts when `proxy_jump` is configured
  - Extracted `connect_with_jump()` utility in `utils.rs`
  - Both `ssh_upload` and `ssh_download` use the same jump host resolution as `ssh_exec`

## [0.4.0] - 2026-01-27

### Changed

- **Build Optimizations**: Release profile tuned for smaller/faster binaries
  - `panic = "abort"`, LTO, single codegen unit
  - mimalloc allocator for better memory performance
  - Optimized tokio feature flags

## [0.3.0] - 2026-01-26

### Added

- Complete documentation for v0.2.0 features:
  - Updated CHANGELOG, README, and module READMEs
  - Documented RateLimiter (Token Bucket algorithm)
  - Documented async AuditLogger with AuditWriterTask
  - Documented ConfigWatcher for hot-reload
  - Documented concurrent MCP request handling architecture

### Fixed

- v0.2.0 release was incomplete (missing documentation commit)

## [0.2.0] - 2026-01-26

### Added

- **Async Audit Logging**: Non-blocking audit writes using tokio mpsc channels
  - Background file writing with `spawn_blocking` to avoid blocking async runtime
  - `AuditWriterTask` for dedicated audit file writer
  - Tracing logs remain synchronous for fast structured logging

- **Per-Host Rate Limiting**: Token Bucket algorithm implementation
  - Configurable via `limits.rate_limit_per_second` (0 = disabled)
  - Independent rate limits per host
  - Protects against accidental command flooding

- **Hot-Reload Infrastructure**: Configuration file watching
  - `ConfigWatcher` using notify crate (v8.2) for file change detection
  - `Arc<RwLock<Config>>` for thread-safe config updates
  - Ready for future server integration

- **Concurrent Request Handling**: MCP server processes requests in parallel
  - Worker pool limited by `max_concurrent_commands`
  - Semaphore-based concurrency control
  - Single writer task for stdout serialization

### Changed

- `AuditLogger::new()` now returns `(AuditLogger, Option<AuditWriterTask>)` tuple
- `McpServer::new()` now returns `(McpServer, Option<AuditWriterTask>)` tuple
- `McpServer::run()` now takes `Arc<Self>` and `audit_task` parameter
- `McpServer.initialized` is now `AtomicBool` for thread-safe access

## [0.1.0] - 2025-01-25

### Added

- Initial release
- MCP server mode (JSON-RPC over stdio) for Claude Code integration
- CLI mode with subcommands:
  - `exec` - Execute remote commands
  - `status` - Show configured hosts
  - `history` - View command history
  - `upload` - Upload files via SSH
  - `download` - Download files via SSH
- Security features:
  - Command whitelist/blacklist validation
  - Output sanitization (password/secret masking)
  - Audit logging
- SSH connection pooling with retry logic
- Multiple authentication methods: SSH key, agent, password
- Host key verification modes (strict/accept-new/off)
- Hexagonal architecture (ports & adapters)
- Extensible tool handler registry (Open/Closed principle)

[1.15.0]: https://github.com/muchiny/bridge-mcp/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/muchiny/bridge-mcp/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/muchiny/bridge-mcp/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/muchiny/bridge-mcp/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/muchiny/bridge-mcp/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/muchiny/bridge-mcp/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/muchiny/bridge-mcp/compare/v1.9.0...v1.9.1
[1.1.0]: https://github.com/muchiny/bridge-mcp/compare/v1.0.0...v1.1.0
[2.0.1]: https://github.com/muchiny/bridge-mcp/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/muchiny/bridge-mcp/compare/v1.9.0...v2.0.0
[1.9.0]: https://github.com/muchiny/bridge-mcp/compare/v1.8.3...v1.9.0
[1.8.3]: https://github.com/muchiny/bridge-mcp/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/muchiny/bridge-mcp/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/muchiny/bridge-mcp/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/muchiny/bridge-mcp/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/muchiny/bridge-mcp/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/muchiny/bridge-mcp/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/muchiny/bridge-mcp/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/muchiny/bridge-mcp/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/muchiny/bridge-mcp/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/muchiny/bridge-mcp/compare/v1.1.0-dev...v1.2.0
[1.1.0-dev]: https://github.com/muchiny/bridge-mcp/compare/v1.0.0...v1.1.0-dev
[1.0.0]: https://github.com/muchiny/bridge-mcp/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/muchiny/bridge-mcp/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/muchiny/bridge-mcp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/muchiny/bridge-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/muchiny/bridge-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/muchiny/bridge-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/bridge-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/bridge-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/bridge-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/bridge-mcp/releases/tag/v0.1.0
