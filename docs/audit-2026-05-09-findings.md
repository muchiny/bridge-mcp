# Security Audit Findings — 2026-05-09

**Branch:** `security/audit-2026-05-09`
**Audit plan:** `docs/superpowers/plans/2026-05-09-full-security-audit.md`
**Last updated:** 2026-05-09 (Tasks 1–8 complete; Tasks 9–17 may add more)
**Status legend:** `open` (not yet fixed) / `in-progress` (fix branch open) / `fixed` (commit referenced) / `wont-fix` (justified) / `verified-fp` (proven false positive)

This file is the **single source of truth** for every concrete problem the audit surfaces. Each task in the audit plan appends to one of the buckets below. After Task 16 (`/fp-check`), `audit/2026-05-09/FINDINGS.md` is generated as a derivative report; this `docs/` file remains the actionable backlog.

**Convention:** every finding row has a stable ID `FIND-NNN`. IDs are append-only — never renumber.

---

## P0 — fix immediately (security-critical or production-blocking)

| ID | File:line | Summary | Fix | Source | Status |
|---|---|---|---|---|---|
| FIND-001 | `src/mcp/tool_handlers/ssh_runbook_validate.rs:75` | `serde_saphyr::from_str::<Runbook>(yaml)` parses untrusted MCP-client YAML body without `Budget`. Billion-laughs / depth-bomb DoS vector. | Switch to `from_str_with_options(yaml, options! { budget: budget! { max_anchors: 100, max_depth: 50, max_nodes: 10000, max_reader_input_bytes: Some(1MB) } })`. Verify saphyr internal defaults first. | Task 4 (context7 drift) + Task 5 (runbook section) | fixed (2d213fb) |
| FIND-002 | `src/domain/runbook.rs:160` | `serde_saphyr::from_str(&content)` in `load_runbook` parses filesystem YAML without `Budget`. Attacker-reachable when path is user-supplied. | Same fix as FIND-001. | Task 4 + Task 5 | fixed (2d213fb) |
| FIND-003 | `src/domain/runbook.rs:188` | `serde_saphyr::from_str` in `builtin_runbooks()` (compile-time constants only, no runtime risk) but uses bare `from_str` — inconsistent codebase pattern. | Apply same `from_str_with_options` for codebase consistency. | Task 4 + Task 5 | fixed (2d213fb) |
| FIND-004 | `src/config/loader.rs:45` | `serde_saphyr::from_str(&content)` in main config loader. Lower risk (file is permission-checked) but completes the codebase pattern fix. | Same as FIND-001. | Task 4 + Task 5 | fixed (2d213fb) |
| FIND-005 | `src/mcp/transport/http.rs:202` | Axum router has only `CorsLayer::new()`. Missing: `TimeoutLayer + HandleErrorLayer`, explicit `DefaultBodyLimit`, `SetSensitiveRequestHeadersLayer + SetSensitiveResponseHeadersLayer`, `RequestIdLayer + PropagateRequestIdLayer`. | Add full tower-http middleware stack per `audit/2026-05-09/surface/context7/axum.md`. Without `HandleErrorLayer`, requests hang on timeout. Without sensitive-headers, `Authorization`/`Cookie` leak in tracing. | Task 4 (context7 drift) + Task 5 (oauth section open Q) | fixed (9747fa6) |
| FIND-006 | `src/mcp/transport/oauth.rs` + `src/mcp/transport/http.rs:275` | `oauth_middleware` constructs `OAuthValidator::new((*config).clone())` per request → `keys: HashMap::new()` → every token rejected with "Unknown JWT signing key". Module doc L9–L18 states production wiring is "left for a follow-up". OAuth feature is not usable in production as wired. | Implement key population path (`set_static_keys` from config or `load_jwks` from JWKS URI) before middleware dispatch. Decide: per-request fresh validator vs shared `Arc<OAuthValidator>` (latter requires `RwLock`). | Task 5 (oauth section, structural observation) | fixed (0864649) — JWKS HTTP fetch deferred to follow-up |
| FIND-038 | `src/mcp/server.rs:91` (`active_requests: Arc<Mutex<HashMap<String, CancellationToken>>>`) + insert at L720, lookup at L274 | **Direct cross-session attack.** HashMap keyed on JSON-RPC request id (caller-chosen, NOT session-scoped). Client A sends `tools/call { id: 42 }` → server stores `active_requests["42"] = token_A`. Client B (concurrent session) sends `notifications/cancelled { params: { requestId: "42" } }` → `cancel_request("42")` removes A's entry, cancels A's token. Client A's request is aborted mid-execution. **Vuln 8 sibling — same defect class, same shape.** | Apply the same per-session fix as Vuln 8: move `active_requests` into a per-session `Arc<...>` allocated in `serve_session` (mirror L641 `session_pending`); clone Arc into spawned task at L720; route `cancel_request` lookups through the session-local map. Also include session id in the key for defense-in-depth. | Task 13 (variant-analysis) | fixed (d031988) |

---

## P1 — fix this sprint (high-impact, deferable a few days)

| ID | File:line | Summary | Fix | Source | Status |
|---|---|---|---|---|---|
| FIND-007 | `src/mcp/transport/oauth.rs:212-216` | `Validation::new(header.alg)` then `set_issuer/set_audience/validate_nbf/leeway`. **Missing `set_required_spec_claims(&["exp","sub","iss","aud"])`**. `jsonwebtoken` 9.x default only requires `exp`. A token without `sub`/`iss`/`aud` claims would pass Validation when `set_issuer`/`set_audience` are also tolerant of missing claims (verify exact 9.x semantics). Alg-confusion class is already mitigated by the L184–L194 allowlist pre-filter. | Add `validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"])` after L211. | Task 4 (context7 drift) + Task 5 (oauth section) | fixed (ebabff0) — empirically only `sub` was unchecked; `iss`/`aud` already implicitly required via `set_issuer`/`set_audience`, but spec claim now explicit |
| FIND-008 | `src/ssh/client.rs:339, 285` | `russh::client::Config { ..Default::default() }` does NOT pin `Preferred { kex, key, cipher, mac }`. Russh upstream default may include legacy algorithms. Also no rekey `Limits` set — pool sessions live up to 1 h (`pool.rs:58-59`) accumulating data without rekey. | Set explicit `Preferred` allowlist (CURVE25519, ED25519, CHACHA20_POLY1305, AES_256_GCM, HMAC_SHA2_256_ETM) per `audit/2026-05-09/surface/context7/russh.md`. Set `Limits::new(1<<30, 1<<30, Duration::from_secs(3600))`. | Task 4 (context7 drift) + Task 5 (ssh/client section) | open |
| FIND-009 | `src/mcp/transport/oauth.rs:184-194` | JWT alg-allowlist excludes `EdDSA` (Ed25519 / RFC 8037). RS/ES/PS families allowed. Likely intentional but undocumented. | Decide: confirm intentional + document in module comment, OR add `Algorithm::EdDSA` to the allowlist. | Task 5 (oauth section open Q) | open |
| FIND-022 | `src/config/types.rs:516` | `SecurityConfig.require_elicitation_on_destructive: false` default. 97 P0-bucket destructive handlers (per `surface/entry-points.md`) execute without MCP `elicitation/create` confirmation by default. Compromised MCP client can mass-execute destructive tools without surfacing to human. | Flip default to `true` with documented opt-out, OR document the opt-in clearly in `config.example.yaml` and security model docs. | Task 9 (insecure-defaults) | open |
| FIND-026 | `Cargo.toml` (`serde-saphyr = "=0.0.21"`) | Pre-1.0 single-maintainer YAML parser on critical-path. Primary author has 649/667 commits, 167 GitHub stars, 0 open issues (low scrutiny). Parses ALL config + runbook YAML. Maintainer-takeover or buggy update would compromise everything that goes through `from_str` (FIND-001..004). | Stay pinned at `=0.0.21`, subscribe to release notifications, plan migration when crate reaches 1.0 or alternative emerges. Vendor source as fallback. | Task 10 (supply-chain) | open |
| FIND-028 | `src/config/types.rs:219` | `HostConfig.sudo_password: Option<String>` not `Zeroizing`. Same class as FIND-014 (SOCKS password) on the sibling field. `HostConfig` lives for entire process lifetime; password sits in heap from start to exit. Hot-reload (`src/config/watcher.rs`) does NOT wipe old allocations. | `pub sudo_password: Option<Zeroizing<String>>`. Update borrow sites with `.as_deref()` — no behavior change. | Task 11 (zeroize-audit) | open |
| FIND-029 | `src/mcp/tool_handlers/ssh_db_query.rs:27` (+ likely `ssh_db_dump.rs`, `ssh_mysql_query.rs`, `ssh_postgresql_query.rs`) | `SshDbQueryArgs.db_password: Option<String>` arg not `Zeroizing`. Password from MCP JSON-RPC request body sits in plain heap during handler. `as_deref()` borrows the underlying `&str` for `database.rs::write_password_env`; drop of `Args` does NOT wipe. | `db_password: Option<Zeroizing<String>>` in every DB handler `Args` struct. | Task 11 (zeroize-audit) | open |
| FIND-032 | `src/domain/yq_filter.rs:42` | `yaml_to_json_string` uses `serde_saphyr::from_str(yaml)` without `Budget`. The `yaml: &str` arg is attacker-influenceable (MCP request body OR captured `ssh_exec` stdout via `output_id`). Same billion-laughs / depth-bomb class as FIND-001..004. Missed by Task 4 context7 review because not a standard config file. | Same as FIND-001..004: `serde_saphyr::from_str_with_options(yaml, options! { budget: budget! { ... } })`. | Task 12 (custom semgrep rule confirmed) | fixed (2d213fb) |
| FIND-033 | `src/mcp/server.rs:65` (`runtime_max_output_chars: Arc<RwLock<Option<usize>>>`), written L1125, read L405+L422 | Single `Option<usize>` slot, written per `initialize` based on `init_params.client_info.name`. Two concurrent HTTP clients with different `client_overrides` profiles: last `initialize` wins, applies to ALL subsequent tool calls regardless of which session sent them. Cross-session quality-of-service contamination. | Same per-session fix shape as Vuln 9: move into per-session `Arc<...>` in `serve_session`; pass via `ToolContext`. | Task 13 (variant-analysis) | open |
| FIND-034 | `src/mcp/server.rs:68` (`notification_tx: Arc<RwLock<Option<mpsc::Sender>>>`), written L653, read L598-603 | Single `Option<Sender>` slot. Each `serve_session` entry overwrites it with that session's tx. Background workers (task_store progress events) `blocking_read()` the slot per notification — fires whoever's tx is current at fire time. Notifications from session A can route to session B's writer. Confirms OQ-008. | Per-session `Arc<RwLock<Option<Sender>>>` allocated in `serve_session`; or use a `HashMap<SessionId, Sender>` if multiplexing. | Task 13 (variant-analysis) | open |
| FIND-036 | `src/mcp/server.rs:77` (`resource_subscriptions: Arc<RwLock<HashMap<String, Vec<String>>>>`), subscribe L1763, unsubscribe L1782 | HashMap keyed on URI (resource path), Vec of subscription IDs not session-scoped. Two clients subscribing to same URI share the Vec; notifications fan out to all sub-IDs (cross-session leakage). Unsubscribe by client A may inadvertently affect notification dispatch for client B. | Switch key to `(SessionId, URI)` tuple, or move to per-session HashMap allocated in `serve_session`. | Task 13 (variant-analysis) | open |
| FIND-037 | `src/mcp/server.rs:79` (`roots: Arc<RwLock<Vec<RootEntry>>>`), written L942 | Single `Vec<RootEntry>` overwritten by `fetch_roots` from the requesting client. Tool handlers reading `ctx.roots` see whichever client called last. Confirms OQ-006. | Per-session `roots` field allocated in `serve_session`; pass via `ToolContext`. | Task 13 (variant-analysis) | open |

---

## P2 — backlog (defense-in-depth, operational hardening)

| ID | File:line | Summary | Fix | Source | Status |
|---|---|---|---|---|---|
| FIND-010 | `src/ssh/retry.rs:204` | `panic-in-function-returning-result` (Trail-of-Bits semgrep). `.unwrap()` / `.expect()` inside `Result`-returning fn on retry hot path. Process crash on edge case. | Replace `.unwrap()` with `?` propagation + structured error variant. | Task 8 (semgrep TOB) | open |
| FIND-011 | `src/ssh/retry.rs:282` | Same class as FIND-010, second site in same module. | Same fix. | Task 8 (semgrep TOB) | open |
| FIND-012 | `src/ssh/pool.rs:395` | Same class. Connection pool drain → server crash. | Same fix. | Task 8 (semgrep TOB) | open |
| FIND-013 | `src/mcp/tool_handlers/ssh_file_write.rs:237` | Same class. Single tool failure (smaller blast radius) but still bypasses `Result`. | Same fix. | Task 8 (semgrep TOB) | open |
| FIND-014 | `src/config/types.rs:420-421` | `SocksProxyConfig.password` is `Option<String>`, NOT `Zeroizing<String>`. All other credentials in the codebase are wrapped (SSH passphrase/password, WinRM NTLM). SOCKS password persists in heap until process exit. | Wrap as `Option<Zeroizing<String>>`, update all call sites to borrow. | Task 5 (ssh/client section) | open |
| FIND-015 | `src/ssh/client.rs:274` | `originator_address` hardcoded as `"127.0.0.1:0"` in `channel_open_direct_tcpip`. Jump-host SSH audit logs record all tunnels as originating from `localhost`, misleading attribution. | Decide: privacy-preserving (keep + document in module comment) OR pass actual originator config. | Task 5 (ssh/client section open Q) | open |
| FIND-016 | `src/ssh/client.rs:418-424, 438-444` | `sanitize_ssh_error` is applied to auth errors (L508, L541, L576) but NOT to connection-phase errors (SOCKS, direct connect). If russh embeds auth-method names in connection-phase diagnostics, they leak unredacted. | Apply `sanitize_ssh_error` consistently in connection-error formatters. | Task 5 (ssh/client section open Q) | open |
| FIND-017 | `src/config/types.rs` (multiple structs) | `#[serde(deny_unknown_fields)]` not on `Config` and most nested config structs. Saphyr strict-typing partially compensates but explicit attribute is belt-and-suspenders. | Add `#[serde(deny_unknown_fields)]` to every config struct. | Task 4 (context7 drift) | open |
| FIND-023 | `src/config/types.rs:1090` (default fn at L1101) | `SshConfigDiscovery.enabled: true` default — `~/.ssh/config` parsed at startup and every Host entry auto-registered as reachable target. MCP client can enumerate operator's full personal host inventory (often >> YAML-declared production set). | Flip default to `false`; document opt-in for ergonomic time-to-first-command users. | Task 9 (insecure-defaults) | open |
| FIND-024 | `src/config/types.rs:1247-1250` | `ToolGroupsConfig`: groups not listed are enabled by default. All 75 groups / 357 handlers exposed out-of-box. Operator who only needs `docker` + `service` is also exposed to AD/LDAP/Vault/K8s/AWS/ESXi/HyperV groups. | Flip to default-disabled; require explicit opt-in per group. Or ship a profile system (`profile: minimal\|standard\|full`) so operators don't have to enumerate 75 groups manually. | Task 9 (insecure-defaults) | open |
| FIND-025 | `Cargo.toml` (`shellexpand = "3"`) used at `src/ssh/client.rs:487` | `shellexpand` GitHub repo is **archived** (last push 2026-02-25, 97 stars). No more security patches. Used on the SSH-key auth path for `~` expansion — regression could cause silent fallback to wrong key. | Replace with `dirs::home_dir()` + manual `~` strip (~30 LOC, `dirs` crate already in deps). OR vendor shellexpand source in-tree under `vendor/`. | Task 10 (supply-chain) | open |
| FIND-027 | `Cargo.toml` (`tokio-socks = "0.5"`) used at `src/ssh/client.rs:373-413` | `tokio-socks` (sticnarf/tokio-socks) — last push 2025-02-19 (>14 months stale), 102 stars, not archived but inactive. SOCKS proxy is auth-perimeter relevant. | Monitor `sticnarf/tokio-socks` for activity. If no release by 2026-08, plan vendoring (crate is ~1500 LOC). | Task 10 (supply-chain) | open |
| FIND-030 | `src/mcp/tool_handlers/ssh_vault_write.rs:13` | `SshVaultWriteArgs.data: Vec<String>` carries vault `key=value` secret pairs unwrapped. Strings sit in heap during handler call; `Args` drop does not wipe. Local heap residency is gratuitous (separate from FIND-031 about remote argv visibility). | `data: Vec<Zeroizing<String>>`; update `build_write_command` to take `&[Zeroizing<String>]`. Optional: add `data_files: Vec<PathBuf>` so secrets can be passed via stdin/file. | Task 11 (zeroize-audit) | open |
| FIND-031 | `src/domain/use_cases/database.rs:90-94`, `src/domain/use_cases/vault.rs:144-170` | Secrets transit shell argv on the remote host. `MYSQL_PWD='pwd' mysql ...` / `PGPASSWORD='pwd' psql ...` / `vault kv put path key=secret_value` — visible in remote `ps eww` (vault) or `/proc/PID/environ` (DB) during execution. Local audit-log sanitizer covers local trace; remote process-list is unprotected. | Vault: pipe `data` via stdin (`vault kv put path - <<EOF`). DB: recommend `~/.my.cnf` / `~/.pgpass` connection files (`0600` mode); document trade-off in handler description text shown to MCP client. | Task 11 (zeroize-audit) | open |
| FIND-035 | `src/mcp/server.rs:70` (`log_level: Arc<AtomicU8>`) | Global atomic set by any client's `notifications/setLevel`. Client B can mute client A's `notifications/message`. Cross-session denial-of-observability. Low operational impact. | Per-session log level, mirror of session_capabilities pattern. | Task 13 (variant-analysis) | open |

---

## P3 — operational / tooling debt (no security impact, but blocks audit infra)

| ID | File:line | Summary | Fix | Source | Status |
|---|---|---|---|---|---|
| FIND-018 | `Cargo.toml` (winrm-rs dep) | `cargo outdated` fails to resolve dep graph: `winrm-rs v1.0.0` declares `reqwest ^0.13` with feature `webpki-roots`, which reqwest 0.13 dropped. Blocks any version-table dep audit until winrm-rs is patched or pinned. | Patch winrm-rs feature flags upstream OR pin in workspace; OR vendor the dep. | Task 3 baseline | open |
| FIND-019 | `tests/security_audit_redaction.rs:84` | `clippy::uninlined_format_args` warning. Branch is NOT clippy-clean — `make ci-full` will fail. | Inline the format args. Trivial fix. | Task 2 baseline | open |
| FIND-020 | `src/mcp/transport/oauth.rs:414` | `clippy::needless_pass_by_value` on `sign_token(claims: serde_json::Value)`. Branch is NOT clippy-clean. | Take `&Value` instead of owned `Value` (or `&Claims` if appropriate). | Task 2 baseline | open |
| FIND-021 | `audit/2026-05-09/baseline/cargo-geiger.txt` | `cargo geiger --all-features` fails extracting `nkeys-0.4.5` (aws-sdk transitive). Workspace falls back to `--forbid-only`. Loses unsafe-density per crate signal. | Either: (a) `cargo fetch` then re-run; (b) gate `--all-features` to skip cloud features; (c) accept `--forbid-only` baseline as sufficient given `#![forbid(unsafe_code)]` on the workspace. | Task 3 baseline | open |

---

## False positives (proven, not actionable)

| ID | File:line | Why FP | Source |
|---|---|---|---|
| FP-001 | `src/security/sanitizer.rs:38` | Doc-comment example `"token: ghp_abc123def456..."` — the sanitizer's job is to redact this pattern; the example is in its own unit test corpus. | Task 8 semgrep `r/generic.secrets` |
| FP-002 | `src/security/sanitizer.rs:1021` | Inline test fixture `-----BEGIN RSA PRIVATE KEY-----` — same rationale. | Task 8 semgrep |
| FP-003 | `src/security/sanitizer.rs:1190` | Test input `"export GITHUB_TOKEN=ghp_1234567..."` — same rationale. | Task 8 semgrep |
| FP-004 | `src/security/sanitizer.rs:1239` | JWT-format test input — same rationale. | Task 8 semgrep |
| FP-005 | `src/security/sanitizer.rs:1289` | Stripe-key-format test input — same rationale. | Task 8 semgrep |

**Optional cleanup:** add `# nosemgrep: <rule-id>` inline at each line, or add `.semgrepignore` entry scoping `src/security/sanitizer.rs` out of `r/generic.secrets`.

---

## Open questions (not yet findings — need code inspection to confirm)

These are anchor points for Tasks 9–13 to resolve. Each becomes a finding (or is dismissed) after the corresponding scan.

| ID | Source | Question | Where to inspect | Owner task |
|---|---|---|---|---|
| OQ-001 | Task 5 validator | Does `cargo install` of `CommandValidator` in `src/main.rs` / `src/mcp/server.rs` use `SecurityConfig::default()` (which would Standard mode + empty whitelist = block all `validate()` calls)? | `src/main.rs`, `src/mcp/server.rs` validator construction | Task 9 |
| OQ-002 | Task 5 validator | `validate_builtin` caller discipline — confirm each of 8 call sites (`standard_tool.rs:296`, `ssh_disk_usage.rs:116`, `ssh_find.rs:154`, `ssh_tail.rs:137`, `ssh_metrics.rs:145`, `ssh_metrics_multi.rs:197`, `ssh_file_write.rs:220`) constructs the command exclusively from domain-builder output before calling `validate_builtin`. | each cited file:line | Task 11 |
| OQ-003 | Task 5 validator | `${IFS:-" "}` (default-value expansion) is NOT covered by `normalize_for_blacklist_match`. Does `rm${IFS:- }-rf${IFS:- }/` actually defeat the default `rm\s+-rf\s+/` blacklist pattern? Build a test. | `src/security/validator.rs` + new proptest | Task 14 |
| OQ-004 | Task 5 validator | `$'\x09'` and `$'\011'` (hex/octal tab encodings) — does bash send literal `$'\x09'` or expanded tab? Does `\s` in regex crate match it? | manual test + `src/security/validator.rs` | Task 14 |
| OQ-005 | Task 5 session_capabilities | `handle_initialize` (server.rs L1083-L1160) does not visibly check `self.initialized.load()` before re-writing capability flags. Does a second `initialize` corrupt session state? | `src/mcp/server.rs:1083-1160` | Task 13 |
| OQ-006 | Task 5 session_capabilities | `runtime_max_output_chars` (server.rs L65/L1125): server-level `Arc<RwLock<Option<usize>>>` written per `initialize`. With 2 concurrent HTTP sessions, last-writer-wins. Cross-session contamination similar to Vuln 9 class. | `src/mcp/server.rs:1125` | Task 13 |
| OQ-007 | Task 5 session_capabilities | `supports_roots` not propagated into `ToolContext` (only elicitation+sampling are). Does any tool handler need to distinguish "client doesn't support roots" from "client supports roots but declared none"? | `src/mcp/server.rs:390-439` + tool handlers consuming `ctx.roots` | Task 13 |
| OQ-008 | Task 5 session_capabilities | HTTP transport's SSE-reconnect path may dispatch handlers with `session_caps = None`. Trace handler dispatch through `SessionData` lookup. | `src/mcp/transport/session_store.rs`, `src/mcp/transport/http.rs` | Task 13 |
| OQ-009 | Task 5 oauth | 9 open questions in oauth section. Highest leverage: per-request empty-key-map gap (covered by FIND-006), `set_required_spec_claims` interaction with jsonwebtoken 9.x defaults (FIND-007), `kid` echo in error responses, EdDSA omission (FIND-009). | various | Tasks 11, 13 |
| OQ-010 | Task 5 ssh/client | 10 open questions in ssh/client section. Covered: FIND-008 (Default config), FIND-014 (SOCKS pwd), FIND-015 (originator), FIND-016 (sanitize coverage). Remaining: russh 0.60 default `Preferred` actual contents, `PrivateKey` `ZeroizeOnDrop` impl status, `best_supported_rsa_hash()` fallback to SHA-1 vs SHA-256, `check_known_hosts` port handling at port 22, `SSH_AUTH_SOCK` trust boundary in containers, last_error in agent auth not sanitized (variant of FIND-016), re-key limit on long-lived pool. | `Cargo.lock` russh 0.60, russh source | Task 11 |
| OQ-011 | Task 5 runbook | 8 open questions in runbook section. Covered: FIND-001/002/003. Remaining: saphyr internal Budget defaults; `command: Some("")` evasion of validator; `save_as` mechanism not implemented despite shipped runbooks referencing it; missing `deny_unknown_fields` on `Runbook`/`RunbookStep`/`RunbookParam` (covered by FIND-017 for `Config` only); HashMap iteration-order non-determinism in `apply_template`; `require_elicitation_on_destructive` gate applied to `ssh_runbook_execute`. | `src/domain/runbook.rs`, saphyr crate, runbook YAML files | Tasks 11, 14 |
| OQ-012 | Task 5 (cross-section) | `McpServer` server-singleton state distinct from Vuln 8/9: `runtime_max_output_chars`, `roots`, `client_info`, `notification_tx`. Are any of these latent Vuln 10/11 cross-session leaks, or all acceptable design? | `src/mcp/server.rs:46-92` field-by-field | Task 13 (variant-analysis) |
| OQ-013 | Task 11 (zeroize-audit) | Does `russh::keys::PrivateKey` (russh 0.60.1) implement `ZeroizeOnDrop`? If not, secret key bytes persist in heap until Arc refcount=0; even then, depends on Drop impl wiping. After `load_secret_key` returns at `src/ssh/client.rs:502`, `Arc::new(key_pair)` wraps the secret. | `~/.cargo/registry/src/index.crates.io-*/russh-keys-*/src/private.rs` or upstream `Eugeny/russh` | Task 11 deferred / manual follow-up |
| OQ-014 | Task 15 (mutation-testing) | `cargo mutants` initial run produced 0 mutants due to `--file` glob quoting issue. SKIPPED per user request. Mutation-testing coverage gap on `src/security/{validator,sanitizer,audit,rate_limiter,rbac}.rs` remains. Next audit cycle should re-run with unquoted path: `cargo mutants -j 4 --file src/security/validator.rs --timeout 120`. | `audit/2026-05-09/variant/mutants-summary.md` | next audit cycle |

---

## Append protocol for Tasks 9–17

Each subsequent task that finds a problem MUST:

1. Append a row to the appropriate severity bucket above (P0 / P1 / P2 / P3).
2. Use the next sequential `FIND-NNN` id (latest assigned: **FIND-021**).
3. Cite source as `Task N (<scanner-or-source>)`.
4. Set initial status to `open`.
5. If the finding turns out to be a false positive after `/fp-check` (Task 16), MOVE the row to the False positives table with rationale.
6. If a finding is actually fixed during the audit, update status to `fixed (<commit-sha>)` rather than deleting the row.

For Open Questions resolved by a later task: update the OQ row's "Owner task" column to indicate the resolving task, and either promote it to a finding (with new `FIND-NNN` id) or move it to the False positives table.

---

## Summary counters (auto-update at end of each commit)

- P0: **7**
- P1: **12**
- P2: **14**
- P3: **5**
- FP (proven): **5** (sanitizer self-tests) **+ 4 confirmed test-only saphyr matches** (rbac.rs:299, runbook.rs:336/355/375)
- OQ (open): **14**
- **Total open findings: 38**

**Last assigned ID:** FIND-038
