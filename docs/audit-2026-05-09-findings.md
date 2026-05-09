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
| FIND-001 | `src/mcp/tool_handlers/ssh_runbook_validate.rs:75` | `serde_saphyr::from_str::<Runbook>(yaml)` parses untrusted MCP-client YAML body without `Budget`. Billion-laughs / depth-bomb DoS vector. | Switch to `from_str_with_options(yaml, options! { budget: budget! { max_anchors: 100, max_depth: 50, max_nodes: 10000, max_reader_input_bytes: Some(1MB) } })`. Verify saphyr internal defaults first. | Task 4 (context7 drift) + Task 5 (runbook section) | open |
| FIND-002 | `src/domain/runbook.rs:160` | `serde_saphyr::from_str(&content)` in `load_runbook` parses filesystem YAML without `Budget`. Attacker-reachable when path is user-supplied. | Same fix as FIND-001. | Task 4 + Task 5 | open |
| FIND-003 | `src/domain/runbook.rs:188` | `serde_saphyr::from_str` in `builtin_runbooks()` (compile-time constants only, no runtime risk) but uses bare `from_str` — inconsistent codebase pattern. | Apply same `from_str_with_options` for codebase consistency. | Task 4 + Task 5 | open |
| FIND-004 | `src/config/loader.rs:45` | `serde_saphyr::from_str(&content)` in main config loader. Lower risk (file is permission-checked) but completes the codebase pattern fix. | Same as FIND-001. | Task 4 + Task 5 | open |
| FIND-005 | `src/mcp/transport/http.rs:202` | Axum router has only `CorsLayer::new()`. Missing: `TimeoutLayer + HandleErrorLayer`, explicit `DefaultBodyLimit`, `SetSensitiveRequestHeadersLayer + SetSensitiveResponseHeadersLayer`, `RequestIdLayer + PropagateRequestIdLayer`. | Add full tower-http middleware stack per `audit/2026-05-09/surface/context7/axum.md`. Without `HandleErrorLayer`, requests hang on timeout. Without sensitive-headers, `Authorization`/`Cookie` leak in tracing. | Task 4 (context7 drift) + Task 5 (oauth section open Q) | open |
| FIND-006 | `src/mcp/transport/oauth.rs` + `src/mcp/transport/http.rs:275` | `oauth_middleware` constructs `OAuthValidator::new((*config).clone())` per request → `keys: HashMap::new()` → every token rejected with "Unknown JWT signing key". Module doc L9–L18 states production wiring is "left for a follow-up". OAuth feature is not usable in production as wired. | Implement key population path (`set_static_keys` from config or `load_jwks` from JWKS URI) before middleware dispatch. Decide: per-request fresh validator vs shared `Arc<OAuthValidator>` (latter requires `RwLock`). | Task 5 (oauth section, structural observation) | open |

---

## P1 — fix this sprint (high-impact, deferable a few days)

| ID | File:line | Summary | Fix | Source | Status |
|---|---|---|---|---|---|
| FIND-007 | `src/mcp/transport/oauth.rs:212-216` | `Validation::new(header.alg)` then `set_issuer/set_audience/validate_nbf/leeway`. **Missing `set_required_spec_claims(&["exp","sub","iss","aud"])`**. `jsonwebtoken` 9.x default only requires `exp`. A token without `sub`/`iss`/`aud` claims would pass Validation when `set_issuer`/`set_audience` are also tolerant of missing claims (verify exact 9.x semantics). Alg-confusion class is already mitigated by the L184–L194 allowlist pre-filter. | Add `validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"])` after L211. | Task 4 (context7 drift) + Task 5 (oauth section) | open |
| FIND-008 | `src/ssh/client.rs:339, 285` | `russh::client::Config { ..Default::default() }` does NOT pin `Preferred { kex, key, cipher, mac }`. Russh upstream default may include legacy algorithms. Also no rekey `Limits` set — pool sessions live up to 1 h (`pool.rs:58-59`) accumulating data without rekey. | Set explicit `Preferred` allowlist (CURVE25519, ED25519, CHACHA20_POLY1305, AES_256_GCM, HMAC_SHA2_256_ETM) per `audit/2026-05-09/surface/context7/russh.md`. Set `Limits::new(1<<30, 1<<30, Duration::from_secs(3600))`. | Task 4 (context7 drift) + Task 5 (ssh/client section) | open |
| FIND-009 | `src/mcp/transport/oauth.rs:184-194` | JWT alg-allowlist excludes `EdDSA` (Ed25519 / RFC 8037). RS/ES/PS families allowed. Likely intentional but undocumented. | Decide: confirm intentional + document in module comment, OR add `Algorithm::EdDSA` to the allowlist. | Task 5 (oauth section open Q) | open |
| FIND-022 | `src/config/types.rs:516` | `SecurityConfig.require_elicitation_on_destructive: false` default. 97 P0-bucket destructive handlers (per `surface/entry-points.md`) execute without MCP `elicitation/create` confirmation by default. Compromised MCP client can mass-execute destructive tools without surfacing to human. | Flip default to `true` with documented opt-out, OR document the opt-in clearly in `config.example.yaml` and security model docs. | Task 9 (insecure-defaults) | open |
| FIND-026 | `Cargo.toml` (`serde-saphyr = "=0.0.21"`) | Pre-1.0 single-maintainer YAML parser on critical-path. Primary author has 649/667 commits, 167 GitHub stars, 0 open issues (low scrutiny). Parses ALL config + runbook YAML. Maintainer-takeover or buggy update would compromise everything that goes through `from_str` (FIND-001..004). | Stay pinned at `=0.0.21`, subscribe to release notifications, plan migration when crate reaches 1.0 or alternative emerges. Vendor source as fallback. | Task 10 (supply-chain) | open |

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

- P0: **6**
- P1: **5**
- P2: **12**
- P3: **4**
- FP (proven): **5**
- OQ (open): **12**
- **Total open findings: 27**

**Last assigned ID:** FIND-027
