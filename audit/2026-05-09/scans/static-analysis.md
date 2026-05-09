# Static Analysis (Semgrep) — 2026-05-09

**Skill:** `static-analysis:semgrep` (trailofbits, v1.2.1)
**Engine:** Semgrep OSS 1.162.0 (Pro not available)
**Mode:** Important-only (severity MEDIUM/HIGH/CRITICAL, post-filtered for security category + ≥MEDIUM confidence/impact)
**Scope:** `src/security/`, `src/ssh/`, `src/mcp/`, `src/domain/`, `src/config/`, `src/winrm/`, `src/psrp/` (502 .rs files)
**Excluded:** `tests/`, `target/`, `audit/`, `*/tests.rs`
**Approval:** user-approved 2026-05-09 (option "Approve full plan" via AskUserQuestion)
**Output:** `audit/2026-05-09/scans/static-analysis-semgrep/{raw,results}/` — merged SARIF at `results/results.sarif` (9 findings, 660KB)

---

## Rulesets executed (parallel via `static-analysis:semgrep-scanner` subagents)

| # | Ruleset | Source | Rules executed | Findings (raw) | Findings (filtered) |
|---|---|---|---|---|---|
| 1 | `r/rust` | Semgrep registry | 4 | 0 | 0 |
| 2 | `p/security-audit` | Semgrep registry | 2 (multilang only — 223 of 225 are non-Rust) | 0 | 0 |
| 3 | `r/generic.secrets` | Semgrep registry | 48 | 5 | 5 (all FP — see below) |
| 4 | `trailofbits/semgrep-rules` (`rust/`) | github.com/trailofbits/semgrep-rules @ HEAD (cloned 2026-05-09) | 1 | 4 | 4 |

**Total:** 9 raw findings → 4 actionable (TOB) + 5 confirmed FP (secrets in sanitizer self-tests).

---

## Findings

### TP1 — Panic in Result-returning function (4 sites)

**Rule:** `trailofbits.rs.panic-in-function-returning-result` (severity: WARNING)
**Class:** Reliability / fail-open. A panic inside a `Result`-returning function bypasses the caller's error-handling contract and crashes the process instead of propagating a recoverable error to the MCP client. On the SSH retry hot path this drops every other in-flight session.

| # | File | Line | Blast radius |
|---|---|---|---|
| FIND-001 | `src/ssh/retry.rs` | 204 | High — retry hot path; panic terminates the bridge process |
| FIND-002 | `src/ssh/retry.rs` | 282 | High — same module, separate site |
| FIND-003 | `src/ssh/pool.rs` | 395 | High — connection pool; panic drains pool, crashes server |
| FIND-004 | `src/mcp/tool_handlers/ssh_file_write.rs` | 237 | Medium — single tool handler; one tool call fails rather than the whole server, but still bypasses `Result` propagation |

Findings are present in raw SARIF at `static-analysis-semgrep/raw/rust-trailofbits.{json,sarif}`. Merged copy in `results/results.sarif`.

### FP1–FP5 — Sanitizer self-test fixtures (5 sites, all in one file)

**Rule:** `r/generic.secrets.security.detected-{github-token,private-key,jwt-token,stripe-api-key}`
**File:** `src/security/sanitizer.rs` (the only file flagged)

| # | Line | Rule |
|---|---|---|
| FP-001 | 38 | GitHub token (doc-comment example: `"token: ghp_abc123def456..."`) |
| FP-002 | 1021 | Private key (inline test fixture: `-----BEGIN RSA PRIVATE KEY-----`) |
| FP-003 | 1190 | GitHub token (test input: `"export GITHUB_TOKEN=ghp_1234567..."`) |
| FP-004 | 1239 | JWT token (test input: JWT-format example string) |
| FP-005 | 1289 | Stripe API key (test input: Stripe key format example) |

**Verdict — FALSE POSITIVE.** All five are deliberate test vectors inside the sanitizer's own unit tests. Their purpose is to verify the sanitizer correctly redacts these patterns. The correct mitigation is `# nosemgrep` inline annotations or a `.semgrepignore` entry scoping `src/security/sanitizer.rs` out of the secrets ruleset; this is a hygiene cleanup, not a security finding.

---

## Cross-reference against Task-4 context7 drift findings

The four drift items flagged by the context7 MCP audit are NOT pattern-matchable by any of the OSS Rust rulesets executed here (they require library-call-shape matching that the Trail-of-Bits + registry rules do not cover). Each is restated below with the verification status from this static-analysis pass.

| Drift item (from `surface/context7-summary.md`) | Severity | Semgrep verdict | Notes |
|---|---|---|---|
| `serde_saphyr::from_str` without `Budget` at `config/loader.rs:45`, `domain/runbook.rs:160,188`, `mcp/tool_handlers/ssh_runbook_validate.rs:75` | P0 | not detected by available rulesets | Confirmed by manual grep in Task 4 + per-function review in Task 5 (runbook.rs section). Custom Semgrep rule needed (Task 12 candidate). |
| Axum HTTP missing `TimeoutLayer` / `DefaultBodyLimit` / `SetSensitive*Headers` / `RequestIdLayer` at `src/mcp/transport/http.rs:202` | P0/P1 | not detected | Confirmed by manual grep in Task 4. Custom Semgrep rule needed (Task 12 candidate). |
| `jsonwebtoken::Validation::new(header.alg)` without `set_required_spec_claims` at `src/mcp/transport/oauth.rs:212-216` | P1 | not detected | Confirmed by manual review in Task 4 + per-function review in Task 5 (oauth.rs section). Note: oauth.rs L184–L194 pre-filters the algorithm allowlist, mitigating the alg-confusion class before `Validation::new`. The remaining gap is missing required-spec-claims set. Custom Semgrep rule needed. |
| russh `client::Config { ..Default::default() }` not pinning `Preferred` algos at `src/ssh/client.rs:339,285` | P1 | not detected | Confirmed by manual review in Task 4 + per-function review in Task 5 (ssh/client.rs section). Custom Semgrep rule needed. |

The four context7 drift items will be re-encoded as custom rules in Task 12 (`semgrep-rule-creator`) and re-run against the same scope.

---

## Cross-reference against Task-5 context-summary Open Questions

The 5 focus areas listed in the user prompt are restated below with semgrep coverage status.

| Focus area | Coverage by available rulesets | Need for custom rule (Task 12) |
|---|---|---|
| (1) Command construction without going through `SecurityValidator` | none | Yes — match `executor.exec(...)` calls without a preceding `validate(...)` / `validate_builtin(...)` |
| (2) Path joined from MCP request input without `canonicalize` + prefix-check | none | Yes — match `Path::join(&user_input)` followed by direct file ops without canonicalize |
| (3) `Vec`/`String`/`HashMap` containing creds not wrapped in `Zeroizing` | none | Yes — match struct fields named like `password`/`passphrase`/`secret` typed as plain `String`/`Vec<u8>` |
| (4) Shared global state across MCP sessions (`static`, `lazy_static`, `OnceCell`, `parking_lot::RwLock<HashMap>`) | none | Yes — match `static` items wrapping mutable maps in `mcp/server.rs` (Vuln 8/9 variant pattern) |
| (5) Audit log fields with raw command before redaction | none | Yes — match `AuditEvent::new(...)` constructions where `command` is the raw input rather than the post-validator value |

---

## Summary

- **9 total findings**, **4 confirmed true positives** (panic-in-Result), **5 confirmed false positives** (sanitizer self-tests).
- The 4 TOB findings are reliability findings (panic propagation), not security vulnerabilities. They are P2 in the audit's severity scheme — operational impact (process crash) but no confidentiality/integrity/auth bypass.
- Real security gaps (the 4 drift items from Task 4 + the 5 focus areas from Task 5) are NOT detectable by available OSS Rust rulesets and require custom Semgrep rules to encode them. That work belongs to Task 12 (`semgrep-rule-creator`).
- Pro engine + cross-file taint tracking would help cover focus-area #1 (validator-bypass patterns) but is unavailable in this environment.

## Output files

- `audit/2026-05-09/scans/static-analysis-semgrep/rulesets.txt`
- `audit/2026-05-09/scans/static-analysis-semgrep/raw/{rust-official,rust-security-audit,secrets,rust-trailofbits}.{json,sarif,filtered.json}`
- `audit/2026-05-09/scans/static-analysis-semgrep/results/results.sarif` (merged, 9 findings)
- `audit/2026-05-09/scans/static-analysis-semgrep/repos/trailofbits-semgrep-rules/` (cloned ruleset; not committed — `.gitignore`'d below)

The cloned `repos/` directory is excluded from the commit via `.gitignore` to keep the audit folder slim.
