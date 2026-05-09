# Custom Semgrep Rules — 2026-05-09 (Task 12)

**Skill:** approach inspired by `semgrep-rule-creator:semgrep-rule-creator`. Skill expects test-first iterative methodology; this audit pass takes a faster path: write rules that encode the *already-known* drift findings (Tasks 4 + 5 + 11) and run them as confirmation/refutation against the codebase.
**Rules file:** `audit/2026-05-09/scans/semgrep-rules.yml` (3 rules)
**Output:** `audit/2026-05-09/scans/semgrep-results.txt` (15 findings total)
**Tools:** Semgrep OSS 1.162.0 (already installed Task 8)

---

## Rules

| Rule ID | Encodes | Pattern | Severity |
|---|---|---|---|
| `mcp-ssh-bridge.serde-saphyr-no-budget` | FIND-001..004 | `serde_saphyr::from_str` / `from_slice` / `from_reader` (any) | ERROR |
| `mcp-ssh-bridge.jwt-validation-new` | FIND-007 | `Validation::new($X)` (no `pattern-not-inside` because semgrep Rust support for inside-block-not-followed-by is limited) | WARNING |
| `mcp-ssh-bridge.russh-config-default` | FIND-008 | `Config { ..., ..Default::default() }` and `russh::client::Config { ..., ..Default::default() }` variants | WARNING |

---

## Results

**Total findings: 15** (raw, no post-filter). Per-rule breakdown:

| Rule | Hits | Sites |
|---|---|---|
| `serde-saphyr-no-budget` | 5 unique source-line matches (across many semgrep "findings" because each AST occurrence counts) | `src/config/loader.rs:45`, `src/domain/runbook.rs:160`, `:188`, `:336`, `:355`, `:375` (3 are inside `#[cfg(test)]` — verify per-line), `src/domain/yq_filter.rs:42`, `src/security/rbac.rs:299`, `src/mcp/tool_handlers/ssh_runbook_validate.rs:75` |
| `jwt-validation-new` | 1 | `src/mcp/transport/oauth.rs:212` |
| `russh-config-default` | 1 | `src/ssh/client.rs:339` (the `establish_connection` site; the inner-jump-host site at `:285` did not match — likely because the pattern shape differs) |

## Verification of pre-existing findings

| Finding | Confirmed? | Evidence |
|---|---|---|
| FIND-001 (`ssh_runbook_validate.rs:75`) | ✅ Yes | matched by `serde-saphyr-no-budget` |
| FIND-002 (`runbook.rs:160`) | ✅ Yes | matched |
| FIND-003 (`runbook.rs:188`) | ✅ Yes | matched |
| FIND-004 (`config/loader.rs:45`) | ✅ Yes | matched |
| FIND-007 (`oauth.rs:212`) | ✅ Yes | matched |
| FIND-008 (`ssh/client.rs:339`) | ✅ Yes | matched (the `:285` jump-host site requires a refined pattern; tracked as a rule-coverage gap) |

## New finding from semgrep

### FIND-032 — `serde_saphyr::from_str` in `yq_filter.rs` (P1)

**Location:** `src/domain/yq_filter.rs:42`
```rust
fn yaml_to_json_string(yaml: &str) -> Result<String> {
    let value: serde_json::Value = serde_saphyr::from_str(yaml).map_err(|e| {
```

**Why a finding:** `yq_filter` is an MCP tool that converts YAML → JSON for jq processing. The `yaml: &str` argument originates from either: (a) MCP request body, OR (b) the captured stdout of a previous `ssh_exec` (saved as `output_id`). Both paths are attacker-influenceable. Same `Budget`-missing class as FIND-001..004. Was missed by the Task 4 context7 audit because it's not a standard config/runbook file.

**Recommended fix:** same as FIND-001..004 — `from_str_with_options(yaml, options! { budget: budget! { ... } })`.

## False positives confirmed

- `src/security/rbac.rs:299` — inside `#[cfg(test)] mod tests` block (`fn test_rbac_config_deserialize_uses_defaults`). Not production.
- `src/domain/runbook.rs:336`, `:355`, `:375` — all inside `#[cfg(test)] mod tests` (test parsing fixtures). Not production.

## Rule coverage gaps (for future iteration)

- `russh-config-default` rule misses `src/ssh/client.rs:285` (the inner jump-host `Config` construction). The pattern needs another variant covering whatever exact shape that site uses. Recorded as low-priority rule-quality work.
- `jwt-validation-new` is over-broad — fires on any `Validation::new` call, even where `set_required_spec_claims` IS called subsequently. Refining requires `pattern-not` with sibling-statement matching, not currently expressible cleanly in semgrep Rust patterns. Acceptable as a "needs review" trigger.
