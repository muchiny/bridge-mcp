# Dependency Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring all 24 outdated dependencies current — semver-compatible bumps via `cargo update`, plus reviewed major-version bumps (jsonwebtoken, sha2, russh, similar, serde-saphyr, opentelemetry stack) and removal of the winrm-rs git-fork patch — with zero regressions.

**Architecture:** Phased. Each phase = one isolated, independently-revertable commit gated by `cargo build` (relevant features) + `cargo test --lib`. Semver-safe bumps first (cheap, low-risk), then one phase per major bump so a single regression never blocks the rest. WSL OOM safety: `--lib`, default parallelism, never concurrent build+test.

**Tech Stack:** Rust 2024 (MSRV 1.94), cargo, cargo-outdated, cargo-machete, make ci. Crates touched: tokio, russh/russh-sftp, jsonwebtoken, sha2, similar, serde-saphyr, opentelemetry stack, winrm-rs, aws-sdk.

---

## Pre-flight (Phase 0)

**Files:** none (git + baseline only)

- [ ] **Step 1: Stash/park current WIP**

Current branch `security/redacted-secret-newtype` is dirty (`src/config/mod.rs`, `src/config/secret.rs`, `docs/`). Do NOT mix dep bumps into it.

Run:
```bash
cd /home/muchini/mcp-ssh-bridge
git stash push -u -m "wip-redacted-secret before dep-update" -- src/config/mod.rs src/config/secret.rs
git status
```
Expected: working tree clean except untracked `docs/` (the plan itself). If `docs/` was already tracked WIP, leave it.

- [ ] **Step 2: Branch from clean main**

Run:
```bash
git fetch origin
git checkout main && git pull --ff-only
git checkout -b chore/dep-updates-2026-05-30
```
Expected: on new branch, tree clean.

- [ ] **Step 3: Capture green baseline**

Run:
```bash
cargo build --all-features 2>&1 | tail -5
cargo test --lib 2>&1 | tail -15
```
Expected: build OK, all lib tests pass. Record the pass count — it is the regression baseline for every later phase. If baseline is red, STOP and fix before bumping anything.

- [ ] **Step 4: Snapshot lockfile**

Run:
```bash
cp Cargo.lock /tmp/Cargo.lock.baseline
```
Expected: copy made (for diffing what each phase moved).

---

## Phase 1: Semver-compatible bumps (`cargo update`)

**Files:**
- Modify: `Cargo.lock` (only — no `Cargo.toml` edits)

Covers: aws-config, aws-sdk-ssm, clap_complete, const-hex, filetime, mimalloc, reqwest, russh 0.60.1→0.60.3, russh-sftp 2.1.1→2.3.0, serde_json, tokio, tokio-socks, tower-http, uuid.

- [ ] **Step 1: Update within semver ranges**

Run:
```bash
cargo update
diff <(grep '^name\|^version' /tmp/Cargo.lock.baseline) <(grep '^name\|^version' Cargo.lock) | head -60
```
Expected: lockfile moves the 14 compatible crates. No `Cargo.toml` change.

- [ ] **Step 2: Build all features**

Run:
```bash
cargo build --all-features 2>&1 | tail -5
```
Expected: compiles clean.

- [ ] **Step 3: Test**

Run:
```bash
cargo test --lib 2>&1 | tail -15
```
Expected: pass count == baseline.

- [ ] **Step 4: Commit**

```bash
git add Cargo.lock
git commit -m "chore(deps): update semver-compatible dependencies

cargo update — patch/minor bumps within existing ranges:
tokio, russh 0.60.3, russh-sftp 2.3.0, reqwest, tower-http,
aws-config, aws-sdk-ssm, clap_complete, const-hex, mimalloc,
serde_json, tokio-socks, uuid, filetime (dev)."
```

---

## Phase 2: winrm-rs 1.0 → 1.1.2 + drop git patch (FIND-018)

**Files:**
- Modify: `Cargo.toml:120` (winrm-rs version)
- Modify: `Cargo.toml:235-236` (remove `[patch.crates-io]` if fixed)

Context: `Cargo.toml` pins winrm-rs to a git fork because crates.io 1.0 declared an obsolete reqwest feature (`webpki-roots`) that broke `cargo outdated`. 1.1.2 is now published and may carry the fix — if so, the patch is dead weight.

- [ ] **Step 1: Check whether 1.1.2 fixes the reqwest feature**

Run:
```bash
cargo info winrm-rs@1.1.2 2>&1 | head -20
# Inspect upstream Cargo.toml for the obsolete feature:
curl -sL https://crates.io/api/v1/crates/winrm-rs/1.1.2/download -o /tmp/winrm.crate \
  && tar xzf /tmp/winrm.crate -C /tmp \
  && grep -n "webpki-roots\|reqwest" /tmp/winrm-rs-1.1.2/Cargo.toml
```
Expected: confirm `reqwest` no longer references `webpki-roots`. If the obsolete feature is gone → patch can be removed (Step 2a). If still present → keep patch, bump the git rev instead (Step 2b).

- [ ] **Step 2a: Bump version + remove patch (if fixed)**

In `Cargo.toml` line 120, change:
```toml
winrm-rs = { version = "1.0", optional = true }
```
to:
```toml
winrm-rs = { version = "1.1", optional = true }
```
Then delete the entire patch block (lines ~229-236):
```toml
# =============================================================================
# Patch overrides (FIND-018 / audit 2026-05-09)
# =============================================================================
[patch.crates-io]
winrm-rs = { git = "https://github.com/muchiny/winrm-rs.git", rev = "573dadf5abcaed681f65999f216164c9f33a6250" }
```

- [ ] **Step 2b: Fallback — keep patch, point fork at 1.1.2 (if NOT fixed)**

Leave line 120 as `version = "1.1"`, update the fork to a rev that tracks 1.1.2, keep the `[patch.crates-io]` block. Document why in a refreshed comment dated 2026-05-30.

- [ ] **Step 3: Build winrm + psrp features**

Run:
```bash
cargo build --features winrm 2>&1 | tail -5
cargo build --features psrp 2>&1 | tail -5
```
Expected: both compile. (psrp depends on winrm.)

- [ ] **Step 4: Verify outdated no longer lists winrm-rs as "Removed"**

Run:
```bash
cargo outdated --root-deps-only 2>&1 | grep -i winrm || echo "winrm-rs current"
```
Expected: `winrm-rs current` (or shows it at 1.1.2 with no "Removed").

- [ ] **Step 5: Test**

Run:
```bash
cargo test --lib --features psrp 2>&1 | tail -15
```
Expected: pass count >= baseline (psrp adds tests).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): bump winrm-rs 1.0 -> 1.1.2, drop git-fork patch (FIND-018)

crates.io 1.1.2 ships the reqwest feature fix the local fork carried;
[patch.crates-io] override removed. Resolves the cargo-outdated
'Removed' status. Update Known Advisories in CLAUDE.md if the patch
removal changes the advisory set."
```

---

## Phase 3: OpenTelemetry stack 0.31 → 0.32 (feature `otel`)

**Files:**
- Modify: `Cargo.toml:144-147` (opentelemetry, opentelemetry_sdk, opentelemetry-otlp, tracing-opentelemetry)
- Likely modify: telemetry init module (find via grep in Step 1)

Coordinated bump — all four versions move together. Metrics/logs/traces APIs have been stable since 0.30, so risk is low, but `tracing-opentelemetry` must match: 0.32 → **0.33**.

- [ ] **Step 1: Locate the otel init code**

Run:
```bash
grep -rln "opentelemetry\|SdkTracerProvider\|tracing_opentelemetry\|OtelLayer\|otlp" src --include="*.rs"
```
Expected: a small set (telemetry/observability module). Read each before editing.

- [ ] **Step 2: Bump the four versions**

In `Cargo.toml`:
```toml
opentelemetry = { version = "0.32", optional = true }
opentelemetry_sdk = { version = "0.32", features = ["rt-tokio"], optional = true }
opentelemetry-otlp = { version = "0.32", features = ["grpc-tonic"], optional = true }
tracing-opentelemetry = { version = "0.33", optional = true }
```

- [ ] **Step 3: Build the otel feature**

Run:
```bash
cargo build --features otel 2>&1 | tail -20
```
Expected: compiles. If errors, they will be in the init module — most likely the `Resource::builder()` / `SdkTracerProvider` builder API (stable since 0.28, but double-check exporter constructor signatures against the 0.32 docs). Fix in the module from Step 1.

- [ ] **Step 4: Test**

Run:
```bash
cargo test --lib --features otel 2>&1 | tail -15
```
Expected: pass count >= baseline.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "chore(deps): bump opentelemetry stack 0.31 -> 0.32

opentelemetry/_sdk/-otlp 0.32, tracing-opentelemetry 0.33 (must match).
otel feature only; trace/metric/log APIs stable since 0.30."
```

---

## Phase 4: similar 2.7 → 3.1 (default feature)

**Files:**
- Modify: `Cargo.toml:148` (similar = "3")
- Possibly touch: `src/domain/diff.rs` (only consumer)

Only consumer is `src/domain/diff.rs` using `ChangeTag`, `TextDiff`, `TextDiff::from_lines` — all stable across the 2→3 major. The 3.0 break is mostly MSRV/internal.

- [ ] **Step 1: Bump version**

In `Cargo.toml` line 148:
```toml
similar = "3"
```

- [ ] **Step 2: Build + test the diff module**

Run:
```bash
cargo build 2>&1 | tail -5
cargo test --lib diff 2>&1 | tail -15
```
Expected: compiles; `domain::diff` tests pass. If `TextDiff::from_lines`/`ChangeTag` signatures shifted, adjust `src/domain/diff.rs:203-209`.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock src/domain/diff.rs
git commit -m "chore(deps): bump similar 2 -> 3"
```

---

## Phase 5: sha2 0.10 → 0.11 (default feature)

**Files:**
- Modify: `Cargo.toml:98` (sha2 = "0.11")
- Possibly touch: `src/ssh/sftp.rs:12,268,462`, `src/security/recording.rs:15,399`

Direct API (`Sha256::new`, `.update`, `.finalize`, `Digest`) is unchanged in 0.11. The 0.11 break is the underlying `digest` 0.11 / `hybrid-array` migration: the `finalize()` output type changes from `GenericArray` to `hybrid_array::Array`. Check that downstream `const_hex::encode(...)` and slice uses still accept it (they take `AsRef<[u8]>`, which both implement).

- [ ] **Step 1: Bump version**

In `Cargo.toml` line 98:
```toml
sha2 = "0.11"
```

- [ ] **Step 2: Build**

Run:
```bash
cargo build 2>&1 | tail -20
```
Expected: compiles. If `const_hex::encode(h.finalize())` fails on the new output type, wrap with `.as_slice()` / `&h.finalize()[..]` at `src/ssh/sftp.rs:341,537`.

- [ ] **Step 3: Test the hashing consumers**

Run:
```bash
cargo test --lib sftp 2>&1 | tail -10
cargo test --lib recording 2>&1 | tail -10
```
Expected: checksum + recording-hash tests pass (proves the hash bytes are byte-identical post-bump).

- [ ] **Step 4: Guard against a duplicate sha2 in the tree**

Run:
```bash
cargo tree -i sha2 2>&1 | head -30
```
Expected: ideally a single 0.11. If `ssh-key`/russh still pull sha2 0.10, that's a tolerated duplicate (not a break) — note it; do not force-downgrade.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "chore(deps): bump sha2 0.10 -> 0.11

Direct API (Sha256::new/update/finalize/Digest) unchanged; 0.11 moves
to digest 0.11 / hybrid-array output. sftp checksum + audit-recording
hash tests confirm byte-identical output."
```

---

## Phase 6: jsonwebtoken 9.3 → 10.4 (feature `http`)

**Files:**
- Modify: `Cargo.toml:151` (jsonwebtoken = "10")
- Likely touch: `src/mcp/transport/oauth.rs:34,217-239,504-535`

Only consumer is the OAuth/JWT validator in `oauth.rs` (HTTP transport). All APIs we use exist in v10: `DecodingKey::from_rsa_components`/`from_rsa_pem`, `Validation::new`, `set_issuer`, `set_audience`, `set_required_spec_claims(&["..."])`, `validate_exp`, `validate_nbf`, `leeway`, `decode`, `decode_header`, `EncodingKey::from_rsa_pem`, `encode`, `Header`. v10 hardens defaults (e.g. `aud` rejection) — our code already requires all four spec claims, so semantics should hold. **Security-sensitive: the existing oauth test suite is the gate, do not weaken it.**

- [ ] **Step 1: Bump version**

In `Cargo.toml` line 151:
```toml
jsonwebtoken = "10"
```

- [ ] **Step 2: Build the http feature**

Run:
```bash
cargo build --features http 2>&1 | tail -20
```
Expected: compiles. Likely-affected spots if v10 shifted a signature:
- `set_required_spec_claims` argument type (still `&[&str]` in v10 per docs — should be fine).
- `from_rsa_components`/`from_rsa_pem` still return `Result` — already handled with `map_err`.
Fix any signature drift inside `src/mcp/transport/oauth.rs` only.

- [ ] **Step 3: Run the full oauth test suite (security gate)**

Run:
```bash
cargo test --lib --features http oauth 2>&1 | tail -25
```
Expected: every oauth test passes — especially the negative cases (missing `sub`, wrong `aud`, expired token, bad signature). If any negative test now passes a token it should reject, STOP — v10 default change must be re-pinned explicitly in `Validation`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/mcp/transport/oauth.rs
git commit -m "chore(deps): bump jsonwebtoken 9 -> 10

OAuth/JWT validator (http feature). v10 hardens claim defaults;
explicit set_required_spec_claims + set_issuer/set_audience preserved
(FIND-007). Full oauth negative-case suite verified."
```

---

## Phase 7: russh 0.60 → 0.61 (default feature, core SSH)

**Files:**
- Modify: `Cargo.toml:68` (russh = "0.61")
- Likely touch: `src/ssh/{client,session,connector,sftp,known_hosts,mod}.rs`, `src/mcp/standard_tool.rs`

Highest blast radius (7 files) and the core transport. 0.61 is a minor-major in the 0.x sense — review the russh CHANGELOG for `client::Handler` trait changes, `Config`, channel/auth signatures, and the kex/mac algorithm registration in `src/ssh/client.rs:48-53`.

- [ ] **Step 1: Read russh 0.61 changelog deltas**

Run:
```bash
cargo info russh@0.61.1 2>&1 | head -20
```
Then check context7 (`/warp-tech/russh` or via resolve-library-id "russh") for `client::Handler` / `Config` API changes 0.60→0.61 before editing.

- [ ] **Step 2: Bump version**

In `Cargo.toml` line 68:
```toml
russh = "0.61"
```

- [ ] **Step 3: Build**

Run:
```bash
cargo build 2>&1 | tail -30
```
Expected: compiles, or a small set of trait/signature errors in the ssh adapter files. Fix each against the 0.61 API. Common 0.x russh breaks: `Handler::check_server_key` signature, `Channel` async return types, `Preferred` algorithm config fields (`src/ssh/client.rs`).

- [ ] **Step 4: Full SSH adapter test pass**

Run:
```bash
cargo test --lib ssh 2>&1 | tail -25
```
Expected: pass count >= baseline for ssh modules. The russh/sftp mock harness (added in commit 4c5cca0) exercises the adapter — it must stay green.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/
git commit -m "chore(deps): bump russh 0.60 -> 0.61

Core SSH transport. Adapter (client/session/connector/sftp/known_hosts)
updated for 0.61 API. Mock harness green."
```

---

## Phase 8: serde-saphyr =0.0.21 → 0.0.27 (default feature, config parser)

**Files:**
- Modify: `Cargo.toml:74` (serde-saphyr = "=0.0.27")
- Likely touch: `src/domain/yaml.rs:50-84`, `src/error.rs:132`

Hard-pinned with `=` because it's 0.0.x — every release is potentially breaking. The central hardened wrapper is `src/domain/yaml.rs` (`Options`, `Budget`, `from_str_with_options`). Security-relevant: this parses untrusted YAML config + runbooks with budget limits. **Bump one minor at a time and read each changelog** — 0.21→0.27 is six releases.

- [ ] **Step 1: Review the changelog 0.0.21 → 0.0.27**

Run:
```bash
cargo info serde-saphyr@0.0.27 2>&1 | head -20
```
Read the repo CHANGELOG (or each version's release notes) for changes to `Options`, `Budget`, `from_str_with_options`, `from_str`, and the `Error` type. Note any field renames/additions to `Budget` (the hardening in `yaml.rs:51-57` depends on its exact fields).

- [ ] **Step 2: Bump the pin**

In `Cargo.toml` line 74:
```toml
serde-saphyr = "=0.0.27"
```

- [ ] **Step 3: Build**

Run:
```bash
cargo build 2>&1 | tail -25
```
Expected: compiles, or errors in `src/domain/yaml.rs` (Budget/Options fields) and `src/error.rs:132` (Error `#[from]`). Fix against the new API, preserving every existing budget limit.

- [ ] **Step 4: Run YAML + config + runbook tests (security gate)**

Run:
```bash
cargo test --lib yaml 2>&1 | tail -15
cargo test --lib config 2>&1 | tail -15
cargo test --lib runbook 2>&1 | tail -15
```
Expected: all pass — especially the budget/DoS-limit tests in `domain::yaml` (they prove the hardening still trips on oversized/over-deep input). If a budget test no longer trips, the field mapping is wrong — STOP and re-check Step 1.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/domain/yaml.rs src/error.rs
git commit -m "chore(deps): bump serde-saphyr 0.0.21 -> 0.0.27

Hardened YAML wrapper (domain/yaml.rs) Budget/Options preserved;
DoS budget-limit tests verified. Pin kept as '=' (0.0.x)."
```

---

## Phase 9: Final verification + integration

**Files:** none (verification only)

- [ ] **Step 1: Confirm nothing left outdated (except intentionally pinned)**

Run:
```bash
cargo outdated --root-deps-only 2>&1
```
Expected: empty or only entries you consciously chose not to bump. Document any deliberate holds.

- [ ] **Step 2: No unused deps introduced**

Run:
```bash
cargo machete 2>&1 | tail -5
```
Expected: "didn't find any unused dependencies".

- [ ] **Step 3: Full CI gate**

Run:
```bash
make ci 2>&1 | tail -40
```
Expected: fmt-check, clippy (`-D warnings`), test, audit, typos all green. `cargo audit` is the check for whether any bump changed the advisory set vs `deny.toml` (6 ignored advisories — see CLAUDE.md "Known Advisories").

- [ ] **Step 4: Build the full feature matrix**

Run:
```bash
cargo build --all-features 2>&1 | tail -5
cargo build --no-default-features 2>&1 | tail -5
cargo build --features all-protocols 2>&1 | tail -5
```
Expected: every combination compiles.

- [ ] **Step 5: Update advisory/docs if changed**

If `cargo audit` / `make ci` surfaced a resolved or new advisory, update the "Known Advisories" list in `CLAUDE.md` and `deny.toml`. Commit separately:
```bash
git add CLAUDE.md deny.toml
git commit -m "docs(deps): refresh Known Advisories after dependency updates"
```

- [ ] **Step 6: Restore parked WIP (optional)**

If the secret-newtype work resumes after this branch merges:
```bash
git checkout security/redacted-secret-newtype
git stash pop
```

---

## Risk Summary (review-order, low → high)

| Phase | Crate(s) | Blast radius | Risk | Gate |
|---|---|---|---|---|
| 1 | 14 semver-compat | Cargo.lock only | minimal | build + test |
| 2 | winrm-rs 1.1.2 | Cargo.toml (patch removal) | low | winrm/psrp build |
| 3 | otel 0.32 | otel init module | low | otel build+test |
| 4 | similar 3 | `domain/diff.rs` | low | diff tests |
| 5 | sha2 0.11 | sftp, recording (2 sites) | low-mod | checksum/hash tests |
| 6 | jsonwebtoken 10 | `oauth.rs` | moderate (security) | oauth negative-case suite |
| 7 | russh 0.61 | 7 ssh files | mod-high | ssh mock harness |
| 8 | serde-saphyr 0.0.27 | `yaml.rs`, `error.rs` | high (untrusted-input parser) | budget/DoS tests |

If any single phase resists within ~30 min of effort, commit the phases before it, open a focused follow-up for the blocker, and ship the rest — the phase isolation is the whole point.
