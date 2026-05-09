# Supply-Chain Risk Audit — 2026-05-09

**Skill:** `supply-chain-risk-auditor:supply-chain-risk-auditor` (trailofbits, v1.0.0)
**Inputs:** `Cargo.toml`, `audit/2026-05-09/baseline/{cargo-audit.json, cargo-deny.txt, cargo-outdated.txt, cargo-geiger.txt, dep-tree.txt}`, `audit/2026-05-09/surface/context7-summary.md`
**Method:** per-direct-dep risk scoring against the skill's Risk Criteria (single maintainer, unmaintained, low popularity, high-risk features, past CVEs, no security contact). `gh api` queries on the audit-critical-path subset.
**Note:** `cargo outdated` baseline is unusable due to FIND-018 (winrm-rs/reqwest feature mismatch); risk assessment uses `dep-tree.txt` + targeted `gh` queries instead.

---

## Executive summary

- **49 direct dependencies** in `[dependencies]`, 7 in `[dev-dependencies]`. 281 unique crates total in the dep graph (314 nodes counting feature variants).
- **3 new high-risk findings** (FIND-025 P2, FIND-026 P1, FIND-027 P2). Each is appended to `docs/audit-2026-05-09-findings.md`.
- **Already-tracked deps** (no duplicate row): `russh`/`russh-keys` (FIND-008 = Default config), `jsonwebtoken` (FIND-007 + FIND-009), `serde-saphyr` Budget API (FIND-001..004), `winrm-rs` blocking `cargo outdated` (FIND-018).
- **6 ignored advisories** in `deny.toml` are all upstream-tracked transitive issues (Marvin attack on RSA via russh, rustls-webpki advisories via aws-sdk). No new ignore-list candidates discovered.

## Counts by risk factor

| Risk factor | Count | Crates |
|---|---|---|
| Archived / explicitly unmaintained | 1 | `shellexpand` |
| Inactive >12 months (no archived flag) | 1 | `tokio-socks` (last push 2025-02-19) |
| Single-maintainer pre-1.0 critical-path | 1 | `serde-saphyr` (v0.0.21, primary author 649/667 commits) |
| Single-maintainer post-1.0 (mitigated) | 2 | `russh` (Eugeny), `jsonwebtoken` (Keats) — both with active community contributors |
| Past CVE in deny.toml ignore | 6 | RUSTSEC-2023-0071, 2026-0044, 2026-0048, 2026-0049, 2025-0134, 2026-0098/0099/0104 (already accepted) |
| Out-of-scope (user-owned crates) | 2 | `winrm-rs`, `psrp-rs` (verified at `~/winrm-rs`, `~/psrp-rs`) |

## High-risk dependencies

| # | Dep | Version | Risk factor | Suggested alternative | Justification |
|---|---|---|---|---|---|
| FIND-025 | `shellexpand` | 3.1.2 | **Archived** (`gh api repos/netvl/shellexpand` → `archived: true`, last push 2026-02-25, 97 stars) — used at `src/ssh/client.rs:487` for `~` expansion in SSH key paths | `dirs::home_dir()` + manual `~` strip (already in workspace via `dirs = "6"`); OR vendor `shellexpand` source in-tree | Archived crates receive no security patches. The current use is in the auth path (key file location), so a regression in expansion semantics could cause silent fallback to wrong key. Replacement is small (~30 lines). |
| FIND-026 | `serde-saphyr` | =0.0.21 (pinned exact) | Pre-1.0 single-maintainer YAML parser on critical-path. `bourumir-wyngs` 649/667 commits (primary), 167 GitHub stars, only 0 open issues (suggests low scrutiny). Parses ALL config + runbook YAML. | Stay on saphyr but pin via vendoring + monitor; OR migrate to `serde_yml` (167+ commits across larger team, but unmaintained-banner risk applies); OR write minimal YAML deserializer scoped to the actual config schema | The library is the only thing standing between attacker-controlled YAML (Vuln class FIND-001..004) and the typed `Config`/`Runbook` structs. A malicious or buggy parser update could change deny-unknown semantics, expose new corruption bugs, or introduce a maintainer-takeover supply-chain attack. The exact-version pin (`=0.0.21`) mitigates by preventing automatic upgrades, but also means manual review on every release. |
| FIND-027 | `tokio-socks` | 0.5.2 | **Inactive >14 months** (`gh api repos/sticnarf/tokio-socks` → last push 2025-02-19, 102 stars, not archived but no commits). Used in SOCKS proxy path at `src/ssh/client.rs:373-413`. | `tokio-socks` fork with active maintainership (none currently); OR if SOCKS use is rare, add a "deprecated_socks" feature gate and document the maintenance state | SOCKS proxy is auth-perimeter relevant. An unpatched protocol bug here could affect the credential transit. The crate is small (~1500 LOC); vendoring is feasible if the crate doesn't see a release in another quarter. |

## Notes on critical-path deps NOT flagged

| Dep | Why considered | Why not flagged |
|---|---|---|
| `russh` 0.60.1 | Single-primary maintainer (Eugeny 404 commits) | Mitigated: 1702 GitHub stars, 30 commits in last 5 months, 8+ secondary contributors (lowlevl, connor4312, EpicEric, others), CVE history actively triaged (Marvin RSA via deny.toml). The single-maintainer concern remains but is industry-accepted for this critical SSH crate (the Rust SSH ecosystem has no real alternative). |
| `russh-sftp` 2.1.1 | Same author as russh | Same mitigation as russh; 2.x stable line, used in our `src/ssh/sftp.rs`. |
| `jsonwebtoken` 9.3.1 | Single-primary maintainer (Keats / Vincent Prouillet) | Mitigated: 2041 GitHub stars, active (last push 2026-05-07), well-known maintainer, 9.x major version stable. Implementation choice already gives us alg-confusion mitigation per FIND-007/009 review. |
| `tokio` 1.52.1 | Foundational | Tokio Foundation governance, hundreds of contributors. Not a supply-chain risk. |
| `axum`, `tower`, `tower-http` | Foundational web stack | Tokio Foundation. Not flagged. |
| `aws-sdk-*`, `aws-config` | AWS-maintained | Amazon org-backed. Not flagged. |
| `kube`, `k8s-openapi` | Kubernetes ecosystem | `kube-rs` org with 30+ contributors. Not flagged. |
| `serde`, `serde_json` | Foundational | dtolnay + serde-rs org, ~hundreds of contributors. Not flagged. |
| `regex`, `aho-corasick` | Foundational | rust-lang/regex official. Not flagged. |
| `chrono` | Foundational | chronotope org, multiple maintainers. Not flagged. |
| `zeroize` | Critical-path crypto | RustCrypto org, Tony Arcieri + ecosystem. Not flagged. |
| `uuid` | Foundational | Multiple maintainers, well-known crate. Not flagged. |
| `rayon` | Foundational | Niko Matsakis + community, hundreds of contributors. Not flagged. |
| `notify` 8.2 | File watcher | Multiple maintainers (passcod / Félix Saparelli + community), 2.x → 8.x active development, well-tested. Not flagged. |
| `inventory` 0.3 | Linker-tricks dep | dtolnay (well-known prolific Rust maintainer with strong reputation). Not flagged. |
| `notify`, `tracing-*` | Tooling | Tokio org-backed. Not flagged. |
| `mimalloc` | Optional allocator | Microsoft-published. Not flagged. |
| `winrm-rs`, `psrp-rs` | Critical-path remote-mgmt | **OUT OF SCOPE**: user-owned local crates (`~/winrm-rs`, `~/psrp-rs`) — they ARE the audit target, not supply-chain dependencies. Cargo.toml references them by version not path because they are published to crates.io by the same author. |
| `jaq-core`, `jaq-std`, `jaq-json` | Optional `jq_filter` feature | Single maintainer (01mf02) but academic-quality, 3592 stars. Optional feature gates the risk. |
| `opentelemetry*` | Optional `otel` feature | OpenTelemetry org. Not flagged. |
| `mcp-ssh-bridge-macros` | Workspace path dep | In-tree, audited as part of this codebase. |

## Reconciliation with `deny.toml` ignored advisories

```
RUSTSEC-2023-0071  (Marvin attack on RSA — transitive via russh)         → accepted
RUSTSEC-2026-0098  (webpki URI name constraints — aws-sdk chain)         → accepted
RUSTSEC-2026-0099  (webpki wildcard name constraint bypass — aws-sdk)    → accepted
RUSTSEC-2026-0104  (webpki CRL IssuingDistributionPoint panic — aws-sdk) → accepted
```

Documented historical (kept as audit-trail comments, no longer matched):
- RUSTSEC-2025-0134 (rustls-pemfile unmaintained)
- RUSTSEC-2026-0049 (rustls-webpki CRL matching)
- RUSTSEC-2026-0074 (libcrux-ml-kem SHAKE API — patched upstream in russh 0.60)

`cargo audit` output (`audit/2026-05-09/baseline/cargo-audit.json`) shows zero non-ignored advisories. Supply-chain CVE posture is current.

## Recommendations

1. **Fix FIND-025 first** — `shellexpand` is the only archived dep on the auth path and the replacement is small. Either swap to `dirs` + manual ~ strip (5 LOC) or vendor the crate.
2. **For FIND-026** — keep the `=0.0.21` exact pin. Subscribe to GitHub release notifications on `bourumir-wyngs/serde-saphyr`. When the crate hits 1.0 (or another solo-maintainer YAML lib reaches stability), reconsider migration.
3. **For FIND-027** — monitor `sticnarf/tokio-socks` for activity; if no release by 2026-08, plan vendoring.
4. **No supply-chain change needed for** russh, jsonwebtoken, jaq family, or any organisation-backed dep.
5. **Quarterly cadence**: re-run this scan + cargo audit on every release branch.
