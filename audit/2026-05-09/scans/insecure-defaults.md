# Insecure Defaults Audit — 2026-05-09

**Skill:** `insecure-defaults:insecure-defaults` (trailofbits, v1.0.0)
**Method:** SEARCH → VERIFY → CONFIRM → REPORT per skill workflow
**Targets:** `config/config.example.yaml`, `src/config/types.rs` (default impls), `src/config/loader.rs`, `src/ssh/{client,known_hosts,pool}.rs`, `src/security/{rate_limiter,validator}.rs`
**Cross-reference:** `audit/2026-05-09/surface/context7-summary.md` (recommended-default snippets)

---

## Verdict

**3 new findings** (FIND-022, FIND-023, FIND-024). Most defaults are **fail-secure** and align with upstream guidance. The audit-context-building work in Task 5 already surfaced the russh `..Default::default()` gap (FIND-008) — this scan re-confirms it but does not duplicate the row.

---

## Defaults examined

### ✅ Secure defaults (no finding)

| Default | Value | File:line | Rationale |
|---|---|---|---|
| `HostKeyVerification` | `Strict` (rejects unknown + mismatched keys) | `src/config/types.rs:319` | Matches OpenSSH `StrictHostKeyChecking=yes` |
| `SecurityMode` | `Standard` (whitelist+blacklist for `validate()` paths) | `src/config/types.rs:634-636` | Not `Permissive`; default whitelist is empty so `validate()` denies all raw exec until operator adds patterns |
| `AuditConfig.enabled` | `true` | `src/config/types.rs:1011` | Logging on by default |
| Audit log file mode | `0o600` (owner-only) | `src/security/audit.rs:140` | Stricter than 0o644 — only owner reads |
| Config file mode check | rejects if `mode & 0o037 != 0` | `src/config/loader.rs:29-32` | Rejects group + world readable; tighter than POSIX 0o644 |
| `SanitizeConfig.enabled` | `true` | `src/config/types.rs:610-612` | Output redaction on by default |
| `HttpTransportConfig.bind` | `127.0.0.1:3000` | `src/config/types.rs:128-130` | Loopback only, not `0.0.0.0` |
| `HttpTransportConfig.allow_unsafe_bind` | `false` | `src/config/types.rs:120-126` | Must opt-in to bind non-loopback |
| `HttpTransportConfig.max_body_size` | `1_048_576` (1 MB) | `src/config/types.rs:143-145` | Tighter than axum default 2 MB |
| `HttpTransportConfig.max_sessions` | `100` | `src/config/types.rs:151-153` | Bounded |
| `HttpTransportConfig.session_timeout_seconds` | `1800` (30 min) | `src/config/types.rs:147-149` | Bounded |
| `HttpTransportConfig.allowed_origins` | localhost variants only | `src/config/types.rs:132-141` | Explicit allowlist, not wildcard |
| `HttpOAuthConfig.enabled` | `false` | `src/config/types.rs:158-161` | OAuth opt-in (disabled by default — wiring gap covered by FIND-006) |
| `LimitsConfig.connection_timeout_seconds` | `10` | `src/config/types.rs:881-883` | Bounded |
| `LimitsConfig.keepalive_interval_seconds` | `30` | `src/config/types.rs:885-887` | Bounded |
| `LimitsConfig.max_concurrent_commands` | `5` | `src/config/types.rs:877-879` | Bounded |
| `LimitsConfig.rate_limit_per_second` | `10` | `src/config/types.rs:897-899` | Bounded; wired into `RateLimiter::new` at `server.rs:153` |
| `LimitsConfig.retry_attempts` | `3` | `src/config/types.rs:889-891` | Bounded |
| `SessionConfig.idle_timeout_seconds` | `300` (5 min) | `src/config/types.rs:1062-1064` | Bounded |
| `PoolConfig.max_connections_per_host` | `10` | `src/ssh/pool.rs:55` | Bounded; clamped to `>=1` at construction |
| `known_hosts.rs::check_known_hosts_permissions` | warns if mode `& 0o077 != 0 && != 0o644` | `src/ssh/known_hosts.rs:91-99` | Permits 0o644 (world-readable, default OpenSSH) but warns on group/other write |

### ⚠️ Findings (drift / fail-open)

| ID | Default | File:line | Severity | Why |
|---|---|---|---|---|
| **FIND-022** | `SecurityConfig.require_elicitation_on_destructive: false` | `src/config/types.rs:516` | **P1** | Destructive tools (`destructive_hint: true`) execute without MCP `elicitation/create` confirmation by default. The 2026-roadmap commit explicitly designed this as opt-in, but in practice most operators won't flip it. The secure default is `true` with documented opt-out. Per `audit/2026-05-09/surface/entry-points.md`, **97 handlers are P0 risk-bucket** (writes-files / cred-bearing / destructive). All 97 run unconfirmed unless the operator explicitly enables this flag. Blast radius: any compromised MCP client can mass-execute destructive tools without surfacing to the human. |
| **FIND-023** | `SshConfigDiscovery.enabled: true` | `src/config/types.rs:1090` (default fn at L1101) | **P2** | `~/.ssh/config` is parsed at startup and every `Host` entry is auto-registered as a reachable target. An MCP client can therefore enumerate the operator's entire personal SSH host inventory (often ≫ the YAML-declared production set) and connect to any of them with the corresponding key (also auto-discovered if `IdentityFile` is set). The MCP authentication boundary is the validator + audit, but the **target inventory leak** widens the attack surface unnecessarily. The ergonomic case for default-on is "reduce time-to-first-command"; the secure default is `false` with one-line opt-in. Blast radius: depends on operator's `~/.ssh/config` content (laptops with personal hosts → high blast). |
| **FIND-024** | `ToolGroupsConfig`: groups not listed are enabled by default | `src/config/types.rs:1247-1250` (`pub groups: HashMap<String, bool>` + comment "Groups not listed are enabled by default") | **P2** | All 75 tool groups (357 handlers) are enabled out-of-box. Principle of least privilege would default to **disabled** and require operator to enumerate the groups they actually use. With current default, an operator who only needs `docker` + `service` groups is exposed to (and audit-logged for) all the AD/LDAP/Vault/K8s/AWS/ESXi/HyperV groups too. Blast radius: full surface unless operator explicitly disables groups (rare). |

### Already-found (covered by Task 5 — not duplicated here)

- **FIND-008**: russh `client::Config { ..Default::default() }` does not pin `Preferred` algorithms or set rekey `Limits` — `src/ssh/client.rs:339, 285`. Already P1 in the tracker.
- **FIND-006**: HTTP OAuth validator constructed per-request with empty key map — production wiring "left for a follow-up". Already P0 in the tracker.

### Accepted-as-designed (documented, not flagged)

| Default | Rationale |
|---|---|
| `LimitsConfig.command_timeout_seconds: 1800` (30 min) | Long but justified by the comment "supports long-running tasks like Molecule tests". Operator can shorten in YAML. |
| `LimitsConfig.max_output_bytes: 10 MB` | Bounded; truncation happens above this. |
| `PoolConfig.max_age_seconds: 3600` (1 h) | Same window as FIND-008 rekey concern; FIND-008 fix (russh `Limits`) covers this. |
| `SecurityConfig.whitelist: Vec::new()` (empty) | **Fail-closed** — `validate()` denies all raw `ssh_exec` until operator populates whitelist. The trade-off is that `validate_builtin` paths (which bypass whitelist) carry the entire builtin-tool surface; that surface is gated by the blacklist + per-handler validation only. Production wiring of `CommandValidator` (OQ-001) must be confirmed to use real config, not `SecurityConfig::default()`. |

---

## Counters

- New P1: 1 (FIND-022)
- New P2: 2 (FIND-023, FIND-024)
- Confirmed existing: 2 (FIND-006, FIND-008)
- Accepted-as-designed: 3
- Secure-default rows: 19

Findings appended to `docs/audit-2026-05-09-findings.md`.
