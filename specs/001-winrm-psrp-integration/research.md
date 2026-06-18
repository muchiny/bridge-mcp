# Research: WinRM/PSRP Protocol Integration

**Branch**: `001-winrm-psrp-integration` | **Date**: 2026-04-12

## R1: russh Version Alignment

### Problem

bridge-mcp uses `russh 0.58`. psrp-rs uses `russh 0.49` (for its `ssh` feature transport).
PSRP-over-SSH (Phase 4) requires version alignment.

### Decision

**Bump psrp-rs to russh 0.58** before integrating.

### Rationale

1. The SSH transport in psrp-rs is already partially written to the 0.50+ API
   (imports `russh::keys::key::PrivateKeyWithHashAlg` — the post-merge namespace).
2. The `ssh` feature is optional and off by default — zero risk to WinRM-only users.
3. Changes confined to `src/ssh.rs` (~200 lines) + 2 lines in `Cargo.toml`.
4. Breaking changes 0.49 -> 0.58 are well-scoped:
   - `russh_keys` merged into `russh` at 0.50 (remove separate dep)
   - `client::Handler` trait changed to native async (remove `#[async_trait]`)
   - `PrivateKeyWithHashAlg::new()` became infallible (remove `.map_err()`)
   - `CryptoVec` -> `impl Into<Bytes>` for non-sensitive buffers at 0.58

### Alternatives Considered

- **Option B (skip SSH transport)**: Don't enable psrp-rs `ssh` feature. Loses PSRP-over-SSH
  entirely — a permanent feature loss for a fixable problem.
- **Option C (two russh copies)**: Cargo semver allows `0.49` + `0.58` coexistence, but
  doubles binary size (~4 MB each), creates type incompatibilities at integration boundary,
  and triggers deny.toml advisory failures on the 0.49 copy.

### Action Required

Bump psrp-rs `russh` dep to 0.58 in a separate PR/commit before this integration.
Migration checklist: remove `russh-keys` dep, remove `ssh-key` dep, update imports
in `src/ssh.rs`, remove `#[async_trait]` from Handler impl, make
`PrivateKeyWithHashAlg::new()` infallible.

---

## R2: Auth Config Mapping Strategy

### Problem

bridge-mcp's `AuthConfig` only supports SSH auth types (`Key`, `Agent`, `Password`).
winrm-rs needs `AuthMethod` (Basic, Ntlm, Kerberos, Certificate) + `WinrmCredentials`
(username, password as SecretString, domain). How to extend config without breaking
existing YAML?

### Decision

**Extend AuthConfig with WinRM-specific variants, guarded by `#[cfg(feature = "winrm")]`.**

New variants:

```rust
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    // Existing SSH variants
    Key { path: String, passphrase: Option<Zeroizing<String>> },
    Agent,
    Password { password: Zeroizing<String> },

    // WinRM variants (feature-gated)
    #[cfg(feature = "winrm")]
    Ntlm {
        password: Zeroizing<String>,
        #[serde(default)]
        domain: Option<String>,
    },
    #[cfg(feature = "winrm")]
    Certificate {
        cert_path: String,
        key_path: String,
    },
    #[cfg(feature = "winrm")]
    Kerberos,
}
```

### Rationale

1. **Backward compatible**: Existing `auth.type: password` still works for both SSH and WinRM
   (maps to Basic auth on WinRM). No existing configs break.
2. **Discoverable**: New auth types appear in YAML as `auth.type: ntlm`, `auth.type: certificate`,
   `auth.type: kerberos` — self-documenting.
3. **Feature-gated**: WinRM auth variants don't appear when `winrm` feature is off.
4. **Clean mapping**: Each variant maps 1:1 to `winrm_rs::AuthMethod`.

### Mapping Table

| AuthConfig variant | winrm_rs::AuthMethod | Notes |
|---|---|---|
| `Password { password }` | `AuthMethod::Basic` | Backward compat, requires HTTPS |
| `Ntlm { password, domain }` | `AuthMethod::Ntlm` | Default for WinRM, NTLMv2 |
| `Kerberos` | `AuthMethod::Kerberos` | Requires `kinit`, feature-gated in winrm-rs too |
| `Certificate { cert, key }` | `AuthMethod::Certificate` | TLS client cert |
| `Key { .. }` / `Agent` | ERROR | Not supported on WinRM — clear error at config validation |

### Protocol-Specific Config

Add optional WinRM fields to `HostConfig` (flat extension, not nested enum):

```rust
pub struct HostConfig {
    // ... existing fields ...

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_use_tls: Option<bool>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_accept_invalid_certs: Option<bool>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_operation_timeout_secs: Option<u64>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_max_envelope_size: Option<u32>,
}
```

### Alternatives Considered

- **Nested ProtocolConfig enum**: Cleaner separation but heavier YAML syntax
  (`protocol_config.winrm.use_tls`). Rejected for YAGNI — flat fields are simpler
  and match the existing `proxy_jump`, `socks_proxy` pattern.
- **Completely separate WinrmHostConfig**: Maximum flexibility but doubles the config
  parsing code. Rejected for complexity.

---

## R3: Connection Pool Strategy

### Problem

Current WinRM pool caches `reqwest::Client` instances. With winrm-rs, what should
be pooled? WinRM is stateless HTTP, but Shell reuse and PSRP RunspacePool are stateful.

### Decision

**Two-level pooling**: Pool `WinrmClient` instances (cheap, reuses HTTP client internally)
and optionally pool `Shell` sessions for repeated commands. For PSRP, pool `RunspacePool`
instances (which are inherently stateful and designed for reuse).

### WinRM Pool (replaces current)

```
WinrmPool {
    inner: Arc<RwLock<HashMap<String, PooledWinrmClient>>>,
    config: WinrmPoolConfig,
}

struct PooledWinrmClient {
    client: WinrmClient,
    last_used: Instant,
}
```

- **Keyed by**: host name (same as current)
- **TTL**: 120s idle (same as current)
- **Lock**: `RwLock` (same as current — concurrent reads, write on cold path)
- **API**: Same surface: `get_connection()`, `evict()`, `cleanup()`, `close_all()`
- **Returns**: `WinRmConnection` wrapping a reference to the cached `WinrmClient`

Key difference: instead of `reqwest::Client` + manual SOAP, we cache `WinrmClient` which
internally manages its own HTTP client and auth state (NTLM sessions, etc.).

### PSRP Pool (new)

```
PsrpPool {
    inner: Arc<RwLock<HashMap<String, PooledRunspace>>>,
    config: PsrpPoolConfig,
}

struct PooledRunspace {
    pool: RunspacePool<WinrmPsrpTransport<'static>>,
    last_used: Instant,
}
```

- **Keyed by**: host name
- **TTL**: 300s idle (RunspacePool designed for reuse; longer than WinRM's 120s)
- **Lock**: `RwLock`
- **API**: Same surface as WinrmPool
- **Returns**: `PsrpConnection` wrapping the cached `RunspacePool`

### Rationale

1. **Follow established pattern**: WinRM/K8s pools use `Arc<RwLock<HashMap>>` with
   `get_connection() -> Connection`, `evict()`, `cleanup()`, `close_all()`. New pools
   follow the same pattern exactly.
2. **WinrmClient is reusable**: winrm-rs `WinrmClient` holds a `reqwest::Client` internally
   and handles auth state. No need to pool the HTTP client separately.
3. **RunspacePool IS the pool**: psrp-rs `RunspacePool` maintains a PowerShell session server-side.
   Our pool manages multiple `RunspacePool` instances (one per host), not individual commands.
4. **Lifetime concern**: `RunspacePool<WinrmPsrpTransport<'static>>` requires `'static`
   because the transport references a `WinrmClient`. We'll need to use `Arc<WinrmClient>`
   or own the client inside the transport. This is resolvable at implementation time.

### Alternatives Considered

- **Single unified pool trait**: Create a `ConnectionPool<C>` generic. Rejected — the three
  pools have different enough semantics (SSH: RAII guard + multiple-per-host; WinRM: stateless
  reuse; PSRP: stateful session) that a shared trait adds complexity for no gain.
- **Pool RunspacePool inside WinrmPool**: Rejected — PSRP and WinRM are separate protocols
  with different TTLs and lifecycle requirements.

### Bug Found

`ExecutorRouter.cleanup()` and `close_all()` exist but are **never called** from McpServer's
cleanup/shutdown sequences. This is a pre-existing bug — pools leak connections on long-running
servers. Should be fixed as part of this work.

---

## R4: ConnectionGuard and exec() Flow for PSRP

### Problem

Current `ConnectionGuard::exec()` dispatches `command: &str` to the protocol adapter.
PSRP's `RunspacePool::run_script()` also takes a `&str` script, so it fits the same
interface. But PSRP produces `Vec<PsValue>` not `CommandOutput { stdout, stderr, exit_code }`.

### Decision

**Phase 1-2**: PSRP adapter converts `Vec<PsValue>` to `CommandOutput` string representation.
**Phase 3**: Optional typed output path for handlers that want structured data.

For Phase 1-2, the PSRP exec flow:

```rust
// PsrpConnection::exec()
async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
    let result = self.pool.run_script(command).await?;
    let stdout = result.iter().map(|v| format!("{v}")).collect::<Vec<_>>().join("\n");
    Ok(CommandOutput { stdout, stderr: String::new(), exit_code: 0, duration_ms })
}
```

For Phase 3, use `run_all_streams()` to capture errors/warnings:

```rust
let pipeline_result = pipeline.run_all_streams(&mut self.pool).await?;
let stdout = serialize_ps_values(&pipeline_result.output);
let stderr = format_errors(&pipeline_result.errors, &pipeline_result.warnings);
let exit_code = if pipeline_result.state == PipelineState::Failed { 1 } else { 0 };
```

### Rationale

1. **Zero handler changes for Phase 1-2**: All 44 Windows handlers continue to receive
   `CommandOutput` with stdout/stderr strings. The PowerShell-to-text conversion happens
   in the adapter layer.
2. **Incremental Phase 3**: Handlers can opt into typed output by checking the protocol
   and using a new `exec_psrp()` method that returns `PipelineResult` directly.
3. **Exit code mapping**: PSRP doesn't have a numeric exit code in the same way. We derive
   it from `PipelineState`: `Completed` -> 0, `Failed` -> 1, `Stopped` -> 2.

---

## R5: Feature Flag Dependencies

### Decision

```toml
[features]
# Protocol adapters (Tier 1)
winrm = ["dep:winrm-rs"]                        # Replaces reqwest+quick-xml
psrp = ["dep:psrp-rs", "winrm"]                 # PSRP implies WinRM

# Bundles
air-gapped = ["winrm", "telnet"]                 # Unchanged
all-protocols = ["winrm", "telnet", "k8s-exec", "serial", "ssm", "azure", "gcp", "psrp"]
```

### Rationale

1. `winrm` no longer needs `reqwest` or `quick-xml` — winrm-rs brings its own.
2. `psrp` implies `winrm` because `psrp-rs` depends on `winrm-rs` for transport.
3. `air-gapped` keeps `winrm` (not `psrp`) — PSRP is opt-in on air-gapped.
4. `all-protocols` gains `psrp` — it's the "everything" bundle.

---

## R6: YAML Config Examples

### Decision

Add documented WinRM and PSRP examples to `config/config.example.yaml`:

```yaml
hosts:
  # WinRM with NTLMv2 (default, recommended)
  windows-dc:
    hostname: 192.168.1.200
    port: 5986
    user: Administrator
    os_type: windows
    protocol: winrm
    auth:
      type: ntlm
      password: "${WIN_PASSWORD}"
      domain: CORP
    winrm_use_tls: true
    winrm_accept_invalid_certs: true

  # WinRM with Kerberos
  windows-app:
    hostname: app01.corp.local
    port: 5985
    user: svc_deploy@CORP.LOCAL
    os_type: windows
    protocol: winrm
    auth:
      type: kerberos

  # PSRP (native PowerShell remoting)
  windows-psrp:
    hostname: 192.168.1.201
    port: 5986
    user: Administrator
    os_type: windows
    protocol: psrp
    auth:
      type: ntlm
      password: "${WIN_PASSWORD}"
    winrm_use_tls: true
```
