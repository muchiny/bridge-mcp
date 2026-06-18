# Implementation Plan: WinRM/PSRP Protocol Integration

**Branch**: `001-winrm-psrp-integration` | **Date**: 2026-04-12 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-winrm-psrp-integration/spec.md`

## Summary

Replace the homegrown WinRM adapter (878 lines, Basic auth only, cmd.exe execution) with
`winrm-rs` v1.0 for proper WS-Management support (NTLMv2, Kerberos, Certificate auth,
PowerShell execution), and add a new PSRP protocol adapter via `psrp-rs` v1.0 for native
PowerShell Remoting with typed outputs, session reuse, and 7 PS output streams. This fixes
the fundamental bug where 44 Windows handlers generate PowerShell but WinRM sends to cmd.exe.

## Technical Context

**Language/Version**: Rust 2024 edition, MSRV 1.94  
**Primary Dependencies**: winrm-rs 1.0, psrp-rs 1.0, russh 0.58, tokio, serde, clap 4  
**Storage**: N/A (YAML config files only)  
**Testing**: cargo test (nextest), 6300+ tests, 57 fuzz targets, property-based (proptest)  
**Target Platform**: Linux (WSL2), cross-compiled to Linux x86_64/aarch64  
**Project Type**: CLI + MCP server (library + binary)  
**Performance Goals**: Connection pooling amortizes TLS/auth overhead; sub-100ms warm calls  
**Constraints**: 24GB WSL2 VM (OOM-prone), air-gapped deployments, `#![forbid(unsafe_code)]`  
**Scale/Scope**: 357 tools, 75 groups, 9 protocols, 44 Windows handlers affected

### Key Version Concern

**russh version mismatch**: bridge-mcp uses `russh 0.58`, psrp-rs uses `russh 0.49`.
The PSRP-over-SSH transport (Phase 4) requires version alignment. See research.md for resolution.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### I. Architecture Hexagonale Stricte

- **PASS**: winrm-rs and psrp-rs are wrapped in adapters (`src/winrm/`, `src/psrp/`).
  Domain layer unchanged. Handlers call `ExecutorRouter` which dispatches to adapters.
  No direct dependency from handlers to winrm-rs/psrp-rs.

### II. Purete du Domaine

- **PASS**: Domain command builders (36 Linux + 13 Windows) remain pure. They produce
  command strings. The adapter decides whether to send via SSH, WinRM `run_powershell()`,
  or PSRP `RunspacePool::run_script()`. Zero changes to `src/domain/`.

### III. Feature Gates et Compilation Conditionnelle

- **PASS**: `winrm = ["dep:winrm-rs"]` replaces `["dep:reqwest", "dep:quick-xml"]`.
  New `psrp = ["dep:psrp-rs", "winrm"]` feature added. All code behind `#[cfg(feature)]`.
  `cargo check` must pass with no features, with `winrm` only, with `psrp` only, with all.

### IV. Discipline de Test

- **PASS**: Unit tests for config mapping, pool lifecycle, auth selection. Integration
  tests with mock WinRM server (wiremock). Registry test counts updated. Fuzz targets
  for SOAP envelope parsing if applicable.

### V. Securite Zero-Trust

- **PASS**: winrm-rs uses `SecretString` (secrecy crate) for passwords. Credentials
  mapped from existing `Zeroizing<String>` in AuthConfig. No OpenSSL by default
  (CredSSP feature not enabled). rustls for TLS.

### VI. Simplicite et YAGNI

- **PASS**: Phase 1 replaces broken code. Phase 2 adds a genuinely new protocol.
  Phase 3 (typed outputs) is incremental. Phase 4 (PSRP-over-SSH) deferred.
  No speculative abstractions.

**Gate result: ALL PASS** - Proceed to Phase 0.

## Project Structure

### Documentation (this feature)

```text
specs/001-winrm-psrp-integration/
├── plan.md              # This file
├── research.md          # Phase 0: version alignment, pool strategy, auth mapping
├── data-model.md        # Phase 1: entity definitions, type mappings
├── quickstart.md        # Phase 1: integration quickstart guide
├── contracts/           # Phase 1: adapter interfaces, config schema
└── tasks.md             # Phase 2: implementation tasks (via /speckit.tasks)
```

### Source Code (repository root)

```text
src/
├── winrm/                    # REPLACE: new adapter wrapping winrm-rs
│   ├── mod.rs                # WinrmAdapter (WinrmClient wrapper + exec logic)
│   └── pool.rs               # WinrmPool (WinrmClient instance caching)
├── psrp/                     # NEW: PSRP protocol adapter
│   ├── mod.rs                # PsrpConnection (RunspacePool wrapper + exec)
│   └── pool.rs               # PsrpPool (RunspacePool instance caching)
├── config/
│   └── types.rs              # UPDATE: Protocol::Psrp, WinrmAuthMethod enum
├── ports/
│   ├── executor.rs           # UNCHANGED: RemoteExecutor trait
│   └── executor_router.rs    # UPDATE: Protocol::Psrp dispatch arm
├── mcp/tool_handlers/
│   └── ssh_win_*.rs          # Phase 3: optional PsValue integration (44 files)
└── lib.rs                    # UPDATE: #[cfg(feature = "psrp")] mod psrp

Cargo.toml                    # UPDATE: winrm/psrp features, dependencies
config/config.example.yaml    # UPDATE: WinRM + PSRP host examples
```

**Structure Decision**: Existing hexagonal layout preserved. `src/winrm/` is replaced
in-place (same module, new implementation). `src/psrp/` follows the identical pattern
as all other protocol adapters (mod.rs + pool.rs).

## Complexity Tracking

> No constitution violations to justify. All changes align with existing patterns.
