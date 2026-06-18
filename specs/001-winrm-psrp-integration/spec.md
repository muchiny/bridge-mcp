# Feature Specification: WinRM/PSRP Protocol Integration

**Feature Branch**: `001-winrm-psrp-integration`  
**Created**: 2026-04-12  
**Status**: Draft  
**Input**: Replace homegrown WinRM adapter with winrm-rs and add PSRP protocol support via psrp-rs

## User Scenarios & Testing *(mandatory)*

### User Story 1 - WinRM with Real Authentication (Priority: P1)

As a sysadmin managing Windows hosts in an air-gapped environment, I need WinRM connections with NTLMv2 authentication so that I can execute commands without exposing credentials in Basic auth headers.

**Why this priority**: The current WinRM adapter only supports Basic auth, making it unusable in any enterprise or security-conscious environment. NTLMv2 is the minimum viable auth for Windows Server.

**Independent Test**: Configure a Windows host with `protocol: winrm` and `auth.type: ntlm` in config.yaml, run `bridge-mcp tool ssh_exec host=winhost command="hostname"`, verify successful execution.

**Acceptance Scenarios**:

1. **Given** a host configured with `protocol: winrm` and `auth.type: ntlm`, **When** I execute a command via any tool, **Then** the connection uses NTLMv2 challenge-response authentication and the command succeeds.
2. **Given** a host configured with `protocol: winrm` and `auth.type: password`, **When** I execute a command, **Then** the connection uses Basic auth over HTTPS (backward compatible).
3. **Given** a host configured with `protocol: winrm` and `auth.type: kerberos`, **When** I execute a command with a valid TGT, **Then** the connection uses SPNEGO/Kerberos authentication.
4. **Given** a host configured with `protocol: winrm` and `auth.type: certificate`, **When** I provide client cert paths, **Then** the connection uses TLS client certificate authentication.

---

### User Story 2 - Windows Handlers Work on WinRM (Priority: P1)

As a user invoking Windows tools (services, events, firewall, etc.), I need the 44 Windows handlers to execute PowerShell commands correctly when the host uses WinRM protocol, not just SSH.

**Why this priority**: Currently all 44 Windows handlers generate PowerShell commands but the WinRM adapter sends them to `cmd.exe /c`, making WinRM mode fundamentally broken for Windows management.

**Independent Test**: Configure a Windows host with `protocol: winrm`, run `bridge-mcp tool ssh_win_service_status host=winhost name=WinRM`, verify it returns structured service status (not a cmd.exe parse error).

**Acceptance Scenarios**:

1. **Given** a Windows host with `protocol: winrm`, **When** I invoke `ssh_win_service_status` with `name=Spooler`, **Then** the handler executes via `WinrmClient::run_powershell()` and returns valid service status.
2. **Given** a Windows host with `protocol: winrm`, **When** I invoke any of the 44 `ssh_win_*` tools, **Then** each tool produces identical functional output to when the same host is configured with `protocol: ssh`.
3. **Given** a Windows host with `protocol: winrm` and a command that times out, **When** the operation_timeout is exceeded, **Then** the connection returns a timeout error without leaving orphan shells on the server.

---

### User Story 3 - PSRP Native PowerShell Remoting (Priority: P2)

As a power user managing Windows servers, I want to use PSRP (PowerShell Remoting Protocol) for native typed PowerShell output, session reuse, and access to all 7 PS output streams.

**Why this priority**: PSRP provides typed `PsValue` objects, session persistence via RunspacePool, and full PS stream access (Output, Error, Warning, Verbose, Debug, Information, Progress) -- a significant upgrade over raw text parsing.

**Independent Test**: Configure a host with `protocol: psrp`, run `bridge-mcp tool ssh_win_service_status host=psrphost name=WinRM --json`, verify the output contains structured typed data.

**Acceptance Scenarios**:

1. **Given** a host configured with `protocol: psrp`, **When** I invoke `ssh_exec` with a PowerShell command, **Then** the command executes via a PSRP RunspacePool and returns structured output.
2. **Given** a host with `protocol: psrp`, **When** I invoke multiple commands in sequence, **Then** all commands share the same RunspacePool (no per-command shell creation overhead).
3. **Given** a PSRP execution that produces warnings and verbose output, **When** the command completes, **Then** warnings and verbose messages appear in stderr (or a dedicated field) alongside stdout.
4. **Given** a PSRP connection idle for longer than the pool TTL, **When** a new command is invoked, **Then** a new RunspacePool is transparently created.

---

### User Story 4 - PSRP over SSH Transport (Priority: P3)

As a user with Windows hosts accessible only via SSH (no WinRM endpoint), I want to use PSRP over SSH for native PowerShell remoting without needing an HTTP WinRM listener.

**Why this priority**: Many modern Windows deployments use OpenSSH with PowerShell as the default shell. PSRP over SSH provides the benefits of typed output without requiring WinRM configuration.

**Independent Test**: Configure a Windows host with `protocol: ssh` and `shell: psrp`, run `bridge-mcp tool ssh_win_service_status host=sshwin name=WinRM`, verify execution uses PSRP layer over the SSH transport.

**Acceptance Scenarios**:

1. **Given** a host with `protocol: ssh` and `shell: psrp`, **When** I invoke a Windows tool, **Then** the command executes via `SshPsrpTransport` using the existing SSH connection.
2. **Given** a host with `protocol: ssh` and `shell: psrp`, **When** multiple commands are invoked, **Then** they share the SSH connection pool (no new SSH sessions per command).

---

### Edge Cases

- What happens when WinRM endpoint is unreachable? Timeout with clear error message including host/port.
- What happens when NTLMv2 credentials are wrong? Auth error returned immediately, no retry loop.
- What happens when PSRP RunspacePool enters a broken state? Pool eviction + transparent recreate on next call.
- What happens when a PSRP command is cancelled mid-execution? CancellationToken propagated to winrm-rs/psrp-rs.
- What happens when WinRM HTTPS has a self-signed cert? `accept_invalid_certs: true` in host config.
- What happens when `kerberos` feature is not enabled but auth.type is kerberos? Clear runtime error at config validation.
- What happens when `psrp` feature is enabled but `winrm` is not? Compile error: psrp implies winrm dependency.
- What happens when a WinRM Shell is orphaned (network drop)? No server-side leak: WinRM shells have server-side idle timeout.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST replace the homegrown WinRM adapter (`src/winrm/`) with an adapter wrapping `winrm_rs::WinrmClient`
- **FR-002**: System MUST support NTLMv2 authentication for WinRM connections (default auth method)
- **FR-003**: System MUST support Basic, Kerberos (feature-gated), and Certificate authentication for WinRM
- **FR-004**: System MUST execute PowerShell commands via `WinrmClient::run_powershell()` instead of `cmd.exe /c`
- **FR-005**: System MUST add a `Protocol::Psrp` variant, feature-gated behind `psrp = ["dep:psrp-rs"]`
- **FR-006**: System MUST manage PSRP `RunspacePool` instances per host via a dedicated `PsrpPool`
- **FR-007**: System MUST map existing `AuthConfig` variants to `WinrmConfig`/`WinrmCredentials`
- **FR-008**: System MUST preserve backward compatibility for `protocol: winrm` in existing configs
- **FR-009**: All 44 `ssh_win_*` handlers MUST work identically on SSH, WinRM, and PSRP protocols
- **FR-010**: System MUST propagate `CancellationToken` from `ToolContext` to winrm-rs/psrp-rs operations
- **FR-011**: System MUST support `accept_invalid_certs` configuration for WinRM HTTPS endpoints
- **FR-012**: System MUST support `save_output` and output truncation for WinRM/PSRP command results
- **FR-013**: The `psrp` feature MUST imply the `winrm` feature (PSRP depends on WinRM transport)
- **FR-014**: System SHOULD support PSRP over SSH transport via `SshPsrpTransport` (Phase 4)

### Key Entities

- **WinrmAdapter**: Adapter wrapping `winrm_rs::WinrmClient`, implementing pool management and auth mapping
- **PsrpAdapter**: Adapter wrapping `psrp_rs::RunspacePool`, managing sessions per host
- **PsrpPool**: Connection pool for PSRP `RunspacePool` instances (keyed by host, with idle TTL)
- **Protocol::Psrp**: New enum variant for PSRP protocol selection in config
- **WinrmAuthConfig**: Extended auth config supporting ntlm, basic, kerberos, certificate types

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All 44 `ssh_win_*` handlers pass integration tests on WinRM protocol (same assertions as SSH)
- **SC-002**: WinRM adapter supports NTLMv2, Basic, Kerberos, and Certificate auth methods
- **SC-003**: PSRP RunspacePool achieves session reuse (measured: no per-command shell creation in traces)
- **SC-004**: No regression in existing SSH-based test suite (6300+ tests pass)
- **SC-005**: Feature-gated compilation: `cargo check` passes with and without `winrm`/`psrp` features
- **SC-006**: WinRM pool idle cleanup works at 120s TTL (matching current behavior)
- **SC-007**: CancellationToken propagation verified: cancelled commands return within 5s
