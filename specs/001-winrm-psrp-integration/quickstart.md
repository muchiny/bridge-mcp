# Quickstart: WinRM/PSRP Protocol Integration

**Branch**: `001-winrm-psrp-integration` | **Date**: 2026-04-12

## Prerequisites

- Rust 1.94+ (edition 2024)
- A Windows host with WinRM enabled (port 5985/5986)
- For PSRP: same host (PSRP uses WinRM transport)

## Build with WinRM support

```bash
# WinRM only
cargo build --features winrm

# WinRM + PSRP
cargo build --features psrp

# Air-gapped bundle (SSH + WinRM + Telnet)
cargo build --features air-gapped

# Everything
cargo build --all-features
```

## Configure a WinRM host

Add to `~/.config/bridge-mcp/config.yaml`:

```yaml
hosts:
  win-server:
    hostname: 192.168.1.200
    port: 5986
    user: Administrator
    os_type: windows
    protocol: winrm
    auth:
      type: ntlm
      password: "YourPassword"
      domain: CORP
    winrm_use_tls: true
    winrm_accept_invalid_certs: true  # For self-signed certs
```

## Test connectivity

```bash
# Check host reachability
bridge-mcp status

# Execute a simple command
bridge-mcp tool ssh_exec host=win-server command="hostname"

# Test a Windows-specific tool
bridge-mcp tool ssh_win_service_status host=win-server name=WinRM
```

## Configure a PSRP host

```yaml
hosts:
  win-psrp:
    hostname: 192.168.1.200
    port: 5986
    user: Administrator
    os_type: windows
    protocol: psrp
    auth:
      type: ntlm
      password: "YourPassword"
    winrm_use_tls: true
```

## Test PSRP

```bash
# PSRP execution (same tools, different transport)
bridge-mcp tool ssh_exec host=win-psrp command="Get-Process | Select-Object -First 5"

# JSON output for structured data
bridge-mcp --json tool ssh_win_service_status host=win-psrp name=WinRM
```

## Run tests

```bash
# All tests (default features)
make test

# Tests with WinRM feature
cargo test --features winrm

# Tests with PSRP feature
cargo test --features psrp

# Feature-gate verification
cargo check                       # No features (SSH only)
cargo check --features winrm      # WinRM only
cargo check --features psrp       # PSRP (implies WinRM)
cargo check --all-features        # Everything
```

## Implementation phases

| Phase | What | When |
|-------|------|------|
| **1** | Replace `src/winrm/` with winrm-rs adapter | First |
| **2** | Add `src/psrp/` with psrp-rs adapter | After Phase 1 |
| **3** | Typed PsValue output in Windows handlers | After Phase 2, incremental |
| **4** | PSRP over SSH transport | After psrp-rs russh bump to 0.58 |
