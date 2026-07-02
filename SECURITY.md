# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.20.x  | Yes       |
| < 1.20  | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Bridge MCP, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: Send details to the project maintainer (see git log for contact)
2. GitHub: Use [GitHub Security Advisories](../../security/advisories/new) to report privately

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix and release**: Depends on severity
  - Critical: Within 72 hours
  - High: Within 1 week
  - Medium/Low: Next release cycle

## Security Model

Bridge MCP acts as a security boundary between an AI client (Claude Code) and remote SSH hosts.

### Key Security Controls

| Control | Description |
|---------|-------------|
| Command Validation | Whitelist/blacklist with regex patterns (`CommandValidator`) |
| Shell Escaping | Single-quote wrapping for all user-supplied parameters |
| Output Sanitization | 63 patterns masking secrets in command output (`Sanitizer`) |
| Rate Limiting | Per-host token bucket rate limiter (`RateLimiter`) |
| Destructive-op Confirmation | Opt-in `security.require_elicitation_on_destructive` asks the client via MCP `elicitation/create` before any tool annotated `destructive_hint: true` executes. Fail-closed when the client does not advertise the elicitation capability. |
| Audit Logging | Async JSON-lines audit trail (`AuditLogger`) |
| Host Key Verification | Strict mode by default (MITM protection) |
| Memory Safety | `#![forbid(unsafe_code)]`, `Zeroizing<String>` for credentials |
| Path Validation | Traversal prevention on file operations |
| Dependency Auditing | `cargo-deny` + `cargo-audit` in CI |

### Security Modes

- **Standard** (default): `ssh_exec` is checked against the whitelist; built-in
  typed tools check the blacklist only
- **Strict**: Only explicitly whitelisted commands are allowed (safest)
- **Permissive**: All commands except blacklisted patterns

### What This Project Does NOT Protect Against

- Compromise of the MCP client (Claude Code) itself
- Compromise of the SSH host being connected to
- Physical access to the machine running the bridge
- Side-channel attacks on the SSH transport (handled by the SSH library)
