# Bridge MCP -- Claude Code Plugin

This plugin integrates [bridge-mcp](https://github.com/muchini/bridge-mcp) into Claude Code, giving you access to **357 tools** for managing remote servers via SSH.

## Prerequisites

Install the bridge-mcp binary (not published on crates.io — install from git):

```bash
cargo install --git https://github.com/muchini/bridge-mcp --features full
```

Then configure at least one host in `~/.config/bridge-mcp/config.yaml`:

```yaml
hosts:
  my-server:
    hostname: 192.168.1.100
    port: 22
    user: admin
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## What's included

### MCP Server

The plugin registers `bridge-mcp` as an MCP server, exposing all 357 tools
directly to Claude Code for remote server management.

### Skills

| Skill | Description |
|-------|-------------|
| `/bridge-mcp:bridge` | Manage remote hosts -- status, config, tool execution |
| `/bridge-mcp:discover` | Explore 357 tools across 75 groups with progressive discovery |

### Capabilities

- **Linux** (60 groups): systemd, Docker, Kubernetes, networking, filesystems, logs, packages, users, cron, firewall, etc.
- **Windows** (13 groups): PowerShell, services, registry, IIS, Active Directory, EventLog, etc.
- **9 protocols**: SSH, WinRM, PSRP, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP
- **Token-efficient**: server-side output filtering (jq/yq, columns, limit, pagination)
- **Secure**: command validation, input sanitization, rate limiting, audit logging

## Links

- [GitHub](https://github.com/muchini/bridge-mcp)
- [crates.io](https://crates.io/crates/bridge-mcp)
- [docs.rs](https://docs.rs/bridge-mcp)
- [Configuration reference](https://github.com/muchini/bridge-mcp/blob/main/config/config.example.yaml)
