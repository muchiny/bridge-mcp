---
name: bridge
description: |
  Use when the user says "bridge", "remote", "ssh", "run on host", "check host",
  "configure host", "setup bridge", or wants to manage remote servers via CLI.
  Provides guided SSH bridge setup, status checks, and tool execution.
user-invocable: true
argument-hint: "[status|config|tool-name] [args...]"
---

# SSH Bridge CLI -- Remote Tool Execution

Execute MCP tools on remote hosts or manage bridge configuration via CLI.

## Current state

Host status:
!`bridge-mcp status 2>/dev/null || echo "bridge-mcp not found -- install with: cargo install --git https://github.com/muchini/bridge-mcp --features full"`

## Instructions

### No arguments or status

Show host status (above) and available tool groups:
!`bridge-mcp list-tools --groups-only`

Then ask the user what they want to do.

### Config mode

Help the user configure the bridge:

1. Config file: `~/.config/bridge-mcp/config.yaml`
2. Validate: `bridge-mcp validate`
3. Example config: see https://github.com/muchini/bridge-mcp/blob/main/config/config.example.yaml

**Adding a host:**

```yaml
hosts:
  my-server:
    hostname: 192.168.1.100
    port: 22
    user: admin
    description: "My server"
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

**Security modes:**

```yaml
security:
  mode: standard  # strict | standard | permissive
```

### Tool group name (e.g., docker, kubernetes, systemd)

List tools in that group:
!`bridge-mcp list-tools --group $ARGUMENTS`

### Search query

Search tools by keyword:
!`bridge-mcp list-tools --search $ARGUMENTS`

### Tool name with key=value pairs

Execute the tool:
!`bridge-mcp --json tool $ARGUMENTS`

### Workflow reminders

1. Verify connectivity with `status` before executing tools
2. Use `--json` output for structured parsing
3. Use `--dry-run` before destructive operations
4. Use `jq_filter` or `columns` params to reduce output tokens
