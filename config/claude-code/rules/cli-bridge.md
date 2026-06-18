---
description: Prefer CLI over MCP for ssh-bridge remote operations
globs: **/*
---

# SSH Bridge: Prefer CLI over MCP

When the user asks to manage remote hosts (Raspberry Pi, servers, containers, etc.),
**prefer the CLI via Bash** over the MCP tools for token efficiency (10-32x savings).

## CLI Quick Reference

```bash
# Discovery (progressive, token-efficient)
bridge-mcp list-tools --groups-only          # 74 groups (~2K tokens)
bridge-mcp list-tools --group <group>        # tools in group (~500 tokens)
bridge-mcp list-tools --search <keyword>     # keyword search
bridge-mcp describe-tool <tool_name>         # full schema (~200 tokens)

# Execution
bridge-mcp tool <tool_name> key=value ...    # invoke tool
bridge-mcp tool <tool_name> --json-args '{}' # JSON input
bridge-mcp --json tool <tool_name> ...       # JSON output

# Direct commands
bridge-mcp exec <host> "<command>"           # raw SSH exec
bridge-mcp status                            # host connectivity
bridge-mcp upload <host> <local> <remote>    # SFTP upload
bridge-mcp download <host> <remote> <local>  # SFTP download

# Configuration
bridge-mcp validate                          # validate config
bridge-mcp config-diff                       # compare vs defaults
```

## Workflow

1. Always run `bridge-mcp status` first to verify connectivity
2. Use `--json` when parsing output programmatically
3. Use `jq_filter` or `columns` params to reduce output size
4. Use `--dry-run` for destructive operations

## When to fall back to MCP tools

- CLI binary not built (`target/release/bridge-mcp` missing)
- User explicitly asks to use MCP tools
- Persistent sessions or output caching (MCP-only features)
