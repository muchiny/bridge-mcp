---
name: ssh-ops
description: This skill should be used when the user asks to "run a command on a server", "check Docker containers", "restart a service", "read a remote file", "check disk usage", or mentions managing remote infrastructure via SSH. Teaches CLI-first workflow with progressive tool discovery.
argument-hint: [tool-name|group|search-term]
compatibility: "2.1+"
---

# Remote Infrastructure Operations

**338 tools** are available via the `bridge-mcp` CLI for managing remote servers over SSH.

## Golden Rule

**ALWAYS use the CLI** (`bridge-mcp tool ...` via Bash) instead of MCP tools.
CLI saves 10-32x tokens compared to MCP by loading schemas on-demand.

## Progressive Discovery Workflow

To find the right tool, follow these steps:

### Step 1 — Browse groups (~2K tokens)

```bash
bridge-mcp list-tools --groups-only
```

### Step 2 — Explore a group (~500 tokens)

```bash
bridge-mcp list-tools --group docker
```

### Step 3 — Get tool schema (~200 tokens)

```bash
bridge-mcp describe-tool ssh_docker_ps
```

### Step 4 — Invoke the tool

```bash
bridge-mcp tool ssh_docker_ps host=myserver --json
```

Search by keyword: `bridge-mcp list-tools --search kubernetes`

## Syntax Reference

```bash
# key=value arguments (auto type-coerced)
bridge-mcp tool ssh_exec host=prod command="df -h"

# Complex/nested args via JSON
bridge-mcp tool ssh_k8s_get --json-args '{"host":"k8s","resource":"pods","namespace":"default"}'

# Multi-file write (inline content + local file upload in one call)
bridge-mcp tool ssh_files_write --json-args '{"host":"prod","files":[{"remote_path":"/tmp/a.conf","content":"key=val"},{"remote_path":"/opt/b.bin","local_path":"/local/b.bin"}]}'

# JSON output for reliable parsing
bridge-mcp tool ssh_docker_ps host=prod --json

# Aliases: t = tool, dt = describe-tool
bridge-mcp t ssh_exec host=prod command="whoami"
bridge-mcp dt ssh_docker_ps
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | Continue |
| 1 | Command failed on remote host | Check stderr, retry or escalate |
| 2 | Unknown tool or bad arguments | Use `describe-tool` to check schema |
| 3 | SSH connection failure | Verify host config, network |
| 4 | Security denial (blocked by policy) | Command not allowed, inform user |
| 5 | Configuration error | Check config.yaml |

## Group Quick Reference

| Category | Groups |
|----------|--------|
| **Core** | core, file_ops, file_transfer, directory, process, monitoring, sessions |
| **System** | systemd, systemd_timers, firewall, package, cron, user_management, storage, journald |
| **Containers** | docker, podman, kubernetes, esxi |
| **Databases** | database, redis, postgresql, mysql, mongodb |
| **Web** | nginx, apache, letsencrypt, certificates |
| **IaC** | ansible, terraform, vault, git |
| **Security** | security_scan, network_security, compliance, security_modules |
| **Observability** | diagnostics, performance, container_logs, cron_analysis, drift |
| **Cloud** | cloud, inventory, multicloud |
| **Ops** | orchestration, runbooks, alerting, capacity, incident, log_aggregation |
| **Config** | templates, config, recording, key_management, chatops, tunnels |
| **Network** | network, network_equipment, ldap, backup |
| **Windows** | windows_services, windows_events, active_directory, scheduled_tasks, windows_firewall, iis, windows_updates, windows_perf, hyperv, windows_registry, windows_features, windows_network, windows_process |
| **Interactive** | pty |

## Top 10 Most-Used Commands

```bash
# Execute arbitrary command
bridge-mcp t ssh_exec host=HOST command="COMMAND"

# System health overview (single call, collects everything)
bridge-mcp t ssh_diagnose host=HOST

# Docker containers
bridge-mcp t ssh_docker_ps host=HOST all=true

# Service status
bridge-mcp t ssh_service_status host=HOST service=nginx

# Read a remote file
bridge-mcp t ssh_file_read host=HOST path=/etc/nginx/nginx.conf

# Write a file (any size — large content auto-streams via SFTP)
bridge-mcp t ssh_file_write host=HOST path=/tmp/config.yaml content="key: value"

# Check disk usage
bridge-mcp t ssh_disk_usage host=HOST

# Recent logs
bridge-mcp t ssh_service_logs host=HOST service=myapp lines=50

# Process list (top consumers)
bridge-mcp t ssh_process_top host=HOST

# Network connections
bridge-mcp t ssh_net_connections host=HOST
```

## Best Practices

1. **Use `--json`** when parsing output programmatically
2. **Use `ssh_diagnose`** first for troubleshooting — it collects everything in one SSH call
3. **Use `ssh_exec`** as fallback for any command not covered by specialized tools
4. **Check exit code** to determine success/failure without parsing output
5. **Use `ssh_files_write`** to write multiple files in a single SFTP session
6. **Use `describe-tool --json`** to get the exact schema before invoking unfamiliar tools
