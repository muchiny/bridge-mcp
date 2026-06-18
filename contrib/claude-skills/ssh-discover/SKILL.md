---
name: ssh-discover
description: This skill should be used when the user asks to "show me the available tools", "what Docker tools exist", "search for kubernetes tools", "explore the tool catalog", or wants to browse the 338 bridge-mcp tools by group or keyword.
argument-hint: [group-name|search-keyword]
compatibility: "2.1+"
---

# Tool Discovery

Explore the bridge-mcp tool catalog interactively.

**Argument:** `$ARGUMENTS`

## How to Explore

Run one of these depending on what was requested:

**No argument — show all groups:**

```bash
bridge-mcp list-tools --groups-only
```

**Group name — show tools in that group:**

```bash
bridge-mcp list-tools --group $ARGUMENTS
```

**Keyword — search by name or description:**

```bash
bridge-mcp list-tools --search $ARGUMENTS
```

After finding interesting tools, show their full schema:

```bash
bridge-mcp describe-tool TOOL_NAME
```

## Category Quick Reference

| Category | Groups to explore |
|----------|-------------------|
| Servers | core, process, monitoring, systemd, storage, journald |
| Files | file_ops, file_transfer, directory |
| Containers | docker, podman, kubernetes, esxi, hyperv |
| Databases | database, redis, postgresql, mysql, mongodb |
| Network | network, firewall, network_equipment, tunnels |
| Security | security_scan, network_security, compliance, certificates |
| Deploy | orchestration, runbooks, ansible, terraform |
| Cloud | cloud, inventory, multicloud, vault |
| Windows | windows_services, windows_events, active_directory, iis |

To invoke any discovered tool:

```bash
bridge-mcp tool TOOL_NAME host=HOST key=value --json
```
