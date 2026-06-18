---
name: discover
description: |
  Use when the user wants to explore available tools, find tools by category,
  or learn what bridge-mcp can do. Progressive discovery workflow.
user-invocable: true
argument-hint: "[group-name|search-term]"
---

# Tool Discovery -- Progressive Exploration

Explore the 357 tools across 75 groups available in bridge-mcp.

## No arguments -- show all groups

!`bridge-mcp list-tools --groups-only`

Ask which group interests the user, or suggest searching by keyword.

## Group name provided

!`bridge-mcp list-tools --group $ARGUMENTS`

For each tool shown, the user can ask for details:
!`bridge-mcp describe-tool <tool_name>`

The `describe-tool` output includes a **Reduction Strategy** line at the top
telling you which params (jq_filter, columns, limit, etc.) apply for token-efficient output.

## Search term provided

!`bridge-mcp list-tools --search $ARGUMENTS`

## Tips for the user

- **74 groups**: docker, kubernetes, systemd, networking, firewall, packages, users, cron, logs, files, etc.
- **Token-efficient**: always use `columns`, `limit`, or `jq_filter` params to reduce output
- **13 protocols**: SSH, WinRM, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP, ZeroMQ, NATS, MQTT, SNMP, NETCONF
