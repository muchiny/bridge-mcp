---
name: discover
description: |
  Use when the user wants to explore, search, or learn what bridge-mcp can do:
  "what tools are available", "list bridge tools", "find a tool for X", "show
  docker / kubernetes / systemd / network tools", "search tools for logs /
  firewall / packages / databases", "which tool groups exist", "what can the
  bridge do". Progressive discovery across the 357 tools and 75 groups, with
  token-efficient describe-tool output.
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

- **75 groups**: docker, kubernetes, systemd, networking, firewall, packages, users, cron, logs, files, etc.
- **Token-efficient**: always use `columns`, `limit`, or `jq_filter` params to reduce output
- **9 protocols**: SSH, WinRM, PSRP, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP
