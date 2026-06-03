# Claude Code Skills for bridge-mcp

Pre-built Skills that teach Claude Code to manage remote infrastructure
via the bridge-mcp CLI. Token-efficient progressive discovery of
338 tools across 74 groups.

> Run `bridge-mcp list-tools --groups-only` to get the current tool/group count.

## Quick Install

Copy the skills to your Claude Code skills directory:

```bash
# Global (all projects)
mkdir -p ~/.claude/skills
cp -r contrib/claude-skills/ssh-* ~/.claude/skills/

# Project-specific
mkdir -p .claude/skills
cp -r contrib/claude-skills/ssh-* .claude/skills/
```

That's it. Claude Code auto-discovers the skills on next session start.

## Prerequisites

- **bridge-mcp** installed and in PATH (`bridge-mcp --version`)
- SSH config at `~/.config/bridge-mcp/config.yaml`
- Claude Code v2.1+

## Skills Overview

| Skill | Invoke | Mode | Description |
|-------|--------|------|-------------|
| **ssh-ops** | Auto | Inline | Main skill — CLI workflow, progressive discovery, syntax reference |
| **ssh-diagnose** | Auto | Agent | Server diagnostics — systematic health checks by symptom |
| **ssh-deploy** | `/ssh-deploy` | Inline | Deployments — canary, rolling, K8s, Helm (manual-only for safety) |
| **ssh-discover** | `/ssh-discover` | Inline | Explore the 338-tool catalog by group or keyword |
| **ssh-audit** | Auto | Agent | Security audit — CIS, CVE, certs, ports, compliance |

### How they work

- **Auto** skills activate when Claude detects relevant context
  (e.g., "check Docker on prod" triggers ssh-ops)
- **Manual** skills require you to type the slash command
  (e.g., `/ssh-deploy prod restart`)
- **Fork agent** skills run in an isolated subagent so verbose output
  doesn't pollute your main conversation

### Skill details

**ssh-ops** — The brain. Teaches Claude to always prefer CLI over MCP
(10-32x token savings). Contains the progressive discovery workflow
(groups -> group -> describe -> invoke), syntax reference, exit codes,
and the top 10 most-used commands.

**ssh-diagnose** — Type "debug my server" or "prod is slow" and Claude
runs a systematic diagnostic: health overview, targeted investigation
by symptom, log analysis, then produces a structured report. Includes
playbooks for slow/crash/OOM/disk/network issues.

**ssh-deploy** — Manual-only (`/ssh-deploy`). Covers service restart,
canary deploy, rolling deploy, K8s rollout, and Helm upgrade. Enforces
pre-deploy health check and post-deploy verification.

**ssh-discover** — Type `/ssh-discover docker` to explore Docker tools,
or `/ssh-discover kubernetes` to find K8s tools. Guides you from group
browsing to tool schema inspection to invocation.

**ssh-audit** — Security scanning with 4 scopes: quick (ports, certs,
firewall), network (SSL, DNS), compliance (CIS, STIG), and full
(everything + SBOM + vulnerability scan). Produces a risk-rated report.

## File Structure

```
ssh-ops/
  SKILL.md            Main CLI workflow and reference

ssh-diagnose/
  SKILL.md            Diagnostic workflow (fork agent)
  playbooks.md        Symptom-specific investigation playbooks

ssh-deploy/
  SKILL.md            Deployment patterns (manual-only)

ssh-discover/
  SKILL.md            Tool catalog exploration

ssh-audit/
  SKILL.md            Security audit workflows (fork agent)
```

## Customization

Edit any SKILL.md after copying. Common customizations:

- Add your host aliases to examples (`host=prod` -> `host=my-server`)
- Add custom playbooks to `ssh-diagnose/playbooks.md`
- Modify audit scopes in `ssh-audit/SKILL.md`
- Add deployment-specific commands to `ssh-deploy/SKILL.md`

## Uninstall

```bash
rm -rf ~/.claude/skills/ssh-ops
rm -rf ~/.claude/skills/ssh-diagnose
rm -rf ~/.claude/skills/ssh-deploy
rm -rf ~/.claude/skills/ssh-discover
rm -rf ~/.claude/skills/ssh-audit
```
