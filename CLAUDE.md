# CLAUDE.md

## Project Overview

Bridge MCP (binary `bridge-mcp`, formerly MCP SSH Bridge / `mcp-ssh-bridge`) is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **476 tools** across **77 groups** (62 Linux, 13 Windows, 2 cross-platform). Count source of truth: `.migration-baseline.json` (`python3 scripts/validate_baseline.py`).

## CLI-as-Tool Mode (Alternative to MCP)

All 476 MCP tools are reachable from the CLI (`bridge-mcp tool <name> key=value`), for
**10-32x token savings** over MCP mode. CLI for dev workflows, MCP for enterprise
integration and for anything needing persistent sessions or the output cache.

**Full reference — progressive discovery, the per-`OutputKind` reduction strategies,
pagination, global flags — is in the `bridge` skill (`/bridge`).** Load it before
invoking tools; do not re-derive it here.

## Build Commands

`make ci` before every commit (fmt-check, lint, test, audit, typos). `make help` lists
every target. `make install` builds with `RELEASE_FEATURES` (`full,winrm,psrp`) and
refuses to install a binary that cannot load the local config or lacks `jq_filter`.

## Worktrees

Create worktrees under `.worktrees/<name>` (git-ignored), never in `~/`. Each has its own
`target/` (several GB): `git worktree remove` it once its branch is merged.

## Feature Flags

Full matrix in `Cargo.toml`. The one thing the matrix does not say: **`cloud` (SSM +
Azure + GCP) is NOT air-gapped** — it requires connectivity to the AWS/Azure/GCP APIs,
and GCP wraps the `gcloud` CLI, which must be installed on the bridge host.

## Configuration

YAML config at `~/.config/bridge-mcp/config.yaml`, falling back to the legacy
`~/.config/mcp-ssh-bridge/config.yaml` when the current path is absent
(`src/config/loader.rs`). **On this machine only the legacy path exists — that is the
file actually loaded.** Schema is `Config` in
`src/config/types.rs` (`deny_unknown_fields`). Conventions, validation flow and the
non-obvious gotchas (`rbac.enabled` rejected at load, session recording is not a YAML
section) live in
`.claude/rules/config.md`, loaded when you touch config code.

## Known Advisories

2 advisories ignored in `deny.toml` + `.cargo/audit.toml` (keep both in sync). Details
and removal conditions in `.claude/rules/advisories.md`, loaded when you touch those
files.

## Recent Changes — carry-forward gotchas

Full detail on 2.2.0, the 3.0.0 Modern-only cut and the 2026-08 conformance and
live-host sweeps is in the `recent-changes` skill (`/recent-changes`) and in
CHANGELOG.md. The land-mines that must not wait for a lazy load:

- **`audit.retain_days` starts DELETING archives** on the first event after
  upgrading past 2.2.0 (`retain_days: 0` opts out).
- **`rbac.enabled: true` is rejected at load** — it was never enforced and
  granted full access.
- **`security.require_elicitation_on_destructive` is the whole confirmation
  policy now** (the nineteen handlers that confirmed a second time are gone) —
  turn it on if you had it off.
- **Destructive tools are gated in the CLI too**, not only over MCP: prompt on a
  terminal, exit 4 without one, `--yes` for scripts.
- **`bridge-mcp tool` rejects arguments the tool does not declare** (exit 5) — a
  typo'd argument used to return the full unreduced output instead.
- **The destructive gate runs before the blacklist**, so a blacklisted command
  asks for confirmation and is then refused anyway (fails closed, known).
