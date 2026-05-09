# Audit 2026-05-09 — Full Security Audit

Branch: `security/audit-2026-05-09`
Driver: loic.wernert@gmail.com
Plugins: 13 from `@trailofbits` marketplace + project's existing cargo toolchain
MCP servers used: `context7` (upstream library docs)

## Layout
- `baseline/` — pre-audit snapshots (cargo audit/deny/clippy/test count)
- `surface/` — entry-point map, context cache from /audit-context-building
- `surface/context7/` — per-library upstream guidance pulled via context7 MCP
- `scans/` — outputs from each scanner (zeroize, insecure-defaults, supply-chain, static)
- `variant/` — variant analysis and mutation results on Vuln 8/9 patterns
- `triage/` — fp-check output, deduped findings
- `FINDINGS.md` — final consolidated report (written in Task 16)

## Re-running
Each task in `docs/superpowers/plans/2026-05-09-full-security-audit.md` is idempotent
and overwrites its own artifact. Re-run any single task to refresh just that file.
