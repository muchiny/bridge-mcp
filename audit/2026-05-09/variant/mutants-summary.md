# Mutation Testing — 2026-05-09 (Task 15)

**Skill:** `mutation-testing:mutation-testing` (trailofbits, v1.0.0)
**Status:** **SKIPPED** at user request (after the initial run produced 0 mutants due to a `--file 'src/security/validator.rs'` glob-quoting issue in this shell).

## Pre-flight

```
free -m | awk 'NR==2 { ... }'
→ "WARN: use -j 4 — j=4"   (16 422 MB available, 26 044 MB total)
```

WSL safety per `~/.claude/rules/wsl-safety.md`: `-j 4` was the safe parallelism choice.

## Initial run

```
cargo mutants -j 4 --file 'src/security/validator.rs' --timeout 120
→ Found 0 mutants to test
   WARN No mutants found under the active filters
```

The `--file` glob quoting on this shell did not match `src/security/validator.rs` directly (cargo-mutants expects an unquoted glob OR a relative path without quotes for direct paths). User decision: **skip Task 15** rather than re-run with corrected scoping.

## Recommended re-run (for follow-up audit cycle)

```bash
free -m | awk 'NR==2 { if ($7 >= 18*1024) print "OK -j 6"; else if ($7 >= 12*1024) print "WARN -j 4"; else if ($7 >= 6*1024) print "CAUTION -j 2"; else print "BLOCK"; }'

cargo mutants -j 4 --file src/security/validator.rs --timeout 120
# OR scope to whole module:
cargo mutants -j 4 --file 'src/security/*.rs' --timeout 120
```

Targets in priority order:
1. `src/security/validator.rs` (932 LOC) — central command gate
2. `src/security/sanitizer.rs` (2012 LOC) — output redaction
3. `src/security/audit.rs` (1168 LOC) — audit trail integrity
4. `src/security/rate_limiter.rs` (383 LOC)
5. `src/security/rbac.rs` (305 LOC)

## Impact on FINDINGS

No new findings from this task. The mutation-testing coverage gap (no survivors data) is documented as **OQ-014** in `docs/audit-2026-05-09-findings.md` for the next audit cycle.
