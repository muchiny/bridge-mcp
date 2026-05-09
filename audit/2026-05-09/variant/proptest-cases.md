# Property-Based Test Suite — 2026-05-09 (Task 14)

**Skill:** `property-based-testing:property-based-testing` (trailofbits, v1.1.0) — guidance applied; tests written directly into the project test suite.
**Test file:** `tests/audit_2026_05_09_proptests.rs`
**Output:** `audit/2026-05-09/variant/proptest-output.txt`
**Result:** 2 properties passed (200+50 cases per property).

---

## Properties implemented

### Property 1 — `validator_blacklist_normalization_resists_whitespace_encodings` (200 cases)

**Invariant tested:** for the default blacklist pattern `(?i)rm\s+-rf\s+/`, ALL 7 documented whitespace encodings MUST be rejected:

| Encoding | Source | Status |
|---|---|---|
| literal space `" "` | trivial | ✅ rejected |
| `${IFS}` | bash IFS expansion | ✅ rejected |
| `$IFS` | unbraced IFS | ✅ rejected |
| `$'\t'` | ANSI-C tab | ✅ rejected |
| `$'\n'` | ANSI-C newline | ✅ rejected |
| `$' '` | ANSI-C space | ✅ rejected |
| `\<NL>` | line continuation | ✅ rejected |

All 7 × 200 cases passed → confirms `normalize_for_blacklist_match` (`src/security/validator.rs:55-63`) holds the invariant for the documented encoding set.

### Property 2 — `validator_does_not_normalize_hex_or_default_value_expansion` (50 cases)

**Invariant documented:** `$'\x09'` (hex tab) and `${IFS:- }` (default-value expansion) are NOT in the normalize list (per OQ-003 / OQ-004 in `docs/audit-2026-05-09-findings.md`). The test is a passive no-panic check; it documents the gap as a NEGATIVE assertion ("we know these are not normalized").

If a future fix closes the gap, this test should be flipped to `prop_assert!(result.is_err())`.

### Properties 3 + 4 — runbook validator + apply_template invariants (DEFERRED)

**Reason:** `mcp_ssh_bridge::domain::runbook::{validate_runbook, apply_template, Runbook}` are `pub(crate)` and not reachable from integration tests. To activate, either:
1. Move proptest cases into `src/domain/runbook.rs` as `#[cfg(test)] mod tests`, OR
2. Add `pub use domain::runbook::{validate_runbook, apply_template, Runbook};` in `src/lib.rs` behind a `cfg(test)` flag.

Tracked as part of OQ-011 follow-up. No new finding from Task 14 — properties simply confirm the existing invariant (Property 1) and document the existing gap (Property 2).

---

## Result

```
running 2 tests
test validator_does_not_normalize_hex_or_default_value_expansion ... ok
test validator_blacklist_normalization_resists_whitespace_encodings ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13.80s
```

**No new findings.** The validator is robust against the 7 documented whitespace encodings (regression coverage added). The 2 known gaps (`$'\x09'`, `${IFS:- }`) remain documented as OQ.

## Updated tracker counters

(unchanged from Task 13 — this task only adds regression test coverage)
