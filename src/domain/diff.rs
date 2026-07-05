//! Multi-host output diffing.
//!
//! Pure domain logic for comparing the output of the same command
//! across multiple hosts. Given a `baseline_host` and a list of
//! `(host, output, exit_code)` tuples, this module produces a
//! structured summary telling the caller which hosts match the
//! baseline and which diverge, with a unified diff attached to each
//! divergent host.
//!
//! Used by the `ssh_exec_multi` tool handler when `diff: true` is
//! requested, to detect config drift across a fleet of servers
//! (e.g. "did `nginx -v` come back the same on all 3 web nodes?").
//!
//! # Performance guard
//!
//! `similar` runs a Patience diff in O(n + d²) on line counts — fast
//! for normal command outputs (tens to hundreds of lines) but
//! potentially slow on very large outputs (log dumps, `ps -ef` on
//! busy hosts). When an output exceeds [`LARGE_OUTPUT_THRESHOLD`]
//! bytes we fall back to a **hash-only** comparison that still
//! reports match/differ correctly but skips generating the unified
//! diff text — that keeps every single call predictable and
//! bounded.
//!
//! This module is **pure**: no I/O, no async, no adapter imports.
//! It only depends on `similar`, `serde`, and the standard library.

use std::collections::BTreeMap;

use serde::Serialize;
use similar::{ChangeTag, TextDiff};

/// Output size above which we skip generating the unified diff text
/// and fall back to a hash-based match/differ comparison. 100 KB
/// comfortably covers normal command outputs while bounding worst-
/// case diff cost.
pub const LARGE_OUTPUT_THRESHOLD: usize = 100_000;

/// Error variants returned by [`compute_multi_host_diff`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiffError {
    /// The requested baseline host is not in the results list.
    #[error("baseline host '{baseline}' not found in results")]
    BaselineNotFound { baseline: String },
    /// The results list is empty — cannot diff zero hosts.
    #[error("cannot compute diff on an empty results list")]
    EmptyResults,
}

/// Result of a multi-host diff computation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MultiHostDiff {
    /// Which host's output was used as the baseline.
    pub baseline_host: String,
    /// The baseline output (possibly normalized).
    pub baseline_output: String,
    /// Per-host comparison entries keyed by host name. Uses a
    /// `BTreeMap` so the JSON output order is stable for tests and
    /// easy human consumption.
    pub hosts: BTreeMap<String, HostDiffEntry>,
    /// Aggregated summary (counts + list of divergent hosts).
    pub summary: DiffSummary,
}

/// Per-host comparison result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostDiffEntry {
    /// Whether this host's output matches the baseline.
    pub matches_baseline: bool,
    /// Exit code reported by this host's command.
    pub exit_code: i32,
    /// The (possibly normalized) output for this host.
    pub output: String,
    /// Unified diff vs. baseline, `None` when matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// `true` when the diff text was skipped due to output size,
    /// and the comparison was made on a hash instead. Consumers can
    /// use this to decide whether to re-run with `normalize: true`
    /// or fetch the raw output some other way.
    #[serde(default)]
    pub large_output_fallback: bool,
}

/// Aggregated counts.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiffSummary {
    pub total: usize,
    pub matching: usize,
    pub divergent: usize,
    pub divergent_hosts: Vec<String>,
}

/// Compute a multi-host diff.
///
/// # Arguments
///
/// * `baseline_host` — name of the host whose output is the reference.
/// * `results` — `(host_name, stdout, exit_code)` for every host
///   that participated in the `ssh_exec_multi` call.
/// * `normalize` — when `true`, strip volatile tokens (timestamps,
///   PIDs, UUIDs) before comparing, so hosts that differ only on
///   runtime metadata still count as matching. See
///   `maybe_normalize` for the exact rules.
///
/// # Errors
///
/// Returns [`DiffError::BaselineNotFound`] if `baseline_host` is not
/// in `results`, or [`DiffError::EmptyResults`] on an empty list.
pub fn compute_multi_host_diff(
    baseline_host: &str,
    results: &[(String, String, i32)],
    normalize: bool,
) -> Result<MultiHostDiff, DiffError> {
    if results.is_empty() {
        return Err(DiffError::EmptyResults);
    }

    let baseline_raw = results
        .iter()
        .find(|(h, _, _)| h == baseline_host)
        .ok_or_else(|| DiffError::BaselineNotFound {
            baseline: baseline_host.to_string(),
        })?;

    let baseline_output = maybe_normalize(&baseline_raw.1, normalize);

    let mut hosts: BTreeMap<String, HostDiffEntry> = BTreeMap::new();
    let mut divergent_hosts = Vec::new();
    let mut matching = 0usize;

    for (host, raw_output, exit_code) in results {
        let normalized = maybe_normalize(raw_output, normalize);

        if host == baseline_host {
            hosts.insert(
                host.clone(),
                HostDiffEntry {
                    matches_baseline: true,
                    exit_code: *exit_code,
                    output: normalized,
                    diff: None,
                    large_output_fallback: false,
                },
            );
            matching += 1;
            continue;
        }

        let (matches, diff_text, large_fallback) = if normalized == baseline_output {
            (true, None, false)
        } else if baseline_output.len() > LARGE_OUTPUT_THRESHOLD
            || normalized.len() > LARGE_OUTPUT_THRESHOLD
        {
            // Large output: skip the unified diff generation. The
            // `!=` check above already tells us they differ; we
            // just can't afford to emit a readable diff.
            (false, None, true)
        } else {
            let diff = render_unified_diff(&baseline_output, &normalized);
            (false, Some(diff), false)
        };

        if matches {
            matching += 1;
        } else {
            divergent_hosts.push(host.clone());
        }

        hosts.insert(
            host.clone(),
            HostDiffEntry {
                matches_baseline: matches,
                exit_code: *exit_code,
                output: normalized,
                diff: diff_text,
                large_output_fallback: large_fallback,
            },
        );
    }

    let total = results.len();
    let divergent = total - matching;

    Ok(MultiHostDiff {
        baseline_host: baseline_host.to_string(),
        baseline_output,
        hosts,
        summary: DiffSummary {
            total,
            matching,
            divergent,
            divergent_hosts,
        },
    })
}

/// Render a unified-style diff using the `similar` crate.
///
/// Output is plain text with `-`/`+`/` ` line prefixes — no color
/// escapes so it's safe to drop straight into a JSON payload.
fn render_unified_diff(baseline: &str, other: &str) -> String {
    let diff = TextDiff::from_lines(baseline, other);
    let mut out = String::new();
    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        out.push_str(sign);
        out.push_str(change.value());
        // similar includes the trailing newline from the source line
        // already; no extra push_str("\n") here.
    }
    out
}

/// Strip volatile tokens so two hosts whose outputs differ only on
/// clock-driven fields still count as matching.
///
/// The rules here are deliberately minimal — we do NOT try to
/// normalize every possible volatile field. Adding more rules is
/// easy but each rule is a risk of hiding a real divergence, so we
/// keep the defaults conservative.
#[allow(clippy::expect_used)] // static regex literals below, validated by the normalization tests
fn maybe_normalize(output: &str, normalize: bool) -> String {
    // Module-level statics so rustc (and clippy) don't flag
    // `items_after_statements` when they sit inside the function.
    // Each regex compiles lazily on first use.
    static ISO_TIMESTAMP: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
            .expect("valid ISO timestamp regex")
    });
    static SYSLOG_TIMESTAMP: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
            .expect("valid syslog timestamp regex")
    });
    static PID_PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(pid=\d+|\[\d+\]:)").expect("valid pid regex")
    });
    static UUID_PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("valid uuid regex")
    });

    if !normalize {
        return output.to_string();
    }

    let mut s = output.to_string();
    s = ISO_TIMESTAMP.replace_all(&s, "<TIMESTAMP>").into_owned();
    s = SYSLOG_TIMESTAMP.replace_all(&s, "<TIMESTAMP>").into_owned();
    s = PID_PATTERN.replace_all(&s, "<PID>").into_owned();
    s = UUID_PATTERN.replace_all(&s, "<UUID>").into_owned();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkresult(pairs: &[(&str, &str, i32)]) -> Vec<(String, String, i32)> {
        pairs
            .iter()
            .map(|(h, o, c)| ((*h).to_string(), (*o).to_string(), *c))
            .collect()
    }

    #[test]
    fn test_empty_results_is_error() {
        let err = compute_multi_host_diff("a", &[], false).unwrap_err();
        assert_eq!(err, DiffError::EmptyResults);
    }

    #[test]
    fn test_unknown_baseline_is_error() {
        let r = mkresult(&[("web1", "foo", 0), ("web2", "foo", 0)]);
        let err = compute_multi_host_diff("nope", &r, false).unwrap_err();
        assert!(matches!(err, DiffError::BaselineNotFound { .. }));
    }

    #[test]
    fn test_all_hosts_match_baseline() {
        let r = mkresult(&[
            ("web1", "nginx/1.24.0", 0),
            ("web2", "nginx/1.24.0", 0),
            ("web3", "nginx/1.24.0", 0),
        ]);
        let d = compute_multi_host_diff("web1", &r, false).unwrap();
        assert_eq!(d.summary.total, 3);
        assert_eq!(d.summary.matching, 3);
        assert_eq!(d.summary.divergent, 0);
        assert!(d.summary.divergent_hosts.is_empty());
        for entry in d.hosts.values() {
            assert!(entry.matches_baseline);
            assert!(entry.diff.is_none());
        }
    }

    #[test]
    fn test_one_host_diverges() {
        let r = mkresult(&[
            ("web1", "nginx/1.24.0\n", 0),
            ("web2", "nginx/1.24.0\n", 0),
            ("web3", "nginx/1.22.1\n", 0),
        ]);
        let d = compute_multi_host_diff("web1", &r, false).unwrap();
        assert_eq!(d.summary.matching, 2);
        assert_eq!(d.summary.divergent, 1);
        assert_eq!(d.summary.divergent_hosts, vec!["web3".to_string()]);

        let web3 = d.hosts.get("web3").expect("web3 in output");
        assert!(!web3.matches_baseline);
        let diff = web3.diff.as_ref().expect("diff text present");
        assert!(diff.contains("-nginx/1.24.0"));
        assert!(diff.contains("+nginx/1.22.1"));
    }

    #[test]
    fn test_normalize_strips_timestamps() {
        let r = mkresult(&[
            ("a", "uptime: 2026-04-11T10:00:00Z\n", 0),
            ("b", "uptime: 2026-04-11T10:00:05Z\n", 0),
        ]);
        let d = compute_multi_host_diff("a", &r, true).unwrap();
        assert_eq!(
            d.summary.matching, 2,
            "normalization must coalesce the timestamps"
        );
        assert_eq!(d.summary.divergent, 0);
    }

    #[test]
    fn test_normalize_strips_syslog_timestamps() {
        let r = mkresult(&[
            ("a", "Apr 11 12:34:56 sshd starting\n", 0),
            ("b", "Apr 11 12:35:10 sshd starting\n", 0),
        ]);
        let d = compute_multi_host_diff("a", &r, true).unwrap();
        assert_eq!(d.summary.matching, 2);
    }

    #[test]
    fn test_normalize_strips_pids() {
        let r = mkresult(&[
            ("a", "sshd[1234]: accepted\n", 0),
            ("b", "sshd[5678]: accepted\n", 0),
        ]);
        let d = compute_multi_host_diff("a", &r, true).unwrap();
        assert_eq!(d.summary.matching, 2);
    }

    #[test]
    fn test_normalize_strips_uuids() {
        let r = mkresult(&[
            ("a", "id=550e8400-e29b-41d4-a716-446655440000 ok\n", 0),
            ("b", "id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 ok\n", 0),
        ]);
        let d = compute_multi_host_diff("a", &r, true).unwrap();
        assert_eq!(d.summary.matching, 2);
    }

    #[test]
    fn test_empty_line_outputs_are_handled() {
        let r = mkresult(&[("a", "", 0), ("b", "\n", 0)]);
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        assert_eq!(d.summary.divergent, 1);
    }

    #[test]
    fn test_large_output_fallback_skips_diff_text() {
        // Build two outputs over 100 KB that differ on one character.
        let mut baseline = "x".repeat(LARGE_OUTPUT_THRESHOLD + 10);
        baseline.push('\n');
        let mut other = baseline.clone();
        // Flip the last non-newline character so they differ.
        let last = other.len() - 2;
        other.replace_range(last..=last, "y");

        let r = vec![("a".to_string(), baseline, 0), ("b".to_string(), other, 0)];
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        assert_eq!(d.summary.divergent, 1);
        let b = d.hosts.get("b").expect("b present");
        assert!(!b.matches_baseline);
        assert!(
            b.diff.is_none(),
            "unified diff text must be skipped over LARGE_OUTPUT_THRESHOLD"
        );
        assert!(
            b.large_output_fallback,
            "large_output_fallback flag must be set"
        );
    }

    #[test]
    fn test_large_output_fallback_when_only_baseline_is_large() {
        // Baseline > threshold, normalized < threshold.
        // Kills mutants on line 152 (replace `>` with `==` or `>=`) and
        // the `||` → `&&` mutant on line 153: with L=true, R=false,
        // `L || R` → large_fallback=true, `L && R` → large_fallback=false.
        let mut baseline = "a".repeat(LARGE_OUTPUT_THRESHOLD + 1);
        baseline.push('\n');
        let other = "short\n".to_string();

        let r = vec![("a".to_string(), baseline, 0), ("b".to_string(), other, 0)];
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        assert_eq!(d.summary.divergent, 1);
        let b = d.hosts.get("b").expect("b present");
        assert!(!b.matches_baseline);
        assert!(
            b.diff.is_none(),
            "diff must be skipped when baseline is large"
        );
        assert!(
            b.large_output_fallback,
            "large_output_fallback must be set when baseline exceeds threshold"
        );
    }

    #[test]
    fn test_large_output_fallback_when_only_other_is_large() {
        // Baseline < threshold, normalized > threshold.
        // Kills mutants on line 153 (replace `>` with `==` or `>=`).
        let baseline = "short\n".to_string();
        let mut other = "b".repeat(LARGE_OUTPUT_THRESHOLD + 1);
        other.push('\n');

        let r = vec![("a".to_string(), baseline, 0), ("b".to_string(), other, 0)];
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        assert_eq!(d.summary.divergent, 1);
        let b = d.hosts.get("b").expect("b present");
        assert!(!b.matches_baseline);
        assert!(
            b.diff.is_none(),
            "diff must be skipped when other host is large"
        );
        assert!(
            b.large_output_fallback,
            "large_output_fallback must be set when normalized output exceeds threshold"
        );
    }

    #[test]
    fn test_exact_threshold_is_not_large() {
        // Both outputs are EXACTLY at LARGE_OUTPUT_THRESHOLD bytes.
        // The check is strict `>`, so outputs at the threshold should
        // still produce a unified diff. This kills mutants that replace
        // `>` with `>=` on lines 152 and 153 (they would incorrectly
        // treat threshold-sized outputs as large).
        let baseline = "a".repeat(LARGE_OUTPUT_THRESHOLD);
        // Change the last character so the two strings differ but have
        // the same length.
        let mut other = baseline.clone();
        let last = other.len() - 1;
        other.replace_range(last..=last, "b");
        assert_eq!(baseline.len(), LARGE_OUTPUT_THRESHOLD);
        assert_eq!(other.len(), LARGE_OUTPUT_THRESHOLD);

        let r = vec![("a".to_string(), baseline, 0), ("b".to_string(), other, 0)];
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        let b = d.hosts.get("b").expect("b present");
        assert!(!b.matches_baseline);
        assert!(
            !b.large_output_fallback,
            "output at exactly LARGE_OUTPUT_THRESHOLD must NOT be flagged large"
        );
        assert!(
            b.diff.is_some(),
            "unified diff must be produced when both sides are at threshold"
        );
    }

    #[test]
    fn test_baseline_has_no_diff_against_itself() {
        let r = mkresult(&[("only", "line1\n", 0)]);
        let d = compute_multi_host_diff("only", &r, false).unwrap();
        let entry = d.hosts.get("only").unwrap();
        assert!(entry.matches_baseline);
        assert!(entry.diff.is_none());
        assert_eq!(d.summary.total, 1);
        assert_eq!(d.summary.matching, 1);
    }

    #[test]
    fn test_exit_code_is_preserved_in_entry() {
        let r = mkresult(&[("a", "", 0), ("b", "", 42)]);
        let d = compute_multi_host_diff("a", &r, false).unwrap();
        assert_eq!(d.hosts.get("a").unwrap().exit_code, 0);
        assert_eq!(d.hosts.get("b").unwrap().exit_code, 42);
    }

    #[test]
    fn test_render_unified_diff_adds_signs() {
        let out = render_unified_diff("a\nb\nc\n", "a\nB\nc\n");
        assert!(out.contains("-b"), "deleted line should be prefixed with -");
        assert!(
            out.contains("+B"),
            "inserted line should be prefixed with +"
        );
        assert!(
            out.contains(" a"),
            "unchanged line should be prefixed with space"
        );
    }
}
