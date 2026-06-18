//! Application metrics for observability
//!
//! Provides counters and gauges for monitoring tool execution,
//! SSH connections, and request handling.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Application-wide metrics collector
pub struct Metrics {
    /// Total tool call count
    pub tool_calls_total: AtomicU64,
    /// Total tool call errors
    pub tool_errors_total: AtomicU64,
    /// Per-tool call counts
    tool_counts: RwLock<HashMap<String, u64>>,
    /// Per-host call counts
    host_counts: RwLock<HashMap<String, u64>>,
    /// Active SSH connections gauge
    pub ssh_connections_active: AtomicU64,
    /// Total SSH connection attempts
    pub ssh_connections_total: AtomicU64,
    /// Total SSH connection errors
    pub ssh_connection_errors: AtomicU64,
    /// Total requests processed
    pub requests_total: AtomicU64,
    /// Server start time (unix timestamp)
    pub start_time: u64,

    // ---- Token consumption analytics ----
    /// Total output characters across all tool calls
    pub output_chars_total: AtomicU64,
    /// Estimated total tokens (~3.5 chars/token)
    pub estimated_tokens_total: AtomicU64,
    /// Per-tool output character totals
    tool_output_chars: RwLock<HashMap<String, u64>>,
    /// Total chars before data reduction pipeline
    pub chars_before_reduction: AtomicU64,
    /// Total chars after data reduction pipeline
    pub chars_after_reduction: AtomicU64,
    /// Number of times output was truncated
    pub truncation_events: AtomicU64,
    /// Per-`OutputKind` call counts
    output_kind_counts: RwLock<HashMap<String, u64>>,
}

impl Metrics {
    /// Create a new metrics collector
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_calls_total: AtomicU64::new(0),
            tool_errors_total: AtomicU64::new(0),
            tool_counts: RwLock::new(HashMap::new()),
            host_counts: RwLock::new(HashMap::new()),
            ssh_connections_active: AtomicU64::new(0),
            ssh_connections_total: AtomicU64::new(0),
            ssh_connection_errors: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            output_chars_total: AtomicU64::new(0),
            estimated_tokens_total: AtomicU64::new(0),
            tool_output_chars: RwLock::new(HashMap::new()),
            chars_before_reduction: AtomicU64::new(0),
            chars_after_reduction: AtomicU64::new(0),
            truncation_events: AtomicU64::new(0),
            output_kind_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Record a tool call
    pub fn record_tool_call(&self, tool_name: &str, host: &str) {
        self.tool_calls_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut counts) = self.tool_counts.write() {
            *counts.entry(tool_name.to_string()).or_insert(0) += 1;
        }
        if let Ok(mut counts) = self.host_counts.write() {
            *counts.entry(host.to_string()).or_insert(0) += 1;
        }
    }

    /// Record a tool error
    pub fn record_tool_error(&self) {
        self.tool_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record output size for a tool call.
    ///
    /// Updates total output chars, estimated tokens (~3.5 chars/token),
    /// and per-tool output tracking.
    pub fn record_tool_output(&self, tool_name: &str, output_chars: u64) {
        self.output_chars_total
            .fetch_add(output_chars, Ordering::Relaxed);
        // ~3.5 chars/token → multiply by 10, divide by 35 to avoid floats
        let estimated_tokens = output_chars * 10 / 35;
        self.estimated_tokens_total
            .fetch_add(estimated_tokens, Ordering::Relaxed);
        if let Ok(mut counts) = self.tool_output_chars.write() {
            *counts.entry(tool_name.to_string()).or_insert(0) += output_chars;
        }
    }

    /// Record data reduction pipeline stats from `StandardToolHandler`.
    pub fn record_pipeline_stats(
        &self,
        chars_before: u64,
        chars_after: u64,
        truncated: bool,
        output_kind: &str,
    ) {
        self.chars_before_reduction
            .fetch_add(chars_before, Ordering::Relaxed);
        self.chars_after_reduction
            .fetch_add(chars_after, Ordering::Relaxed);
        if truncated {
            self.truncation_events.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut counts) = self.output_kind_counts.write() {
            *counts.entry(output_kind.to_string()).or_insert(0) += 1;
        }
    }

    /// Render a human-readable token consumption summary for `ssh_health`.
    #[must_use]
    pub fn render_token_summary(&self) -> String {
        let mut out = String::new();
        let total_calls = self.tool_calls_total.load(Ordering::Relaxed);
        let total_chars = self.output_chars_total.load(Ordering::Relaxed);
        let total_tokens = self.estimated_tokens_total.load(Ordering::Relaxed);

        out.push_str("=== Token Consumption ===\n");
        let _ = writeln!(out, "Total output chars: {total_chars}");
        let _ = writeln!(out, "Estimated tokens: {total_tokens} (~3.5 chars/token)");
        let _ = writeln!(out, "Total tool calls: {total_calls}");
        if total_calls > 0 {
            let _ = writeln!(out, "Avg chars/call: {}", total_chars / total_calls);
            let _ = writeln!(out, "Avg tokens/call: {}", total_tokens / total_calls);
        }
        out.push('\n');

        // Top 5 tools by output
        if let Ok(output_chars) = self.tool_output_chars.read()
            && let Ok(call_counts) = self.tool_counts.read()
        {
            let mut sorted: Vec<_> = output_chars.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            if !sorted.is_empty() {
                out.push_str("Top 5 tools by output:\n");
                for (tool, chars) in sorted.iter().take(5) {
                    let tokens = *chars * 10 / 35;
                    let calls = call_counts.get(*tool).copied().unwrap_or(0);
                    let _ = writeln!(
                        out,
                        "  {tool:<25} {chars} chars (~{tokens} tokens, {calls} calls)"
                    );
                }
                out.push('\n');
            }
        }

        // Data reduction effectiveness
        let before = self.chars_before_reduction.load(Ordering::Relaxed);
        let after = self.chars_after_reduction.load(Ordering::Relaxed);
        let truncations = self.truncation_events.load(Ordering::Relaxed);
        if before > 0 {
            out.push_str("Data Reduction:\n");
            let _ = writeln!(out, "  Before reduction: {before} chars");
            let _ = writeln!(out, "  After reduction:  {after} chars");
            let saved = before.saturating_sub(after);
            // Outer guard ensures `before > 0`, so the division is safe.
            let pct = saved * 100 / before;
            let tokens_saved = saved * 10 / 35;
            let _ = writeln!(out, "  Savings: {pct}% (~{tokens_saved} tokens saved)");
            let _ = writeln!(out, "  Truncation events: {truncations}");
            out.push('\n');
        }

        // Output format distribution
        if let Ok(kinds) = self.output_kind_counts.read()
            && !kinds.is_empty()
        {
            let total_kind: u64 = kinds.values().sum();
            out.push_str("Output Format Distribution:\n");
            let mut sorted: Vec<_> = kinds.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (kind, count) in &sorted {
                // Outer guard ensures `!kinds.is_empty()` and every
                // `record_pipeline_stats` call increments a kind by 1,
                // so `total_kind` is always > 0 here.
                let pct = *count * 100 / total_kind;
                let _ = writeln!(out, "  {kind:<10} {count} calls ({pct}%)");
            }
            out.push('\n');
        }

        out
    }

    /// Render metrics in Prometheus text exposition format
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();

        // Uptime
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time);

        let _ = write!(
            output,
            "# HELP bridge_mcp_uptime_seconds Server uptime in seconds\n\
             # TYPE bridge_mcp_uptime_seconds gauge\n\
             bridge_mcp_uptime_seconds {uptime}\n\n"
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_requests_total Total requests processed\n\
             # TYPE bridge_mcp_requests_total counter\n\
             bridge_mcp_requests_total {}\n\n",
            self.requests_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_tool_calls_total Total tool calls\n\
             # TYPE bridge_mcp_tool_calls_total counter\n\
             bridge_mcp_tool_calls_total {}\n\n",
            self.tool_calls_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_tool_errors_total Total tool errors\n\
             # TYPE bridge_mcp_tool_errors_total counter\n\
             bridge_mcp_tool_errors_total {}\n\n",
            self.tool_errors_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_ssh_connections_active Active SSH connections\n\
             # TYPE bridge_mcp_ssh_connections_active gauge\n\
             bridge_mcp_ssh_connections_active {}\n\n",
            self.ssh_connections_active.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_ssh_connections_total Total SSH connection attempts\n\
             # TYPE bridge_mcp_ssh_connections_total counter\n\
             bridge_mcp_ssh_connections_total {}\n\n",
            self.ssh_connections_total.load(Ordering::Relaxed)
        );

        // Per-tool counts
        if let Ok(counts) = self.tool_counts.read() {
            output.push_str(
                "# HELP bridge_mcp_tool_calls_by_name Tool calls by tool name\n\
                 # TYPE bridge_mcp_tool_calls_by_name counter\n",
            );
            for (tool, count) in counts.iter() {
                let _ = writeln!(
                    output,
                    "bridge_mcp_tool_calls_by_name{{tool=\"{tool}\"}} {count}"
                );
            }
            output.push('\n');
        }

        // Token consumption
        let _ = write!(
            output,
            "# HELP bridge_mcp_output_chars_total Total output characters\n\
             # TYPE bridge_mcp_output_chars_total counter\n\
             bridge_mcp_output_chars_total {}\n\n",
            self.output_chars_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_estimated_tokens_total Estimated tokens (~3.5 chars/token)\n\
             # TYPE bridge_mcp_estimated_tokens_total counter\n\
             bridge_mcp_estimated_tokens_total {}\n\n",
            self.estimated_tokens_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP bridge_mcp_truncation_events_total Times output was truncated\n\
             # TYPE bridge_mcp_truncation_events_total counter\n\
             bridge_mcp_truncation_events_total {}\n\n",
            self.truncation_events.load(Ordering::Relaxed)
        );

        // Per-host counts
        if let Ok(counts) = self.host_counts.read() {
            output.push_str(
                "# HELP bridge_mcp_tool_calls_by_host Tool calls by host\n\
                 # TYPE bridge_mcp_tool_calls_by_host counter\n",
            );
            for (host, count) in counts.iter() {
                let _ = writeln!(
                    output,
                    "bridge_mcp_tool_calls_by_host{{host=\"{host}\"}} {count}"
                );
            }
            output.push('\n');
        }

        output
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let m = Metrics::new();
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.tool_errors_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_tool_call() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod-1");
        m.record_tool_call("ssh_exec", "prod-2");
        m.record_tool_call("ssh_ls", "prod-1");
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 3);

        // Per-tool count must accumulate via `+=`, not `*=`. The
        // `*= 1` mutation leaves the entry at 0 — assert the
        // accumulated count is what we recorded.
        let tool_counts = m.tool_counts.read().expect("tool_counts");
        assert_eq!(
            *tool_counts.get("ssh_exec").expect("ssh_exec recorded"),
            2,
            "ssh_exec must have been recorded twice"
        );
        assert_eq!(*tool_counts.get("ssh_ls").expect("ssh_ls recorded"), 1);

        let host_counts = m.host_counts.read().expect("host_counts");
        assert_eq!(
            *host_counts.get("prod-1").expect("prod-1 recorded"),
            2,
            "prod-1 must have been recorded twice"
        );
        assert_eq!(*host_counts.get("prod-2").expect("prod-2 recorded"), 1);
    }

    #[test]
    fn test_record_tool_error() {
        let m = Metrics::new();
        m.record_tool_error();
        m.record_tool_error();
        assert_eq!(m.tool_errors_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_ssh_connection_counters() {
        let m = Metrics::new();
        m.ssh_connections_total.fetch_add(3, Ordering::Relaxed);
        m.ssh_connection_errors.fetch_add(1, Ordering::Relaxed);
        m.ssh_connections_active.fetch_add(2, Ordering::Relaxed);
        assert_eq!(m.ssh_connections_total.load(Ordering::Relaxed), 3);
        assert_eq!(m.ssh_connection_errors.load(Ordering::Relaxed), 1);
        assert_eq!(m.ssh_connections_active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_requests_counter() {
        let m = Metrics::new();
        m.requests_total.fetch_add(5, Ordering::Relaxed);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_metrics_default() {
        let m = Metrics::default();
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 0);
        assert!(m.start_time > 0);
    }

    #[test]
    fn test_render_prometheus_with_ssh_metrics() {
        let m = Metrics::new();
        m.ssh_connections_total.fetch_add(10, Ordering::Relaxed);
        m.ssh_connections_active.fetch_add(2, Ordering::Relaxed);
        m.requests_total.fetch_add(50, Ordering::Relaxed);
        let output = m.render_prometheus();
        assert!(output.contains("bridge_mcp_ssh_connections_total 10"));
        assert!(output.contains("bridge_mcp_ssh_connections_active 2"));
        assert!(output.contains("bridge_mcp_requests_total 50"));
    }

    #[test]
    fn test_render_prometheus() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod-1");
        m.record_tool_error();
        let output = m.render_prometheus();
        assert!(output.contains("bridge_mcp_tool_calls_total 1"));
        assert!(output.contains("bridge_mcp_tool_errors_total 1"));
        assert!(output.contains("ssh_exec"));
        assert!(output.contains("prod-1"));
    }

    #[test]
    fn test_record_tool_output() {
        let m = Metrics::new();
        m.record_tool_output("ssh_exec", 3500);
        m.record_tool_output("ssh_ls", 700);

        assert_eq!(m.output_chars_total.load(Ordering::Relaxed), 4200);
        // 3500 * 10/35 = 1000, 700 * 10/35 = 200
        assert_eq!(m.estimated_tokens_total.load(Ordering::Relaxed), 1200);

        let counts = m.tool_output_chars.read().unwrap();
        assert_eq!(*counts.get("ssh_exec").unwrap(), 3500);
        assert_eq!(*counts.get("ssh_ls").unwrap(), 700);
    }

    #[test]
    fn test_record_pipeline_stats() {
        let m = Metrics::new();
        m.record_pipeline_stats(10000, 6000, true, "Tabular");
        m.record_pipeline_stats(5000, 5000, false, "Json");

        assert_eq!(m.chars_before_reduction.load(Ordering::Relaxed), 15000);
        assert_eq!(m.chars_after_reduction.load(Ordering::Relaxed), 11000);
        assert_eq!(m.truncation_events.load(Ordering::Relaxed), 1);

        let kinds = m.output_kind_counts.read().unwrap();
        assert_eq!(*kinds.get("Tabular").unwrap(), 1);
        assert_eq!(*kinds.get("Json").unwrap(), 1);
    }

    #[test]
    fn test_render_token_summary() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod");
        m.record_tool_call("ssh_ls", "prod");
        m.record_tool_output("ssh_exec", 3500);
        m.record_tool_output("ssh_ls", 700);
        m.record_pipeline_stats(5000, 3000, true, "Tabular");

        let summary = m.render_token_summary();
        assert!(summary.contains("=== Token Consumption ==="));
        assert!(summary.contains("Total output chars: 4200"));
        assert!(summary.contains("Top 5 tools by output:"));
        assert!(summary.contains("ssh_exec"));
        assert!(summary.contains("Data Reduction:"));
        assert!(summary.contains("Tabular"));
    }

    /// Pin the *numeric* output of `render_token_summary` so that
    /// arithmetic mutations on `/`, `*`, `+`, and `>` in the token /
    /// percentage / tokens-saved formulas produce observably wrong
    /// strings. The numbers below are chosen so each formula yields
    /// a unique, easy-to-assert integer.
    #[test]
    fn render_token_summary_pins_arithmetic_results() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod");
        m.record_tool_output("ssh_exec", 350); // 350*10/35 = 100 tokens
        m.record_pipeline_stats(1000, 500, false, "Json");

        let s = m.render_token_summary();
        // total_chars
        assert!(
            s.contains("Total output chars: 350"),
            "exact total_chars missing — got:\n{s}"
        );
        // total_tokens = 350*10/35 = 100 — kills line 105 token math
        // (record_tool_output) and pins the Estimated tokens line.
        assert!(
            s.contains("Estimated tokens: 100"),
            "Estimated tokens=100 missing — got:\n{s}"
        );
        // Avg chars/call = 350/1 = 350
        assert!(
            s.contains("Avg chars/call: 350"),
            "Avg chars/call=350 missing — got:\n{s}"
        );
        // Avg tokens/call = 100/1 = 100
        assert!(
            s.contains("Avg tokens/call: 100"),
            "Avg tokens/call=100 missing — got:\n{s}"
        );
        // Per-tool token line: 350 chars (~100 tokens, 1 calls) — kills
        // line 155 mutations (`*` and `/` on `chars * 10 / 35`).
        assert!(
            s.contains("350 chars (~100 tokens, 1 calls)"),
            "per-tool numbers wrong — got:\n{s}"
        );
        // Data reduction: before=1000, after=500, saved=500, pct=50%,
        // tokens_saved = 500*10/35 = 142. Pins lines 175/176.
        assert!(
            s.contains("Savings: 50% (~142 tokens saved)"),
            "savings/tokens_saved wrong — got:\n{s}"
        );
        // Output kind 100% — kills line 191/192 mutations on the
        // `*count * 100 / total_kind` percentage formula.
        assert!(
            s.contains("Json       1 calls (100%)"),
            "kind percentage wrong — got:\n{s}"
        );
    }

    /// `render_token_summary` must NOT divide by zero when no calls
    /// have been recorded. Mutations `> -> ==`, `> -> >=` on line 140
    /// turn the `total_calls > 0` guard into "always enter" or
    /// "enter when zero", which divides by zero.
    #[test]
    fn render_token_summary_handles_empty_state_safely() {
        let m = Metrics::new();
        let s = m.render_token_summary();
        assert!(
            s.contains("=== Token Consumption ==="),
            "header still rendered on empty state"
        );
        // Avg lines are gated on `total_calls > 0` — must be absent.
        assert!(
            !s.contains("Avg chars/call:"),
            "must not render Avg lines when no calls — got:\n{s}"
        );
        // Data Reduction block is gated on `before > 0` (line 170).
        // The mutation `> -> >=` would render the section with
        // all-zero stats; assert the marker is absent.
        assert!(
            !s.contains("Data Reduction:"),
            "must not render Data Reduction block when before=0 — got:\n{s}"
        );
        // Output Format Distribution is gated on `!kinds.is_empty()`.
        assert!(
            !s.contains("Output Format Distribution:"),
            "must not render Output Format block when no kinds — got:\n{s}"
        );
    }

    /// Two-kind variant pins the percentage formula
    /// `*count * 100 / total_kind`. With kinds `{Json: 2, Tabular: 1}`,
    /// `total = 3`:
    ///
    /// - Json:    `2 * 100 / 3 = 66`
    /// - Tabular: `1 * 100 / 3 = 33`
    ///
    /// The mutation `/ -> *` would print `2 * 100 * 3 = 600` and
    /// `1 * 100 * 3 = 300` instead.
    #[test]
    fn render_token_summary_kind_percentages_use_division() {
        let m = Metrics::new();
        m.record_pipeline_stats(100, 50, false, "Json");
        m.record_pipeline_stats(100, 50, false, "Json");
        m.record_pipeline_stats(100, 50, false, "Tabular");
        let s = m.render_token_summary();
        assert!(
            s.contains("Json       2 calls (66%)"),
            "Json must report 66% — got:\n{s}"
        );
        assert!(
            s.contains("Tabular    1 calls (33%)"),
            "Tabular must report 33% — got:\n{s}"
        );
    }

    #[test]
    fn test_prometheus_includes_token_metrics() {
        let m = Metrics::new();
        m.record_tool_output("ssh_exec", 1000);
        m.record_pipeline_stats(2000, 1500, true, "Json");

        let output = m.render_prometheus();
        assert!(output.contains("bridge_mcp_output_chars_total 1000"));
        assert!(output.contains("bridge_mcp_estimated_tokens_total"));
        assert!(output.contains("bridge_mcp_truncation_events_total 1"));
    }
}
