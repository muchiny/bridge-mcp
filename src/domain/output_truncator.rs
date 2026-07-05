//! Output Truncator
//!
//! Smart head+tail truncation for command output that exceeds
//! client display limits. Keeps the beginning (context) and
//! end (result/summary) of the output, removing the middle.

use crate::domain::output_cache::OutputCache;

/// Legacy default max output characters.
///
/// This constant is kept for backward compatibility only — the runtime
/// default is `LimitsConfig::max_output_chars` (`40_000`, see
/// `config::types::default_max_output_chars`), with per-client overrides.
pub const DEFAULT_MAX_OUTPUT_CHARS: usize = 20_000;

/// Truncate output keeping head and tail, removing the middle.
///
/// - If `max_chars` is 0, truncation is disabled (returns original).
/// - If output fits within `max_chars`, returns original unchanged.
/// - Otherwise, keeps 20% from the start and 80% from the end,
///   cutting at line boundaries to avoid splitting lines.
#[must_use]
pub fn truncate_output(output: &str, max_chars: usize) -> String {
    if max_chars == 0 || output.len() <= max_chars {
        return output.to_string();
    }

    // 20% head, 80% tail (results are always at the end)
    let head_budget = max_chars / 5;
    let tail_budget = max_chars - head_budget;

    let head = take_head_lines(output, head_budget);
    let tail = take_tail_lines(output, tail_budget);

    let total_lines = output.lines().count();
    let head_lines = head.lines().count();
    let tail_lines = tail.lines().count();
    let omitted = total_lines.saturating_sub(head_lines + tail_lines);

    format!(
        "{head}\n\n--- [truncated: {total_lines} lines total, \
         {omitted} lines omitted, {orig} → {new} chars] ---\n\n{tail}",
        orig = output.len(),
        new = head.len() + tail.len(),
    )
}

/// Truncate output and cache the full version if truncation occurs.
///
/// When `cache` is `Some` and the output is truncated, the full output
/// is stored in the cache and an `output_id` hint is appended to the
/// truncation message so the LLM can use `ssh_output_fetch` to retrieve more.
///
/// When `reduction_tip` is `Some` and the output is truncated, a
/// `💡 Better: …` line is appended suggesting the server-side reduction
/// params (`jq_filter`/`columns`/`limit`) for the tool's `OutputKind` —
/// so the model learns the cheaper alternative to pagination in-band.
///
/// When `cache` is `None` (e.g., CLI mode), no `output_id` is emitted but
/// the reduction tip still applies.
pub async fn truncate_output_with_cache(
    output: &str,
    max_chars: usize,
    cache: Option<&OutputCache>,
    reduction_tip: Option<&str>,
) -> String {
    if max_chars == 0 || output.len() <= max_chars {
        return output.to_string();
    }

    // 20% head, 80% tail (results are always at the end)
    let head_budget = max_chars / 5;
    let tail_budget = max_chars - head_budget;

    let head = take_head_lines(output, head_budget);
    let tail = take_tail_lines(output, tail_budget);

    let total_lines = output.lines().count();
    let head_lines = head.lines().count();
    let tail_lines = tail.lines().count();
    let omitted = total_lines.saturating_sub(head_lines + tail_lines);

    let tip = reduction_tip.map_or_else(String::new, |t| format!("\n💡 Better: {t}."));

    if let Some(cache) = cache {
        let output_id = cache.store(output.to_string()).await;
        format!(
            "{head}\n\n\
             ⚠️ MORE DATA AVAILABLE — Truncated: {total_lines} lines total, \
             {omitted} lines omitted ({orig} → {new} chars).\n\
             To get the complete output, call: \
             ssh_output_fetch(output_id=\"{output_id}\", offset=0, limit=50000){tip}\
             \n\n{tail}",
            orig = output.len(),
            new = head.len() + tail.len(),
        )
    } else {
        format!(
            "{head}\n\n--- [truncated: {total_lines} lines total, \
             {omitted} lines omitted, {orig} → {new} chars] ---{tip}\n\n{tail}",
            orig = output.len(),
            new = head.len() + tail.len(),
        )
    }
}

/// Take lines from the start of the string, up to `budget` bytes.
fn take_head_lines(s: &str, budget: usize) -> &str {
    if budget >= s.len() {
        return s;
    }

    // Find the nearest char boundary at or before budget (UTF-8 safe)
    let safe_budget = floor_char_boundary(s, budget);

    // Find the last newline before the budget
    s[..safe_budget]
        .rfind('\n')
        .map_or(&s[..safe_budget], |pos| &s[..pos])
}

/// Take lines from the end of the string, up to `budget` bytes.
fn take_tail_lines(s: &str, budget: usize) -> &str {
    if budget >= s.len() {
        return s;
    }

    let start = s.len().saturating_sub(budget);

    // Find the nearest char boundary at or after start (UTF-8 safe)
    let safe_start = ceil_char_boundary(s, start);

    // Find the first newline after the start position
    s[safe_start..]
        .find('\n')
        .map_or(&s[safe_start..], |pos| &s[safe_start + pos + 1..])
}

/// Find the largest index that is both <= `index` and a valid char boundary.
/// This is a UTF-8 safe version of slicing.
///
/// UTF-8 encodes a char in at most 4 bytes, so a boundary always exists in
/// the 4-position window ending at `index` — the scan is bounded by
/// construction (no open loop that a mutation could turn infinite).
#[doc(hidden)]
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    let index = index.min(s.len());
    (index.saturating_sub(3)..=index)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0)
}

/// Find the smallest index that is both >= `index` and a valid char boundary.
/// This is a UTF-8 safe version of slicing.
#[doc(hidden)]
pub fn ceil_char_boundary(s: &str, index: usize) -> usize {
    let index = index.min(s.len());
    (index..=index.saturating_add(3).min(s.len()))
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    #[test]
    fn test_short_output_not_truncated() {
        let output = "Hello, world!\nLine 2\nLine 3\n";
        let result = truncate_output(output, 1000);
        assert_eq!(result, output);
    }

    #[test]
    fn test_disabled_with_zero() {
        let output = "a".repeat(50_000);
        let result = truncate_output(&output, 0);
        assert_eq!(result, output);
    }

    #[test]
    fn test_truncation_preserves_head_and_tail() {
        // Build a large output with identifiable head and tail
        let mut output = String::new();
        output.push_str("=== START ===\n");
        for i in 0..100 {
            let _ = writeln!(output, "Middle line {i}: some verbose log output here");
        }
        output.push_str("=== END: ALL TESTS PASSED ===\n");

        let result = truncate_output(&output, 500);

        // Head should be preserved
        assert!(result.contains("=== START ==="));
        // Tail should be preserved
        assert!(result.contains("=== END: ALL TESTS PASSED ==="));
        // Truncation message should be present
        assert!(result.contains("[truncated:"));
        assert!(result.contains("lines omitted"));
        // Result should be within budget (plus truncation message overhead)
        assert!(result.len() < 700); // 500 + message overhead
    }

    #[test]
    fn test_truncation_cuts_at_line_boundaries() {
        let mut output = String::new();
        for i in 0..50 {
            let _ = writeln!(output, "Line {i}");
        }

        let result = truncate_output(&output, 100);

        // Should not cut in the middle of "Line XX"
        for line in result.lines() {
            if line.starts_with("Line") {
                assert!(line.starts_with("Line "));
            }
        }
    }

    #[test]
    fn test_exact_boundary() {
        let output = "exactly at limit";
        let result = truncate_output(output, output.len());
        assert_eq!(result, output);
    }

    #[test]
    fn test_truncation_message_format() {
        let mut output = String::new();
        for i in 0..100 {
            let _ = writeln!(output, "Line {i}");
        }

        let result = truncate_output(&output, 200);

        // Check the truncation message contains useful info
        assert!(result.contains("lines total"));
        assert!(result.contains("lines omitted"));
        assert!(result.contains("chars]"));
    }

    #[test]
    fn test_tail_gets_more_budget_than_head() {
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i:03}");
        }

        let result = truncate_output(&output, 400);

        // Count lines from tail vs head
        let parts: Vec<&str> = result.split("[truncated:").collect();
        assert_eq!(parts.len(), 2);

        let head_part = parts[0];
        let tail_part = parts[1].split("---\n\n").last().unwrap_or("");

        // Tail should be larger than head (80% vs 20%)
        assert!(tail_part.len() > head_part.len());
    }

    #[test]
    fn test_empty_output() {
        let result = truncate_output("", 100);
        assert_eq!(result, "");
    }

    #[test]
    fn test_single_line_no_newline() {
        let output = "a".repeat(100);
        let result = truncate_output(&output, 50);

        // Should still truncate even without newlines
        assert!(result.contains("[truncated:"));
    }

    // ============== Unicode Tests ==============

    #[test]
    fn test_unicode_content_preserved() {
        let output = "日本語テスト\n中文测试\nКириллица\nÉmoji: 🎉🚀\n";
        let result = truncate_output(output, 1000);
        assert_eq!(result, output);
    }

    #[test]
    fn test_unicode_truncation_safe() {
        // Build output with unicode characters
        let mut output = String::new();
        output.push_str("=== 开始 ===\n");
        for i in 0..50 {
            let _ = writeln!(output, "行 {i}: これはテストです 🎉");
        }
        output.push_str("=== 終了 ===\n");

        let result = truncate_output(&output, 500);

        // Should contain head and tail
        assert!(result.contains("开始"));
        assert!(result.contains("終了"));
        assert!(result.contains("[truncated:"));

        // Result should be valid UTF-8 (no panic)
        assert!(result.is_ascii() || !result.is_empty());
    }

    #[test]
    fn test_emoji_content() {
        let output = "🎉".repeat(100) + "\n" + &"🚀".repeat(100);
        let result = truncate_output(&output, 200);

        // Should handle emojis (4 bytes each)
        assert!(result.contains("[truncated:") || result.len() <= 200);
    }

    #[test]
    fn test_mixed_width_characters() {
        let mut output = String::new();
        for i in 0..50 {
            let _ = writeln!(output, "Line {i}: Hello 世界 مرحبا שלום");
        }

        let result = truncate_output(&output, 500);
        assert!(result.contains("[truncated:") || output.len() <= 500);
    }

    // ============== CRLF Tests ==============

    #[test]
    fn test_crlf_line_endings() {
        let output = "Line 1\r\nLine 2\r\nLine 3\r\n";
        let result = truncate_output(output, 1000);
        assert_eq!(result, output);
    }

    #[test]
    fn test_mixed_line_endings() {
        let output = "Unix line\nWindows line\r\nMac classic line\rAnother line\n";
        let result = truncate_output(output, 1000);
        assert_eq!(result, output);
    }

    #[test]
    fn test_crlf_truncation() {
        let mut output = String::new();
        for i in 0..100 {
            let _ = write!(output, "Line {i}\r\n");
        }

        let result = truncate_output(&output, 200);
        assert!(result.contains("[truncated:"));
    }

    // ============== Edge Case Tests ==============

    #[test]
    fn test_very_small_budget() {
        let output = "This is a test\nWith multiple lines\nAnd some content\n";
        let result = truncate_output(output, 20);

        // Should handle very small budgets
        assert!(result.contains("[truncated:"));
    }

    #[test]
    fn test_budget_smaller_than_single_line() {
        let output = "This is a very long line that exceeds the budget";
        let result = truncate_output(output, 10);

        // Should still work without panicking
        assert!(result.contains("[truncated:"));
    }

    #[test]
    fn test_only_newlines() {
        let output = "\n\n\n\n\n\n\n\n\n\n";
        let result = truncate_output(output, 5);

        // Should handle newline-only content
        assert!(result.contains("[truncated:") || result == output);
    }

    #[test]
    fn test_trailing_newlines_preserved() {
        let output = "Content\n\n\n";
        let result = truncate_output(output, 1000);
        assert_eq!(result, output);
    }

    #[test]
    fn test_no_trailing_newline() {
        let mut output = String::new();
        for i in 0..50 {
            if i < 49 {
                let _ = writeln!(output, "Line {i}");
            } else {
                let _ = write!(output, "Line {i}"); // No trailing newline
            }
        }

        let result = truncate_output(&output, 200);
        // Should work without trailing newline
        assert!(result.contains("[truncated:"));
    }

    #[test]
    fn test_one_character_budget() {
        let output = "test";
        let result = truncate_output(output, 1);

        // Should handle minimum budget
        assert!(result.contains("[truncated:"));
    }

    #[test]
    fn test_budget_equals_output_minus_one() {
        let output = "test";
        let result = truncate_output(output, output.len() - 1);

        // Should truncate when budget is one less than output
        assert!(result.contains("[truncated:"));
    }

    #[test]
    fn test_repeated_truncation_idempotent_on_short() {
        let output = "Short output";
        let result1 = truncate_output(output, 1000);
        let result2 = truncate_output(&result1, 1000);

        assert_eq!(result1, result2);
    }

    // ============== Performance-related Tests ==============

    #[test]
    fn test_large_output_performance() {
        // 1 MB of text
        let line = "This is a test line with some content to fill space.\n";
        let mut output = String::new();
        while output.len() < 1_000_000 {
            output.push_str(line);
        }

        let result = truncate_output(&output, 10_000);

        assert!(result.contains("[truncated:"));
        assert!(result.len() < 15_000); // Should be close to budget + overhead
    }

    #[test]
    fn test_many_short_lines() {
        let mut output = String::new();
        for i in 0..10_000 {
            let _ = writeln!(output, "{i}");
        }

        let result = truncate_output(&output, 1000);

        assert!(result.contains("[truncated:"));
        assert!(result.contains("10000 lines total"));
    }

    // ============== truncate_output_with_cache Tests ==============

    #[tokio::test]
    async fn test_with_cache_stores_full_output() {
        let cache = OutputCache::new(300, 100);
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i}: verbose log data here");
        }

        let result = truncate_output_with_cache(&output, 500, Some(&cache), None).await;

        // Should include cache hint
        assert!(result.contains("ssh_output_fetch"));
        assert!(result.contains("output_id="));

        // Cache should have one entry
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn test_with_cache_includes_output_id() {
        let cache = OutputCache::new(300, 100);
        let output = "x".repeat(1000);

        let result = truncate_output_with_cache(&output, 100, Some(&cache), None).await;

        assert!(result.contains("out-0000"));
    }

    #[tokio::test]
    async fn test_without_cache_no_hint() {
        let output = "x".repeat(1000);

        let result = truncate_output_with_cache(&output, 100, None, None).await;

        assert!(result.contains("[truncated:"));
        assert!(!result.contains("ssh_output_fetch"));
    }

    #[tokio::test]
    async fn test_no_truncation_no_cache_store() {
        let cache = OutputCache::new(300, 100);
        let output = "short output";

        let result = truncate_output_with_cache(output, 1000, Some(&cache), None).await;

        assert_eq!(result, output);
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_with_cache_zero_max_disables() {
        let cache = OutputCache::new(300, 100);
        let output = "x".repeat(1000);

        let result = truncate_output_with_cache(&output, 0, Some(&cache), None).await;

        assert_eq!(result, output);
        assert_eq!(cache.len().await, 0);
    }

    // ============== floor / ceil char-boundary tests ==============

    /// `floor_char_boundary` must walk *backwards* and terminate. Two
    /// arithmetic mutations on the loop body — `-= -> +=` and `-= -> /=`
    /// — survive coverage-only tests because the loop never enters
    /// when the index is already a boundary.
    /// Wrapping the call in a thread with a hard timeout catches both:
    /// `+=` returns the wrong value (the upper boundary), and `/=` is
    /// equivalent to `i /= 1 == i`, which spins forever.
    #[test]
    fn floor_char_boundary_walks_back_inside_multibyte() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        let _h = thread::spawn(move || {
            // "日" is 3 UTF-8 bytes; index 1 is inside the char.
            let result = floor_char_boundary("日", 1);
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_millis(500))
            .expect("floor_char_boundary must terminate within 500ms");
        assert_eq!(result, 0, "must walk BACK to byte 0, not forward");
    }

    #[test]
    fn floor_char_boundary_returns_index_when_already_boundary() {
        assert_eq!(floor_char_boundary("hello", 3), 3);
        assert_eq!(floor_char_boundary("日本", 3), 3);
    }

    #[test]
    fn floor_char_boundary_clamps_to_len() {
        assert_eq!(floor_char_boundary("abc", 100), 3);
    }

    /// Symmetric to the floor case: `ceil_char_boundary` must walk
    /// *forwards*. Mutations `+= -> -=` and `+= -> *=` produce wrong
    /// boundary or infinite loop respectively.
    #[test]
    fn ceil_char_boundary_walks_forward_inside_multibyte() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        let _h = thread::spawn(move || {
            let result = ceil_char_boundary("日", 1);
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_millis(500))
            .expect("ceil_char_boundary must terminate within 500ms");
        assert_eq!(
            result, 3,
            "must walk FORWARD to byte 3 (end of `日`), not back"
        );
    }

    #[test]
    fn ceil_char_boundary_returns_index_when_already_boundary() {
        assert_eq!(ceil_char_boundary("hello", 3), 3);
        assert_eq!(ceil_char_boundary("日本", 3), 3);
    }

    #[test]
    fn ceil_char_boundary_clamps_to_len() {
        assert_eq!(ceil_char_boundary("abc", 100), 3);
    }

    // ============== truncation message arithmetic invariants ==============

    /// `truncate_output` and `truncate_output_with_cache` build the
    /// message containing `"{orig} → {new} chars"`. Mutations that
    /// flip `head.len() + tail.len()` to `head.len() * tail.len()`
    /// produce a wildly wrong `new` figure for any non-zero head/tail.
    /// The exact `orig` value is taken from `output.len()` and pins
    /// the input arithmetic.
    #[test]
    fn truncation_message_includes_exact_orig_size() {
        let output: String = "x".repeat(2_000);
        let result = truncate_output(&output, 500);
        assert!(
            result.contains("2000 →"),
            "truncation message must report orig size 2000, got: {result}"
        );
    }

    /// `head_budget = max_chars / 5; tail_budget = max_chars -
    /// head_budget`. Mutations `/ -> %`, `- -> +`, `- -> /` change
    /// the head/tail split dramatically:
    ///
    /// - `/ -> %`: `head_budget = max % 5` (0..4) → near-zero head.
    /// - `- -> +`: `tail_budget = max + head` (1.2× max) → tail grows.
    /// - `- -> /`: `tail_budget = max / head` (small) → tail shrinks.
    ///
    /// The 80/20 ratio (tail > head by ~4×) is the observable
    /// invariant that fails under all three.
    #[test]
    fn truncation_split_keeps_tail_about_four_times_head() {
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i:03}");
        }
        let result = truncate_output(&output, 500);
        let parts: Vec<&str> = result.split("[truncated:").collect();
        assert_eq!(parts.len(), 2, "message present");

        let head_part = parts[0];
        let tail_part = parts[1].split("---\n\n").last().unwrap_or("");

        // Tail should be ~4× the head (80/20 split). Mutations skew
        // this ratio sharply.
        assert!(
            tail_part.len() >= head_part.len() * 2,
            "tail must be at least 2× head — got head={} tail={}",
            head_part.len(),
            tail_part.len()
        );
        assert!(
            !head_part.is_empty(),
            "head must be non-empty (mutation `/` -> `%` would zero it)"
        );
    }

    /// `omitted = total_lines.saturating_sub(head_lines + tail_lines)`.
    /// Mutation `+ -> *` makes the subtraction over-count when both
    /// counts are >1 (typical case), driving `omitted` to 0.
    #[test]
    fn truncation_omitted_count_is_total_minus_kept() {
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i:03}");
        }
        let result = truncate_output(&output, 500);
        let total_lines = output.lines().count();

        // Extract the "X lines omitted" number.
        let after = result
            .split("lines total, ")
            .nth(1)
            .expect("`lines total,` marker present");
        let omitted_str = after
            .split(' ')
            .next()
            .expect("number before ` lines omitted`");
        let omitted: usize = omitted_str.parse().expect("omitted is numeric");
        assert!(
            omitted > 0 && omitted < total_lines,
            "omitted must be strictly between 0 and total ({total_lines}) — got {omitted}"
        );
    }

    /// `take_tail_lines` advances past the first newline by adding 1
    /// to its position. Mutation `+ -> *` (`pos * 1 == pos`) leaves
    /// the slice starting *at* the newline, so the tail begins with
    /// `\n`. The original slice is one byte further in.
    #[test]
    fn take_tail_lines_does_not_keep_leading_newline() {
        let s = "AAA\nBBB\nCCC\n";
        let tail = take_tail_lines(s, 8);
        assert!(
            !tail.starts_with('\n'),
            "tail must skip past the boundary newline — got {tail:?}"
        );
        assert_eq!(tail, "CCC\n");
    }

    /// Async cache-version twin of the head/tail split ratio
    /// invariant. Covers `head_budget = max / 5; tail_budget =
    /// max - head_budget` arithmetic in `truncate_output_with_cache`
    /// (lines 65-66): mutations `/ -> %`, `- -> +`, `- -> /` skew
    /// the 80/20 split.
    /// Tight numeric bounds — each kills one specific mutation:
    /// * `head ≥ 50` kills `/ -> %` (max % 5 ∈ {0..4} → head=0).
    /// * `tail ≤ 500` kills `- -> +` (tail = max + head ≈ 600).
    /// * `tail ≥ 100` kills `- -> /` (tail = max / head = 5).
    #[tokio::test]
    async fn truncate_with_cache_split_keeps_tail_about_four_times_head() {
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i:03}");
        }
        let result = truncate_output_with_cache(&output, 500, None, None).await;
        let head_only = result
            .split("\n\n--- [truncated:")
            .next()
            .expect("`---` marker present after head");
        let parts: Vec<&str> = result.split("[truncated:").collect();
        let tail_only = parts[1].split("---\n\n").last().unwrap_or("");

        assert!(
            head_only.len() >= 50,
            "head must be ≥ 50 bytes (kills `/` -> `%`) — got {}",
            head_only.len()
        );
        assert!(
            tail_only.len() <= 500,
            "tail must be ≤ max_chars=500 (kills `- -> +`) — got {}",
            tail_only.len()
        );
        assert!(
            tail_only.len() >= 100,
            "tail must be ≥ 100 bytes (kills `- -> /`) — got {}",
            tail_only.len()
        );
    }

    /// Async cache-version twin of the omitted-count invariant.
    /// Covers `total.saturating_sub(head + tail)` (line 74):
    /// mutation `+ -> *` saturates `omitted` to 0.
    #[tokio::test]
    async fn truncate_with_cache_omitted_count_is_total_minus_kept() {
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i:03}");
        }
        let result = truncate_output_with_cache(&output, 500, None, None).await;
        let total_lines = output.lines().count();
        let after = result
            .split("lines total, ")
            .nth(1)
            .expect("`lines total,` marker present");
        let omitted_str = after
            .split(' ')
            .next()
            .expect("number before ` lines omitted`");
        let omitted: usize = omitted_str.parse().expect("omitted is numeric");
        assert!(
            omitted > 0 && omitted < total_lines,
            "omitted must be strictly between 0 and total ({total_lines}) — got {omitted}"
        );
    }

    #[tokio::test]
    async fn test_with_cache_directive_message() {
        let cache = OutputCache::new(300, 100);
        let mut output = String::new();
        for i in 0..200 {
            let _ = writeln!(output, "Line {i}: verbose log data here");
        }

        let result = truncate_output_with_cache(&output, 500, Some(&cache), None).await;

        // Directive markers that help LLMs paginate
        assert!(result.contains("MORE DATA AVAILABLE"));
        assert!(result.contains("To get the complete output, call:"));
        assert!(result.contains("offset=0, limit=50000"));
    }

    // ============== reduction-tip Tests ==============

    #[tokio::test]
    async fn test_with_cache_appends_reduction_tip() {
        let cache = OutputCache::new(300, 100);
        let output = "x".repeat(1000);

        let result = truncate_output_with_cache(
            &output,
            100,
            Some(&cache),
            Some("re-run with jq_filter='.field'"),
        )
        .await;

        assert!(result.contains("💡 Better: re-run with jq_filter='.field'."));
        // Pagination hint must still be present alongside the tip.
        assert!(result.contains("ssh_output_fetch"));
    }

    #[tokio::test]
    async fn test_without_cache_appends_reduction_tip() {
        let output = "x".repeat(1000);

        let result =
            truncate_output_with_cache(&output, 100, None, Some("use columns=[...]")).await;

        assert!(result.contains("💡 Better: use columns=[...]."));
    }

    #[tokio::test]
    async fn test_no_tip_when_none() {
        let cache = OutputCache::new(300, 100);
        let output = "x".repeat(1000);

        let result = truncate_output_with_cache(&output, 100, Some(&cache), None).await;

        assert!(!result.contains("💡"));
    }

    #[tokio::test]
    async fn test_no_tip_when_not_truncated() {
        let result =
            truncate_output_with_cache("short", 1000, None, Some("use columns=[...]")).await;

        assert_eq!(result, "short");
    }

    proptest::proptest! {
        /// Characterization of the char-boundary helpers: results are always
        /// valid boundaries bracketing the requested index.
        #[test]
        fn char_boundary_helpers_invariants(s in "\\PC*", idx in 0usize..64) {
            let f = floor_char_boundary(&s, idx);
            let c = ceil_char_boundary(&s, idx);
            proptest::prop_assert!(s.is_char_boundary(f));
            proptest::prop_assert!(s.is_char_boundary(c));
            proptest::prop_assert!(f <= idx.min(s.len()));
            proptest::prop_assert!(c >= idx.min(s.len()));
            proptest::prop_assert!(f <= c);
        }
    }
}
