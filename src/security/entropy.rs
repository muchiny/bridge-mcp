//! Shannon entropy-based secret detection
//!
//! Detects high-entropy strings that are likely secrets (API keys, tokens, passwords)
//! even when they don't match any known pattern. Complements the regex-based sanitizer.

use std::collections::HashMap;

/// Configuration for entropy-based detection
#[derive(Debug, Clone)]
pub struct EntropyDetector {
    /// Minimum Shannon entropy threshold (bits per character)
    threshold: f64,
    /// Optional separate threshold for hexadecimal tokens.
    ///
    /// Hex maxes out at log2(16) = 4.0 bits/char, so the main `threshold`
    /// (default 4.5) can mathematically never flag a hex secret. `None`
    /// (default) skips bare-hex analysis entirely — keyword-anchored hex
    /// values are already covered by the regex tiers, and bare hex is FP
    /// territory (checksums, git SHAs).
    hex_threshold: Option<f64>,
    /// Minimum token length to analyze
    min_length: usize,
    /// Known safe strings that should not be flagged
    whitelist: Vec<String>,
    /// Whether detection is enabled
    enabled: bool,
}

/// Replacement tag for high-entropy tokens
const ENTROPY_REDACTED: &str = "[HIGH_ENTROPY_REDACTED]";

impl EntropyDetector {
    /// Create a new entropy detector with the given configuration
    #[must_use]
    pub fn new(threshold: f64, min_length: usize, whitelist: Vec<String>, enabled: bool) -> Self {
        Self {
            threshold,
            hex_threshold: None,
            min_length,
            whitelist,
            enabled,
        }
    }

    /// Create a disabled detector (pass-through)
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            threshold: 0.0,
            hex_threshold: None,
            min_length: 0,
            whitelist: Vec::new(),
            enabled: false,
        }
    }

    /// Enable hex-charset detection with its own threshold (e.g. 3.1).
    #[must_use]
    pub fn with_hex_threshold(mut self, hex_threshold: Option<f64>) -> Self {
        self.hex_threshold = hex_threshold;
        self
    }

    /// Check if entropy detection is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Calculate Shannon entropy of a string (bits per character)
    ///
    /// Returns a value between 0.0 (all same character) and ~6.5 (random base64).
    /// Typical thresholds:
    /// - English text: 3.5-4.5 bits
    /// - Hex secrets: 3.7-4.0 bits
    /// - Base64 secrets: 5.0-6.0 bits
    /// - Random bytes (base64): ~5.95 bits
    #[must_use]
    #[expect(clippy::cast_precision_loss)]
    pub fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let len = s.len() as f64;
        let mut freq: HashMap<u8, u32> = HashMap::new();

        for &byte in s.as_bytes() {
            *freq.entry(byte).or_insert(0) += 1;
        }

        freq.values().fold(0.0_f64, |entropy, &count| {
            let p = f64::from(count) / len;
            entropy - p * p.log2()
        })
    }

    /// Scan text and replace high-entropy tokens with redaction markers
    ///
    /// Tokens are extracted by splitting on whitespace, `=`, `:`, `"`, `'`, and newlines.
    /// Each token is checked for entropy and length thresholds.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        if !self.enabled || text.len() < self.min_length {
            return text.to_string();
        }

        let mut result = text.to_string();
        let tokens = Self::extract_tokens(text);

        // Sort tokens by length descending to replace longest first
        // (avoids partial replacement issues)
        let mut tokens_sorted: Vec<&str> = tokens.collect();
        tokens_sorted.sort_by_key(|t| std::cmp::Reverse(t.len()));

        for token in tokens_sorted {
            if token.len() < self.min_length {
                continue;
            }

            // Skip whitelisted tokens
            if self.whitelist.iter().any(|w| w == token) {
                continue;
            }

            // Skip tokens that look like paths, URLs, or common patterns
            if Self::is_safe_token(token) {
                continue;
            }

            let threshold = if Self::is_hex_token(token) {
                // 40-char hex = git SHA-1: structural false positive.
                match self.hex_threshold {
                    Some(t) if token.len() != 40 => t,
                    _ => continue,
                }
            } else {
                self.threshold
            };

            let entropy = Self::shannon_entropy(token);
            if entropy >= threshold {
                result = result.replace(token, ENTROPY_REDACTED);
            }
        }

        result
    }

    /// Extract potential secret tokens from text
    fn extract_tokens(text: &str) -> impl Iterator<Item = &str> {
        text.split(|c: char| {
            c.is_whitespace() || c == '=' || c == ':' || c == '"' || c == '\'' || c == ','
        })
        .filter(|s| !s.is_empty())
    }

    /// Check if a token is a safe non-secret (path, URL, command, etc.)
    fn is_safe_token(token: &str) -> bool {
        // File paths
        if token.starts_with('/') || token.starts_with("./") || token.starts_with("~/") {
            return true;
        }

        // URLs (http/https)
        if token.starts_with("http://") || token.starts_with("https://") {
            return true;
        }

        // Hex color codes
        if token.starts_with('#') && token.len() <= 7 {
            return true;
        }

        // Version strings (v1.2.3, 1.2.3-beta, 12.34.56-beta-rc1)
        if token
            .trim_start_matches('v')
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && token
                .trim_start_matches('v')
                .starts_with(|c: char| c.is_ascii_digit())
            && token.contains('.')
        {
            return true;
        }

        // All lowercase with hyphens (likely a package name or command)
        if token.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            return true;
        }

        // All uppercase with underscores (likely an env var name, not a value)
        if token.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            return true;
        }

        // UUIDs (8-4-4-4-12 hex format) — common, not secrets
        if token.len() == 36
            && token.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            && token.chars().filter(|&c| c == '-').count() == 4
        {
            return true;
        }

        false
    }

    /// Hex-only token containing both digits and letters (pure digits or
    /// pure letters are not hex-encoded material).
    fn is_hex_token(token: &str) -> bool {
        token.chars().all(|c| c.is_ascii_hexdigit())
            && token.chars().any(|c| c.is_ascii_digit())
            && token.chars().any(|c| c.is_ascii_alphabetic())
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            threshold: 4.5,
            hex_threshold: None,
            min_length: 16,
            whitelist: Vec::new(),
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert!(EntropyDetector::shannon_entropy("").abs() < f64::EPSILON);
    }

    #[test]
    fn test_shannon_entropy_single_char() {
        assert!(EntropyDetector::shannon_entropy("aaaa").abs() < f64::EPSILON);
    }

    #[test]
    fn test_shannon_entropy_low_for_text() {
        let entropy = EntropyDetector::shannon_entropy("hello world this is normal text");
        assert!(
            entropy < 4.5,
            "English text entropy should be below 4.5, got {entropy}"
        );
    }

    #[test]
    fn test_shannon_entropy_high_for_random() {
        // Simulated base64 API key
        let entropy = EntropyDetector::shannon_entropy("a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv");
        assert!(
            entropy >= 4.0,
            "Random-looking string should have high entropy, got {entropy}"
        );
    }

    #[test]
    fn test_redact_high_entropy_token() {
        let detector = EntropyDetector::new(4.0, 16, Vec::new(), true);
        let input = "API_KEY=a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv";
        let result = detector.redact(input);
        assert!(
            result.contains(ENTROPY_REDACTED),
            "High entropy token should be redacted: {result}"
        );
        assert!(
            !result.contains("a8Kz9xQ2m4Fp7Lw1"),
            "Original token should not appear"
        );
    }

    #[test]
    fn test_skip_safe_paths() {
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);
        let input = "/usr/local/bin/some-complex-binary";
        let result = detector.redact(input);
        assert_eq!(result, input, "File paths should not be redacted");
    }

    #[test]
    fn test_skip_urls() {
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);
        let input = "https://api.example.com/v2/complex-endpoint";
        let result = detector.redact(input);
        assert_eq!(result, input, "URLs should not be redacted");
    }

    #[test]
    fn test_skip_uuids() {
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);
        let input = "id=550e8400-e29b-41d4-a716-446655440000";
        let result = detector.redact(input);
        assert!(
            result.contains("550e8400-e29b-41d4-a716-446655440000"),
            "UUIDs should not be redacted"
        );
    }

    #[test]
    fn test_whitelist() {
        let detector = EntropyDetector::new(
            4.0,
            16,
            vec!["a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv".to_string()],
            true,
        );
        let input = "KEY=a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv";
        let result = detector.redact(input);
        assert!(
            result.contains("a8Kz9xQ2m4Fp7Lw1"),
            "Whitelisted tokens should not be redacted"
        );
    }

    #[test]
    fn test_disabled_detector() {
        let detector = EntropyDetector::disabled();
        let input = "SECRET=a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv";
        let result = detector.redact(input);
        assert_eq!(result, input, "Disabled detector should pass through");
    }

    #[test]
    fn test_short_tokens_skipped() {
        let detector = EntropyDetector::new(4.0, 16, Vec::new(), true);
        let input = "short=abc123";
        let result = detector.redact(input);
        assert_eq!(result, input, "Short tokens should be skipped");
    }

    #[test]
    fn test_skip_env_var_names() {
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);
        let input = "MY_SECRET_KEY_NAME";
        let result = detector.redact(input);
        assert_eq!(
            result, input,
            "All-uppercase env var names should not be redacted"
        );
    }

    #[test]
    fn test_skip_version_strings() {
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);
        let input = "v12.34.56-beta-rc1";
        let result = detector.redact(input);
        assert_eq!(result, input, "Version strings should not be redacted");
    }

    // ============== Tests to catch previously-missed mutations ==============

    #[test]
    fn test_is_enabled_true_when_enabled() {
        let detector = EntropyDetector::new(4.0, 16, Vec::new(), true);
        assert!(detector.is_enabled(), "Enabled detector should return true");
    }

    #[test]
    fn test_is_enabled_false_when_disabled() {
        let detector = EntropyDetector::disabled();
        assert!(
            !detector.is_enabled(),
            "Disabled detector should return false"
        );
    }

    #[test]
    fn test_redact_boundary_min_length_exact() {
        // Token exactly at min_length should be analyzed
        let detector = EntropyDetector::new(3.0, 8, Vec::new(), true);

        // High-entropy 8-char token (exactly at min_length)
        let input = "key=Xk9Z2mQ1";
        let _result_8 = detector.redact(input);
        // The token "Xk9Z2mQ1" is 8 chars — should be checked

        // Token of 7 chars (below min_length) — must be skipped
        let input_short = "key=Xk9Z2mQ";
        let result_7 = detector.redact(input_short);
        assert_eq!(
            result_7, input_short,
            "Token below min_length should not be redacted"
        );
    }

    #[test]
    fn test_redact_text_shorter_than_min_length_skipped() {
        let detector = EntropyDetector::new(4.0, 100, Vec::new(), true);
        // Entire text is shorter than min_length
        let input = "short text";
        let result = detector.redact(input);
        assert_eq!(
            result, input,
            "Text shorter than min_length should pass through"
        );
    }

    #[test]
    fn test_enabled_detector_redacts_but_disabled_does_not() {
        let enabled = EntropyDetector::new(4.0, 16, Vec::new(), true);
        let disabled = EntropyDetector::new(4.0, 16, Vec::new(), false);
        let input = "TOKEN=a8Kz9xQ2m4Fp7Lw1Bn3Yd5Rj6Gt0Hv";

        let result_enabled = enabled.redact(input);
        let result_disabled = disabled.redact(input);

        assert_ne!(
            result_enabled, input,
            "Enabled detector should redact high-entropy"
        );
        assert_eq!(
            result_disabled, input,
            "Disabled detector should not redact"
        );
    }

    // ============== Hex threshold (opt-in) tests ==============

    #[test]
    fn test_hex_secret_never_flagged_by_default() {
        // 64-char hex ≈ 3.9 bits/char — mathematically below the 4.5 default.
        let detector = EntropyDetector::default();
        let input =
            "token value 3f7a9c2e8b1d4f6a0c5e7b9d2f4a6c8e1b3d5f7a9c2e4b6d8f0a2c4e6b8d0f2a here";
        let result = detector.redact(input);
        assert_eq!(result, input, "hex detection must be opt-in (default off)");
    }

    #[test]
    fn test_hex_secret_flagged_when_hex_threshold_enabled() {
        let detector = EntropyDetector::default().with_hex_threshold(Some(3.1));
        let input = "leaked 3f7a9c2e8b1d4f6a0c5e7b9d2f4a6c8e1b3d5f7a9c2e4b6d8f0a2c4e6b8d0f2a here";
        let result = detector.redact(input);
        assert!(
            !result.contains("3f7a9c2e"),
            "hex secret must be redacted: {result}"
        );
        assert!(result.contains("[HIGH_ENTROPY_REDACTED]"));
    }

    #[test]
    fn test_git_sha1_skipped_even_with_hex_threshold() {
        // 40-char hex = git SHA-1 — structural false positive, always skipped.
        let detector = EntropyDetector::default().with_hex_threshold(Some(3.1));
        let sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let input = format!("commit {sha} (HEAD -> main)");
        let result = detector.redact(&input);
        assert!(result.contains(sha), "git SHA-1 wrongly redacted: {result}");
    }

    #[test]
    fn test_base64_detection_unchanged_by_hex_threshold() {
        let detector = EntropyDetector::default().with_hex_threshold(Some(3.1));
        // Mixed-case base64ish ≥24 chars with entropy ≥4.5 must still be caught
        // by the general threshold (regression guard).
        let input = "key Zx9!kQ2@pL5#mN8$vB3^cR7&wT1*yU4( end";
        let result = detector.redact(input);
        assert!(
            !result.contains("Zx9!kQ2"),
            "general detection regressed: {result}"
        );
    }
}
