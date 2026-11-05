//! Compliance Command Builder
//!
//! Builds compliance auditing CLI commands for remote execution via SSH.
//! Supports CIS benchmarks, DISA STIG checks, compliance scoring,
//! and structured compliance reporting.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate a CIS benchmark level (must be 1 or 2).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the level is not 1 or 2.
pub fn validate_cis_level(level: u8) -> Result<()> {
    if level != 1 && level != 2 {
        return Err(BridgeError::CommandDenied {
            reason: format!("CIS benchmark level must be 1 or 2, got {level}"),
        });
    }
    Ok(())
}

/// Validate a CIS benchmark category string.
///
/// A valid category should only contain alphanumeric characters,
/// hyphens, underscores, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the category is empty or contains
/// invalid characters.
pub fn validate_category(category: &str) -> Result<()> {
    if category.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Category cannot be empty".to_string(),
        });
    }
    if !category
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid category '{category}': must contain only alphanumeric characters, \
                 hyphens, underscores, or dots"
            ),
        });
    }
    Ok(())
}

/// Validate a STIG ID string (e.g., "V-12345" or "RHEL-07-010010").
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the STIG ID is empty, starts with
/// `-` (a STIG ID never does, and `grep` would read it as an option) or
/// contains invalid characters.
pub fn validate_stig_id(stig_id: &str) -> Result<()> {
    if stig_id.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "STIG ID cannot be empty".to_string(),
        });
    }
    super::shell::refuse_option_like("stig_id", stig_id)?;
    if !stig_id
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid STIG ID '{stig_id}': must contain only alphanumeric characters, \
                 hyphens, or underscores"
            ),
        });
    }
    Ok(())
}

/// Validate a report format string.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the format is not "text" or "json".
pub fn validate_report_format(format: &str) -> Result<()> {
    if format != "text" && format != "json" {
        return Err(BridgeError::CommandDenied {
            reason: format!("Report format must be 'text' or 'json', got '{format}'"),
        });
    }
    Ok(())
}

/// Builds compliance auditing commands for remote execution.
pub struct ComplianceCommandBuilder;

impl ComplianceCommandBuilder {
    /// Build a command to run CIS benchmark checks.
    ///
    /// Produces a compound command that checks:
    /// - File permissions on sensitive files
    /// - SSH hardening settings in `sshd_config`
    /// - Kernel security parameters via sysctl
    /// - Password policy configuration
    /// - Audit rules
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the level or category is invalid.
    pub fn build_cis_benchmark_command(
        level: Option<u8>,
        category: Option<&str>,
    ) -> Result<String> {
        if let Some(l) = level {
            validate_cis_level(l)?;
        }
        if let Some(c) = category {
            validate_category(c)?;
        }

        let effective_level = level.unwrap_or(1);

        let mut cmd = String::from("echo '=== CIS Benchmark Check ==='; ");

        // File permissions checks
        if category.is_none() || category == Some("filesystem") {
            let _ = write!(
                cmd,
                "echo '--- File Permissions ---'; \
                 stat -c '%a %U %G %n' /etc/passwd /etc/shadow /etc/group \
                 /etc/gshadow /etc/crontab 2>/dev/null; "
            );
        }

        // SSH hardening checks
        if category.is_none() || category == Some("ssh") {
            let _ = write!(
                cmd,
                "echo '--- SSH Hardening ---'; \
                 grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding|\
                 MaxAuthTries|Protocol|PermitEmptyPasswords|ClientAliveInterval|\
                 ClientAliveCountMax|LoginGraceTime|AllowTcpForwarding)' \
                 /etc/ssh/sshd_config 2>/dev/null; "
            );
        }

        // Kernel params checks
        if category.is_none() || category == Some("kernel") {
            let _ = write!(
                cmd,
                "echo '--- Kernel Parameters ---'; \
                 sysctl net.ipv4.ip_forward net.ipv4.conf.all.send_redirects \
                 net.ipv4.conf.all.accept_source_route \
                 net.ipv4.conf.all.accept_redirects \
                 net.ipv4.conf.all.log_martians \
                 net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null; "
            );
        }

        // Password policy checks
        if category.is_none() || category == Some("password") {
            let _ = write!(
                cmd,
                "echo '--- Password Policy ---'; \
                 grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' \
                 /etc/login.defs 2>/dev/null; "
            );
        }

        // Level 2 additional checks
        if effective_level >= 2 {
            let _ = write!(
                cmd,
                "echo '--- Audit Rules ---'; \
                 auditctl -l 2>/dev/null || echo 'auditctl not available'; \
                 echo '--- SELinux/AppArmor ---'; \
                 getenforce 2>/dev/null || aa-status --enabled 2>/dev/null \
                 || echo 'No MAC framework detected'; "
            );
        }

        let _ = write!(cmd, "echo '=== End CIS Benchmark ==='");
        Ok(cmd)
    }

    /// Build a command to check specific DISA STIG rules.
    ///
    /// When a specific STIG ID is given, checks that specific rule.
    /// Otherwise runs a general subset of common STIG checks.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the STIG ID is invalid.
    pub fn build_stig_check_command(stig_id: Option<&str>) -> Result<String> {
        if let Some(id) = stig_id {
            validate_stig_id(id)?;
        }

        let mut cmd = String::from("echo '=== DISA STIG Check ==='; ");

        if let Some(id) = stig_id {
            let escaped_id = shell_escape(id);
            // Each label is one quoted word, never an escaped id inside a
            // second pair of quotes.
            let checking = shell_escape(&format!("Checking STIG: {id}"));
            let header = shell_escape(&format!("--- STIG {id} ---"));
            let _ = write!(cmd, "printf '%s\\n' {checking}; ");
            // Run targeted checks based on STIG ID pattern: the id is the
            // pattern (`-e`), the directories come after `--`.
            let _ = write!(
                cmd,
                "printf '%s\\n' {header}; \
                 grep -r -F -e {escaped_id} -- /etc/audit/rules.d/ 2>/dev/null; \
                 grep -r -F -e {escaped_id} -- /etc/security/ 2>/dev/null; "
            );
        } else {
            // General STIG checks
            let _ = write!(
                cmd,
                "echo '--- Account Policy ---'; \
                 grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|INACTIVE|UMASK)' \
                 /etc/login.defs 2>/dev/null; \
                 echo '--- File Integrity ---'; \
                 rpm -Va --nomtime --nosize --nomd5 2>/dev/null | head -20 \
                 || dpkg --verify 2>/dev/null | head -20 \
                 || echo 'Package verification not available'; \
                 echo '--- Audit Configuration ---'; \
                 cat /etc/audit/auditd.conf 2>/dev/null | \
                 grep -E '^(max_log_file|space_left_action|action_mail_acct)' \
                 2>/dev/null; \
                 echo '--- Crypto Policy ---'; \
                 update-crypto-policies --show 2>/dev/null \
                 || echo 'crypto-policies not available'; "
            );
        }

        let _ = write!(cmd, "echo '=== End STIG Check ==='");
        Ok(cmd)
    }

    /// Build a command to calculate a compliance score.
    ///
    /// Runs a scored subset of checks and outputs pass/fail/total counts.
    #[must_use]
    pub fn build_compliance_score_command() -> String {
        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "echo '=== Compliance Score ==='; \
             pass=0; fail=0; total=0; \
             check() {{ total=$((total+1)); if eval \"$1\" >/dev/null 2>&1; then \
             pass=$((pass+1)); echo \"PASS: $2\"; else \
             fail=$((fail+1)); echo \"FAIL: $2\"; fi; }}; \
             check 'test $(stat -c %a /etc/passwd) = 644' 'passwd permissions'; \
             check 'test $(stat -c %a /etc/shadow) = 0 -o $(stat -c %a /etc/shadow) = 640' \
             'shadow permissions'; \
             check 'grep -q \"^PermitRootLogin no\" /etc/ssh/sshd_config' \
             'SSH root login disabled'; \
             check 'grep -q \"^PasswordAuthentication no\" /etc/ssh/sshd_config' \
             'SSH password auth disabled'; \
             check 'grep -q \"^PermitEmptyPasswords no\" /etc/ssh/sshd_config' \
             'SSH empty passwords disabled'; \
             check 'sysctl -n net.ipv4.ip_forward | grep -q 0' \
             'IP forwarding disabled'; \
             check 'sysctl -n net.ipv4.conf.all.send_redirects | grep -q 0' \
             'ICMP redirects disabled'; \
             check 'sysctl -n net.ipv4.conf.all.accept_source_route | grep -q 0' \
             'Source routing disabled'; \
             check 'test -f /etc/audit/auditd.conf' 'Audit daemon configured'; \
             check 'test -f /etc/security/pwquality.conf -o -f /etc/pam.d/common-password' \
             'Password quality configured'; \
             echo \"=== Score: $pass/$total (Failed: $fail) ===\""
        );
        cmd
    }

    /// Build a command to generate a full compliance report.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the format is invalid.
    pub fn build_compliance_report_command(format: Option<&str>) -> Result<String> {
        if let Some(f) = format {
            validate_report_format(f)?;
        }

        let fmt = format.unwrap_or("text");

        let mut cmd = String::new();

        if fmt == "json" {
            let _ = write!(
                cmd,
                "echo '{{'; \
                 echo '  \"compliance_report\": {{'; \
                 echo '    \"timestamp\": \"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\",'; \
                 echo '    \"hostname\": \"'$(hostname)'\",'; \
                 echo '    \"os\": \"'$(cat /etc/os-release 2>/dev/null | \
                 grep ^PRETTY_NAME | cut -d= -f2 | tr -d '\"')'\",'; \
                 echo '    \"checks\": ['; \
                 echo '      {{\"id\": \"file-perms\", \"result\": \"'$(test \
                 $(stat -c %a /etc/passwd) = 644 && echo pass || echo fail)'\"}},'; \
                 echo '      {{\"id\": \"ssh-root\", \"result\": \"'$(grep -q \
                 \"^PermitRootLogin no\" /etc/ssh/sshd_config 2>/dev/null && \
                 echo pass || echo fail)'\"}},'; \
                 echo '      {{\"id\": \"ip-forward\", \"result\": \"'$(sysctl -n \
                 net.ipv4.ip_forward 2>/dev/null | grep -q 0 && echo pass || \
                 echo fail)'\"}},'; \
                 echo '      {{\"id\": \"audit-conf\", \"result\": \"'$(test -f \
                 /etc/audit/auditd.conf && echo pass || echo fail)'\"}}'; \
                 echo '    ]'; \
                 echo '  }}'; \
                 echo '}}'"
            );
        } else {
            let _ = write!(
                cmd,
                "echo '=== Compliance Report ==='; \
                 echo \"Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)\"; \
                 echo \"Hostname: $(hostname)\"; \
                 echo \"OS: $(cat /etc/os-release 2>/dev/null | \
                 grep ^PRETTY_NAME | cut -d= -f2 | tr -d '\"')\"; \
                 echo ''; \
                 echo '--- File Permissions ---'; \
                 stat -c '%a %U %G %n' /etc/passwd /etc/shadow /etc/group \
                 /etc/gshadow 2>/dev/null; \
                 echo ''; \
                 echo '--- SSH Configuration ---'; \
                 grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding|\
                 MaxAuthTries|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null; \
                 echo ''; \
                 echo '--- Kernel Security ---'; \
                 sysctl net.ipv4.ip_forward net.ipv4.conf.all.send_redirects \
                 net.ipv4.conf.all.accept_source_route 2>/dev/null; \
                 echo ''; \
                 echo '--- Password Policy ---'; \
                 grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' \
                 /etc/login.defs 2>/dev/null; \
                 echo ''; \
                 echo '--- Audit Status ---'; \
                 systemctl is-active auditd 2>/dev/null || echo 'auditd not running'; \
                 echo ''; \
                 echo '=== End Compliance Report ==='"
            );
        }

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_cis_level ──────────────────────────────────

    #[test]
    fn test_validate_cis_level_valid() {
        assert!(validate_cis_level(1).is_ok());
        assert!(validate_cis_level(2).is_ok());
    }

    #[test]
    fn test_validate_cis_level_invalid() {
        assert!(validate_cis_level(0).is_err());
        assert!(validate_cis_level(3).is_err());
        assert!(validate_cis_level(255).is_err());
    }

    #[test]
    fn test_validate_cis_level_error_message() {
        let result = validate_cis_level(5);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains('5'));
                assert!(reason.contains("1 or 2"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_category ───────────────────────────────────

    #[test]
    fn test_validate_category_valid() {
        assert!(validate_category("filesystem").is_ok());
        assert!(validate_category("ssh").is_ok());
        assert!(validate_category("kernel").is_ok());
        assert!(validate_category("password").is_ok());
        assert!(validate_category("my-category").is_ok());
        assert!(validate_category("my_category").is_ok());
        assert!(validate_category("cat.sub").is_ok());
    }

    #[test]
    fn test_validate_category_empty() {
        assert!(validate_category("").is_err());
    }

    #[test]
    fn test_validate_category_invalid_chars() {
        assert!(validate_category("cat; rm -rf /").is_err());
        assert!(validate_category("$(whoami)").is_err());
        assert!(validate_category("cat`id`").is_err());
    }

    // ── validate_stig_id ────────────────────────────────────

    #[test]
    fn test_validate_stig_id_valid() {
        assert!(validate_stig_id("V-12345").is_ok());
        assert!(validate_stig_id("RHEL-07-010010").is_ok());
        assert!(validate_stig_id("SV-204399r603261").is_ok());
    }

    #[test]
    fn test_validate_stig_id_empty() {
        assert!(validate_stig_id("").is_err());
    }

    #[test]
    fn test_validate_stig_id_injection() {
        assert!(validate_stig_id("V-123; cat /etc/shadow").is_err());
        assert!(validate_stig_id("$(whoami)").is_err());
    }

    // ── validate_report_format ──────────────────────────────

    #[test]
    fn test_validate_report_format_valid() {
        assert!(validate_report_format("text").is_ok());
        assert!(validate_report_format("json").is_ok());
    }

    #[test]
    fn test_validate_report_format_invalid() {
        assert!(validate_report_format("xml").is_err());
        assert!(validate_report_format("html").is_err());
        assert!(validate_report_format("").is_err());
    }

    #[test]
    fn test_validate_report_format_error_message() {
        let result = validate_report_format("csv");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("csv"));
                assert!(reason.contains("text"));
                assert!(reason.contains("json"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_cis_benchmark_command ─────────────────────────

    #[test]
    fn test_cis_benchmark_default() {
        let cmd = ComplianceCommandBuilder::build_cis_benchmark_command(None, None).unwrap();
        assert!(cmd.contains("CIS Benchmark"));
        assert!(cmd.contains("File Permissions"));
        assert!(cmd.contains("SSH Hardening"));
        assert!(cmd.contains("Kernel Parameters"));
        assert!(cmd.contains("Password Policy"));
    }

    #[test]
    fn test_cis_benchmark_level1() {
        let cmd = ComplianceCommandBuilder::build_cis_benchmark_command(Some(1), None).unwrap();
        assert!(cmd.contains("CIS Benchmark"));
        // Level 1 should NOT include audit rules
        assert!(!cmd.contains("Audit Rules"));
    }

    #[test]
    fn test_cis_benchmark_level2() {
        let cmd = ComplianceCommandBuilder::build_cis_benchmark_command(Some(2), None).unwrap();
        assert!(cmd.contains("Audit Rules"));
        assert!(cmd.contains("SELinux"));
    }

    #[test]
    fn test_cis_benchmark_category_ssh() {
        let cmd = ComplianceCommandBuilder::build_cis_benchmark_command(None, Some("ssh")).unwrap();
        assert!(cmd.contains("SSH Hardening"));
        assert!(!cmd.contains("File Permissions"));
        assert!(!cmd.contains("Kernel Parameters"));
    }

    #[test]
    fn test_cis_benchmark_category_filesystem() {
        let cmd = ComplianceCommandBuilder::build_cis_benchmark_command(None, Some("filesystem"))
            .unwrap();
        assert!(cmd.contains("File Permissions"));
        assert!(!cmd.contains("SSH Hardening"));
    }

    #[test]
    fn test_cis_benchmark_invalid_level() {
        let result = ComplianceCommandBuilder::build_cis_benchmark_command(Some(3), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cis_benchmark_invalid_category() {
        let result =
            ComplianceCommandBuilder::build_cis_benchmark_command(None, Some("cat; rm -rf /"));
        assert!(result.is_err());
    }

    // ── build_stig_check_command ────────────────────────────

    #[test]
    fn test_stig_check_default() {
        let cmd = ComplianceCommandBuilder::build_stig_check_command(None).unwrap();
        assert!(cmd.contains("DISA STIG"));
        assert!(cmd.contains("Account Policy"));
        assert!(cmd.contains("File Integrity"));
        assert!(cmd.contains("Audit Configuration"));
        assert!(cmd.contains("Crypto Policy"));
    }

    #[test]
    fn test_stig_check_specific_id() {
        let cmd = ComplianceCommandBuilder::build_stig_check_command(Some("V-12345")).unwrap();
        assert!(cmd.contains("V-12345"));
        assert!(cmd.contains("DISA STIG"));
    }

    #[test]
    fn test_stig_id_cannot_be_a_grep_option() {
        for bad in ["-v", "-rv", "-e", "-L", "-"] {
            let err = ComplianceCommandBuilder::build_stig_check_command(Some(bad)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("'stig_id' must not start with '-'"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_stig_id_is_the_pattern_of_both_greps() {
        let cmd = ComplianceCommandBuilder::build_stig_check_command(Some("V-12345")).unwrap();
        assert!(
            cmd.contains("grep -r -F -e 'V-12345' -- /etc/audit/rules.d/"),
            "{cmd}"
        );
        assert!(
            cmd.contains("grep -r -F -e 'V-12345' -- /etc/security/"),
            "{cmd}"
        );
        assert!(
            cmd.contains("printf '%s\\n' 'Checking STIG: V-12345'"),
            "{cmd}"
        );
    }

    #[test]
    fn test_stig_check_invalid_id() {
        let result =
            ComplianceCommandBuilder::build_stig_check_command(Some("V-123; cat /etc/shadow"));
        assert!(result.is_err());
    }

    // ── build_compliance_score_command ───────────────────────

    #[test]
    fn test_compliance_score() {
        let cmd = ComplianceCommandBuilder::build_compliance_score_command();
        assert!(cmd.contains("Compliance Score"));
        assert!(cmd.contains("PASS"));
        assert!(cmd.contains("FAIL"));
        assert!(cmd.contains("passwd permissions"));
        assert!(cmd.contains("SSH root login"));
    }

    // ── build_compliance_report_command ──────────────────────

    #[test]
    fn test_compliance_report_text() {
        let cmd = ComplianceCommandBuilder::build_compliance_report_command(Some("text")).unwrap();
        assert!(cmd.contains("Compliance Report"));
        assert!(cmd.contains("File Permissions"));
        assert!(cmd.contains("SSH Configuration"));
        assert!(cmd.contains("Kernel Security"));
    }

    #[test]
    fn test_compliance_report_json() {
        let cmd = ComplianceCommandBuilder::build_compliance_report_command(Some("json")).unwrap();
        assert!(cmd.contains("compliance_report"));
        assert!(cmd.contains("hostname"));
        assert!(cmd.contains("checks"));
    }

    #[test]
    fn test_compliance_report_default() {
        let cmd = ComplianceCommandBuilder::build_compliance_report_command(None).unwrap();
        // Default is text format
        assert!(cmd.contains("Compliance Report"));
    }

    #[test]
    fn test_compliance_report_invalid_format() {
        let result = ComplianceCommandBuilder::build_compliance_report_command(Some("xml"));
        assert!(result.is_err());
    }

    // ── Shell injection prevention ──────────────────────────

    #[test]
    fn test_stig_id_escaped() {
        let cmd = ComplianceCommandBuilder::build_stig_check_command(Some("V-12345")).unwrap();
        assert!(cmd.contains("'V-12345'"));
    }
}
