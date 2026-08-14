//! Diagnostics Command Builder
//!
//! Builds comprehensive diagnostic commands that collect multiple
//! system metrics in a single SSH call, avoiding sequential round-trips.

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds diagnostic commands for remote system analysis.
pub struct DiagnosticsCommandBuilder;

impl DiagnosticsCommandBuilder {
    /// Build a comprehensive host diagnostic command.
    ///
    /// Collects: uptime, CPU, memory, disk, top processes, failed services,
    /// recent errors, OOM kills, and network listeners in a single compound command.
    #[must_use]
    pub fn build_diagnose_command() -> String {
        [
            r#"echo "=== UPTIME ===""#,
            "uptime",
            r#"echo "=== MEMORY ===""#,
            "free -m",
            r#"echo "=== DISK ===""#,
            "df -h --output=target,pcent,avail,size 2>/dev/null || df -h",
            r#"echo "=== LOAD ===""#,
            "cat /proc/loadavg 2>/dev/null || echo 'N/A'",
            r#"echo "=== TOP PROCESSES (CPU) ===""#,
            "ps aux --sort=-%cpu 2>/dev/null | head -11 || ps aux | head -11",
            r#"echo "=== TOP PROCESSES (MEM) ===""#,
            "ps aux --sort=-%mem 2>/dev/null | head -6 || true",
            r#"echo "=== FAILED SERVICES ===""#,
            "systemctl --failed --no-pager 2>/dev/null || echo 'systemctl not available'",
            r#"echo "=== RECENT ERRORS (1h) ===""#,
            "journalctl -p err --since '1 hour ago' --no-pager -n 30 2>/dev/null || dmesg | tail -20",
            r#"echo "=== OOM KILLS ===""#,
            "dmesg 2>/dev/null | grep -i 'oom\\|kill' | tail -10 || echo 'none detected'",
            r#"echo "=== NETWORK LISTENERS ===""#,
            "ss -tunapl 2>/dev/null | head -25 || netstat -tunapl 2>/dev/null | head -25",
        ]
        .join(" && ")
    }

    /// Build an incident triage command tailored to a specific symptom.
    ///
    /// Adapts the diagnostic commands based on the reported issue type.
    #[must_use]
    pub fn build_triage_command(symptom: &str, since: &str) -> String {
        // Both parameters are free-form request input. `symptom` used to land
        // inside a double-quoted `echo`, where command substitution is live
        // with no breakout needed; `since` sat inside single quotes, one `'`
        // away from a breakout. `echo` joins its arguments with a single
        // space, so the rendered banner is unchanged.
        let escaped_symptom = shell_escape(symptom);
        let since = shell_escape(since);
        let base = format!(
            r#"echo "=== TRIAGE:" {escaped_symptom} "===" && echo "=== UPTIME ===" && uptime && echo "=== MEMORY ===" && free -m"#
        );

        let specific = match symptom {
            "slow" | "performance" => format!(
                r#"echo "=== CPU LOAD ===" && cat /proc/loadavg && \
                echo "=== TOP CPU ===" && ps aux --sort=-%cpu | head -11 && \
                echo "=== IO WAIT ===" && iostat -x 1 2 2>/dev/null | tail -20 || true && \
                echo "=== DISK LATENCY ===" && iostat 2>/dev/null | head -10 || true && \
                echo "=== RECENT SLOW QUERIES ===" && journalctl --since {since} -p warning --no-pager -n 20 2>/dev/null || true"#
            ),
            "crash" | "restart" => format!(
                r#"echo "=== RECENT BOOTS ===" && last reboot | head -5 && \
                echo "=== CORE DUMPS ===" && coredumpctl list 2>/dev/null | tail -10 || ls /var/crash/ 2>/dev/null || echo 'none' && \
                echo "=== FAILED SERVICES ===" && systemctl --failed --no-pager 2>/dev/null || true && \
                echo "=== KERNEL PANICS ===" && journalctl -k --since {since} -p err --no-pager -n 20 2>/dev/null || dmesg | grep -i panic | tail -10"#
            ),
            "oom" | "memory" => format!(
                r#"echo "=== MEMORY DETAIL ===" && cat /proc/meminfo | head -20 && \
                echo "=== TOP MEM ===" && ps aux --sort=-%mem | head -11 && \
                echo "=== OOM KILLS ===" && dmesg | grep -i 'oom\|kill' | tail -20 && \
                echo "=== SWAP ===" && swapon --show 2>/dev/null || cat /proc/swaps && \
                echo "=== RECENT OOM LOGS ===" && journalctl --since {since} -g 'oom|killed' --no-pager -n 20 2>/dev/null || true"#
            ),
            "disk" | "storage" => format!(
                r#"echo "=== DISK USAGE ===" && df -h && \
                echo "=== INODE USAGE ===" && df -i | grep -v '^$' && \
                echo "=== LARGE FILES ===" && find / -xdev -type f -size +100M -exec ls -lh {{}} + 2>/dev/null | sort -k5 -rh | head -20 && \
                echo "=== RECENT DISK ERRORS ===" && journalctl --since {since} -g 'disk|io.error|ext4|xfs' --no-pager -n 20 2>/dev/null || dmesg | grep -i 'error\|disk' | tail -10"#
            ),
            "network" | "connectivity" => format!(
                r#"echo "=== INTERFACES ===" && ip -brief addr 2>/dev/null || ifconfig && \
                echo "=== ROUTES ===" && ip route 2>/dev/null || route -n && \
                echo "=== DNS ===" && cat /etc/resolv.conf && \
                echo "=== LISTENERS ===" && ss -tunapl 2>/dev/null | head -30 || netstat -tunapl 2>/dev/null | head -30 && \
                echo "=== DROPPED PACKETS ===" && netstat -s 2>/dev/null | grep -i 'drop\|error\|fail' | head -10 && \
                echo "=== RECENT NETWORK ERRORS ===" && journalctl --since {since} -g 'network|eth|nic|drop' --no-pager -n 20 2>/dev/null || true"#
            ),
            _ => format!(
                r#"echo "=== GENERAL TRIAGE ===" && \
                systemctl --failed --no-pager 2>/dev/null || true && \
                echo "=== ERRORS ===" && journalctl --since {since} -p err --no-pager -n 30 2>/dev/null || dmesg | tail -20"#
            ),
        };

        format!("{base} && {specific}")
    }

    /// Build a command to capture the current system state for comparison.
    #[must_use]
    pub fn build_state_snapshot_command() -> String {
        [
            r#"echo "=== PACKAGES ===""#,
            "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null || apk list -I 2>/dev/null || echo 'unknown pkg manager'",
            r#"echo "=== SERVICES ===""#,
            "systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null | awk '{print $1}' || true",
            r#"echo "=== LISTENERS ===""#,
            "ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null || true",
            r#"echo "=== KERNEL ===""#,
            "uname -r",
            r#"echo "=== HOSTNAME ===""#,
            "hostname -f 2>/dev/null || hostname",
        ]
        .join(" && ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnose_command_contains_all_sections() {
        let cmd = DiagnosticsCommandBuilder::build_diagnose_command();
        assert!(cmd.contains("UPTIME"));
        assert!(cmd.contains("MEMORY"));
        assert!(cmd.contains("DISK"));
        assert!(cmd.contains("FAILED SERVICES"));
        assert!(cmd.contains("OOM"));
        assert!(cmd.contains("NETWORK"));
        assert!(cmd.contains("free -m"));
        assert!(cmd.contains("df -h"));
    }

    #[test]
    fn test_triage_slow() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("slow", "1 hour ago");
        assert!(cmd.contains("CPU LOAD"));
        assert!(cmd.contains("IO WAIT"));
        assert!(cmd.contains("1 hour ago"));
    }

    #[test]
    fn test_triage_oom() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("oom", "2 hours ago");
        assert!(cmd.contains("MEMORY DETAIL"));
        assert!(cmd.contains("TOP MEM"));
        assert!(cmd.contains("SWAP"));
    }

    #[test]
    fn test_triage_disk() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("disk", "30 min ago");
        assert!(cmd.contains("INODE USAGE"));
        assert!(cmd.contains("LARGE FILES"));
    }

    #[test]
    fn test_triage_network() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("network", "1 hour ago");
        assert!(cmd.contains("INTERFACES"));
        assert!(cmd.contains("ROUTES"));
        assert!(cmd.contains("DNS"));
    }

    #[test]
    fn test_triage_crash() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("crash", "6 hours ago");
        assert!(cmd.contains("RECENT BOOTS"));
        assert!(cmd.contains("CORE DUMPS"));
        assert!(cmd.contains("KERNEL PANICS"));
    }

    #[test]
    fn test_triage_unknown() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("unknown", "1 hour ago");
        assert!(cmd.contains("GENERAL TRIAGE"));
    }

    #[test]
    fn test_state_snapshot_command() {
        let cmd = DiagnosticsCommandBuilder::build_state_snapshot_command();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("KERNEL"));
    }

    // ── injection hardening (AUDIT-2026-08 B1) ───────────────
    //
    // `symptom` used to land inside a *double-quoted* echo, where command
    // substitution is active with no breakout needed; `since` landed inside
    // single quotes, one `'` away from a breakout.

    #[test]
    fn test_triage_symptom_is_shell_escaped() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("$(id > /tmp/pwn)", "1 hour ago");
        assert!(
            cmd.contains("'$(id > /tmp/pwn)'"),
            "symptom must be single-quoted, got: {cmd}"
        );
        assert!(
            !cmd.contains(r#""=== TRIAGE: $(id"#),
            "symptom must not sit inside a double-quoted string: {cmd}"
        );
    }

    #[test]
    fn test_triage_symptom_single_quote_cannot_break_out() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("a' ; id ; '", "1 hour ago");
        assert!(
            cmd.contains(r"'a'\'' ; id ; '\'''"),
            "single quotes in symptom must be escaped, got: {cmd}"
        );
    }

    #[test]
    fn test_triage_since_single_quote_cannot_break_out() {
        // "slow" reaches the branch with the most `since` interpolations.
        let cmd = DiagnosticsCommandBuilder::build_triage_command("slow", "'; id; '");
        assert!(
            !cmd.contains("--since ''; id; ''"),
            "since must not break out of its quoting, got: {cmd}"
        );
        assert!(cmd.contains(r"''\''; id; '\'''"), "got: {cmd}");
    }

    #[test]
    fn test_triage_benign_input_is_unchanged_in_meaning() {
        let cmd = DiagnosticsCommandBuilder::build_triage_command("slow", "1 hour ago");
        assert!(cmd.contains("TRIAGE:"));
        assert!(cmd.contains("'slow'"));
        assert!(cmd.contains("'1 hour ago'"));
        assert!(cmd.contains("CPU LOAD"));
    }
}
