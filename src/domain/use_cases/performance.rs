//! Performance Command Builder
//!
//! Builds performance profiling CLI commands for remote execution via SSH.
//! Supports perf/strace tracing, I/O tracing, network latency testing,
//! and quick benchmarks (CPU, I/O, memory).

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a network target is a plausible hostname or IP address.
/// Rejects empty strings and strings with shell-dangerous characters.
pub fn validate_latency_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Latency target cannot be empty".to_string(),
        });
    }
    // `ping '-f'` and `mtr '-F/etc/shadow'` are one shell word and still
    // options. No hostname or IP starts with a hyphen.
    super::shell::refuse_option_like("target", target)?;
    // A valid hostname/IP should only contain: alphanumeric, dots, hyphens, colons (IPv6)
    if !target
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid latency target '{target}': must contain only alphanumeric characters, \
                 dots, hyphens, colons, or underscores"
            ),
        });
    }
    Ok(())
}

/// Validate the `device` argument of `iostat`.
///
/// Block device names never start with `-`; `iostat -x '-f' 1 5` would read
/// the word as an option.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `device` starts with `-`.
pub fn validate_io_device(device: &str) -> Result<()> {
    super::shell::refuse_option_like("device", device)
}

/// Builds performance profiling commands for remote execution.
pub struct PerformanceCommandBuilder;

impl PerformanceCommandBuilder {
    /// Validate that a duration does not exceed 60 seconds.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if duration exceeds 60.
    pub fn validate_duration(duration: u64) -> Result<()> {
        if duration > 60 {
            return Err(BridgeError::CommandDenied {
                reason: "Duration cannot exceed 60 seconds".to_string(),
            });
        }
        Ok(())
    }

    /// Validate that a count does not exceed 100.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if count exceeds 100.
    pub fn validate_count(count: u64) -> Result<()> {
        if count > 100 {
            return Err(BridgeError::CommandDenied {
                reason: "Count cannot exceed 100".to_string(),
            });
        }
        Ok(())
    }

    /// Validate that a benchmark type is one of: cpu, io, memory.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the type is not allowed.
    pub fn validate_bench_type(bench_type: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["cpu", "io", "memory"];
        if !ALLOWED.contains(&bench_type) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid benchmark type '{bench_type}': must be one of: cpu, io, memory"
                ),
            });
        }
        Ok(())
    }

    /// Build a performance trace command.
    ///
    /// Constructs: `perf stat -p PID sleep DURATION` or system-wide
    /// `perf stat -a sleep DURATION` with strace fallback.
    #[must_use]
    pub fn build_perf_trace_command(pid: Option<u32>, duration: u64) -> String {
        if let Some(p) = pid {
            format!(
                "perf stat -p {p} sleep {duration} 2>&1 || \
                 strace -c -p {p} -S time -e trace=all timeout {duration} cat /dev/null 2>&1"
            )
        } else {
            format!(
                "perf stat -a sleep {duration} 2>&1 || \
                 strace -c -S time -e trace=all timeout {duration} cat /dev/null 2>&1"
            )
        }
    }

    /// Build an I/O trace command.
    ///
    /// Constructs: `iostat -x DEVICE 1 DURATION` with `/proc/diskstats` fallback.
    #[must_use]
    pub fn build_io_trace_command(device: Option<&str>, duration: u64) -> String {
        if let Some(dev) = device {
            let escaped = shell_escape(dev);
            format!("iostat -x {escaped} 1 {duration} 2>/dev/null || cat /proc/diskstats")
        } else {
            format!("iostat -x 1 {duration} 2>/dev/null || cat /proc/diskstats")
        }
    }

    /// Build a network latency test command.
    ///
    /// Constructs: `ping -c COUNT TARGET` or `mtr --report -c COUNT TARGET`
    /// based on method.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the target is invalid.
    pub fn build_latency_test_command(
        target: &str,
        count: u64,
        method: Option<&str>,
    ) -> Result<String> {
        validate_latency_target(target)?;
        let escaped = shell_escape(target);
        match method {
            Some("mtr") => Ok(format!("mtr --report -c {count} {escaped}")),
            _ => Ok(format!("ping -c {count} {escaped}")),
        }
    }

    /// Build a quick benchmark command.
    ///
    /// Supports: "cpu" (md5sum throughput), "io" (dd write speed),
    /// "memory" (throughput).
    #[must_use]
    pub fn build_benchmark_command(bench_type: &str) -> String {
        match bench_type {
            "cpu" => "dd if=/dev/zero bs=1M count=256 2>/dev/null | md5sum".to_string(),
            "io" => "dd if=/dev/zero of=/tmp/bench_test bs=1M count=256 conv=fdatasync 2>&1 \
                 && rm -f /tmp/bench_test"
                .to_string(),
            "memory" => "dd if=/dev/zero of=/dev/null bs=1M count=1024 2>&1".to_string(),
            _ => format!(
                "printf '%s\\n' {}",
                shell_escape(&format!("Unknown benchmark type: {bench_type}"))
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_target_refuses_a_leading_dash() {
        for bad in ["-F/etc/passwd", "-f", "-s65507"] {
            for method in [None, Some("mtr")] {
                let err = PerformanceCommandBuilder::build_latency_test_command(bad, 3, method)
                    .unwrap_err();
                assert!(
                    err.to_string().contains("'target' must not start with '-'"),
                    "{err}"
                );
            }
        }
        assert!(PerformanceCommandBuilder::build_latency_test_command("web-1", 3, None).is_ok());
    }

    #[test]
    fn test_unknown_benchmark_type_is_one_quoted_word() {
        let cmd = PerformanceCommandBuilder::build_benchmark_command("x'; id");
        assert_eq!(cmd, r"printf '%s\n' 'Unknown benchmark type: x'\''; id'");
    }

    #[test]
    fn test_validate_io_device_refuses_a_leading_dash() {
        let err = validate_io_device("-f").unwrap_err();
        assert!(
            err.to_string().contains("'device' must not start with '-'"),
            "{err}"
        );
        assert!(validate_io_device("nvme0n1").is_ok());
    }

    // ---- Duration validation ----

    #[test]
    fn test_validate_duration_ok() {
        assert!(PerformanceCommandBuilder::validate_duration(0).is_ok());
        assert!(PerformanceCommandBuilder::validate_duration(30).is_ok());
        assert!(PerformanceCommandBuilder::validate_duration(60).is_ok());
    }

    #[test]
    fn test_validate_duration_too_long() {
        let err = PerformanceCommandBuilder::validate_duration(61).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("60 seconds"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ---- Count validation ----

    #[test]
    fn test_validate_count_ok() {
        assert!(PerformanceCommandBuilder::validate_count(1).is_ok());
        assert!(PerformanceCommandBuilder::validate_count(100).is_ok());
    }

    #[test]
    fn test_validate_count_too_high() {
        let err = PerformanceCommandBuilder::validate_count(101).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("100"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ---- Bench type validation ----

    #[test]
    fn test_validate_bench_type_ok() {
        assert!(PerformanceCommandBuilder::validate_bench_type("cpu").is_ok());
        assert!(PerformanceCommandBuilder::validate_bench_type("io").is_ok());
        assert!(PerformanceCommandBuilder::validate_bench_type("memory").is_ok());
    }

    #[test]
    fn test_validate_bench_type_invalid() {
        let err = PerformanceCommandBuilder::validate_bench_type("gpu").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("gpu"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ---- Latency target validation ----

    #[test]
    fn test_validate_latency_target_ok() {
        assert!(validate_latency_target("8.8.8.8").is_ok());
        assert!(validate_latency_target("example.com").is_ok());
        assert!(validate_latency_target("::1").is_ok());
    }

    #[test]
    fn test_validate_latency_target_empty() {
        assert!(validate_latency_target("").is_err());
    }

    #[test]
    fn test_validate_latency_target_shell_injection() {
        assert!(validate_latency_target("; rm -rf /").is_err());
        assert!(validate_latency_target("$(whoami)").is_err());
        assert!(validate_latency_target("foo`bar`").is_err());
    }

    // ---- Perf trace command ----

    #[test]
    fn test_build_perf_trace_with_pid() {
        let cmd = PerformanceCommandBuilder::build_perf_trace_command(Some(1234), 10);
        assert!(cmd.contains("perf stat -p 1234"));
        assert!(cmd.contains("sleep 10"));
        assert!(cmd.contains("strace"));
    }

    #[test]
    fn test_build_perf_trace_system_wide() {
        let cmd = PerformanceCommandBuilder::build_perf_trace_command(None, 5);
        assert!(cmd.contains("perf stat -a"));
        assert!(cmd.contains("sleep 5"));
    }

    // ---- IO trace command ----

    #[test]
    fn test_build_io_trace_with_device() {
        let cmd = PerformanceCommandBuilder::build_io_trace_command(Some("sda"), 10);
        assert!(cmd.contains("iostat"));
        assert!(cmd.contains("sda"));
        assert!(cmd.contains("1 10"));
    }

    #[test]
    fn test_build_io_trace_all_devices() {
        let cmd = PerformanceCommandBuilder::build_io_trace_command(None, 5);
        assert!(cmd.contains("iostat -x 1 5"));
        assert!(cmd.contains("/proc/diskstats"));
    }

    // ---- Latency test command ----

    #[test]
    fn test_build_latency_test_ping() {
        let cmd =
            PerformanceCommandBuilder::build_latency_test_command("8.8.8.8", 5, None).unwrap();
        assert!(cmd.contains("ping -c 5"));
        assert!(cmd.contains("8.8.8.8"));
    }

    #[test]
    fn test_build_latency_test_mtr() {
        let cmd =
            PerformanceCommandBuilder::build_latency_test_command("example.com", 10, Some("mtr"))
                .unwrap();
        assert!(cmd.contains("mtr --report -c 10"));
        assert!(cmd.contains("example.com"));
    }

    #[test]
    fn test_build_latency_test_invalid_target() {
        let result = PerformanceCommandBuilder::build_latency_test_command("; rm -rf /", 5, None);
        assert!(result.is_err());
    }

    // ---- Benchmark command ----

    #[test]
    fn test_build_benchmark_cpu() {
        let cmd = PerformanceCommandBuilder::build_benchmark_command("cpu");
        assert!(cmd.contains("md5sum"));
        assert!(cmd.contains("dd"));
    }

    #[test]
    fn test_build_benchmark_io() {
        let cmd = PerformanceCommandBuilder::build_benchmark_command("io");
        assert!(cmd.contains("/tmp/bench_test"));
        assert!(cmd.contains("fdatasync"));
        assert!(cmd.contains("rm -f"));
    }

    #[test]
    fn test_build_benchmark_memory() {
        let cmd = PerformanceCommandBuilder::build_benchmark_command("memory");
        assert!(cmd.contains("/dev/null"));
        assert!(cmd.contains("1024"));
    }

    #[test]
    fn test_build_benchmark_unknown() {
        let cmd = PerformanceCommandBuilder::build_benchmark_command("gpu");
        assert!(cmd.contains("Unknown benchmark type"));
    }
}
