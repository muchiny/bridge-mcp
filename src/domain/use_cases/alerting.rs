//! Alerting Command Builder
//!
//! Builds metric alert check commands for remote execution via SSH.
//! Supports CPU, memory, disk, load, and swap metrics with configurable thresholds.

use crate::error::{BridgeError, Result};

/// Allowed metric names for alerting.
const ALLOWED_METRICS: &[&str] = &["cpu", "memory", "disk", "load", "swap"];

/// Allowed comparison operators for threshold checks.
const ALLOWED_OPERATORS: &[&str] = &[">", "<", ">=", "<=", "=="];

/// Validate that a metric name is one of the allowed values.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the metric is not in the allowed list.
pub fn validate_metric(metric: &str) -> Result<()> {
    if !ALLOWED_METRICS.contains(&metric) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid metric '{}'. Allowed metrics: {}",
                metric,
                ALLOWED_METRICS.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate that an operator is one of the allowed comparison operators.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the operator is not in the allowed list.
pub fn validate_operator(op: &str) -> Result<()> {
    if !ALLOWED_OPERATORS.contains(&op) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid operator '{}'. Allowed operators: {}",
                op,
                ALLOWED_OPERATORS.join(", ")
            ),
        });
    }
    Ok(())
}

/// Builds alerting commands for remote execution.
pub struct AlertingCommandBuilder;

impl AlertingCommandBuilder {
    /// Build a command that collects the current value of a metric and compares it
    /// against a threshold using the given operator.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the metric or operator is invalid.
    pub fn build_alert_check_command(
        metric: &str,
        threshold: f64,
        operator: &str,
    ) -> Result<String> {
        validate_metric(metric)?;
        validate_operator(operator)?;

        let collect_cmd = Self::metric_command(metric);
        // `operator` is one of `ALLOWED_OPERATORS`, so it goes into the awk
        // program as is. Quoted, it was a literal `'>'` inside the awk program
        // (a syntax error): the double quotes around the program already
        // quote it for the shell.

        Ok(format!(
            "VALUE=$({collect_cmd}); echo \"metric={metric} value=$VALUE threshold={threshold} \
             operator={operator}\"; \
             awk \"BEGIN {{ if ($VALUE {operator} {threshold}) print \\\"ALERT: {metric} is $VALUE \
             (threshold {threshold})\\\"; else print \\\"OK: {metric} is $VALUE \
             (threshold {threshold})\\\" }}\""
        ))
    }

    /// Build a compound command that shows all metric values in a single overview.
    #[must_use]
    pub fn build_alert_list_command() -> String {
        "echo '=== CPU ===' && \
         awk '{u=$2+$4; t=$2+$4+$5; if (NR>1) printf \"cpu_usage=%.1f%%\\n\", \
         ((u-pu)/(t-pt))*100; pu=u; pt=t}' \
         <(head -1 /proc/stat) <(sleep 1 && head -1 /proc/stat) && \
         echo '=== Memory ===' && \
         free | awk '/Mem:/{printf \"memory_usage=%.1f%%\\n\", $3/$2*100}' && \
         echo '=== Swap ===' && \
         free | awk '/Swap:/{if($2>0) printf \"swap_usage=%.1f%%\\n\", $3/$2*100; \
         else print \"swap_usage=0.0% (no swap)\"}' && \
         echo '=== Disk ===' && \
         df -h / | awk 'NR==2{printf \"disk_usage=%s\\n\", $5}' && \
         echo '=== Load ===' && \
         cat /proc/loadavg | awk '{printf \"load_1m=%s load_5m=%s load_15m=%s\\n\", $1, $2, $3}'"
            .to_string()
    }

    /// Build a command to check a specific metric, optionally comparing against a threshold.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the metric or operator is invalid.
    pub fn build_alert_check_metric_command(
        metric: &str,
        threshold: Option<f64>,
        operator: Option<&str>,
    ) -> Result<String> {
        validate_metric(metric)?;

        let collect_cmd = Self::metric_command(metric);

        match (threshold, operator) {
            (Some(t), Some(op)) => Self::build_alert_check_command(metric, t, op),
            (Some(t), None) => Self::build_alert_check_command(metric, t, ">"),
            _ => Ok(format!("VALUE=$({collect_cmd}); echo \"{metric}=$VALUE\"")),
        }
    }

    /// Return the shell command snippet to collect a single metric value.
    #[must_use]
    fn metric_command(metric: &str) -> &'static str {
        match metric {
            "cpu" => {
                "awk '{u=$2+$4; t=$2+$4+$5; if (NR>1) printf \"%.1f\", \
                      ((u-pu)/(t-pt))*100; pu=u; pt=t}' \
                      <(head -1 /proc/stat) <(sleep 1 && head -1 /proc/stat)"
            }
            "memory" => "free | awk '/Mem:/{printf \"%.1f\", $3/$2*100}'",
            "disk" => "df / | awk 'NR==2{print $5}' | tr -d '%'",
            "load" => "cat /proc/loadavg | awk '{print $1}'",
            "swap" => {
                "free | awk '/Swap:/{if($2>0) printf \"%.1f\", $3/$2*100; else print \"0.0\"}'"
            }
            _ => "echo 0",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_metric ──────────────────────────────────────────

    #[test]
    fn test_validate_metric_valid() {
        assert!(validate_metric("cpu").is_ok());
        assert!(validate_metric("memory").is_ok());
        assert!(validate_metric("disk").is_ok());
        assert!(validate_metric("load").is_ok());
        assert!(validate_metric("swap").is_ok());
    }

    #[test]
    fn test_validate_metric_invalid() {
        assert!(validate_metric("gpu").is_err());
        assert!(validate_metric("").is_err());
        assert!(validate_metric("CPU").is_err());
        assert!(validate_metric("network").is_err());
    }

    #[test]
    fn test_validate_metric_error_message() {
        let result = validate_metric("invalid");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Invalid metric"));
                assert!(reason.contains("invalid"));
                assert!(reason.contains("cpu"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_operator ────────────────────────────────────────

    #[test]
    fn test_validate_operator_valid() {
        assert!(validate_operator(">").is_ok());
        assert!(validate_operator("<").is_ok());
        assert!(validate_operator(">=").is_ok());
        assert!(validate_operator("<=").is_ok());
        assert!(validate_operator("==").is_ok());
    }

    #[test]
    fn test_validate_operator_invalid() {
        assert!(validate_operator("!=").is_err());
        assert!(validate_operator("").is_err());
        assert!(validate_operator("; rm -rf /").is_err());
        assert!(validate_operator("gt").is_err());
    }

    #[test]
    fn test_validate_operator_error_message() {
        let result = validate_operator("!!");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Invalid operator"));
                assert!(reason.contains("!!"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_alert_check_command ────────────────────────────────

    #[test]
    fn test_alert_check_puts_the_operator_in_the_awk_program_unquoted() {
        for op in [">", "<", ">=", "<=", "=="] {
            let cmd = AlertingCommandBuilder::build_alert_check_command("cpu", 80.0, op).unwrap();
            assert!(cmd.contains(&format!("if ($VALUE {op} 80)")), "{cmd}");
            assert!(!cmd.contains(&format!("'{op}'")), "{cmd}");
        }
    }

    #[test]
    fn test_alert_check_cpu() {
        let cmd = AlertingCommandBuilder::build_alert_check_command("cpu", 80.0, ">").unwrap();
        assert!(cmd.contains("metric=cpu"));
        assert!(cmd.contains("threshold=80"));
        assert!(cmd.contains("ALERT"));
        assert!(cmd.contains("OK"));
    }

    #[test]
    fn test_alert_check_memory() {
        let cmd = AlertingCommandBuilder::build_alert_check_command("memory", 90.0, ">=").unwrap();
        assert!(cmd.contains("metric=memory"));
        assert!(cmd.contains("threshold=90"));
    }

    #[test]
    fn test_alert_check_disk() {
        let cmd = AlertingCommandBuilder::build_alert_check_command("disk", 85.0, ">").unwrap();
        assert!(cmd.contains("metric=disk"));
    }

    #[test]
    fn test_alert_check_load() {
        let cmd = AlertingCommandBuilder::build_alert_check_command("load", 4.0, ">=").unwrap();
        assert!(cmd.contains("metric=load"));
        assert!(cmd.contains("threshold=4"));
    }

    #[test]
    fn test_alert_check_invalid_metric() {
        let result = AlertingCommandBuilder::build_alert_check_command("gpu", 80.0, ">");
        assert!(result.is_err());
    }

    #[test]
    fn test_alert_check_invalid_operator() {
        let result = AlertingCommandBuilder::build_alert_check_command("cpu", 80.0, "!=");
        assert!(result.is_err());
    }

    // ── build_alert_list_command ─────────────────────────────────

    #[test]
    fn test_alert_list_command() {
        let cmd = AlertingCommandBuilder::build_alert_list_command();
        assert!(cmd.contains("CPU"));
        assert!(cmd.contains("Memory"));
        assert!(cmd.contains("Swap"));
        assert!(cmd.contains("Disk"));
        assert!(cmd.contains("Load"));
    }

    // ── build_alert_check_metric_command ─────────────────────────

    #[test]
    fn test_check_metric_no_threshold() {
        let cmd =
            AlertingCommandBuilder::build_alert_check_metric_command("cpu", None, None).unwrap();
        assert!(cmd.contains("cpu="));
    }

    #[test]
    fn test_check_metric_with_threshold() {
        let cmd = AlertingCommandBuilder::build_alert_check_metric_command(
            "memory",
            Some(90.0),
            Some(">="),
        )
        .unwrap();
        assert!(cmd.contains("metric=memory"));
        assert!(cmd.contains("threshold=90"));
    }

    #[test]
    fn test_check_metric_threshold_no_operator_defaults_gt() {
        let cmd =
            AlertingCommandBuilder::build_alert_check_metric_command("disk", Some(80.0), None)
                .unwrap();
        assert!(cmd.contains("metric=disk"));
        assert!(cmd.contains("threshold=80"));
    }

    #[test]
    fn test_check_metric_invalid_metric() {
        let result =
            AlertingCommandBuilder::build_alert_check_metric_command("invalid", None, None);
        assert!(result.is_err());
    }

    // ── metric_command ──────────────────────────────────────────

    #[test]
    fn test_metric_command_cpu() {
        let cmd = AlertingCommandBuilder::metric_command("cpu");
        assert!(cmd.contains("/proc/stat"));
    }

    #[test]
    fn test_metric_command_memory() {
        let cmd = AlertingCommandBuilder::metric_command("memory");
        assert!(cmd.contains("free"));
        assert!(cmd.contains("Mem:"));
    }

    #[test]
    fn test_metric_command_disk() {
        let cmd = AlertingCommandBuilder::metric_command("disk");
        assert!(cmd.contains("df /"));
    }

    #[test]
    fn test_metric_command_load() {
        let cmd = AlertingCommandBuilder::metric_command("load");
        assert!(cmd.contains("/proc/loadavg"));
    }

    #[test]
    fn test_metric_command_swap() {
        let cmd = AlertingCommandBuilder::metric_command("swap");
        assert!(cmd.contains("Swap:"));
    }
}
