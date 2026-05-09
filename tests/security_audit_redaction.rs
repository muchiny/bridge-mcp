//! Audit-log secret redaction tests (Vuln 3 / 2026-05-09).

use mcp_ssh_bridge::config::{AuditConfig, SanitizeConfig};
use mcp_ssh_bridge::security::{AuditEvent, AuditLogger, CommandResult, Sanitizer};

#[tokio::test]
async fn audit_log_redacts_password_in_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        ..AuditConfig::default()
    };
    let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
    let (logger, task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();
    let writer = tokio::spawn(task.unwrap().run());

    logger.log(AuditEvent::new(
        "prod-db",
        "MYSQL_PWD='hunter2-supersecret-do-not-leak' mysql -e 'SELECT 1'",
        CommandResult::Success {
            exit_code: 0,
            duration_ms: 12,
        },
    ));

    drop(logger); // closes the channel so the writer task ends
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        !contents.contains("hunter2-supersecret-do-not-leak"),
        "password leaked into audit log:\n{contents}"
    );
}

#[tokio::test]
async fn audit_log_redacts_bearer_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        ..AuditConfig::default()
    };
    let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
    let (logger, task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();
    let writer = tokio::spawn(task.unwrap().run());

    logger.log(AuditEvent::new(
        "awx",
        "curl -H 'Authorization: Bearer abc123def456ghi789jkl012mno345' https://awx/api",
        CommandResult::Success {
            exit_code: 0,
            duration_ms: 5,
        },
    ));
    drop(logger);
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        !contents.contains("abc123def456ghi789jkl012mno345"),
        "bearer token leaked:\n{contents}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn audit_log_file_has_0600_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        ..AuditConfig::default()
    };
    let sanitizer = Sanitizer::from_config(&SanitizeConfig::default());
    let (_logger, _task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "audit log must be created with mode 0600 (got {mode:o})"
    );
}
