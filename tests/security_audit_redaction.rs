//! Audit-log secret redaction tests (Vuln 3 / 2026-05-09).

use bridge_mcp::config::{AuditConfig, CustomSanitizePattern, SanitizeConfig};
use bridge_mcp::security::{AuditEvent, AuditLogger, CommandResult, Sanitizer};

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

    logger.log(
        "test_tool",
        AuditEvent::new(
            "prod-db",
            "MYSQL_PWD='hunter2-supersecret-do-not-leak' mysql -e 'SELECT 1'",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 12,
            },
        ),
    );

    drop(logger); // closes the channel so the writer task ends
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        !contents.contains("hunter2-supersecret-do-not-leak"),
        "password leaked into audit log:\n{contents}"
    );
}

/// A prefixed JSON key (`db_password`) in the command text, read back from
/// the `audit.log` the writer task actually produced.
#[tokio::test]
async fn audit_log_redacts_prefixed_json_key() {
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

    logger.log(
        "test_tool",
        AuditEvent::new(
            "prod-db",
            r#"{"db_password":"S3cr3t!x","dbPassword":"S3cr3t!y","admin_token":"S3cr3t!xyz"}"#,
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 12,
            },
        ),
    );

    drop(logger);
    writer.await.unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("db_password"),
        "the line must have been written, with its key:\n{contents}"
    );
    for secret in ["S3cr3t!x", "S3cr3t!y", "S3cr3t!xyz"] {
        assert!(!contents.contains(secret), "{secret} leaked:\n{contents}");
    }
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

    logger.log(
        "test_tool",
        AuditEvent::new(
            "awx",
            "curl -H 'Authorization: Bearer abc123def456ghi789jkl012mno345' https://awx/api",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 5,
            },
        ),
    );
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

/// Writes one line carrying `command` through a real `audit.log` and returns
/// the file's contents.
async fn audit_file_for(sanitizer: Sanitizer, command: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let config = AuditConfig {
        enabled: true,
        path: path.clone(),
        ..AuditConfig::default()
    };
    let (logger, task) = AuditLogger::new_with_sanitizer(&config, sanitizer).unwrap();
    let writer = tokio::spawn(task.unwrap().run());
    logger.log(
        "test_tool",
        AuditEvent::new(
            "prod-db",
            command,
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 12,
            },
        ),
    );
    drop(logger);
    writer.await.unwrap();
    std::fs::read_to_string(&path).unwrap()
}

/// An operator pattern with no built-in keyword near its match reaches the
/// real file: `--key` is not a built-in keyword, so this was inert.
#[tokio::test]
async fn audit_log_redacts_a_custom_pattern_without_builtin_keyword() {
    let cfg = SanitizeConfig {
        custom_patterns: vec![CustomSanitizePattern {
            pattern: r"WIDGETKEY-\d{4}".to_string(),
            replacement: "[WIDGET]".to_string(),
            description: None,
        }],
        ..SanitizeConfig::default()
    };
    let contents =
        audit_file_for(Sanitizer::from_config(&cfg), "deploy --key WIDGETKEY-4242").await;
    assert!(
        contents.contains("deploy --key"),
        "line not written:\n{contents}"
    );
    assert!(!contents.contains("WIDGETKEY-4242"), "leaked:\n{contents}");
}

/// Same, through the legacy list (`security.sanitize_patterns`).
#[tokio::test]
async fn audit_log_redacts_a_legacy_pattern_without_builtin_keyword() {
    let sanitizer = Sanitizer::from_config_with_legacy(
        &SanitizeConfig::default(),
        &[r"WIDGETKEY-\d{4}".to_string()],
    );
    let contents = audit_file_for(sanitizer, "deploy --key WIDGETKEY-4242").await;
    assert!(
        contents.contains("deploy --key"),
        "line not written:\n{contents}"
    );
    assert!(!contents.contains("WIDGETKEY-4242"), "leaked:\n{contents}");
}
