//! Backup Advanced Command Builder
//!
//! Builds snapshot, verification, and scheduled backup commands for
//! remote execution via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate backup paths for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if paths are empty, contain
/// path traversal patterns, or contain a control character (a newline would
/// start a new line in a crontab).
pub fn validate_paths(paths: &str) -> Result<()> {
    if paths.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Backup paths must not be empty".to_string(),
        });
    }
    if paths.chars().any(char::is_control) {
        return Err(BridgeError::CommandDenied {
            reason: "Backup paths must not contain control characters (newline, carriage \
                     return, NUL)"
                .to_string(),
        });
    }
    if paths.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: "Backup paths must not contain '..' (path traversal)".to_string(),
        });
    }
    if paths.len() > 4096 {
        return Err(BridgeError::CommandDenied {
            reason: format!("Backup paths too long: {} chars (max 4096)", paths.len()),
        });
    }
    Ok(())
}

/// Refuse an archive name that GNU `tar` would read as a remote archive.
///
/// `tar -f host:path` (a `:` before the first `/`) is an archive on `host`:
/// tar starts its remote shell (`ssh` or `rsh`) to that host and streams the
/// archive there, or reads one from it. Quoting and `--` do not change how tar
/// reads the name, and `--force-local` is not available on busybox tar, so the
/// name is refused. A relative name with a `:` after a `/` (`./a:b.tar`,
/// `dir/a:b.tar`) is a local file and stays accepted.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] naming `arg` when `name` has a `:` before
/// its first `/`.
pub fn refuse_remote_archive(arg: &str, name: &str) -> Result<()> {
    if name
        .split('/')
        .next()
        .is_some_and(|head| head.contains(':'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "'{arg}' must not have a ':' before its first '/': tar would read it as an \
                 archive on a remote host. Use an absolute path or prefix it with './'"
            ),
        });
    }
    Ok(())
}

/// Validate an archive path for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the archive path is empty,
/// contains path traversal, does not end with a tar extension, or names a
/// remote archive (see [`refuse_remote_archive`]).
pub fn validate_archive(archive: &str) -> Result<()> {
    if archive.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must not be empty".to_string(),
        });
    }
    if archive.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must not contain '..' (path traversal)".to_string(),
        });
    }
    if !archive.contains(".tar") {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must contain '.tar' extension".to_string(),
        });
    }
    refuse_remote_archive("archive", archive)?;
    Ok(())
}

/// Validate a cron expression for scheduled backups.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the expression is invalid.
pub fn validate_cron_expr(cron_expr: &str) -> Result<()> {
    let fields: Vec<&str> = cron_expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid cron expression: expected 5 fields, got {}",
                fields.len()
            ),
        });
    }
    for (i, field) in fields.iter().enumerate() {
        if !field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | '-' | ','))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid cron field {}: '{}' contains invalid characters",
                    i + 1,
                    field
                ),
            });
        }
    }
    Ok(())
}

/// Builds advanced backup commands for remote execution.
pub struct BackupAdvancedCommandBuilder;

impl BackupAdvancedCommandBuilder {
    /// Build a command to create a snapshot archive of specified paths.
    ///
    /// Creates a timestamped tar.gz archive in `/tmp/`.
    ///
    /// # Errors
    ///
    /// Returns an error if paths are invalid.
    pub fn build_snapshot_command(paths: &str, label: Option<&str>) -> Result<String> {
        validate_paths(paths)?;

        // The label only ever named the archive after being filtered to
        // `[A-Za-z0-9_-]` by the remote `tr`; filtering here gives the same
        // name and leaves nothing of the caller's text for the shell to parse.
        let label_part: String = label
            .unwrap_or("snapshot")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            .collect();
        let escaped_paths = shell_escape(paths);

        Ok(format!(
            "TIMESTAMP=$(date +%Y%m%d_%H%M%S) && \
             ARCHIVE=\"/tmp/snapshot_{label_part}_${{TIMESTAMP}}.tar.gz\" && \
             tar czf \"$ARCHIVE\" -- {escaped_paths} 2>/dev/null && \
             echo \"Snapshot created: $ARCHIVE\" && \
             ls -lh \"$ARCHIVE\" && \
             sha256sum \"$ARCHIVE\""
        ))
    }

    /// Build a command to verify a backup archive.
    ///
    /// Tests archive integrity and prints a checksum.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive path is invalid.
    pub fn build_verify_command(archive: &str) -> Result<String> {
        validate_archive(archive)?;

        let escaped = shell_escape(archive);

        Ok(format!(
            "tar tzf {escaped} >/dev/null 2>&1 && \
             echo 'Archive OK' && \
             sha256sum -- {escaped} && \
             echo '--- Archive Contents ---' && \
             tar tzf {escaped} | head -20 && \
             echo '--- Archive Size ---' && \
             ls -lh -- {escaped}"
        ))
    }

    /// Build a command to schedule a periodic backup via cron.
    ///
    /// # Errors
    ///
    /// Returns an error if the cron expression or paths are invalid.
    pub fn build_schedule_command(cron_expr: &str, paths: &str, dest: &str) -> Result<String> {
        validate_cron_expr(cron_expr)?;
        validate_paths(paths)?;

        if dest.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Backup destination must not be empty".to_string(),
            });
        }
        // The archive name is `{dest}/backup_...`: a ':' in the first segment
        // of `dest` is a ':' before the first '/' of the name.
        refuse_remote_archive("dest", dest)?;
        // The cron line is one line of a crontab: cron splits on newlines
        // whatever the shell quoting, and turns an unescaped `%` into one.
        for (name, value) in [("paths", paths), ("dest", dest)] {
            if value.chars().any(|c| c.is_control() || c == '%') {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Backup {name} must not contain control characters or '%' (they would \
                         break the crontab line)"
                    ),
                });
            }
        }

        let escaped_paths = shell_escape(paths);
        let escaped_dest = shell_escape(dest);
        let backup_cmd = format!(
            "tar czf {escaped_dest}/backup_$(date +\\%Y\\%m\\%d_\\%H\\%M\\%S).tar.gz -- {escaped_paths}"
        );

        let cron_line = format!("{cron_expr} {backup_cmd}");
        let escaped_cron_line = shell_escape(&cron_line);

        Ok(format!(
            "(crontab -l 2>/dev/null; printf '%s\\n' {escaped_cron_line}) | crontab - && \
             echo 'Backup schedule added successfully' && \
             crontab -l | tail -3"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_paths ────────────────────────────────────────

    #[test]
    fn test_validate_paths_valid() {
        assert!(validate_paths("/var/data").is_ok());
        assert!(validate_paths("/etc/config /var/log").is_ok());
    }

    #[test]
    fn test_validate_paths_empty() {
        let err = validate_paths("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_paths_traversal() {
        assert!(validate_paths("/var/../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_paths_too_long() {
        let long = "/a".repeat(2049);
        assert!(validate_paths(&long).is_err());
    }

    // ── validate_archive ──────────────────────────────────────

    #[test]
    fn test_validate_archive_valid() {
        assert!(validate_archive("/tmp/backup.tar.gz").is_ok());
        assert!(validate_archive("/backups/data.tar").is_ok());
        assert!(validate_archive("/tmp/snap.tar.xz").is_ok());
    }

    #[test]
    fn test_validate_archive_empty() {
        assert!(validate_archive("").is_err());
    }

    #[test]
    fn test_validate_archive_traversal() {
        assert!(validate_archive("/tmp/../etc/backup.tar.gz").is_err());
    }

    #[test]
    fn test_validate_archive_no_tar() {
        let err = validate_archive("/tmp/backup.zip").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains(".tar"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_cron_expr ────────────────────────────────────

    #[test]
    fn test_validate_cron_expr_valid() {
        assert!(validate_cron_expr("0 2 * * *").is_ok());
        assert!(validate_cron_expr("*/15 * * * *").is_ok());
        assert!(validate_cron_expr("0 0 1 1 *").is_ok());
    }

    #[test]
    fn test_validate_cron_expr_wrong_fields() {
        assert!(validate_cron_expr("* * *").is_err());
        assert!(validate_cron_expr("* * * * * *").is_err());
    }

    #[test]
    fn test_validate_cron_expr_invalid_chars() {
        assert!(validate_cron_expr("0 * * * ; rm -rf /").is_err());
    }

    // ── build_snapshot_command ─────────────────────────────────

    #[test]
    fn test_snapshot_defaults() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command("/var/data", None).unwrap();
        assert!(cmd.contains("tar czf"));
        assert!(cmd.contains("snapshot"));
        assert!(cmd.contains("sha256sum"));
        assert!(cmd.contains("/var/data"));
    }

    #[test]
    fn test_snapshot_with_label() {
        let cmd =
            BackupAdvancedCommandBuilder::build_snapshot_command("/var/data", Some("mybackup"))
                .unwrap();
        assert!(cmd.contains("mybackup"));
    }

    #[test]
    fn test_snapshot_invalid_paths() {
        let result = BackupAdvancedCommandBuilder::build_snapshot_command("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_shell_injection() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command(
            "/var/data",
            Some("'; rm -rf /; echo '"),
        )
        .unwrap();
        // The label is filtered to `[A-Za-z0-9_-]` before it reaches the shell.
        assert!(!cmd.contains("'; rm"), "{cmd}");
        assert!(cmd.contains("snapshot_rm-rfecho_"), "{cmd}");
    }

    #[test]
    fn snapshot_puts_paths_after_end_of_options() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command("-x", None).unwrap();
        assert!(cmd.contains("tar czf \"$ARCHIVE\" -- '-x'"), "{cmd}");
    }

    #[test]
    fn snapshot_label_with_metacharacters_is_filtered() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command(
            "/var/data",
            Some("a'b\"c;d$(e)`f"),
        )
        .unwrap();
        assert!(cmd.contains("/tmp/snapshot_abcdef_"), "{cmd}");
    }

    #[test]
    fn verify_puts_archive_after_end_of_options() {
        let cmd = BackupAdvancedCommandBuilder::build_verify_command("-x.tar").unwrap();
        assert!(cmd.contains("sha256sum -- '-x.tar'"), "{cmd}");
        assert!(cmd.contains("ls -lh -- '-x.tar'"), "{cmd}");
    }

    // ── build_verify_command ──────────────────────────────────

    #[test]
    fn test_verify_valid() {
        let cmd = BackupAdvancedCommandBuilder::build_verify_command("/tmp/backup.tar.gz").unwrap();
        assert!(cmd.contains("tar tzf"));
        assert!(cmd.contains("Archive OK"));
        assert!(cmd.contains("sha256sum"));
        assert!(cmd.contains("Archive Contents"));
    }

    #[test]
    fn test_verify_invalid_archive() {
        assert!(BackupAdvancedCommandBuilder::build_verify_command("").is_err());
        assert!(BackupAdvancedCommandBuilder::build_verify_command("/tmp/file.zip").is_err());
    }

    #[test]
    fn test_verify_shell_injection() {
        let cmd =
            BackupAdvancedCommandBuilder::build_verify_command("/tmp/'; rm -rf /.tar.gz").unwrap();
        assert!(cmd.contains("'\\''"));
    }

    // ── build_schedule_command ─────────────────────────────────

    #[test]
    fn test_schedule_valid() {
        let cmd = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 2 * * *",
            "/var/data",
            "/backups",
        )
        .unwrap();
        assert!(cmd.contains("crontab"));
        assert!(cmd.contains("0 2 * * *"));
        assert!(cmd.contains("/var/data"));
        assert!(cmd.contains("/backups"));
        assert!(cmd.contains("schedule added"));
    }

    #[test]
    fn test_schedule_invalid_cron() {
        let result =
            BackupAdvancedCommandBuilder::build_schedule_command("bad", "/var/data", "/backups");
        assert!(result.is_err());
    }

    #[test]
    fn test_schedule_invalid_paths() {
        let result =
            BackupAdvancedCommandBuilder::build_schedule_command("0 * * * *", "", "/backups");
        assert!(result.is_err());
    }

    #[test]
    fn schedule_refuses_a_newline_in_paths_or_dest() {
        let in_dest = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 2 * * *",
            "/etc",
            "/x\n* * * * * id >/tmp/o\n# ",
        )
        .unwrap_err();
        assert!(in_dest.to_string().contains("dest"), "{in_dest}");
        let in_paths = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 2 * * *",
            "a\r* * * * * id\n#",
            "/backups",
        )
        .unwrap_err();
        assert!(in_paths.to_string().contains("control"), "{in_paths}");
    }

    #[test]
    fn schedule_refuses_a_percent_sign() {
        for (paths, dest) in [("/a%b", "/backups"), ("/a", "/b%c")] {
            let err =
                BackupAdvancedCommandBuilder::build_schedule_command("0 2 * * *", paths, dest)
                    .unwrap_err();
            assert!(err.to_string().contains("'%'"), "{err}");
        }
    }

    #[test]
    fn schedule_puts_paths_after_end_of_options() {
        let cmd =
            BackupAdvancedCommandBuilder::build_schedule_command("0 2 * * *", "-x", "/backups")
                .unwrap();
        // The crontab line is itself quoted for `printf`, so its own quotes
        // appear as `'\''`.
        assert!(cmd.contains(r".tar.gz -- '\''-x'\''"), "{cmd}");
        assert!(cmd.contains("printf '%s\\n' '0 2 * * * tar czf"), "{cmd}");
    }

    #[test]
    fn test_schedule_empty_dest() {
        let result =
            BackupAdvancedCommandBuilder::build_schedule_command("0 * * * *", "/var/data", "");
        assert!(result.is_err());
    }

    // ── refuse_remote_archive ─────────────────────────────────

    #[test]
    fn test_refuse_remote_archive() {
        for bad in [
            "exfil.example:etc.tar",
            "user@host:a.tar",
            "h:/a.tar",
            ":a.tar",
        ] {
            assert!(
                refuse_remote_archive("archive", bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        for ok in [
            "/tmp/a:b.tar",
            "./exfil.example:etc.tar",
            "dir/a:b.tar",
            "/tmp/backup.tar.gz",
            "backup.tar",
        ] {
            assert!(
                refuse_remote_archive("archive", ok).is_ok(),
                "{ok:?} must be accepted"
            );
        }
    }

    #[test]
    fn test_validate_archive_refuses_remote_archive() {
        assert!(validate_archive("exfil.example:etc.tar").is_err());
        assert!(
            BackupAdvancedCommandBuilder::build_verify_command("exfil.example:etc.tar").is_err()
        );
        assert!(
            BackupAdvancedCommandBuilder::build_verify_command("./exfil.example:etc.tar").is_ok()
        );
    }

    #[test]
    fn test_schedule_refuses_remote_dest() {
        let r = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 2 * * *",
            "/etc",
            "exfil.example:",
        );
        assert!(r.is_err());
        let ok =
            BackupAdvancedCommandBuilder::build_schedule_command("0 2 * * *", "/etc", "/backups");
        assert!(ok.is_ok());
    }
}
