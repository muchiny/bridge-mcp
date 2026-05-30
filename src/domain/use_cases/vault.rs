//! Vault Command Builder
//!
//! Builds `HashiCorp` Vault CLI commands for remote execution via SSH.
//! Supports status, read, list, and write operations.

use std::fmt::Write;

use crate::config::{RedactedSecret, ShellType};
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a Vault path contains only safe characters.
/// Allows: alphanumeric, slashes, hyphens, underscores, dots.
/// Rejects path traversal (`..`).
pub fn validate_vault_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Vault path cannot be empty".to_string(),
        });
    }
    if path.split('/').any(|component| component == "..") {
        return Err(BridgeError::CommandDenied {
            reason: "Path traversal ('..') is not allowed in Vault paths".to_string(),
        });
    }
    if !path
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid Vault path '{path}': must contain only alphanumeric characters, \
                 slashes, hyphens, underscores, or dots"
            ),
        });
    }
    Ok(())
}

/// Builds Vault CLI commands for remote execution.
pub struct VaultCommandBuilder;

impl VaultCommandBuilder {
    /// Build a `vault status` command.
    ///
    /// Constructs: `vault status [-format={fmt}]`
    #[must_use]
    pub fn build_status_command(vault_addr: Option<&str>, output_format: Option<&str>) -> String {
        let mut cmd = String::new();

        if let Some(addr) = vault_addr {
            let _ = write!(cmd, "VAULT_ADDR={} ", shell_escape(addr));
        }

        cmd.push_str("vault status");

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        cmd
    }

    /// Build a `vault kv get` command.
    ///
    /// Constructs: `vault kv get [-mount={mount}] [-format={fmt}] [-field={f}] {path}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_read_command(
        path: &str,
        vault_addr: Option<&str>,
        mount: Option<&str>,
        field: Option<&str>,
        output_format: Option<&str>,
    ) -> Result<String> {
        validate_vault_path(path)?;
        let mut cmd = String::new();

        if let Some(addr) = vault_addr {
            let _ = write!(cmd, "VAULT_ADDR={} ", shell_escape(addr));
        }

        cmd.push_str("vault kv get");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        if let Some(f) = field {
            let _ = write!(cmd, " -field={}", shell_escape(f));
        }

        let _ = write!(cmd, " {}", shell_escape(path));
        Ok(cmd)
    }

    /// Build a `vault kv list` command.
    ///
    /// Constructs: `vault kv list [-mount={mount}] [-format={fmt}] {path}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_list_command(
        path: &str,
        vault_addr: Option<&str>,
        mount: Option<&str>,
        output_format: Option<&str>,
    ) -> Result<String> {
        validate_vault_path(path)?;
        let mut cmd = String::new();

        if let Some(addr) = vault_addr {
            let _ = write!(cmd, "VAULT_ADDR={} ", shell_escape(addr));
        }

        cmd.push_str("vault kv list");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        if let Some(fmt) = output_format {
            let _ = write!(cmd, " -format={}", shell_escape(fmt));
        }

        let _ = write!(cmd, " {}", shell_escape(path));
        Ok(cmd)
    }

    /// Build a `vault kv put` command.
    ///
    /// Constructs:
    /// ```text
    /// vault kv put [-mount={mount}] {path} - <<'VAULT_DATA_EOF_<uuid>'
    /// k1=v1
    /// k2=v2
    /// VAULT_DATA_EOF_<uuid>
    /// ```
    ///
    /// **FIND-031 (Sprint 2 Task 21):** the `key=value` pairs are piped via
    /// stdin (`-` argument + heredoc) instead of being appended to argv.
    /// The previous shape `vault kv put path key=secret_value` exposed every
    /// secret value to anyone running `ps eww` on the remote host for the
    /// lifetime of the vault process. The heredoc body is shell-literal
    /// (single-quoted terminator, no expansion) and the terminator is
    /// randomized per call to defeat any value that tries to close the
    /// heredoc early. Same pattern as `template_apply` (commit 2da5d55).
    ///
    /// `data` carries `key=value` pairs; values are typically secrets, so the
    /// caller is expected to pass [`RedactedSecret`] (FIND-030) to avoid
    /// gratuitous heap residency and to make the pairs leak-proof under
    /// `Debug`/`Display`/`Serialize`. The slice is borrowed immutably here;
    /// the owner controls when the secret bytes are wiped. Each element is
    /// read here through its `Deref<Target = str>` (the audited plaintext
    /// boundary) only to assemble the shell-literal heredoc body.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_write_command(
        path: &str,
        data: &[RedactedSecret],
        vault_addr: Option<&str>,
        mount: Option<&str>,
    ) -> Result<String> {
        validate_vault_path(path)?;
        let mut cmd = String::new();

        if let Some(addr) = vault_addr {
            let _ = write!(cmd, "VAULT_ADDR={} ", shell_escape(addr));
        }

        cmd.push_str("vault kv put");

        if let Some(m) = mount {
            let _ = write!(cmd, " -mount={}", shell_escape(m));
        }

        let _ = write!(cmd, " {}", shell_escape(path));

        // FIND-031: pipe data via stdin heredoc. Terminator is randomized
        // and re-rolled if any value happens to contain a line equal to the
        // candidate terminator (astronomically unlikely with a UUID, but
        // defended in depth — an attacker who controls a value could
        // otherwise close the heredoc early).
        let terminator = loop {
            let candidate = format!("VAULT_DATA_EOF_{}", uuid::Uuid::new_v4().simple());
            if !data
                .iter()
                .any(|kv| kv.lines().any(|l| l == candidate.as_str()))
            {
                break candidate;
            }
        };

        let _ = writeln!(cmd, " - <<'{terminator}'");
        for kv in data {
            let _ = writeln!(cmd, "{}", kv.as_str());
        }
        cmd.push_str(&terminator);

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_vault_path_valid() {
        assert!(validate_vault_path("secret/myapp").is_ok());
        assert!(validate_vault_path("secret/my-app/config").is_ok());
        assert!(validate_vault_path("kv/data/app_config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_invalid() {
        assert!(validate_vault_path("").is_err());
        assert!(validate_vault_path("secret/$(whoami)").is_err());
        assert!(validate_vault_path("secret; rm -rf /").is_err());
    }

    #[test]
    fn test_status_default() {
        let cmd = VaultCommandBuilder::build_status_command(None, None);
        assert_eq!(cmd, "vault status");
    }

    #[test]
    fn test_status_with_addr() {
        let cmd =
            VaultCommandBuilder::build_status_command(Some("https://vault.example.com:8200"), None);
        assert!(cmd.contains("VAULT_ADDR='https://vault.example.com:8200'"));
        assert!(cmd.contains("vault status"));
    }

    #[test]
    fn test_status_json() {
        let cmd = VaultCommandBuilder::build_status_command(None, Some("json"));
        assert!(cmd.contains("-format='json'"));
    }

    #[test]
    fn test_read_simple() {
        let cmd = VaultCommandBuilder::build_read_command("secret/myapp", None, None, None, None)
            .unwrap();
        assert!(cmd.contains("vault kv get 'secret/myapp'"));
    }

    #[test]
    fn test_read_with_mount() {
        let cmd = VaultCommandBuilder::build_read_command(
            "myapp/config",
            None,
            Some("secret"),
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("-mount='secret'"));
        assert!(cmd.contains("'myapp/config'"));
    }

    #[test]
    fn test_read_with_field() {
        let cmd = VaultCommandBuilder::build_read_command(
            "secret/myapp",
            None,
            None,
            Some("password"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-field='password'"));
    }

    #[test]
    fn test_list_simple() {
        let cmd = VaultCommandBuilder::build_list_command("secret/", None, None, None).unwrap();
        assert!(cmd.contains("vault kv list 'secret/'"));
    }

    #[test]
    fn test_list_json() {
        let cmd =
            VaultCommandBuilder::build_list_command("secret/", None, None, Some("json")).unwrap();
        assert!(cmd.contains("-format='json'"));
    }

    #[test]
    fn test_write_simple() {
        let data = vec![
            RedactedSecret::from("username=admin"),
            RedactedSecret::from("password=secret"),
        ];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        // FIND-031: argv is `vault kv put 'path' - <<'TERMINATOR'`; values
        // live in the heredoc body, not as argv-visible `key=value` pairs.
        assert!(cmd.contains("vault kv put 'secret/myapp' - <<"));
        // Body is shell-literal — values appear verbatim, not single-quoted.
        assert!(cmd.contains("\nusername=admin\n"));
        assert!(cmd.contains("\npassword=secret\n"));
    }

    #[test]
    fn test_write_with_mount() {
        let data = vec![RedactedSecret::from("key=value")];
        let cmd = VaultCommandBuilder::build_write_command("myapp/config", &data, None, Some("kv"))
            .unwrap();
        assert!(cmd.contains("-mount='kv'"));
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_status_injection_in_vault_addr() {
        let cmd =
            VaultCommandBuilder::build_status_command(Some("https://vault.com; whoami"), None);
        assert!(cmd.contains("VAULT_ADDR='https://vault.com; whoami'"));
    }

    #[test]
    fn test_write_injection_in_data_value() {
        let data = vec![RedactedSecret::from("password=s3cr3t; rm -rf /")];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/app", &data, None, None).unwrap();
        // FIND-031: value is a heredoc body line (single-quoted terminator
        // disables shell expansion), so `;` and `rm -rf /` are literal data,
        // not shell metacharacters. Verify the line shape.
        assert!(cmd.contains("\npassword=s3cr3t; rm -rf /\n"));
    }

    #[test]
    fn test_read_injection_in_field() {
        let cmd = VaultCommandBuilder::build_read_command(
            "secret/app",
            None,
            None,
            Some("$(cat /etc/passwd)"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-field='$(cat /etc/passwd)'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_read_all_options() {
        let cmd = VaultCommandBuilder::build_read_command(
            "secret/myapp",
            Some("https://vault:8200"),
            Some("kv"),
            Some("password"),
            Some("json"),
        )
        .unwrap();
        assert!(cmd.contains("VAULT_ADDR='https://vault:8200'"));
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("-format='json'"));
        assert!(cmd.contains("-field='password'"));
        assert!(cmd.contains("'secret/myapp'"));
    }

    #[test]
    fn test_list_all_options() {
        let cmd = VaultCommandBuilder::build_list_command(
            "secret/apps/",
            Some("https://vault:8200"),
            Some("kv"),
            Some("json"),
        )
        .unwrap();
        assert!(cmd.contains("VAULT_ADDR='https://vault:8200'"));
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("-format='json'"));
        assert!(cmd.contains("'secret/apps/'"));
    }

    #[test]
    fn test_write_all_options() {
        let data = vec![
            RedactedSecret::from("user=admin"),
            RedactedSecret::from("pass=secret"),
        ];
        let cmd = VaultCommandBuilder::build_write_command(
            "secret/myapp",
            &data,
            Some("https://vault:8200"),
            Some("kv"),
        )
        .unwrap();
        assert!(cmd.contains("VAULT_ADDR='https://vault:8200'"));
        assert!(cmd.contains("-mount='kv'"));
        assert!(cmd.contains("'secret/myapp'"));
        // FIND-031: values are heredoc body lines, not argv args.
        assert!(cmd.contains("\nuser=admin\n"));
        assert!(cmd.contains("\npass=secret\n"));
    }

    #[test]
    fn test_status_all_options() {
        let cmd =
            VaultCommandBuilder::build_status_command(Some("https://vault:8200"), Some("json"));
        assert!(cmd.contains("VAULT_ADDR='https://vault:8200'"));
        assert!(cmd.contains("-format='json'"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_write_empty_data() {
        let data: Vec<RedactedSecret> = vec![];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        // FIND-031: even with no data, the heredoc structure is still produced
        // (vault accepts an empty body — a no-op write).
        assert!(cmd.contains("vault kv put 'secret/myapp' - <<"));
    }

    #[test]
    fn test_write_single_data_item() {
        let data = vec![RedactedSecret::from("key=val")];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        // FIND-031: shape is `... 'secret/myapp' - <<'TERMINATOR'\nkey=val\nTERMINATOR`.
        assert!(cmd.contains("'secret/myapp' - <<"));
        assert!(cmd.contains("\nkey=val\n"));
    }

    #[test]
    fn test_write_data_with_single_quotes() {
        let data = vec![RedactedSecret::from("msg=it's secret")];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/app", &data, None, None).unwrap();
        // FIND-031: heredoc body is shell-literal; the apostrophe is preserved
        // verbatim, no shell-escape needed (the single-quoted terminator
        // disables expansion).
        assert!(cmd.contains("\nmsg=it's secret\n"));
    }

    #[test]
    fn test_read_minimal() {
        let cmd = VaultCommandBuilder::build_read_command("secret/myapp", None, None, None, None)
            .unwrap();
        assert_eq!(cmd, "vault kv get 'secret/myapp'");
    }

    #[test]
    fn test_list_minimal() {
        let cmd = VaultCommandBuilder::build_list_command("secret/", None, None, None).unwrap();
        assert_eq!(cmd, "vault kv list 'secret/'");
    }

    // ============== validate_vault_path Additional Tests ==============

    #[test]
    fn test_validate_vault_path_with_dots() {
        assert!(validate_vault_path("secret/v1.0/config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_with_underscores() {
        assert!(validate_vault_path("kv/my_app/data_config").is_ok());
    }

    #[test]
    fn test_validate_vault_path_with_spaces() {
        assert!(validate_vault_path("secret/my app").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_pipe() {
        assert!(validate_vault_path("secret/app|cmd").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_ampersand() {
        assert!(validate_vault_path("secret/app&data").is_err());
    }

    #[test]
    fn test_validate_vault_path_with_backtick() {
        assert!(validate_vault_path("secret/`whoami`").is_err());
    }

    #[test]
    fn test_validate_vault_path_traversal_rejected() {
        assert!(validate_vault_path("secret/../etc/shadow").is_err());
        assert!(validate_vault_path("../secret/data").is_err());
        assert!(validate_vault_path("secret/data/..").is_err());
    }

    #[test]
    fn test_validate_vault_path_single_dot_allowed() {
        assert!(validate_vault_path("secret/v1.0/config").is_ok());
        assert!(validate_vault_path("secret/my.app").is_ok());
    }

    // ============== FIND-031: argv leak prevention ==============

    /// FIND-031: secrets must not appear as `vault kv put path KEY=VALUE`
    /// because the remote process's `ps eww` would expose `VALUE`.
    /// Instead the builder pipes a stdin heredoc whose body is shell-literal
    /// (single-quoted terminator), so `VALUE` lives in the kernel pipe buffer
    /// and never in argv.
    #[test]
    fn vault_write_excludes_secret_value_from_argv() {
        let data = vec![RedactedSecret::from("k=topsecret")];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/foo", &data, None, None).unwrap();

        // Split on `<<` — anything before is argv, anything after is the
        // heredoc construct (terminator + body). Secret may appear in the
        // body, never in argv.
        let argv_only = cmd.split("<<").next().unwrap();
        assert!(
            !argv_only.contains("topsecret"),
            "FIND-031: secret leaked into argv portion of command: {cmd}"
        );
    }

    /// FIND-031: the builder must use a stdin pipe (`-` argument + heredoc).
    #[test]
    fn vault_write_uses_stdin_heredoc() {
        let data = vec![RedactedSecret::from("k=v")];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/foo", &data, None, None).unwrap();

        assert!(
            cmd.contains("vault kv put"),
            "command must still invoke vault kv put: {cmd}"
        );
        // The dash signals "read key=value lines from stdin" to vault.
        assert!(
            cmd.contains(" - <<"),
            "FIND-031: must pipe data via stdin heredoc, got: {cmd}"
        );
    }

    /// FIND-031: heredoc terminator is randomized so a malicious value
    /// cannot close the heredoc early and inject shell. Same pattern as
    /// `template_apply` (commit 2da5d55).
    #[test]
    fn vault_write_heredoc_terminator_is_randomized() {
        let data = vec![RedactedSecret::from("k=v")];
        let cmd1 =
            VaultCommandBuilder::build_write_command("secret/foo", &data, None, None).unwrap();
        let cmd2 =
            VaultCommandBuilder::build_write_command("secret/foo", &data, None, None).unwrap();
        assert_ne!(
            cmd1, cmd2,
            "heredoc terminator must be re-rolled per call to defeat injection"
        );
    }
}
