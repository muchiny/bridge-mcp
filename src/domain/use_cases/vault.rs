//! Vault Command Builder
//!
//! Builds `HashiCorp` Vault CLI commands for remote execution via SSH.
//! Supports status, read, list, and write operations.

use std::fmt::Write;

use crate::config::ShellType;
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
    /// Constructs: `vault kv put [-mount={mount}] {path} {key=value}...`
    ///
    /// `data` carries `key=value` pairs; values are typically secrets, so the
    /// caller is expected to pass `Zeroizing<String>` (FIND-030) to avoid
    /// gratuitous heap residency. The slice is borrowed immutably here; the
    /// owner controls when the secret bytes are wiped.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `path` contains unsafe characters.
    pub fn build_write_command(
        path: &str,
        data: &[zeroize::Zeroizing<String>],
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

        for kv in data {
            let _ = write!(cmd, " {}", shell_escape(kv));
        }

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
            zeroize::Zeroizing::new("username=admin".to_string()),
            zeroize::Zeroizing::new("password=secret".to_string()),
        ];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        assert!(cmd.contains("vault kv put 'secret/myapp'"));
        assert!(cmd.contains("'username=admin'"));
        assert!(cmd.contains("'password=secret'"));
    }

    #[test]
    fn test_write_with_mount() {
        let data = vec![zeroize::Zeroizing::new("key=value".to_string())];
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
        let data = vec![zeroize::Zeroizing::new("password=s3cr3t; rm -rf /".to_string())];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/app", &data, None, None).unwrap();
        assert!(cmd.contains("'password=s3cr3t; rm -rf /'"));
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
            zeroize::Zeroizing::new("user=admin".to_string()),
            zeroize::Zeroizing::new("pass=secret".to_string()),
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
        assert!(cmd.contains("'user=admin'"));
        assert!(cmd.contains("'pass=secret'"));
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
        let data: Vec<zeroize::Zeroizing<String>> = vec![];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        assert!(cmd.contains("vault kv put 'secret/myapp'"));
    }

    #[test]
    fn test_write_single_data_item() {
        let data = vec![zeroize::Zeroizing::new("key=val".to_string())];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/myapp", &data, None, None).unwrap();
        assert!(cmd.contains("'secret/myapp' 'key=val'"));
    }

    #[test]
    fn test_write_data_with_single_quotes() {
        let data = vec![zeroize::Zeroizing::new("msg=it's secret".to_string())];
        let cmd =
            VaultCommandBuilder::build_write_command("secret/app", &data, None, None).unwrap();
        assert!(cmd.contains("it'\\''s secret"));
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
}
