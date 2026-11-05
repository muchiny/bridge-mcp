//! SSH Key Management Command Builder
//!
//! Builds SSH key audit, distribution, and generation commands for
//! remote execution via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

const VALID_KEY_TYPES: &[&str] = &["ed25519", "rsa", "ecdsa"];

/// Validate the SSH key type.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the key type is not supported.
pub fn validate_key_type(key_type: &str) -> Result<()> {
    if !VALID_KEY_TYPES.contains(&key_type) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Unsupported key type '{}'. Supported types: {}",
                key_type,
                VALID_KEY_TYPES.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate the key bit length.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the bit length is invalid.
pub fn validate_bits(bits: u32) -> Result<()> {
    if !(256..=16384).contains(&bits) {
        return Err(BridgeError::CommandDenied {
            reason: format!("Invalid key bit length {bits}: must be between 256 and 16384"),
        });
    }
    Ok(())
}

/// Validate a public key string.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the public key is empty,
/// contains newlines, or does not look like an SSH public key.
pub fn validate_public_key(public_key: &str) -> Result<()> {
    if public_key.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Public key must not be empty".to_string(),
        });
    }
    if public_key.contains('\n') || public_key.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Public key must not contain newlines".to_string(),
        });
    }
    if public_key.len() > 10000 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Public key too long: {} chars (max 10000)",
                public_key.len()
            ),
        });
    }
    // Basic format check: should start with a known key type prefix
    let valid_prefixes = [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-",
        "sk-ssh-ed25519",
        "sk-ecdsa-sha2-",
    ];
    if !valid_prefixes.iter().any(|p| public_key.starts_with(p)) {
        return Err(BridgeError::CommandDenied {
            reason: "Public key does not start with a recognized key type prefix".to_string(),
        });
    }
    Ok(())
}

/// Builds SSH key management commands for remote execution.
pub struct KeyManagementCommandBuilder;

impl KeyManagementCommandBuilder {
    /// Build a command to audit SSH authorized keys on a remote host.
    ///
    /// Checks `~/.ssh/authorized_keys` for key count, types, lengths, and ages.
    #[must_use]
    pub fn build_key_audit_command() -> String {
        "echo '=== SSH Key Audit ===' && \
         if [ -f ~/.ssh/authorized_keys ]; then \
           echo \"Key count: $(wc -l < ~/.ssh/authorized_keys)\"; \
           echo '--- Key Types ---'; \
           awk '{print $1}' ~/.ssh/authorized_keys 2>/dev/null | sort | uniq -c | sort -rn; \
           echo '--- Key Details ---'; \
           while IFS= read -r line; do \
             type=$(echo \"$line\" | awk '{print $1}'); \
             comment=$(echo \"$line\" | awk '{print $NF}'); \
             echo \"Type=$type Comment=$comment\"; \
           done < ~/.ssh/authorized_keys; \
           echo '--- File Info ---'; \
           ls -la ~/.ssh/authorized_keys; \
           stat ~/.ssh/authorized_keys 2>/dev/null; \
         else \
           echo 'No authorized_keys file found'; \
         fi"
        .to_string()
    }

    /// Build a command to distribute (append) a public key to a remote host.
    ///
    /// Only appends if the key is not already present.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid.
    pub fn build_key_distribute_command(public_key: &str) -> Result<String> {
        validate_public_key(public_key)?;

        let escaped_key = shell_escape(public_key);
        Ok(format!(
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
             grep -qF -e {escaped_key} ~/.ssh/authorized_keys 2>/dev/null || \
             printf '%s\\n' {escaped_key} >> ~/.ssh/authorized_keys && \
             chmod 600 ~/.ssh/authorized_keys && \
             echo 'Key distributed successfully'"
        ))
    }

    /// Build a command to generate a new SSH key pair.
    ///
    /// Generates the key at `/tmp/mcp_generated_key` with an empty passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the key type or bit length is invalid.
    pub fn build_key_generate_command(key_type: Option<&str>, bits: Option<u32>) -> Result<String> {
        let kt = key_type.unwrap_or("ed25519");
        validate_key_type(kt)?;

        if let Some(b) = bits {
            validate_bits(b)?;
        }

        let escaped_type = shell_escape(kt);
        let mut cmd = format!(
            "rm -f /tmp/mcp_generated_key /tmp/mcp_generated_key.pub && \
             ssh-keygen -t {escaped_type}"
        );

        if let Some(b) = bits {
            cmd = format!("{cmd} -b {b}");
        }

        cmd = format!(
            "{cmd} -f /tmp/mcp_generated_key -N '' -q && \
             echo '=== Public Key ===' && \
             cat /tmp/mcp_generated_key.pub && \
             echo '=== Key Fingerprint ===' && \
             ssh-keygen -lf /tmp/mcp_generated_key.pub"
        );

        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribute_prints_the_key_with_a_format() {
        let cmd = KeyManagementCommandBuilder::build_key_distribute_command(
            "ssh-ed25519 AAAAC3 user\\nhost",
        )
        .unwrap();
        assert!(
            cmd.contains(r"printf '%s\n' 'ssh-ed25519 AAAAC3 user\nhost' >>"),
            "{cmd}"
        );
        assert!(cmd.contains("grep -qF -e 'ssh-ed25519"), "{cmd}");
        assert!(!cmd.contains("echo 'ssh"), "{cmd}");
    }

    // ── validate_key_type ─────────────────────────────────────

    #[test]
    fn test_validate_key_type_valid() {
        assert!(validate_key_type("ed25519").is_ok());
        assert!(validate_key_type("rsa").is_ok());
        assert!(validate_key_type("ecdsa").is_ok());
    }

    #[test]
    fn test_validate_key_type_invalid() {
        let err = validate_key_type("dsa").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("dsa"));
                assert!(reason.contains("Unsupported"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_key_type_empty() {
        assert!(validate_key_type("").is_err());
    }

    // ── validate_bits ─────────────────────────────────────────

    #[test]
    fn test_validate_bits_valid() {
        assert!(validate_bits(256).is_ok());
        assert!(validate_bits(2048).is_ok());
        assert!(validate_bits(4096).is_ok());
        assert!(validate_bits(16384).is_ok());
    }

    #[test]
    fn test_validate_bits_too_small() {
        let err = validate_bits(128).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("128"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_bits_too_large() {
        assert!(validate_bits(32768).is_err());
    }

    // ── validate_public_key ───────────────────────────────────

    #[test]
    fn test_validate_public_key_valid() {
        assert!(validate_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host").is_ok());
        assert!(validate_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ user@host").is_ok());
        assert!(validate_public_key("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI user@host").is_ok());
    }

    #[test]
    fn test_validate_public_key_empty() {
        let err = validate_public_key("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_public_key_newline() {
        assert!(validate_public_key("ssh-rsa key\ninjection").is_err());
    }

    #[test]
    fn test_validate_public_key_too_long() {
        let long_key = format!("ssh-rsa {}", "A".repeat(10000));
        assert!(validate_public_key(&long_key).is_err());
    }

    #[test]
    fn test_validate_public_key_bad_prefix() {
        assert!(validate_public_key("invalid-type AAAAB3 user@host").is_err());
    }

    // ── build_key_audit_command ──────────────────────────────

    #[test]
    fn test_audit_command() {
        let cmd = KeyManagementCommandBuilder::build_key_audit_command();
        assert!(cmd.contains("SSH Key Audit"));
        assert!(cmd.contains("authorized_keys"));
        assert!(cmd.contains("wc -l"));
        assert!(cmd.contains("Key Types"));
    }

    #[test]
    fn test_audit_command_checks_file_exists() {
        let cmd = KeyManagementCommandBuilder::build_key_audit_command();
        assert!(cmd.contains("if [ -f ~/.ssh/authorized_keys ]"));
    }

    // ── build_key_distribute_command ────────────────────────

    #[test]
    fn test_distribute_valid_key() {
        let cmd = KeyManagementCommandBuilder::build_key_distribute_command(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host",
        )
        .unwrap();
        assert!(cmd.contains("grep -qF"));
        assert!(cmd.contains("authorized_keys"));
        assert!(cmd.contains("mkdir -p ~/.ssh"));
        assert!(cmd.contains("chmod 700"));
        assert!(cmd.contains("chmod 600"));
    }

    #[test]
    fn test_distribute_invalid_key() {
        let result = KeyManagementCommandBuilder::build_key_distribute_command("not-a-valid-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_distribute_empty_key() {
        let result = KeyManagementCommandBuilder::build_key_distribute_command("");
        assert!(result.is_err());
    }

    #[test]
    fn test_distribute_shell_injection() {
        let cmd = KeyManagementCommandBuilder::build_key_distribute_command(
            "ssh-rsa AAAAB3'; rm -rf /; echo '",
        )
        .unwrap();
        assert!(cmd.contains("'\\''"));
    }

    // ── build_key_generate_command ──────────────────────────

    #[test]
    fn test_generate_defaults() {
        let cmd = KeyManagementCommandBuilder::build_key_generate_command(None, None).unwrap();
        assert!(cmd.contains("ssh-keygen"));
        assert!(cmd.contains("ed25519"));
        assert!(cmd.contains("/tmp/mcp_generated_key"));
        assert!(cmd.contains("-N ''"));
    }

    #[test]
    fn test_generate_rsa_with_bits() {
        let cmd = KeyManagementCommandBuilder::build_key_generate_command(Some("rsa"), Some(4096))
            .unwrap();
        assert!(cmd.contains("-t 'rsa'"));
        assert!(cmd.contains("-b 4096"));
    }

    #[test]
    fn test_generate_invalid_type() {
        let result = KeyManagementCommandBuilder::build_key_generate_command(Some("dsa"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_invalid_bits() {
        let result = KeyManagementCommandBuilder::build_key_generate_command(Some("rsa"), Some(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_shows_fingerprint() {
        let cmd = KeyManagementCommandBuilder::build_key_generate_command(None, None).unwrap();
        assert!(cmd.contains("Key Fingerprint"));
        assert!(cmd.contains("ssh-keygen -lf"));
    }

    #[test]
    fn test_generate_cleans_up_old_key() {
        let cmd = KeyManagementCommandBuilder::build_key_generate_command(None, None).unwrap();
        assert!(cmd.contains("rm -f /tmp/mcp_generated_key"));
    }
}
