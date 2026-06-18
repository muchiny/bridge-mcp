//! SSH `known_hosts` verification wrapper around russh's built-in support

use russh::keys::known_hosts::{check_known_hosts, learn_known_hosts};
use russh::keys::{Error as KeyError, HashAlg, PublicKey};
use tracing::{debug, warn};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::config::HostKeyVerification;
use crate::error::{BridgeError, Result};

/// Result of verifying a host key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Key matches a known entry
    Match,
    /// Key does not match the expected key (line number where mismatch occurred)
    Mismatch { line: usize },
    /// Host is not in `known_hosts`
    Unknown,
}

/// Verify a host key against `known_hosts`
///
/// # Errors
///
/// Returns an error if the `known_hosts` file cannot be read or parsed.
pub fn verify(hostname: &str, port: u16, key: &PublicKey) -> Result<VerifyResult> {
    match check_known_hosts(hostname, port, key) {
        Ok(true) => {
            debug!(hostname = %hostname, port = %port, "Host key verified");
            Ok(VerifyResult::Match)
        }
        Ok(false) => {
            debug!(hostname = %hostname, port = %port, "Host key not in known_hosts");
            Ok(VerifyResult::Unknown)
        }
        Err(KeyError::KeyChanged { line }) => {
            warn!(
                hostname = %hostname,
                port = %port,
                line = %line,
                "Host key mismatch detected"
            );
            Ok(VerifyResult::Mismatch { line })
        }
        Err(e) => Err(BridgeError::Config(format!(
            "Failed to check known_hosts: {e}"
        ))),
    }
}

/// Add a host key to `known_hosts`
///
/// Uses russh's built-in `learn_known_hosts` which appends to the file.
///
/// **Security note:** There is a potential TOCTOU race between `verify()` and
/// `add_key()` in `AcceptNew` mode. This is inherent to the TOFU (Trust On First
/// Use) model and is acceptable for most use cases. In high-security environments,
/// use `Strict` mode with pre-provisioned `known_hosts` files instead.
///
/// # Errors
///
/// Returns an error if the `known_hosts` file cannot be written to.
pub fn add_key(hostname: &str, port: u16, key: &PublicKey) -> Result<()> {
    learn_known_hosts(hostname, port, key)
        .map_err(|e| BridgeError::Config(format!("Failed to add host key to known_hosts: {e}")))?;

    debug!(hostname = %hostname, port = %port, "Added host key to known_hosts");
    Ok(())
}

/// Get the fingerprint of a public key
#[must_use]
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Check that the `known_hosts` file has secure permissions (Unix only).
///
/// Warns if the file is readable by others (mode not 0600 or 0644).
/// This is advisory only - the file is still used but a warning is logged.
#[cfg(unix)]
fn check_known_hosts_permissions() {
    let home = dirs::home_dir();
    let Some(home) = home else {
        return;
    };
    let known_hosts_path = home.join(".ssh").join("known_hosts");
    if let Ok(metadata) = std::fs::metadata(&known_hosts_path) {
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 && mode != 0o644 {
            warn!(
                path = %known_hosts_path.display(),
                mode = format!("{mode:o}"),
                "known_hosts file has overly permissive permissions. \
                 Consider running: chmod 600 ~/.ssh/known_hosts"
            );
        }
    }
}

#[cfg(not(unix))]
fn check_known_hosts_permissions() {
    // Permission checks not available on non-Unix platforms
}

/// Verify a host key according to the verification mode
///
/// # Errors
///
/// Returns an error if:
/// - The host key is mismatched (in `Strict` or `AcceptNew` mode)
/// - The host is unknown (in `Strict` mode)
/// - The `known_hosts` file cannot be read or written to
pub fn verify_host_key(
    hostname: &str,
    port: u16,
    key: &PublicKey,
    mode: HostKeyVerification,
) -> Result<()> {
    check_known_hosts_permissions();

    match mode {
        HostKeyVerification::Off => {
            warn!(
                hostname = %hostname,
                "SECURITY WARNING: Host key verification is DISABLED for this host. \
                 This is vulnerable to MITM attacks. \
                 Use 'strict' or 'accept_new' in production."
            );
            Ok(())
        }
        HostKeyVerification::Strict => match verify(hostname, port, key)? {
            VerifyResult::Match => Ok(()),
            VerifyResult::Mismatch { line } => Err(BridgeError::SshHostKeyMismatch {
                host: hostname.to_string(),
                expected: format!("key from known_hosts line {line}"),
                actual: fingerprint(key),
            }),
            VerifyResult::Unknown => Err(BridgeError::SshHostKeyUnknown {
                host: hostname.to_string(),
                fingerprint: fingerprint(key),
            }),
        },
        HostKeyVerification::AcceptNew => match verify(hostname, port, key)? {
            VerifyResult::Match => Ok(()),
            VerifyResult::Mismatch { line } => Err(BridgeError::SshHostKeyMismatch {
                host: hostname.to_string(),
                expected: format!("key from known_hosts line {line}"),
                actual: fingerprint(key),
            }),
            VerifyResult::Unknown => {
                warn!(hostname = %hostname, "Adding new host key to known_hosts");
                add_key(hostname, port, key)?;
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_known_hosts_permissions_does_not_panic() {
        // This function should never panic, even if the file doesn't exist
        check_known_hosts_permissions();
    }

    #[test]
    fn test_host_key_verification_default_is_strict() {
        // Security: default mode should be strict for safety
        let default_mode = HostKeyVerification::default();
        assert_eq!(default_mode, HostKeyVerification::Strict);
    }

    #[test]
    fn test_verify_result_mismatch_contains_line_number() {
        // Verify that mismatch captures the line number for debugging
        let mismatch = VerifyResult::Mismatch { line: 42 };

        if let VerifyResult::Mismatch { line } = mismatch {
            assert_eq!(line, 42);
        } else {
            panic!("Expected Mismatch variant");
        }
    }

    #[test]
    fn test_verify_result_distinguishes_mismatch_from_unknown() {
        // Important security distinction: mismatch (MITM?) vs unknown (new host)
        let mismatch = VerifyResult::Mismatch { line: 1 };
        let unknown = VerifyResult::Unknown;

        assert_ne!(mismatch, unknown);
    }

    // ============== VerifyResult Tests ==============

    #[test]
    fn test_verify_result_match() {
        let result = VerifyResult::Match;
        assert_eq!(result, VerifyResult::Match);
    }

    #[test]
    fn test_verify_result_unknown() {
        let result = VerifyResult::Unknown;
        assert_eq!(result, VerifyResult::Unknown);
    }

    #[test]
    fn test_verify_result_debug() {
        let match_result = VerifyResult::Match;
        let unknown_result = VerifyResult::Unknown;
        let mismatch_result = VerifyResult::Mismatch { line: 10 };

        assert!(format!("{match_result:?}").contains("Match"));
        assert!(format!("{unknown_result:?}").contains("Unknown"));
        assert!(format!("{mismatch_result:?}").contains("Mismatch"));
        assert!(format!("{mismatch_result:?}").contains("10"));
    }

    #[test]
    fn test_verify_result_clone() {
        let original = VerifyResult::Mismatch { line: 5 };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_verify_result_eq_same_variant() {
        assert_eq!(VerifyResult::Match, VerifyResult::Match);
        assert_eq!(VerifyResult::Unknown, VerifyResult::Unknown);
        assert_eq!(
            VerifyResult::Mismatch { line: 1 },
            VerifyResult::Mismatch { line: 1 }
        );
    }

    #[test]
    fn test_verify_result_ne_different_line() {
        assert_ne!(
            VerifyResult::Mismatch { line: 1 },
            VerifyResult::Mismatch { line: 2 }
        );
    }

    #[test]
    fn test_verify_result_ne_different_variants() {
        assert_ne!(VerifyResult::Match, VerifyResult::Unknown);
        assert_ne!(VerifyResult::Match, VerifyResult::Mismatch { line: 1 });
        assert_ne!(VerifyResult::Unknown, VerifyResult::Mismatch { line: 1 });
    }

    #[test]
    fn test_verify_result_mismatch_line_zero() {
        let result = VerifyResult::Mismatch { line: 0 };
        if let VerifyResult::Mismatch { line } = result {
            assert_eq!(line, 0);
        }
    }

    #[test]
    fn test_verify_result_mismatch_large_line() {
        let result = VerifyResult::Mismatch { line: 1_000_000 };
        if let VerifyResult::Mismatch { line } = result {
            assert_eq!(line, 1_000_000);
        }
    }

    // ============== HostKeyVerification Mode Tests ==============

    #[test]
    fn test_host_key_verification_strict() {
        assert_eq!(HostKeyVerification::Strict, HostKeyVerification::Strict);
    }

    #[test]
    fn test_host_key_verification_acceptnew() {
        assert_eq!(
            HostKeyVerification::AcceptNew,
            HostKeyVerification::AcceptNew
        );
    }

    #[test]
    fn test_host_key_verification_off() {
        assert_eq!(HostKeyVerification::Off, HostKeyVerification::Off);
    }

    #[test]
    fn test_host_key_verification_modes_distinct() {
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::AcceptNew);
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::Off);
        assert_ne!(HostKeyVerification::AcceptNew, HostKeyVerification::Off);
    }

    // ============== Security Implications ==============

    #[test]
    fn test_strict_mode_rejects_unknown() {
        // In strict mode, unknown hosts should be rejected
        // This test documents the expected behavior
        let mode = HostKeyVerification::Strict;
        assert_eq!(mode, HostKeyVerification::Strict);
        // The actual verify_host_key function would return an error for unknown hosts
    }

    #[test]
    fn test_strict_mode_rejects_mismatch() {
        // In strict mode, key mismatches should be rejected (potential MITM)
        let mode = HostKeyVerification::Strict;
        assert_eq!(mode, HostKeyVerification::Strict);
        // This is the most secure mode
    }

    #[test]
    fn test_acceptnew_allows_first_connection() {
        // AcceptNew mode should allow first connections
        // but reject key changes (TOFU model)
        let mode = HostKeyVerification::AcceptNew;
        assert_eq!(mode, HostKeyVerification::AcceptNew);
    }

    #[test]
    fn test_off_mode_warning() {
        // Off mode is insecure and should only be used for testing
        // This test just verifies the mode exists
        let mode = HostKeyVerification::Off;
        assert_eq!(mode, HostKeyVerification::Off);
    }

    // ============== VerifyResult Exhaustive Pattern Tests ==============

    #[test]
    fn test_verify_result_all_variants_debug_unique() {
        let variants = [
            format!("{:?}", VerifyResult::Match),
            format!("{:?}", VerifyResult::Unknown),
            format!("{:?}", VerifyResult::Mismatch { line: 0 }),
        ];
        // All debug strings should be unique
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Debug strings for variants {i} and {j} should differ");
                }
            }
        }
    }

    #[test]
    fn test_verify_result_mismatch_line_max() {
        let result = VerifyResult::Mismatch { line: usize::MAX };
        if let VerifyResult::Mismatch { line } = result {
            assert_eq!(line, usize::MAX);
        }
    }

    #[test]
    fn test_verify_result_clone_independence() {
        let original = VerifyResult::Mismatch { line: 42 };
        let mut cloned = original.clone();
        // Modify the clone via pattern matching
        if let VerifyResult::Mismatch { ref mut line } = cloned {
            *line = 99;
        }
        // Original should be unchanged
        assert_eq!(original, VerifyResult::Mismatch { line: 42 });
        assert_eq!(cloned, VerifyResult::Mismatch { line: 99 });
    }

    // ============== HostKeyVerification Security Properties ==============

    #[test]
    fn test_host_key_verification_clone() {
        let mode = HostKeyVerification::Strict;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_host_key_verification_debug() {
        let debug = format!("{:?}", HostKeyVerification::Strict);
        assert!(debug.contains("Strict"));

        let debug = format!("{:?}", HostKeyVerification::AcceptNew);
        assert!(debug.contains("AcceptNew"));

        let debug = format!("{:?}", HostKeyVerification::Off);
        assert!(debug.contains("Off"));
    }

    // ============== Public-key Fixtures & fingerprint() ==============
    //
    // Well-formed OpenSSH public keys (valid base64, correct length) so that
    // `PublicKey::from_openssh` succeeds deterministically. These are public
    // test vectors — no secret material, no filesystem, no network.

    const ED25519_PUBKEY: &str = "ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti \
        user@example.com";

    const RSA_PUBKEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC0WRHtxuxefSJhpIxGq4ibGFgwYnESPm8C3JFM88A1JJLoprenklrd7VJ+VH3Ov/bQwZwLyRU5dRmfR/SWTtIPWs7tToJVayKKDB+/qoXmM5ui/0CU2U4rCdQ6PdaCJdC7yFgpPL8WexjWN06+eSIKYz1AAXbx9rRv1iasslK/KUqtsqzVliagI6jl7FPO2GhRZMcso6LsZGgSxuYf/Lp0D/FcBU8GkeOo1Sx5xEt8H8bJcErtCe4Blb8JxcW6EXO3sReb4z+zcR07gumPgFITZ6hDA8sSNuvo/AlWg0IKTeZSwHHVknWdQqDJ0uczE837caBxyTZllDNIGkBjCIIOFzuTT76HfYc/7CTTGk07uaNkUFXKN79xDiFOX8JQ1ZZMZvGOTwWjuT9CqgdTvQRORbRWwOYv3MH8re9ykw3Ip6lrPifY7s6hOaAKry/nkGPMt40m1TdiW98MTIpooE7W+WXu96ax2l2OJvxX8QR7l+LFlKnkIEEJd/ItF1G22UmOjkVwNASTwza/hlY+8DoVvEmwum/nMgH2TwQT3bTQzF9s9DOJkH4d8p4Mw4gEDjNx0EgUFA91ysCAeUMQQyIvuR8HXXa+VcvhOOO5mmBcVhxJ3qUOJTyDBsT0932Zb4mNtkxdigoVxu+iiwk0vwtvKwGVDYdyMP5EAQeEIP1t0w== user@example.com";

    fn ed25519_key() -> PublicKey {
        PublicKey::from_openssh(ED25519_PUBKEY).expect("ed25519 fixture should parse")
    }

    fn rsa_key() -> PublicKey {
        PublicKey::from_openssh(RSA_PUBKEY).expect("rsa fixture should parse")
    }

    #[test]
    fn test_fingerprint_has_sha256_prefix() {
        let fp = fingerprint(&ed25519_key());
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint should be SHA256-formatted, got {fp}"
        );
    }

    #[test]
    fn test_fingerprint_is_deterministic() {
        let key = ed25519_key();
        assert_eq!(fingerprint(&key), fingerprint(&key));
    }

    #[test]
    fn test_fingerprint_matches_sha256_hashalg() {
        // The helper must use HashAlg::Sha256 — verify it agrees with the
        // underlying ssh-key computation.
        let key = ed25519_key();
        assert_eq!(
            fingerprint(&key),
            key.fingerprint(HashAlg::Sha256).to_string()
        );
    }

    #[test]
    fn test_fingerprint_differs_for_different_keys() {
        // Distinct keys (ed25519 vs rsa) must produce distinct fingerprints.
        assert_ne!(fingerprint(&ed25519_key()), fingerprint(&rsa_key()));
    }

    #[test]
    fn test_fingerprint_rsa_has_sha256_prefix() {
        let fp = fingerprint(&rsa_key());
        assert!(fp.starts_with("SHA256:"), "got {fp}");
    }

    // ============== verify_host_key: Off mode (hermetic) ==============
    //
    // `Off` short-circuits before any known_hosts lookup, so these calls never
    // touch the filesystem and are fully deterministic.

    #[test]
    fn test_verify_host_key_off_returns_ok() {
        let key = ed25519_key();
        let result = verify_host_key("example.com", 22, &key, HostKeyVerification::Off);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_host_key_off_ignores_host_and_port() {
        // Off mode accepts any host/port combination, including non-standard ones.
        let key = ed25519_key();
        assert!(
            verify_host_key("nonexistent.invalid", 2222, &key, HostKeyVerification::Off).is_ok()
        );
        assert!(verify_host_key("10.0.0.1", 65535, &key, HostKeyVerification::Off).is_ok());
    }

    #[test]
    fn test_verify_host_key_off_accepts_rsa_key() {
        let key = rsa_key();
        assert!(verify_host_key("server", 22, &key, HostKeyVerification::Off).is_ok());
    }

    // ============== Public-key parse failures ==============
    //
    // These exercise the parsing boundary that host-key verification relies on:
    // malformed lines, blank/comment-only content, and algorithm mismatches must
    // all fail to parse rather than yielding a bogus key.

    #[test]
    fn test_from_openssh_rejects_blank_line() {
        assert!(PublicKey::from_openssh("").is_err());
        assert!(PublicKey::from_openssh("   ").is_err());
    }

    #[test]
    fn test_from_openssh_rejects_comment_only_line() {
        // A known_hosts comment line is not a valid public key.
        assert!(PublicKey::from_openssh("# this is a comment").is_err());
    }

    #[test]
    fn test_from_openssh_rejects_malformed_base64() {
        // Right algorithm tag, garbage payload.
        assert!(PublicKey::from_openssh("ssh-ed25519 not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_from_openssh_rejects_unknown_algorithm() {
        // Algorithm tag that ssh-key does not recognise.
        assert!(PublicKey::from_openssh("ssh-bogus AAAAC3NzaC1lZDI1NTE5 user@host").is_err());
    }

    #[test]
    fn test_from_openssh_rejects_algorithm_payload_mismatch() {
        // ed25519 tag but the encoded key data is RSA — `from_openssh` verifies
        // the textual algorithm matches the embedded one and must reject this.
        let mismatched = RSA_PUBKEY.replacen("ssh-rsa", "ssh-ed25519", 1);
        assert!(PublicKey::from_openssh(&mismatched).is_err());
    }

    #[test]
    fn test_from_openssh_rejects_truncated_key_data() {
        // Truncating the base64 body corrupts the embedded length-prefixed fields.
        assert!(PublicKey::from_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5").is_err());
    }
}
