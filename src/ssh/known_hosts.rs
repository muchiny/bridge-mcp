//! SSH `known_hosts` verification wrapper around russh's built-in support

use std::path::Path;

use russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path};
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
    let result = match default_known_hosts_path() {
        Some(path) => verify_at(&path, hostname, port, key)?,
        // No home directory: nothing has been pinned, so nothing is known.
        None => VerifyResult::Unknown,
    };
    match result {
        VerifyResult::Match => debug!(hostname = %hostname, port = %port, "Host key verified"),
        VerifyResult::Unknown => {
            debug!(hostname = %hostname, port = %port, "Host key not in known_hosts");
        }
        VerifyResult::Mismatch { line } => {
            warn!(hostname = %hostname, port = %port, line = %line, "Host key mismatch detected");
        }
    }
    Ok(result)
}

/// The `known_hosts` file russh reads by default.
///
/// Mirrors russh's own private `known_hosts_path()`
/// (`home_dir()/.ssh/known_hosts`) so [`verify`] and [`add_key`] can delegate to
/// the path-taking variants that tests can actually exercise. Duplicating three
/// lines is the price of moving the SUBSTANCE — the `KeyError` to
/// [`VerifyResult`] mapping, and the write itself — into functions a test can
/// reach.
#[must_use]
pub fn default_known_hosts_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|home| home.join(".ssh").join("known_hosts"))
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
    let path = default_known_hosts_path().ok_or_else(|| {
        BridgeError::Config("Cannot locate known_hosts: no home directory".to_string())
    })?;
    add_key_at(&path, hostname, port, key)?;
    debug!(hostname = %hostname, port = %port, "Added host key to known_hosts");
    Ok(())
}

/// Append a host key to a specific `known_hosts` file.
///
/// [`add_key`] writes to the operator's real `~/.ssh/known_hosts`, which no test
/// can own — so nothing verified that it wrote anything at all, and a mutant
/// replacing its body with `Ok(())` survived. That mutant is not cosmetic: this
/// is the write that makes trust-on-first-use *stick*. If it silently did
/// nothing, every connection would look like a first contact and a changed host
/// key would never be detected — the whole point of `AcceptNew`.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn add_key_at(path: &Path, hostname: &str, port: u16, key: &PublicKey) -> Result<()> {
    learn_known_hosts_path(hostname, port, key, path)
        .map_err(|e| BridgeError::Config(format!("Failed to add host key to known_hosts: {e}")))?;
    Ok(())
}

/// Check a host key against a specific `known_hosts` file.
///
/// The path-taking twin of [`verify`], for the same reason as [`add_key_at`]:
/// it is what lets a test assert that a key written by `add_key_at` is
/// afterwards recognised, which is the round trip trust-on-first-use rests on.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn verify_at(path: &Path, hostname: &str, port: u16, key: &PublicKey) -> Result<VerifyResult> {
    match check_known_hosts_path(hostname, port, key, path) {
        Ok(true) => Ok(VerifyResult::Match),
        Ok(false) => Ok(VerifyResult::Unknown),
        Err(KeyError::KeyChanged { line }) => Ok(VerifyResult::Mismatch { line }),
        Err(e) => Err(BridgeError::Config(format!(
            "Failed to check known_hosts: {e}"
        ))),
    }
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
/// Whether a `known_hosts` mode is too permissive to hold pinned host keys.
///
/// Split out of [`check_known_hosts_permissions`] because that function's only
/// effect is a `warn!`, which no test can observe — a mutant replacing its whole
/// body with `()` survived, and would have gone on surviving whatever tests were
/// added around it. The RULE is what matters and the rule is pure, so it is
/// tested here and the logging stays a thin wrapper.
///
/// `0o644` is allowed as the common default even though it is group/world
/// readable: `known_hosts` holds public keys, and readability is not the risk —
/// writability is, since anyone who can write it can re-pin a host.
#[cfg(unix)]
const fn mode_is_too_permissive(mode: u32) -> bool {
    let mode = mode & 0o777;
    mode & 0o077 != 0 && mode != 0o644
}

#[cfg(unix)]
fn check_known_hosts_permissions() {
    let home = dirs::home_dir();
    let Some(home) = home else {
        return;
    };
    let known_hosts_path = home.join(".ssh").join("known_hosts");
    if let Ok(metadata) = std::fs::metadata(&known_hosts_path) {
        let mode = metadata.mode() & 0o777;
        if mode_is_too_permissive(mode) {
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
        mode => match decide(hostname, key, mode, verify(hostname, port, key)?) {
            Decision::Allow => Ok(()),
            Decision::Reject(e) => Err(e),
            Decision::LearnThenAllow => {
                warn!(hostname = %hostname, "Adding new host key to known_hosts");
                add_key(hostname, port, key)?;
                Ok(())
            }
        },
    }
}

/// What [`verify_host_key`] does with what [`verify`] found.
#[derive(Debug)]
enum Decision {
    /// The key is trusted; proceed.
    Allow,
    /// The host is new and the mode says to trust it on first use.
    LearnThenAllow,
    /// Refuse the connection.
    Reject(BridgeError),
}

/// The host-key decision, separated from the I/O that feeds it.
///
/// This is the anti-MITM boundary, and until this split it could not be tested:
/// `verify` reads the operator's real `~/.ssh/known_hosts` through russh, so
/// exercising the (mode, result) matrix meant owning the filesystem. It was
/// therefore never exercised — coverage showed the whole `Strict` and
/// `AcceptNew` arms untouched, the two arms that decide whether a changed host
/// key stops a connection.
///
/// `Off` is handled by the caller and never reaches here: it returns without
/// consulting `known_hosts` at all, so there is nothing to decide.
///
/// A `Mismatch` is refused in BOTH modes. That is the MITM case — a host whose
/// key changed since it was pinned — and `AcceptNew` means "trust a host I have
/// never seen", not "trust a host whose key changed".
fn decide(
    hostname: &str,
    key: &PublicKey,
    mode: HostKeyVerification,
    result: VerifyResult,
) -> Decision {
    match (mode, result) {
        (_, VerifyResult::Match) => Decision::Allow,

        (_, VerifyResult::Mismatch { line }) => Decision::Reject(BridgeError::SshHostKeyMismatch {
            host: hostname.to_string(),
            expected: format!("key from known_hosts line {line}"),
            actual: fingerprint(key),
        }),

        (HostKeyVerification::AcceptNew, VerifyResult::Unknown) => Decision::LearnThenAllow,

        // `Off` shares `Strict`'s answer here, but for a different reason, and
        // the pairing is deliberate rather than incidental: `Off`
        // short-circuits in `verify_host_key` and never reaches this function.
        // If a refactor ever routes it here, refusing is the only safe reading
        // — this function's contract is "decide from known_hosts", and `Off`
        // means known_hosts was never consulted. A silent `Allow` would be a
        // MITM hole introduced by an unrelated change.
        (HostKeyVerification::Strict | HostKeyVerification::Off, VerifyResult::Unknown) => {
            Decision::Reject(BridgeError::SshHostKeyUnknown {
                host: hostname.to_string(),
                fingerprint: fingerprint(key),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================== the host-key decision matrix =====================
    //
    // Coverage showed the `Strict` and `AcceptNew` arms of `verify_host_key`
    // entirely unexercised — the two arms that decide whether a CHANGED host
    // key stops a connection. Nothing here touches the filesystem: `decide` is
    // fed the `VerifyResult` directly, which is what made the matrix testable.

    /// A real ed25519 public key, generated once and pinned as a test vector so
    /// these tests need neither an RNG nor a keypair on disk.
    // No trailing comment, deliberately — see
    // `russh_writes_a_comment_its_own_reader_then_rejects` below.
    const TEST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN5xFcKcptRUc9Cr9bSE4MXUBAVTHnFwXhp+b06rDdq2";

    fn test_key() -> PublicKey {
        PublicKey::from_openssh(TEST_KEY).expect("pinned test vector must parse")
    }

    // ============== trust-on-first-use actually persists ==============
    //
    // A mutant replacing `add_key`'s body with `Ok(())` survived: nothing
    // asserted that it wrote anything. That is the write TOFU rests on — if it
    // silently did nothing, every connection would look like a first contact
    // and a changed host key would never be caught.

    const OTHER_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZSsIIjBzfod0v6mcme2PjFBk4nS2gKjs21YVXaVZmX";

    fn other_key() -> PublicKey {
        PublicKey::from_openssh(OTHER_KEY).expect("pinned test vector must parse")
    }

    // ============== the permission rule ==============

    #[cfg(unix)]
    #[test]
    fn private_and_default_modes_are_accepted() {
        for mode in [0o600, 0o400, 0o644] {
            assert!(
                !mode_is_too_permissive(mode),
                "{mode:o} must be accepted: known_hosts holds public keys, and \
                 readability is not the risk"
            );
        }
    }

    /// Writability is the risk: whoever can write `known_hosts` can re-pin a
    /// host, which turns the anti-MITM control off without touching config.
    #[cfg(unix)]
    #[test]
    fn group_or_world_writable_modes_are_refused() {
        for mode in [0o666, 0o777, 0o620, 0o602, 0o660, 0o606] {
            assert!(
                mode_is_too_permissive(mode),
                "{mode:o} lets someone else re-pin a host and must be flagged"
            );
        }
    }

    /// `0o640` is group-READABLE only, yet flagged — the rule treats any bit
    /// outside owner as suspect except the 0o644 default. Pinned so the
    /// deliberate asymmetry with 0o644 is not "simplified" away by accident.
    #[cfg(unix)]
    #[test]
    fn the_rule_flags_group_readable_modes_other_than_the_644_default() {
        assert!(mode_is_too_permissive(0o640));
        assert!(!mode_is_too_permissive(0o644));
    }

    #[cfg(unix)]
    #[test]
    fn high_bits_outside_the_permission_mask_are_ignored() {
        // A full st_mode carries the file type in the high bits; the rule must
        // judge the permission bits alone.
        assert!(!mode_is_too_permissive(0o100_600));
        assert!(mode_is_too_permissive(0o100_666));
    }

    /// A russh 0.63 defect, pinned so we notice if it is ever fixed.
    ///
    /// `learn_known_hosts_path` writes the key's trailing comment verbatim, and
    /// `check_known_hosts_path` — russh's own reader — then reports that line as
    /// `KeyChanged`. A `known_hosts` entry carrying a comment is therefore read
    /// as a CHANGED host key: a false MITM alarm.
    ///
    /// It fails closed, so it refuses rather than trusts, and keys taken off the
    /// wire during a handshake carry no comment — so bridge-mcp's own writes are
    /// unaffected. An operator whose `known_hosts` has commented entries would
    /// see spurious mismatches.
    ///
    /// This test asserts the CURRENT behaviour, not the desired one. When it
    /// starts failing, russh has fixed the round trip and this can go.
    #[test]
    fn russh_writes_a_comment_its_own_reader_then_rejects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let commented = PublicKey::from_openssh(&format!("{TEST_KEY} a-comment"))
            .expect("a commented key must parse");

        add_key_at(&path, "example.test", 22, &commented).expect("add_key_at");

        assert!(
            matches!(
                verify_at(&path, "example.test", 22, &commented).expect("verify"),
                VerifyResult::Mismatch { .. }
            ),
            "russh still misreads its own commented entry; if this fails, the \
             upstream round trip is fixed and this test can be removed"
        );
    }

    #[test]
    fn a_learned_key_is_written_and_then_recognised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");

        // Before: the host is unknown.
        assert_eq!(
            verify_at(&path, "example.test", 22, &test_key()).expect("verify"),
            VerifyResult::Unknown,
            "an empty known_hosts must not recognise anything"
        );

        add_key_at(&path, "example.test", 22, &test_key()).expect("add_key_at");

        // The file must actually have grown — an `Ok(())` that wrote nothing
        // would pass every assertion that only looks at return values.
        let written = std::fs::read_to_string(&path).expect("known_hosts must exist");
        assert!(
            !written.trim().is_empty(),
            "add_key_at must write the key, not merely return Ok"
        );

        // After: the same key is recognised.
        assert_eq!(
            verify_at(&path, "example.test", 22, &test_key()).expect("verify"),
            VerifyResult::Match,
            "a key just learned must be recognised on the next connection"
        );
    }

    /// The reason TOFU is worth persisting: once pinned, a DIFFERENT key for
    /// the same host is a mismatch, not a new host.
    #[test]
    fn a_different_key_for_a_pinned_host_is_a_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");

        add_key_at(&path, "example.test", 22, &test_key()).expect("add_key_at");

        match verify_at(&path, "example.test", 22, &other_key()).expect("verify") {
            VerifyResult::Mismatch { line } => {
                assert!(line > 0, "line must be 1-based, got {line}");
            }
            other => panic!("a changed key must be a Mismatch, got {other:?}"),
        }
    }

    /// A different host is unknown, not a mismatch — the pin is per host.
    #[test]
    fn a_pinned_key_does_not_vouch_for_another_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");

        add_key_at(&path, "example.test", 22, &test_key()).expect("add_key_at");

        assert_eq!(
            verify_at(&path, "other.test", 22, &test_key()).expect("verify"),
            VerifyResult::Unknown,
            "pinning one host must not vouch for another"
        );
    }

    #[test]
    fn a_matching_key_is_allowed_in_every_mode() {
        for mode in [
            HostKeyVerification::Strict,
            HostKeyVerification::AcceptNew,
            HostKeyVerification::Off,
        ] {
            assert!(
                matches!(
                    decide("h", &test_key(), mode, VerifyResult::Match),
                    Decision::Allow
                ),
                "a pinned, matching key must be allowed under {mode:?}"
            );
        }
    }

    /// The MITM case. `AcceptNew` means "trust a host I have never seen", NOT
    /// "trust a host whose key changed" — so it must refuse too.
    #[test]
    fn a_changed_key_is_refused_in_every_mode_including_accept_new() {
        for mode in [
            HostKeyVerification::Strict,
            HostKeyVerification::AcceptNew,
            HostKeyVerification::Off,
        ] {
            let d = decide("h", &test_key(), mode, VerifyResult::Mismatch { line: 7 });
            match d {
                Decision::Reject(BridgeError::SshHostKeyMismatch { host, expected, .. }) => {
                    assert_eq!(host, "h");
                    assert!(
                        expected.contains('7'),
                        "the refusal must name the known_hosts line: {expected}"
                    );
                }
                other => panic!("a changed key must be refused under {mode:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_host_is_refused_under_strict() {
        match decide(
            "h",
            &test_key(),
            HostKeyVerification::Strict,
            VerifyResult::Unknown,
        ) {
            Decision::Reject(BridgeError::SshHostKeyUnknown { host, fingerprint }) => {
                assert_eq!(host, "h");
                assert!(
                    fingerprint.starts_with("SHA256:"),
                    "the refusal must carry a usable fingerprint: {fingerprint}"
                );
            }
            other => panic!("Strict must refuse an unknown host, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_host_is_learned_under_accept_new() {
        assert!(
            matches!(
                decide(
                    "h",
                    &test_key(),
                    HostKeyVerification::AcceptNew,
                    VerifyResult::Unknown
                ),
                Decision::LearnThenAllow
            ),
            "AcceptNew is trust-on-first-use: an unseen host is learned"
        );
    }

    /// `Off` short-circuits before `decide`, so this arm is unreachable in
    /// practice. It is pinned anyway: if a refactor ever routes `Off` through
    /// here, refusing is the only safe reading, and a silent `Allow` would be a
    /// MITM hole introduced by an unrelated change.
    #[test]
    fn off_reaching_the_decision_refuses_rather_than_allowing() {
        assert!(
            matches!(
                decide(
                    "h",
                    &test_key(),
                    HostKeyVerification::Off,
                    VerifyResult::Unknown
                ),
                Decision::Reject(_)
            ),
            "an unknown host must never be allowed by default"
        );
    }

    /// The whole matrix in one place, so a new mode or result cannot be added
    /// without someone deciding what it means.
    #[test]
    fn the_decision_matrix_is_complete_and_has_no_accidental_allow() {
        use HostKeyVerification::{AcceptNew, Off, Strict};
        let cases = [
            (Strict, VerifyResult::Match, "allow"),
            (Strict, VerifyResult::Mismatch { line: 1 }, "reject"),
            (Strict, VerifyResult::Unknown, "reject"),
            (AcceptNew, VerifyResult::Match, "allow"),
            (AcceptNew, VerifyResult::Mismatch { line: 1 }, "reject"),
            (AcceptNew, VerifyResult::Unknown, "learn"),
            (Off, VerifyResult::Match, "allow"),
            (Off, VerifyResult::Mismatch { line: 1 }, "reject"),
            (Off, VerifyResult::Unknown, "reject"),
        ];
        for (mode, result, want) in cases {
            let got = match decide("h", &test_key(), mode, result.clone()) {
                Decision::Allow => "allow",
                Decision::Reject(_) => "reject",
                Decision::LearnThenAllow => "learn",
            };
            assert_eq!(got, want, "({mode:?}, {result:?}) must {want}");
        }
    }

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
