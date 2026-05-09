//! FIND-008: russh client must pin a hardened `Preferred` algo set + rekey limits.
//!
//! Prior to this fix, `Config { ..Default::default() }` left
//! `preferred` and `limits` at upstream defaults. Russh 0.60.1's
//! `negotiation::Preferred::DEFAULT` includes legacy MAC algorithms
//! (`hmac-sha1`, `hmac-sha1-etm@openssh.com`) in `HMAC_ORDER` (see
//! `~/.cargo/registry/src/index.crates.io-*/russh-0.60.1/src/negotiation.rs:134`).
//! These tests assert the helper builds a `Config` whose `preferred` lists
//! exclude SHA-1, MD5, 3DES, blowfish, and DH-Group1, and whose `limits`
//! pin rekey thresholds to 1 GiB / 1 hour per RFC 4253 §9.

use mcp_ssh_bridge::config::LimitsConfig;
use mcp_ssh_bridge::ssh::build_russh_client_config;

#[test]
fn pinned_preferred_excludes_legacy_kex() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    for algo in cfg.preferred.kex.iter() {
        let n: &str = algo.as_ref();
        assert!(
            !n.ends_with("sha1") && !n.contains("sha1@") && !n.contains("-sha1-"),
            "kex {n} contains sha1 — must be excluded"
        );
        assert!(
            !n.contains("group1-") && !n.starts_with("diffie-hellman-group1-"),
            "kex {n} is diffie-hellman-group1 — excluded"
        );
    }
}

#[test]
fn pinned_preferred_excludes_legacy_ciphers() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    for cipher in cfg.preferred.cipher.iter() {
        let n: &str = cipher.as_ref();
        assert!(!n.contains("3des"), "cipher {n} is 3DES — excluded");
        assert!(!n.contains("blowfish"), "cipher {n} is blowfish — excluded");
        assert!(!n.contains("arcfour"), "cipher {n} is arcfour/RC4 — excluded");
        assert!(!n.contains("-cbc"), "cipher {n} is CBC mode — excluded (CTR/GCM/ChaCha only)");
    }
}

#[test]
fn pinned_preferred_excludes_legacy_macs() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    for mac in cfg.preferred.mac.iter() {
        let n: &str = mac.as_ref();
        assert!(!n.contains("md5"), "mac {n} uses md5 — excluded");
        assert!(!n.contains("sha1"), "mac {n} uses sha1 — excluded");
    }
}

#[test]
fn pinned_preferred_includes_modern_kex() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    let names: Vec<&str> = cfg.preferred.kex.iter().map(AsRef::as_ref).collect();
    assert!(
        names.iter().any(|n| n == &"curve25519-sha256"),
        "kex list must include curve25519-sha256, got: {names:?}"
    );
}

#[test]
fn pinned_preferred_includes_modern_ciphers() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    let names: Vec<&str> = cfg.preferred.cipher.iter().map(AsRef::as_ref).collect();
    assert!(
        names
            .iter()
            .any(|n| n == &"chacha20-poly1305@openssh.com" || n == &"aes256-gcm@openssh.com"),
        "cipher list must include chacha20-poly1305 or aes256-gcm, got: {names:?}"
    );
}

#[test]
fn pinned_preferred_includes_etm_macs_only() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    let names: Vec<&str> = cfg.preferred.mac.iter().map(AsRef::as_ref).collect();
    // Hardened set: only EtM (encrypt-then-MAC) variants.
    for n in &names {
        assert!(
            n.contains("etm@openssh.com"),
            "mac {n} is not encrypt-then-MAC — excluded"
        );
    }
    assert!(
        names
            .iter()
            .any(|n| n == &"hmac-sha2-512-etm@openssh.com"),
        "mac list must include hmac-sha2-512-etm@openssh.com, got: {names:?}"
    );
}

#[test]
fn rekey_limits_set_to_one_gigabyte_one_hour() {
    let cfg = build_russh_client_config(&LimitsConfig::default());
    let limits = &cfg.limits;
    assert_eq!(
        limits.rekey_write_limit,
        1 << 30,
        "rekey_write_limit should be 1 GiB"
    );
    assert_eq!(
        limits.rekey_read_limit,
        1 << 30,
        "rekey_read_limit should be 1 GiB"
    );
    assert_eq!(
        limits.rekey_time_limit,
        std::time::Duration::from_secs(3600),
        "rekey_time_limit should be 1 hour"
    );
}

#[test]
fn keepalive_uses_limits_config() {
    let mut limits = LimitsConfig::default();
    limits.keepalive_interval_seconds = 42;
    let cfg = build_russh_client_config(&limits);
    assert_eq!(
        cfg.keepalive_interval,
        Some(std::time::Duration::from_secs(42))
    );
    assert_eq!(
        cfg.inactivity_timeout,
        Some(std::time::Duration::from_secs(42))
    );
    assert_eq!(cfg.keepalive_max, 3);
}
