//! FIND-028: `HostConfig.sudo_password` must be wrapped in a zeroizing,
//! leak-proof secret type so the heap residency does not survive process
//! lifetime / hot-reload.
//!
//! The field is now [`RedactedSecret`] (a newtype over `Zeroizing<String>`
//! that also blocks `Debug`/`Display`/`Serialize` leaks). This test pins the
//! field type at compile time: if the field reverts to `Option<String>`, the
//! `RedactedSecret::from(...)` literal stops type-checking and this file fails
//! to compile — which is exactly the regression signal we want.

use mcp_ssh_bridge::config::{AuthConfig, HostConfig, HostKeyVerification, OsType, RedactedSecret};

fn host_config_with_sudo(password: Option<RedactedSecret>) -> HostConfig {
    HostConfig {
        hostname: "192.0.2.10".to_string(),
        port: 22,
        user: "tester".to_string(),
        auth: AuthConfig::Agent,
        description: None,
        host_key_verification: HostKeyVerification::Strict,
        proxy_jump: None,
        socks_proxy: None,
        sudo_password: password,
        tags: Vec::new(),
        os_type: OsType::Linux,
        shell: None,
        retry: None,
        protocol: mcp_ssh_bridge::config::Protocol::default(),

        #[cfg(feature = "winrm")]
        winrm_use_tls: None,
        #[cfg(feature = "winrm")]
        winrm_accept_invalid_certs: None,
        #[cfg(feature = "winrm")]
        winrm_operation_timeout_secs: None,
        #[cfg(feature = "winrm")]
        winrm_max_envelope_size: None,
    }
}

#[test]
fn sudo_password_field_is_redacted_secret() {
    // Type-level assertion: this only compiles if the field is
    // `Option<RedactedSecret>`. If the field type regresses to
    // `Option<String>`, the literal below fails to type-check.
    let host = host_config_with_sudo(Some(RedactedSecret::from("s3cret")));

    // Borrow site stays backwards-compatible: callers can still grab a `&str`
    // at the audited boundary. `RedactedSecret` derefs to `str`, so
    // `Option<RedactedSecret>::as_deref` yields `Option<&str>` directly. Real
    // call sites pass `&*secret` (or `secret.as_str()`) to functions taking
    // `&str` and the compiler chains the Deref impl automatically.
    let borrowed: Option<&str> = host.sudo_password.as_deref();
    assert_eq!(borrowed, Some("s3cret"));

    // Verify the raw secret bytes are reachable through the audited accessor
    // (defense-in-depth check that the wrapper does not silently mangle the
    // value).
    let raw: &str = host.sudo_password.as_ref().expect("set above").as_str();
    assert_eq!(raw, "s3cret");

    // Defense-in-depth: the secret must NOT leak through Debug — `RedactedSecret`
    // renders `[REDACTED]` instead of the plaintext, which is the leak-proofing
    // guarantee that distinguishes it from a bare `Zeroizing<String>`.
    let debug = format!("{:?}", host.sudo_password);
    assert!(
        !debug.contains("s3cret"),
        "sudo_password leaked via Debug: {debug}"
    );
}

#[test]
fn sudo_password_none_still_compiles() {
    // The ~519 fixture sites that assign `sudo_password: None` must keep
    // working — `None` is type-agnostic.
    let host = host_config_with_sudo(None);
    assert!(host.sudo_password.is_none());
}
