//! FIND-028: `HostConfig.sudo_password` must be wrapped in `Zeroizing<String>`
//! so the heap residency does not survive process lifetime / hot-reload.
//!
//! This test pins the field type at compile time. If the field reverts to
//! `Option<String>`, the `Zeroizing::new(...)` literal stops type-checking
//! and this file fails to compile — which is exactly the regression signal
//! we want.

use mcp_ssh_bridge::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
use zeroize::Zeroizing;

fn host_config_with_sudo(password: Option<Zeroizing<String>>) -> HostConfig {
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
fn sudo_password_field_is_zeroizing() {
    // Type-level assertion: this only compiles if the field is
    // `Option<Zeroizing<String>>`. If the field type regresses to
    // `Option<String>`, the literal below fails to type-check.
    let host = host_config_with_sudo(Some(Zeroizing::new("s3cret".to_string())));

    // Borrow site stays backwards-compatible: callers can still grab a `&str`
    // via Deref coercion. `Option<Zeroizing<String>>::as_deref` yields
    // `Option<&String>` (one Deref hop); a second hop reaches `&str`. Real
    // call sites pass `&Zeroizing<String>` to functions taking `&str` and
    // the compiler chains both Deref impls automatically.
    let borrowed: Option<&String> = host.sudo_password.as_deref();
    assert_eq!(borrowed.map(String::as_str), Some("s3cret"));

    // Verify the raw secret bytes are reachable (defense-in-depth check
    // that the wrapper does not silently mangle the value).
    let raw: &str = host.sudo_password.as_ref().expect("set above");
    assert_eq!(raw, "s3cret");
}

#[test]
fn sudo_password_none_still_compiles() {
    // The ~519 fixture sites that assign `sudo_password: None` must keep
    // working — `None` is type-agnostic.
    let host = host_config_with_sudo(None);
    assert!(host.sudo_password.is_none());
}
