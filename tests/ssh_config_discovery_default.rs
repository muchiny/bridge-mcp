//! FIND-023: SSH config auto-discovery must be opt-in.
//!
//! Enabling discovery by default exposed every host in `~/.ssh/config` to
//! MCP clients via the bridge's host-listing surfaces, often vastly
//! exceeding the YAML-declared production set. Operators who want the
//! time-to-first-command convenience must now opt in explicitly.

use bridge_mcp::config::types::SshConfigDiscovery;

#[test]
fn ssh_config_discovery_default_off() {
    let d = SshConfigDiscovery::default();
    assert!(
        !d.enabled,
        "FIND-023: SshConfigDiscovery::default().enabled must be false"
    );
}

#[test]
fn ssh_config_discovery_omitted_field_defaults_off() {
    // When the YAML omits the `enabled` field entirely, the saphyr-driven
    // serde-default path must also resolve to false — otherwise an existing
    // operator config that listed `ssh_config: {}` (relying on the old
    // default) would silently re-enable discovery.
    let yaml = "{}";
    let d: SshConfigDiscovery = serde_json::from_str(yaml).expect("deserialize");
    assert!(
        !d.enabled,
        "FIND-023: omitted `enabled` must resolve to false via serde default"
    );
}
