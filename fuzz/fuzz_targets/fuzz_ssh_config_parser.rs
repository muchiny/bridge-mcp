#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::config::ssh_config::parse_ssh_config_content;

fuzz_target!(|data: &str| {
    // Fuzz the SSH config parser with arbitrary content.
    // This simulates malformed or malicious ~/.ssh/config files.

    let hosts = parse_ssh_config_content(data, &[]);

    // Invariants:

    // 1. Empty input must produce empty output
    if data.trim().is_empty() || data.lines().all(|l| l.trim().is_empty() || l.trim().starts_with('#')) {
        assert!(hosts.is_empty(), "Empty/comment-only config must produce no hosts");
    }

    // 2. All returned hosts must have non-empty hostname and user
    for (alias, host) in &hosts {
        assert!(!alias.is_empty(), "Host alias must not be empty");
        assert!(!host.hostname.is_empty(), "Hostname must not be empty");
        assert!(!host.user.is_empty(), "User must not be empty");
        assert!(host.port > 0, "Port must be positive");
    }

    // 3. Wildcard hosts must never appear in output
    for alias in hosts.keys() {
        assert!(!alias.contains('*'), "Wildcard hosts must be skipped");
        assert!(!alias.contains('?'), "Wildcard hosts must be skipped");
    }

    // 4. Test with exclusions
    if let Some(first_alias) = hosts.keys().next().cloned() {
        let exclude = vec![first_alias.clone()];
        let filtered = parse_ssh_config_content(data, &exclude);
        assert!(
            !filtered.contains_key(&first_alias),
            "Excluded host must not appear"
        );
    }

    // 5. Should never panic (implicit)
});
