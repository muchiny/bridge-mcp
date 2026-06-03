#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::firewall::{
    validate_port, validate_source, FirewallCommandBuilder,
};

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_port(data);
    let _ = validate_source(data);

    // status
    let _ = FirewallCommandBuilder::build_status_command(Some(data));

    // list
    let _ = FirewallCommandBuilder::build_list_command(Some(data), Some(data));

    // allow (ufw)
    let _ = FirewallCommandBuilder::build_allow_command(
        Some("ufw"),
        data,
        Some(data),
        Some(data),
    );

    // deny (iptables)
    let _ = FirewallCommandBuilder::build_deny_command(
        Some("iptables"),
        data,
        Some(data),
        Some(data),
    );
});
