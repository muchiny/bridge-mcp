#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use bridge_mcp::AnsibleCommandBuilder;

fuzz_target!(|data: &str| {
    // Fuzz all 3 AnsibleCommandBuilder methods with arbitrary strings.
    // Invariant: output must contain the expected binary name and never panic.

    // 1. build_playbook_command
    let mut extra_vars = HashMap::new();
    extra_vars.insert(data.to_string(), data.to_string());
    let cmd = AnsibleCommandBuilder::build_playbook_command(
        data,                // playbook
        Some(data),          // inventory
        Some(data),          // limit
        Some(data),          // tags
        Some(data),          // skip_tags
        Some(&extra_vars),   // extra_vars
        true,                // check
        true,                // diff
        Some(4),             // verbose
        Some(10),            // forks
        true,                // use_become
        Some(data),          // become_user
        Some(data),          // working_dir
    );
    assert!(cmd.contains("ansible-playbook"),
        "playbook must contain 'ansible-playbook': {cmd}");

    // 2. build_inventory_command
    let cmd = AnsibleCommandBuilder::build_inventory_command(
        Some(data), // inventory
        true,       // list
        true,       // graph
        Some(data), // host_pattern
        Some(data), // group
        true,       // yaml
        true,       // vars
    );
    assert!(cmd.contains("ansible-inventory"),
        "inventory must contain 'ansible-inventory': {cmd}");

    // Test default action (no list/graph/host)
    let cmd = AnsibleCommandBuilder::build_inventory_command(
        None, false, false, None, None, false, false,
    );
    assert!(cmd.contains("--list"),
        "inventory with no action must default to --list");

    // 3. build_adhoc_command
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        data,       // pattern
        data,       // module
        Some(data), // args
        Some(data), // inventory
        true,       // use_become
        Some(data), // become_user
        Some(data), // user
        Some(5),    // forks
        Some(2),    // verbose
        true,       // check
    );
    assert!(cmd.starts_with("ansible "),
        "adhoc must start with 'ansible ': {cmd}");

    // Test with no optional args
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        data, "ping", None, None, false, None, None, None, None, false,
    );
    assert!(cmd.contains("-m 'ping'"),
        "adhoc ping must contain -m 'ping'");
});
