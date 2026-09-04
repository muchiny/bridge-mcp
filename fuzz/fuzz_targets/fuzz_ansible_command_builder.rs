#![no_main]

use std::collections::HashMap;

use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::AnsibleCommandBuilder;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "--list"))`. That is a string the builder writes itself, in every branch,
// whatever the caller passed — so NO INPUT COULD EVER FAIL IT. A builder that
// pastes `data` into the command line in bare does not panic and does not drop
// the program name; it produces a dangerous command and the target stays
// green. An echo, not a property.
//
// What it asserts now: whatever the builder ACCEPTED arrives in the command as
// TEXT — inside one literal run, having contributed no shell syntax. Refusal
// is always fine; the fuzzer is looking for values that get THROUGH.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_ansible_command_builder -- -dict=fuzz/dicts/shell.dict`

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
        Some(data),          // callback
        Some(data),          // vault_password_file
        Some(data),          // vault_id
    );
    assert_arrives_as_text(&cmd, data, "playbook");

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
    assert_arrives_as_text(&cmd, data, "inventory");

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
        Some(data), // vault_password_file
        Some(data), // vault_id
    );
    assert!(cmd.starts_with("ansible "),
        "adhoc must start with 'ansible ': {cmd}");

    // Test with no optional args
    let cmd = AnsibleCommandBuilder::build_adhoc_command(
        data, "ping", None, None, false, None, None, None, None, false, None, None,
    );
    assert_arrives_as_text(&cmd, data, "adhoc ping");
});
