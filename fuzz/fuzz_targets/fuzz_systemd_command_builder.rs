#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::systemd::{validate_service_name, SystemdCommandBuilder};

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "the program name"))`. That is a string the builder writes itself, in every branch,
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
// `cargo +nightly fuzz run fuzz_systemd_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_service_name(data);
    let _ = SystemdCommandBuilder::validate_restart_action(data);

    // status
    let cmd = SystemdCommandBuilder::build_status_command(data);
    assert_arrives_as_text(&cmd, data, "status");

    // start
    let cmd = SystemdCommandBuilder::build_start_command(data);
    assert_arrives_as_text(&cmd, data, "start");

    // stop
    let cmd = SystemdCommandBuilder::build_stop_command(data);
    assert_arrives_as_text(&cmd, data, "stop");

    // restart (may fail validation)
    let _ = SystemdCommandBuilder::build_restart_command(data, data);

    // enable
    let cmd = SystemdCommandBuilder::build_enable_command(data);
    assert_arrives_as_text(&cmd, data, "enable");

    // disable
    let cmd = SystemdCommandBuilder::build_disable_command(data);
    assert_arrives_as_text(&cmd, data, "disable");

    // daemon-reload
    let cmd = SystemdCommandBuilder::build_daemon_reload_command();
    assert_eq!(cmd, "systemctl daemon-reload");

    // list
    // Returns Result: the builder validates `state` and `unit_type`, so an
    // arbitrary fuzz string is expected to be rejected most of the time.
    if let Ok(cmd) = SystemdCommandBuilder::build_list_command(Some(data), true, Some(data)) {
        assert_arrives_as_text(&cmd, data, "list");
    }

    // logs
    let cmd = SystemdCommandBuilder::build_logs_command(
        data,
        Some(100),
        Some(data),
        Some(data),
        Some(data),
        Some(data),
        true,
    );
    assert_arrives_as_text(&cmd, data, "logs");
});
