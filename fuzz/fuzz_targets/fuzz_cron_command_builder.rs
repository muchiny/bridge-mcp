#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::cron::{
    validate_cron_comment, validate_cron_schedule, CronCommandBuilder,
};

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
// `cargo +nightly fuzz run fuzz_cron_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_cron_schedule(data);
    let _ = validate_cron_comment(data);

    // list
    let cmd = CronCommandBuilder::build_list_command(Some(data), true);
    assert_arrives_as_text(&cmd, data, "list");

    // add (may fail validation)
    let _ = CronCommandBuilder::build_add_command(data, data, Some(data), Some(data));

    // remove
    let _ = CronCommandBuilder::build_remove_command(data, Some(data));
});
