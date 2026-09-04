#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::redis::RedisCommandBuilder;

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
// `cargo +nightly fuzz run fuzz_redis_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // validate_redis_command
    let _ = RedisCommandBuilder::validate_redis_command(data);

    // info
    let cmd = RedisCommandBuilder::build_info_command(Some(data), Some(6379), Some(data));
    assert_arrives_as_text(&cmd, data, "info");

    // cli
    let cmd = RedisCommandBuilder::build_cli_command(Some(data), Some(6379), data);
    assert_arrives_as_text(&cmd, data, "cli");

    // keys
    let cmd = RedisCommandBuilder::build_keys_command(Some(data), Some(6379), Some(data), Some(100));
    assert_arrives_as_text(&cmd, data, "keys");
});
