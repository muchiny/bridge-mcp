#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::config::RedactedSecret;
use bridge_mcp::domain::use_cases::vault::{validate_vault_path, VaultCommandBuilder};

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
// `cargo +nightly fuzz run fuzz_vault_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // `build_write_command` takes `&[RedactedSecret]` — the KV payload was
    // moved behind the zeroizing wrapper and the fuzz target never followed.
    let kv_data = vec![RedactedSecret::from(data)];

    // validate_vault_path
    let _ = validate_vault_path(data);

    // status
    let cmd = VaultCommandBuilder::build_status_command(Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "status");

    // read
    if let Ok(cmd) =
        VaultCommandBuilder::build_read_command(data, Some(data), Some(data), Some(data), Some(data))
    {
        assert_arrives_as_text(&cmd, data, "read");
    }

    // list
    if let Ok(cmd) =
        VaultCommandBuilder::build_list_command(data, Some(data), Some(data), Some(data))
    {
        assert_arrives_as_text(&cmd, data, "list");
    }

    // write
    if let Ok(cmd) =
        VaultCommandBuilder::build_write_command(data, &kv_data, Some(data), Some(data))
    {
        assert_arrives_as_text(&cmd, data, "write");
    }
});
