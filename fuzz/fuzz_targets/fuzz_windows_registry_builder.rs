#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text_ps;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_registry::{
    validate_file_path, validate_registry_name, validate_registry_path,
    WindowsRegistryCommandBuilder,
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
// PowerShell, not `/bin/sh`. This builder escapes through
// `shell::escape(s, ShellType::PowerShell)`, which emits `'...'` with the
// quote DOUBLED (`it's` -> `'it''s'`). The POSIX reader parses that as two
// adjacent words and yields `its`, silently dropping the apostrophe — so
// reusing the POSIX oracle here would have been red on healthy code for every
// value containing a quote. Hence `*_ps`.
//
// `assert_arrives_as_text` rather than `assert_survives_as_one_word`: these
// builders emit pipelines and `&&` chains of their own, and an oracle that
// refuses every operator would be red on healthy code. It is `contains` on the
// literal run rather than equality because a value legitimately lands inside a
// larger word (`--filter=name=VALUE`); an operator still splits the run either
// way, which is what the assertion is for.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_windows_registry_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // validators
    let _ = validate_registry_path(data);
    let _ = validate_registry_name(data);
    let _ = validate_file_path(data);

    // query
    let cmd = WindowsRegistryCommandBuilder::query(data, Some(data));
    assert_arrives_as_text_ps(&cmd, data, "query");

    // query without name
    let cmd = WindowsRegistryCommandBuilder::query(data, None);
    assert_arrives_as_text_ps(&cmd, data, "query (no name)");

    // set_value
    let cmd = WindowsRegistryCommandBuilder::set_value(data, data, data, Some(data));
    assert_arrives_as_text_ps(&cmd, data, "set_value");

    // set_value without type
    let cmd = WindowsRegistryCommandBuilder::set_value(data, data, data, None);
    assert_arrives_as_text_ps(&cmd, data, "set_value (no type)");

    // list
    let cmd = WindowsRegistryCommandBuilder::list(data);
    assert_arrives_as_text_ps(&cmd, data, "list");

    // export_key
    let cmd = WindowsRegistryCommandBuilder::export_key(data, data);
    assert_arrives_as_text_ps(&cmd, data, "export_key");

    // delete_property
    let cmd = WindowsRegistryCommandBuilder::delete_property(data, data);
    assert_arrives_as_text_ps(&cmd, data, "delete_property");
});
