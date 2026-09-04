#![no_main]
use bridge_mcp_fuzz::{assert_arrives_as_text_ps, powershell_shape};
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_event::{
    validate_log_name, WindowsEventCommandBuilder,
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
// `cargo +nightly fuzz run fuzz_windows_event_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: (u32, &str)| {
    let (count, text) = data;

    // validator
    let _ = validate_log_name(text);

    // query
    let cmd = WindowsEventCommandBuilder::build_query_command(text, count, Some(text));
    assert_arrives_as_text_ps(&cmd, text, "query");

    // query without after
    let cmd = WindowsEventCommandBuilder::build_query_command(text, count, None);
    assert_arrives_as_text_ps(&cmd, text, "query (no after)");

    // sources
    let cmd = WindowsEventCommandBuilder::build_sources_command();
    // `sources` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "sources: emitted a line no shell can parse: {cmd}"
    );

    // tail
    let cmd = WindowsEventCommandBuilder::build_tail_command(text, count);
    assert_arrives_as_text_ps(&cmd, text, "tail");

    // export
    let cmd = WindowsEventCommandBuilder::build_export_command(text, text);
    assert_arrives_as_text_ps(&cmd, text, "export");
});
