#![no_main]
use bridge_mcp_fuzz::{assert_arrives_as_text_ps, powershell_shape};
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_service::{
    validate_service_name, WindowsServiceCommandBuilder,
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
// `cargo +nightly fuzz run fuzz_windows_service_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: (u32, &str)| {
    let (count, text) = data;

    // Every builder below is reached in production through a handler that has
    // already called `validate_service_name` — all seven of
    // `ssh_win_service_{status,start,stop,restart,enable,disable,config}` do.
    // So the property this target measures is the one production relies on:
    // *a name the validator ACCEPTED produces a safe command line*. Feeding
    // the builders names the validator rejects would measure a path no caller
    // can reach.
    //
    // That distinction is not academic here. `build_config_command` drops the
    // name into a PowerShell DOUBLE-quoted string
    // (`-Filter "Name='{name}'"`), and it defends that position by doubling
    // single quotes only — so a name carrying `"` closes the string early and
    // the rest is read as syntax. `validate_service_name` refuses `"`, which
    // is why the hole is latent rather than live, and why this gate is where
    // it is rather than being an assertion that the builder alone is safe.
    if validate_service_name(text).is_err() {
        return;
    }

    // status
    let cmd = WindowsServiceCommandBuilder::build_status_command(text);
    assert_arrives_as_text_ps(&cmd, text, "status");

    // start
    let cmd = WindowsServiceCommandBuilder::build_start_command(text);
    assert_arrives_as_text_ps(&cmd, text, "start");

    // stop
    let cmd = WindowsServiceCommandBuilder::build_stop_command(text);
    assert_arrives_as_text_ps(&cmd, text, "stop");

    // restart
    let cmd = WindowsServiceCommandBuilder::build_restart_command(text);
    assert_arrives_as_text_ps(&cmd, text, "restart");

    // list
    let cmd = WindowsServiceCommandBuilder::build_list_command();
    // `list` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "list: emitted a line no shell can parse: {cmd}"
    );

    // enable
    let cmd = WindowsServiceCommandBuilder::build_enable_command(text);
    assert_arrives_as_text_ps(&cmd, text, "enable");

    // disable
    let cmd = WindowsServiceCommandBuilder::build_disable_command(text);
    assert_arrives_as_text_ps(&cmd, text, "disable");

    // config
    let cmd = WindowsServiceCommandBuilder::build_config_command(text);
    assert_arrives_as_text_ps(&cmd, text, "config");

    // event_logs
    let cmd = WindowsServiceCommandBuilder::build_event_logs_command(text, count);
    assert_arrives_as_text_ps(&cmd, text, "event_logs");
});
