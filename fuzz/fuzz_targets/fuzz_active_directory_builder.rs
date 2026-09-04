#![no_main]
use bridge_mcp_fuzz::{assert_arrives_as_text_ps, powershell_shape};
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::active_directory::{
    validate_ad_identity, ActiveDirectoryCommandBuilder,
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
// `cargo +nightly fuzz run fuzz_active_directory_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    // validator
    let _ = validate_ad_identity(data);

    // user_list
    // `Result` since the injection fix: the filter lands inside a DOUBLE-quoted
    // PowerShell string, where `$` and the backtick are live and `ps_escape`'s
    // single quotes are inert. It is validated now, not escaped. Refusal is the
    // expected answer for most fuzzer input; the assertion is about what gets
    // THROUGH.
    if let Ok(cmd) = ActiveDirectoryCommandBuilder::build_user_list_command(Some(data)) {
        assert_arrives_as_text_ps(&cmd, data, "user_list");
    }

    // user_list without filter
    let cmd = ActiveDirectoryCommandBuilder::build_user_list_command(None)
        .expect("the no-filter branch validates nothing and cannot fail");
    // `user_list (no filter)` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "user_list (no filter): emitted a line no shell can parse: {cmd}"
    );

    // user_info
    let cmd = ActiveDirectoryCommandBuilder::build_user_info_command(data);
    assert_arrives_as_text_ps(&cmd, data, "user_info");

    // group_list
    let cmd = ActiveDirectoryCommandBuilder::build_group_list_command();
    // `group_list` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "group_list: emitted a line no shell can parse: {cmd}"
    );

    // group_members
    let cmd = ActiveDirectoryCommandBuilder::build_group_members_command(data);
    assert_arrives_as_text_ps(&cmd, data, "group_members");

    // computer_list
    let cmd = ActiveDirectoryCommandBuilder::build_computer_list_command();
    // `computer_list` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "computer_list: emitted a line no shell can parse: {cmd}"
    );

    // domain_info
    let cmd = ActiveDirectoryCommandBuilder::build_domain_info_command();
    // `domain_info` takes no caller value: input-independent, so all a
    // fuzzer can say about it is that it parses at all.
    assert!(
        powershell_shape(&cmd).is_some(),
        "domain_info: emitted a line no shell can parse: {cmd}"
    );
});
