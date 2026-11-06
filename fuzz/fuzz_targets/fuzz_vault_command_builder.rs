#![no_main]
use bridge_mcp::config::RedactedSecret;
use bridge_mcp::domain::use_cases::vault::{VaultCommandBuilder, validate_vault_path};
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;

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
// The 6.0.0 rules are asserted too, each on input where it is TRUE: whatever
// `validate_vault_path` ACCEPTS satisfies the path rules and builds in every
// builder (never the reverse direction, which would be false on arbitrary
// fuzz data); the `--` before the path, the one-line JSON heredoc body and its
// terminator are checked on the accepted path and on a fuzzed VALUE; and the
// fixed hand-picked inputs at the end (`-x`, no `VAULT_ADDR`) cover over-refusal.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_vault_command_builder -- -dict=fuzz/dicts/shell.dict`

fuzz_target!(|data: &str| {
    let kv_ok = vec![RedactedSecret::from("k=v")];

    // validate_vault_path: whatever it ACCEPTS obeys the 6.0.0 path rules, and
    // every builder (which only call it first) then accepts it too. The reverse
    // ("no `..` => accepted") is not asserted: it is false on arbitrary data.
    if validate_vault_path(data).is_ok() {
        assert!(
            !data.is_empty()
                && !data.split('/').any(|c| c == "..")
                && data
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')),
            "validate_vault_path accepted {data:?}"
        );

        // read / list with the fuzzed value as PATH. `--` must sit right before
        // it (a path may start with `-`); the path holds no `'`, so its quoting
        // is exactly `'path'`.
        let read = VaultCommandBuilder::build_read_command(data, None, None, None)
            .expect("read refused a path validate_vault_path accepted");
        assert_arrives_as_text(&read, data, "read-path");
        assert!(read.ends_with(&format!(" -- '{data}'")), "read: {read:?}");
        let list = VaultCommandBuilder::build_list_command(data, None, None)
            .expect("list refused a path validate_vault_path accepted");
        assert_arrives_as_text(&list, data, "list-path");
        assert!(list.ends_with(&format!(" -- '{data}'")), "list: {list:?}");

        // write with the fuzzed value as PATH and a fixed valid entry: exactly
        // command / one JSON body line / terminator, `--` before the path, and
        // the terminator named on the first line is the third line.
        assert!(VaultCommandBuilder::validate_write_args(data, &kv_ok).is_ok());
        let write = VaultCommandBuilder::build_write_command(data, &kv_ok, None)
            .expect("write refused a path validate_vault_path accepted");
        let lines: Vec<&str> = write.lines().collect();
        assert_eq!(lines.len(), 3, "write: {write:?}");
        assert_eq!(lines[1], r#"{"k":"v"}"#, "write: {write:?}");
        assert!(lines[2].starts_with("VAULT_DATA_EOF_"), "write: {write:?}");
        assert_eq!(
            lines[0],
            format!("vault kv put -- '{data}' - <<'{}'", lines[2]),
            "write: {write:?}"
        );
    }

    // status
    let cmd = VaultCommandBuilder::build_status_command(Some(data));
    assert_arrives_as_text(&cmd, data, "status");

    // read / list: a FIXED valid path, the fuzzed value in every other slot.
    // With `data` as the path too, only shell-inert values (alphanumerics and
    // `/ - _ .`) get past `validate_vault_path`, so a hostile mount, field or
    // format would be refused before it reached any assertion and a builder
    // pasting them in bare would stay green. These calls are always `Ok`.
    let cmd =
        VaultCommandBuilder::build_read_command("secret/app", Some(data), Some(data), Some(data))
            .expect("read refused the fixed valid path");
    assert_arrives_as_text(&cmd, data, "read");
    let cmd = VaultCommandBuilder::build_list_command("secret/app", Some(data), Some(data))
        .expect("list refused the fixed valid path");
    assert_arrives_as_text(&cmd, data, "list");

    // write
    //
    // `build_write_command` takes `&[RedactedSecret]`, and since 6.0.0 it refuses
    // a path that is not a valid Vault path AND an entry that is not `key=value`
    // with a non-empty key. `=` is not a path character, so no single string is
    // both: `build_write_command(data, &[data], ..)` is `Err` for EVERY input and
    // an assertion below it could never run. The path is therefore a fixed valid
    // one.
    //
    // Mount: the entry is the fixed `k=v`, so the heredoc body holds no `data`
    // and only `-mount=` can carry it. (With `k=<data>` the JSON body, which
    // `shell_shape` scans as shell since it has no heredoc support, would put a
    // literal run containing `data` and mask a bare-pasted mount.) The body
    // line is scanned too and stays balanced: serde_json escapes `"` and `\`.
    let cmd = VaultCommandBuilder::build_write_command("secret/app", &kv_ok, Some(data))
        .expect("write refused the fixed valid path and entry");
    assert_arrives_as_text(&cmd, data, "write-mount");

    // Value: `data` goes into the JSON heredoc body, escaped for JSON rather
    // than for the shell, so `assert_arrives_as_text` is the wrong oracle there.
    // Instead the body must parse back to exactly `{"k": data}`. serde_json
    // escapes every `\n`, `\r` and control character, so the body is one line
    // and the command is always three lines; the heredoc cannot close early.
    let kv_data = vec![RedactedSecret::from(format!("k={data}"))];
    let cmd = VaultCommandBuilder::build_write_command("secret/app", &kv_data, None)
        .expect("write refused `k=<value>` on the fixed valid path");
    let lines: Vec<&str> = cmd.lines().collect();
    assert_eq!(lines.len(), 3, "write: {cmd:?}");
    let body: serde_json::Value = serde_json::from_str(lines[1]).expect("heredoc body is not JSON");
    assert_eq!(body, serde_json::json!({ "k": data }), "write: {cmd:?}");
    assert!(
        lines[0].ends_with(&format!("<<'{}'", lines[2])),
        "write: {cmd:?}"
    );

    // Fixed known-good inputs (not fuzz data): `-x` is a valid path that must
    // not be read as a flag, and no builder sets VAULT_ADDR (the host's token
    // would go to whatever address the caller named).
    let read = VaultCommandBuilder::build_read_command("-x", None, None, None).expect("-x");
    assert!(read.contains(" -- '-x'"), "read: {read:?}");
    let list = VaultCommandBuilder::build_list_command("-x", None, None).expect("-x");
    assert!(list.contains(" -- '-x'"), "list: {list:?}");
    let write = VaultCommandBuilder::build_write_command("-x", &kv_ok, None).expect("-x");
    assert!(write.contains(" -- '-x' - <<'"), "write: {write:?}");
    for cmd in [
        VaultCommandBuilder::build_status_command(Some("json")),
        read,
        list,
        write,
    ] {
        assert!(!cmd.contains("VAULT_ADDR"), "{cmd:?}");
    }
});
