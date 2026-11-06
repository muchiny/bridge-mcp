#![no_main]

use bridge_mcp::domain::use_cases::database::{DatabaseCommandBuilder, DatabaseType};
use bridge_mcp_fuzz::{assert_arrives_as_text, assert_same_shell_skeleton};
use libfuzzer_sys::fuzz_target;

// This target used to assert only the PROGRAM NAME: `assert!(cmd.contains(
// "MYSQL_PWD="))`. That is a string the builder writes itself, in every branch,
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
// `assert_arrives_as_text` alone cannot see ONE field pasted in bare while the
// others are quoted: every builder parameter receives `data`, so a quoted host
// supplies an intact literal run containing `data` even when `query` (or the
// output file, or a table) was pasted raw. So each builder is also built once
// per field with `data` in that field only and every other field benign, and
// the skeleton is compared with the all-benign build
// (`assert_same_shell_skeleton`): quoted runs, empty ones included, all collapse
// to `\0`, so a correct builder always matches and a bare paste in any single
// field changes the skeleton.
//
// The 6.0.0 hardening (`--binary-mode` on the MySQL query and restore commands)
// is pinned too. The flag is written unconditionally, so asserting it is true
// for every input.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_db_command_builder -- -dict=fuzz/dicts/shell.dict`

/// Assert that `data`, placed in any single one of the `n` fields while the
/// others stay benign, adds no shell syntax to what `build` emits.
fn assert_each_field_inert(context: &str, data: &str, n: usize, build: &dyn Fn(&[&str]) -> String) {
    let benign_fields = vec!["x"; n];
    let benign = build(&benign_fields[..]);
    for i in 0..n {
        let mut fields = vec!["x"; n];
        fields[i] = data;
        let hostile = build(&fields[..]);
        assert_same_shell_skeleton(&benign, &hostile, &format!("{context}, field {i}"));
    }
}

/// How the password reaches the DB client, for any builder.
fn check_password_plumbing(cmd: &str, data: &str, is_mysql: bool, with_pw: bool, context: &str) {
    // The password must not travel as a `MYSQL_PWD` / `PGPASSWORD` environment
    // variable. FIND-031 moved these builders to `--defaults-extra-file` (MySQL)
    // and `PGPASSFILE` (PostgreSQL) so the secret stays out of argv and environ
    // of the DB client. It is still in the command STRING, as the `printf`
    // argument that writes the tempfile (the "Known gap" note in database.rs).
    // This target used to assert `cmd.contains("MYSQL_PWD=")` — the pre-fix
    // shape — so it demanded the vulnerability back. It would have failed on
    // every input, and did not, because the fuzz harness had not compiled for
    // six weeks.
    // Guarded on `data`: the builder pastes the fuzzed host, user, database and
    // query into the command as text, so an input that itself spells the token
    // puts it in the command without the builder ever writing it. Absent from
    // the input, it can only come from the builder.
    for token in ["MYSQL_PWD", "PGPASSWORD"] {
        if !data.contains(token) {
            assert!(
                !cmd.contains(token),
                "{context}: password must not travel in {token}: {cmd}"
            );
        }
    }
    // The positive side, unconditional: the builder writes these itself.
    if with_pw {
        let marker = if is_mysql {
            "--defaults-extra-file=$TMPF"
        } else {
            "PGPASSFILE=$TMPF "
        };
        assert!(
            cmd.contains(marker),
            "{context}: password given but {marker:?} missing: {cmd}"
        );
    } else {
        // No password: no tempfile prelude at all (guarded on `data` as above).
        for token in ["PGPASSFILE", "TMPF"] {
            if !data.contains(token) {
                assert!(
                    !cmd.contains(token),
                    "{context}: no password but {token} present: {cmd}"
                );
            }
        }
    }
}

fuzz_target!(|data: &str| {
    // Fuzz the database command builder with arbitrary input as queries,
    // database names, user names, passwords, etc.
    let cases = [
        (DatabaseType::MySQL, 3306_u16, "MySQL", true),
        (DatabaseType::PostgreSQL, 5432_u16, "PostgreSQL", false),
    ];

    for (db_type, port, name, is_mysql) in &cases {
        let port = *port;
        let is_mysql = *is_mysql;
        for with_pw in [true, false] {
            let all5: [&str; 5] = [data; 5];

            // 1. Query command. Fields: host, user, database, query, password.
            let build = |f: &[&str]| -> String {
                DatabaseCommandBuilder::build_query_command(
                    db_type,
                    f[0],
                    port,
                    f[1],
                    with_pw.then_some(f[4]),
                    f[2],
                    f[3],
                    Some("csv"),
                )
            };
            let ctx = format!("{name} query, password={with_pw}");
            let cmd = build(&all5[..]);
            // - The input must reach the command as text, not as syntax.
            assert_arrives_as_text(&cmd, data, &ctx);
            assert_each_field_inert(&ctx, data, 5, &build);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, &ctx);
            // The same checks on an all-benign build, where none of them is
            // skipped: the fuzzed run above has to step aside whenever `data`
            // spells one of the tokens, which the fuzzer does quickly.
            check_password_plumbing(&build(&["x"; 5][..]), "x", is_mysql, with_pw, &ctx);
            if is_mysql {
                // 6.0.0: `--binary-mode` switches the client's own commands
                // (`\!`, `system`, ...) off. Written in both branches.
                assert!(
                    cmd.contains(" --binary-mode -e '"),
                    "{ctx}: --binary-mode missing: {cmd}"
                );
            }

            // 2. Restore command. Fields: host, user, database, input file, password.
            let build = |f: &[&str]| -> String {
                DatabaseCommandBuilder::build_restore_command(
                    db_type,
                    f[0],
                    port,
                    f[1],
                    with_pw.then_some(f[4]),
                    f[2],
                    f[3],
                )
            };
            let ctx = format!("{name} restore, password={with_pw}");
            let cmd = build(&all5[..]);
            assert_arrives_as_text(&cmd, data, &ctx);
            assert_each_field_inert(&ctx, data, 5, &build);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, &ctx);
            check_password_plumbing(&build(&["x"; 5][..]), "x", is_mysql, with_pw, &ctx);
            if is_mysql {
                assert!(
                    cmd.contains(" --binary-mode < "),
                    "{ctx}: --binary-mode missing: {cmd}"
                );
            }

            // 3. Dump command. Fields: host, user, database, table, password, output file.
            let all6: [&str; 6] = [data; 6];
            let build = |f: &[&str]| -> String {
                let tables = vec![f[3].to_string()];
                DatabaseCommandBuilder::build_dump_command(
                    db_type,
                    f[0],
                    port,
                    f[1],
                    with_pw.then_some(f[4]),
                    f[2],
                    Some(tables.as_slice()),
                    Some("gzip"),
                    f[5],
                )
            };
            let ctx = format!("{name} dump, password={with_pw}");
            let cmd = build(&all6[..]);
            assert_arrives_as_text(&cmd, data, &ctx);
            assert_each_field_inert(&ctx, data, 6, &build);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, &ctx);
            check_password_plumbing(&build(&["x"; 6][..]), "x", is_mysql, with_pw, &ctx);
            // The builder's own structure (a dropped compression suffix), not
            // an injection property.
            assert!(
                cmd.contains("| gzip >"),
                "{ctx}: must have gzip compression: {cmd}"
            );
        }
    }

    // 4. Should never panic (implicit)
});
