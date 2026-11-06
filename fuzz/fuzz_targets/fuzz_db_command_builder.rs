#![no_main]

use std::net::IpAddr;

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
// Another server than the local one: a `db_host` that is not `localhost`,
// a loopback address or, for PostgreSQL, a fixed socket directory must never be
// handed a password or client certificate stored on the host. The builders
// write a different shape for it (an `unset` prefix, `HOME=/nonexistent` and
// `--defaults-file` for MySQL, `--local-infile=0`, `PGSSLCERT=/nonexistent` and
// an empty or the caller's `PGPASSFILE` for PostgreSQL), and every builder is
// checked in BOTH shapes. Every PostgreSQL client runs with `-w`, local or not,
// and a socket directory gets `*` as the host field of its password line. The
// classification is re-implemented here (`is_local_host`) on purpose: an oracle
// that called the product's own function would agree with it by construction.
// The benign build of the per-field comparison uses a host of the SAME shape as
// the fuzzed one when the host is the field under test, since the two shapes
// legitimately have different skeletons.
//
// Run with the dictionary or this explores very little:
// `cargo +nightly fuzz run fuzz_db_command_builder -- -dict=fuzz/dicts/shell.dict`

/// The PostgreSQL socket directories the product treats as local.
const PG_SOCKET_DIRS: [&str; 2] = ["/var/run/postgresql", "/run/postgresql"];

/// The `unset` prefix of a PostgreSQL command that connects to another server.
const PG_UNSET: &str = "unset PGPASSWORD PGSERVICE PGSERVICEFILE PGSYSCONFDIR PGHOSTADDR && ";

/// Whether `host` is the local server for the builders: `localhost`, a
/// loopback address (IPv4-mapped IPv6 included) and, for PostgreSQL, a fixed
/// socket directory.
fn is_local_host(host: &str, is_mysql: bool) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_canonical().is_loopback();
    }
    !is_mysql && PG_SOCKET_DIRS.contains(&host)
}

/// Assert that `data`, placed in any single one of the `n` fields while the
/// others stay benign, adds no shell syntax to what `build` emits. Field 0 is
/// the database host. The comparison runs with an other-server host and with a
/// local host; when the host itself is under test, only against the shape its
/// own value selects.
fn assert_each_field_inert(
    context: &str,
    data: &str,
    n: usize,
    is_mysql: bool,
    build: &dyn Fn(&[&str]) -> String,
) {
    for benign_host in ["x", "localhost"] {
        let mut benign_fields = vec!["x"; n];
        benign_fields[0] = benign_host;
        let benign = build(&benign_fields[..]);
        for i in 0..n {
            if i == 0 && is_local_host(data, is_mysql) != (benign_host == "localhost") {
                continue;
            }
            let mut fields = benign_fields.clone();
            fields[i] = data;
            let hostile = build(&fields[..]);
            assert_same_shell_skeleton(
                &benign,
                &hostile,
                &format!("{context}, host {benign_host}, field {i}"),
            );
        }
    }
}

/// How the password reaches the DB client, for any builder. `local` is whether
/// the host of the build is the local server.
fn check_password_plumbing(
    cmd: &str,
    data: &str,
    is_mysql: bool,
    with_pw: bool,
    local: bool,
    context: &str,
) {
    // The password must not travel as a `MYSQL_PWD` / `PGPASSWORD` environment
    // variable. FIND-031 moved these builders to an option file (MySQL) and
    // `PGPASSFILE` (PostgreSQL) so the secret stays out of argv and environ
    // of the DB client. It is still in the command STRING, as the `printf`
    // argument that writes the tempfile (the "Known gap" note in database.rs).
    // The assertion is on the ASSIGNMENT (`NAME=`): another-server commands
    // legitimately carry `unset MYSQL_PWD` / `unset PGPASSWORD ...`.
    // Guarded on `data`: the builder pastes the fuzzed host, user, database and
    // query into the command as text, so an input that itself spells the token
    // puts it in the command without the builder ever writing it. Absent from
    // the input, it can only come from the builder.
    for token in ["MYSQL_PWD", "PGPASSWORD"] {
        if !data.contains(token) {
            assert!(
                !cmd.contains(&format!("{token}=")),
                "{context}: password must not travel in {token}: {cmd}"
            );
        }
    }
    // The positive side, unconditional: the builder writes these itself.
    if with_pw {
        let marker = if is_mysql && local {
            "--defaults-extra-file=$TMPF"
        } else if is_mysql {
            // Another server: the client reads the file of the call only.
            "--defaults-file=$TMPF"
        } else {
            "PGPASSFILE=$TMPF "
        };
        assert!(
            cmd.contains(marker),
            "{context}: password given but {marker:?} missing: {cmd}"
        );
        // One-directional: the extra option file (read after the host's own
        // files) is the local shape only.
        if is_mysql && !local && !data.contains("--defaults-extra-file") {
            assert!(
                !cmd.contains("--defaults-extra-file"),
                "{context}: another server: --defaults-extra-file present: {cmd}"
            );
        }
    } else if local {
        // No password, local server: no tempfile prelude at all (guarded on
        // `data` as above).
        for token in ["PGPASSFILE", "TMPF"] {
            if !data.contains(token) {
                assert!(
                    !cmd.contains(token),
                    "{context}: no password but {token} present: {cmd}"
                );
            }
        }
    } else if is_mysql {
        // No password, another server: no option file at all.
        assert!(
            cmd.contains(" --no-defaults "),
            "{context}: no password, another server: --no-defaults missing: {cmd}"
        );
        if !data.contains("TMPF") {
            assert!(
                !cmd.contains("TMPF"),
                "{context}: no password but TMPF present: {cmd}"
            );
        }
    } else {
        // No password, another server (PostgreSQL): an EMPTY password file, so
        // that no stored source is reachable.
        assert!(
            cmd.contains("PGPASSFILE=$TMPF "),
            "{context}: no password, another server: PGPASSFILE missing: {cmd}"
        );
        if !data.contains("printf") {
            assert!(
                !cmd.contains("printf"),
                "{context}: no password but a password line is written: {cmd}"
            );
        }
    }

    // The shape that depends on the host (the builder writes these itself, so
    // unconditional where they are positive).
    if local {
        assert!(
            !cmd.starts_with("unset "),
            "{context}: local server but an unset prefix: {cmd}"
        );
        for token in [
            "HOME=/nonexistent",
            "MYSQL_TEST_LOGIN_FILE",
            "--local-infile",
            "PGSSLCERT",
        ] {
            if !data.contains(token) {
                assert!(
                    !cmd.contains(token),
                    "{context}: local server but {token} present: {cmd}"
                );
            }
        }
    } else if is_mysql {
        assert!(
            cmd.starts_with("unset MYSQL_PWD && "),
            "{context}: another server: unset prefix missing: {cmd}"
        );
        assert!(
            cmd.contains("HOME=/nonexistent MYSQL_TEST_LOGIN_FILE=/dev/null mysql"),
            "{context}: another server: ~/.my.cnf not hidden: {cmd}"
        );
    } else {
        assert!(
            cmd.starts_with(PG_UNSET),
            "{context}: another server: unset prefix missing: {cmd}"
        );
        // `-w`: never prompt for a password. A prompt without a terminal is
        // answered from standard input, which for a restore is the input file.
        assert!(
            cmd.contains("PGPASSFILE=$TMPF PGSSLCERT=/nonexistent psql -w -h ")
                || cmd.contains("PGPASSFILE=$TMPF PGSSLCERT=/nonexistent pg_dump -w -h "),
            "{context}: another server: PGSSLCERT or -w missing: {cmd}"
        );
    }
    // `-w` on every PostgreSQL client, local or not (written by the builder).
    if !is_mysql {
        assert!(
            cmd.contains("psql -w -h ") || cmd.contains("pg_dump -w -h "),
            "{context}: PostgreSQL client without -w: {cmd}"
        );
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
            assert_each_field_inert(&ctx, data, 5, is_mysql, &build);
            let local = is_local_host(data, is_mysql);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, local, &ctx);
            if !is_mysql && with_pw {
                // A socket directory gets `*` as the host field of its password
                // line, every other host keeps its own (benign other fields).
                for dir in PG_SOCKET_DIRS {
                    let line = build(&[dir, "x", "x", "x", "x"]);
                    assert!(
                        line.contains("printf '%s:%s:%s:%s:%s\\n' '*' '5432' 'x' 'x' 'x'"),
                        "{ctx}: socket directory {dir}: host field is not '*': {line}"
                    );
                }
                let line = build(&["x", "x", "x", "x", "x"]);
                assert!(
                    line.contains("printf '%s:%s:%s:%s:%s\\n' 'x' '5432' 'x' 'x' 'x'"),
                    "{ctx}: host field is not the host: {line}"
                );
            }
            // The same checks on all-benign builds (another server, then the
            // local one), where none of them is skipped: the fuzzed run above
            // has to step aside whenever `data` spells one of the tokens, which
            // the fuzzer does quickly.
            let mut benign = ["x"; 5];
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, false, &ctx);
            benign[0] = "localhost";
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, true, &ctx);
            if is_mysql {
                // 6.0.0: `--binary-mode` switches the client's own commands
                // (`\!`, `system`, ...) off. Written in both branches. Another
                // server also gets `--local-infile=0`.
                let tail = if local {
                    " --binary-mode -e '"
                } else {
                    " --binary-mode --local-infile=0 -e '"
                };
                assert!(cmd.contains(tail), "{ctx}: {tail:?} missing: {cmd}");
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
            assert_each_field_inert(&ctx, data, 5, is_mysql, &build);
            let local = is_local_host(data, is_mysql);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, local, &ctx);
            let mut benign = ["x"; 5];
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, false, &ctx);
            benign[0] = "localhost";
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, true, &ctx);
            if is_mysql {
                let tail = if local {
                    " --binary-mode < "
                } else {
                    " --binary-mode --local-infile=0 < "
                };
                assert!(cmd.contains(tail), "{ctx}: {tail:?} missing: {cmd}");
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
            assert_each_field_inert(&ctx, data, 6, is_mysql, &build);
            let local = is_local_host(data, is_mysql);
            check_password_plumbing(&cmd, data, is_mysql, with_pw, local, &ctx);
            let mut benign = ["x"; 6];
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, false, &ctx);
            benign[0] = "localhost";
            check_password_plumbing(&build(&benign[..]), "x", is_mysql, with_pw, true, &ctx);
            // `mysqldump` refuses `--local-infile` on its command line: never
            // written, whatever the host (guarded on `data`).
            if !data.contains("local-infile") {
                assert!(
                    !cmd.contains("local-infile"),
                    "{ctx}: dump must not carry --local-infile: {cmd}"
                );
            }
            // The builder's own structure (a dropped compression suffix), not
            // an injection property.
            assert!(
                cmd.contains("| gzip >"),
                "{ctx}: must have gzip compression: {cmd}"
            );
        }
    }

    // 4. `validate_connection` and the classification agree: a host accepted
    //    WITHOUT a password is a local one (an other-server host without a
    //    password would fall back to the credentials stored on the SSH host),
    //    and a host accepted WITH one is a single name or address. (The
    //    converse, that every name-like host is accepted, is not a property:
    //    an other-server host also needs a password, and the user and database
    //    rules apply, so only the "accepted implies" direction is asserted.)
    //    A password accepted is at most 1024 bytes.
    for (db_type, _, name, is_mysql) in &cases {
        let accepted_without = DatabaseCommandBuilder::validate_connection(
            db_type,
            Some(data),
            None,
            "db",
            None,
            None,
        )
        .is_ok();
        if accepted_without {
            assert!(
                is_local_host(data, *is_mysql),
                "{name}: db_host {data:?} accepted without db_password but is not local"
            );
        }
        let accepted_with = DatabaseCommandBuilder::validate_connection(
            db_type,
            Some(data),
            None,
            "db",
            Some("pw"),
            None,
        )
        .is_ok();
        if accepted_with {
            let socket_dir = !*is_mysql && PG_SOCKET_DIRS.contains(&data);
            let name_like = !data.is_empty()
                && data.len() <= 253
                && data
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b));
            assert!(
                socket_dir || name_like,
                "{name}: db_host {data:?} accepted but is not one host name or address"
            );
        }
    }

    for (db_type, _, name, _) in &cases {
        let accepted = DatabaseCommandBuilder::validate_connection(
            db_type,
            None,
            None,
            "db",
            Some(data),
            None,
        )
        .is_ok();
        if accepted {
            assert!(
                data.len() <= 1024,
                "{name}: db_password of {} bytes accepted",
                data.len()
            );
        }
    }

    // 5. Should never panic (implicit)
});
