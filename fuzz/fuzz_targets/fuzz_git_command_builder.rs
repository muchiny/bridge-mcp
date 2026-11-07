#![no_main]
use bridge_mcp_fuzz::assert_arrives_as_text;
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::git::GitCommandBuilder;

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
// `cargo +nightly fuzz run fuzz_git_command_builder -- -dict=fuzz/dicts/shell.dict`

/// Git's `git_url_basename` (`dir.c`, git 2.56), the name `git clone <url>` gives
/// its target when no directory is passed, ported statement by statement from the
/// C and on bytes, INCLUDING the rewriting of control bytes and whitespace in the
/// name and the trimming of trailing whitespace. It is deliberately NOT the
/// validator's algorithm (`str` operations, no whitespace handling): an oracle
/// that copies the code under test cannot fail. `None` is git's
/// `No directory name could be guessed`.
///
/// Checked against the real `git clone` ("Cloning into" line) on 43 URLs and on
/// 300 random ones; the evidence is in the tests of `validate_clone_destination`.
fn git_url_basename(repo: &[u8]) -> Option<Vec<u8>> {
    let is_sep = |b: u8| b == b'/';
    // git's ctype: space, \t, \n, \r only.
    let is_space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r');
    let mut end = repo.len();
    // Skip the scheme.
    let mut start = repo
        .windows(3)
        .position(|w| w == b"://")
        .map_or(0, |i| i + 3);
    // Skip authentication data: up to the last '@' before the first separator.
    let mut ptr = start;
    while ptr < end && !is_sep(repo[ptr]) {
        if repo[ptr] == b'@' {
            start = ptr + 1;
        }
        ptr += 1;
    }
    // Strip trailing spaces, slashes and /.git
    while start < end && (is_sep(repo[end - 1]) || is_space(repo[end - 1])) {
        end -= 1;
    }
    if end - start > 5 && is_sep(repo[end - 5]) && repo[end - 4..end] == *b".git" {
        end -= 5;
        while start < end && is_sep(repo[end - 1]) {
            end -= 1;
        }
    }
    // Strip a trailing port number when there is only a host.
    if !repo[start..end].contains(&b'/') && repo[start..end].contains(&b':') {
        ptr = end;
        while start < ptr && repo[ptr - 1].is_ascii_digit() && repo[ptr - 1] != b':' {
            ptr -= 1;
        }
        if start < ptr && repo[ptr - 1] == b':' {
            end = ptr - 1;
        }
    }
    // Find the last component ('/' and ':' both separate).
    ptr = end;
    while start < ptr && !is_sep(repo[ptr - 1]) && repo[ptr - 1] != b':' {
        ptr -= 1;
    }
    start = ptr;
    // Strip .git
    let mut len = end - start;
    if len >= 4 && repo[start + len - 4..start + len] == *b".git" {
        len -= 4;
    }
    if len == 0 {
        return None;
    }
    // Replace runs of control bytes and whitespace with one space, and remove
    // leading and trailing spaces.
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut prev_space = true;
    for &raw in &repo[start..start + len] {
        let ch = if raw < 0x20 { b' ' } else { raw };
        if is_space(ch) {
            if prev_space {
                continue;
            }
            prev_space = true;
        } else {
            prev_space = false;
        }
        out.push(ch);
    }
    if prev_space {
        out.pop();
    }
    Some(out)
}

fuzz_target!(|data: &str| {
    // validate_branch_action
    let _ = GitCommandBuilder::validate_branch_action(data);

    // status
    let cmd = GitCommandBuilder::build_status_command(data, true);
    assert_arrives_as_text(&cmd, data, "status");

    // log
    let cmd = GitCommandBuilder::build_log_command(
        data,
        Some(10),
        true,
        Some(data),
        Some(data),
        Some(data),
        Some(data),
    );
    assert_arrives_as_text(&cmd, data, "log");

    // diff
    let cmd = GitCommandBuilder::build_diff_command(data, true, Some(data), Some(data));
    assert_arrives_as_text(&cmd, data, "diff");

    // pull
    let cmd = GitCommandBuilder::build_pull_command(data, Some(data), Some(data), true, true);
    assert_arrives_as_text(&cmd, data, "pull");

    // pull: the second property. A `remote` the validator accepts is the name
    // of a configured remote and nothing else: no URL (`:` `@`), no path (`/`
    // `\`), no option (leading `-`), no `.`-leading name, no whitespace or
    // shell syntax. A `branch` with no `remote` is always refused (git would
    // read it as the repository) and is never emitted.
    if GitCommandBuilder::validate_pull_target(Some(data), None).is_ok() {
        assert!(
            !data.is_empty() && !data.starts_with(['-', '.']),
            "remote {data:?}"
        );
        assert!(
            data.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
            "remote {data:?}"
        );
    }
    assert!(GitCommandBuilder::validate_pull_target(None, Some(data)).is_err());
    let cmd = GitCommandBuilder::build_pull_command("/r", None, Some(data), false, false);
    assert_eq!(
        cmd,
        "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
         git -C '/r' -c safe.bareRepository=explicit -c http.extraHeader= pull"
    );

    // `clone` drops the client certificate variables and resets the unscoped
    // extra header before anything the caller chose, whatever the arguments.
    let cmd = GitCommandBuilder::build_clone_command(data, None, None, None, false);
    assert!(
        cmd.starts_with(
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone -- "
        ),
        "{cmd}"
    );

    // Every builder runs git with `safe.bareRepository=explicit`, whatever the
    // path: a bare repository is never discovered implicitly.
    for cmd in [
        GitCommandBuilder::build_status_command(data, false),
        GitCommandBuilder::build_log_command(data, None, false, None, None, None, None),
        GitCommandBuilder::build_diff_command(data, false, None, None),
        GitCommandBuilder::build_pull_command(data, None, None, false, false),
        GitCommandBuilder::build_branch_command(data, "list", None, false),
        GitCommandBuilder::build_checkout_command(data, "x", false),
    ] {
        assert!(cmd.contains(" -c safe.bareRepository=explicit "), "{cmd}");
    }
    let cmd = GitCommandBuilder::build_clone_command(data, None, None, None, false);
    assert!(cmd.contains(" -c safe.bareRepository=explicit "), "{cmd}");

    // The destination property: whatever `validate_clone_destination` accepts
    // is an absolute path with no component starting with `.`; whatever it
    // accepts without a destination makes git create a directory whose name is
    // not empty and does not start with `.` (`git_url_basename`, ported above
    // with git's whitespace rewriting). Refusal is always fine.
    if GitCommandBuilder::validate_clone_destination(Some(data), "https://h/r.git").is_ok() {
        assert!(data.starts_with('/'), "destination {data:?}");
        assert!(
            data.split(['/', '\\']).all(|c| !c.starts_with('.')),
            "destination {data:?}"
        );
    }
    if GitCommandBuilder::validate_clone_destination(None, data).is_ok() {
        // No byte git would rewrite.
        assert!(data.bytes().all(|b| b > 0x20 && b != 0x7f), "url {data:?}");
        // The directory git really creates is neither empty (git would stop)
        // nor hidden: the oracle is the port above, not the validator's code.
        let created = git_url_basename(data.as_bytes());
        assert!(
            created
                .as_ref()
                .is_some_and(|name| !name.is_empty() && !name.starts_with(b".")),
            "url {data:?} would create {created:?}"
        );
    }

    // `pull` drops them too, whatever the path.
    let cmd = GitCommandBuilder::build_pull_command(data, None, None, false, false);
    assert!(
        cmd.starts_with(
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && git -C "
        ),
        "{cmd}"
    );

    // clone
    let cmd =
        GitCommandBuilder::build_clone_command(data, Some(data), Some(data), Some(1), true);
    assert_arrives_as_text(&cmd, data, "clone");

    // branch
    let cmd = GitCommandBuilder::build_branch_command(data, "list", Some(data), true);
    assert_arrives_as_text(&cmd, data, "branch");

    // checkout
    let cmd = GitCommandBuilder::build_checkout_command(data, data, true);
    assert_arrives_as_text(&cmd, data, "checkout");
});
