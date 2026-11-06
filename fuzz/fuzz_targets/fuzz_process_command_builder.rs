#![no_main]

use bridge_mcp::domain::use_cases::process::ProcessCommandBuilder;
use bridge_mcp_fuzz::{assert_same_shell_skeleton, shell_shape, shell_words};
use libfuzzer_sys::fuzz_target;

/// The `N` of the builder's trailing `| head -n N`.
///
/// Whatever follows the last unquoted `|` is the builder's own text: a caller
/// value only ever reaches the line inside quotes, where `shell_shape` reads it
/// as literal and keeps it before that pipe. So the last three literal runs of
/// a `top` command are `head`, `-n` and the count, and nothing a caller wrote
/// can stand in for them.
fn head_rows(command: &str) -> u64 {
    let shape = shell_shape(command)
        .unwrap_or_else(|| panic!("top emitted an unscannable command: {command:?}"));
    let [.., head, flag, n] = shape.literals.as_slice() else {
        panic!("top has no trailing `head -n N`: {command:?}");
    };
    assert!(
        head.as_str() == "head" && flag.as_str() == "-n",
        "top must end in `head -n N`, got {:?} from {command:?}",
        shape.literals
    );
    n.parse::<u64>()
        .unwrap_or_else(|_| panic!("head count {n:?} is not a number: {command:?}"))
}

// `build_list_command` emits an `awk` pipeline, so its operators are its own.
// What must never happen is the caller adding one — `user`, `sort_by` and
// `filter` all reach the command line, and none of them has a validator.
// Comparing the shell skeleton against a benign build says exactly that.
fuzz_target!(|data: (&str, &str, &str, u32)| {
    let (user, sort_by, filter, count) = data;

    assert_same_shell_skeleton(
        &ProcessCommandBuilder::build_list_command(Some("root"), Some("%cpu"), Some("nginx")),
        &ProcessCommandBuilder::build_list_command(Some(user), Some(sort_by), Some(filter)),
        "list",
    );
    assert_same_shell_skeleton(
        &ProcessCommandBuilder::build_top_command(Some("%cpu"), Some("root"), Some(20)),
        &ProcessCommandBuilder::build_top_command(Some(sort_by), Some(user), Some(count)),
        "top",
    );

    // The user reaches `ps -u {}` and must arrive whole, or the snapshot is
    // of somebody else's processes.
    let top = ProcessCommandBuilder::build_top_command(Some(sort_by), Some(user), Some(count));
    let shape =
        shell_shape(&top).unwrap_or_else(|| panic!("top emitted an unscannable command: {top:?}"));
    assert!(
        shape.literals.iter().any(|l| l == user),
        "user {user:?} did not arrive intact; literals {:?} from {top:?}",
        shape.literals
    );

    // `head -n {count + 1}` used to wrap to 0 on `u32::MAX`, so asking for
    // every process produced an empty listing that read as "no processes".
    //
    // The row count is read from the builder's own tail, never searched for as
    // text. `user` and `sort_by` are quoted literals and may contain any string,
    // "head -n 0" included (the fuzzer writes it into `user` within minutes);
    // a substring test on the whole line took that correctly quoted text for the
    // builder's output and failed the job on every run (issue #222).
    let rows = head_rows(&top);
    let asked = u64::from(count);
    assert!(
        rows >= 1,
        "count {count} collapsed the listing to nothing: {top:?}"
    );
    // Never fewer rows than asked for (up to a floor far below any ceiling the
    // builder may apply), never more than the request plus its header line.
    assert!(
        rows >= asked.saturating_add(1).min(1001),
        "count {count} was cut short to {rows} rows: {top:?}"
    );
    assert!(
        rows <= asked.saturating_add(1),
        "count {count} grew to {rows} rows: {top:?}"
    );

    // Fixed inputs, where over-refusal can be checked without risk: zero rows
    // asked for is the header alone, an ordinary count is untouched, and the
    // value that used to wrap still lists something.
    assert_eq!(
        head_rows(&ProcessCommandBuilder::build_top_command(
            None,
            None,
            Some(0)
        )),
        1
    );
    assert_eq!(
        head_rows(&ProcessCommandBuilder::build_top_command(
            None,
            None,
            Some(20)
        )),
        21
    );
    assert!(
        head_rows(&ProcessCommandBuilder::build_top_command(
            None,
            None,
            Some(u32::MAX)
        )) >= 1001,
        "u32::MAX rows must not collapse"
    );

    // ── kill: a closed signal list, and three inert words ─────────────
    let allowed = ProcessCommandBuilder::validate_signal(sort_by).is_ok();
    let built = ProcessCommandBuilder::build_kill_command(1234, Some(sort_by));
    assert_eq!(
        built.is_ok(),
        allowed,
        "kill: builder disagrees with validate_signal on {sort_by:?}"
    );
    if let Ok(cmd) = built {
        let words =
            shell_words(&cmd).unwrap_or_else(|| panic!("kill emitted shell syntax: {cmd:?}"));
        assert_eq!(words.len(), 3, "kill must be three words, got {words:?}");
        assert!(
            words
                .iter()
                .all(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
            "kill emitted a word that is not inert: {words:?}"
        );
    }

    // Protected PIDs are refused whatever the signal.
    for pid in [0, 1] {
        ProcessCommandBuilder::build_kill_command(pid, Some("TERM"))
            .expect_err("PID 0 and 1 are protected");
    }
});
