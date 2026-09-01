#![no_main]

use bridge_mcp::domain::use_cases::process::ProcessCommandBuilder;
use bridge_mcp_fuzz::{assert_same_shell_skeleton, shell_shape, shell_words};
use libfuzzer_sys::fuzz_target;

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
    let shape = shell_shape(&top)
        .unwrap_or_else(|| panic!("top emitted an unscannable command: {top:?}"));
    assert!(
        shape.literals.iter().any(|l| l == user),
        "user {user:?} did not arrive intact; literals {:?} from {top:?}",
        shape.literals
    );

    // `head -n {count + 1}` used to wrap to 0 on `u32::MAX`, so asking for
    // every process produced an empty listing that read as "no processes".
    assert!(
        !top.contains("head -n 0"),
        "count {count} collapsed the listing to nothing: {top:?}"
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
        let words = shell_words(&cmd)
            .unwrap_or_else(|| panic!("kill emitted shell syntax: {cmd:?}"));
        assert_eq!(words.len(), 3, "kill must be three words, got {words:?}");
        assert!(
            words.iter().all(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
            "kill emitted a word that is not inert: {words:?}"
        );
    }

    // Protected PIDs are refused whatever the signal.
    for pid in [0, 1] {
        ProcessCommandBuilder::build_kill_command(pid, Some("TERM"))
            .expect_err("PID 0 and 1 are protected");
    }
});
