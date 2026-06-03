#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::git::GitCommandBuilder;

fuzz_target!(|data: &str| {
    // validate_branch_action
    let _ = GitCommandBuilder::validate_branch_action(data);

    // status
    let cmd = GitCommandBuilder::build_status_command(data, true);
    assert!(cmd.contains("git"), "status must contain 'git': {cmd}");

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
    assert!(cmd.contains("git"), "log must contain 'git': {cmd}");

    // diff
    let cmd = GitCommandBuilder::build_diff_command(data, true, Some(data), Some(data));
    assert!(cmd.contains("git"), "diff must contain 'git': {cmd}");

    // pull
    let cmd = GitCommandBuilder::build_pull_command(data, Some(data), Some(data), true, true);
    assert!(cmd.contains("git"), "pull must contain 'git': {cmd}");

    // clone
    let cmd =
        GitCommandBuilder::build_clone_command(data, Some(data), Some(data), Some(1), true);
    assert!(cmd.contains("git"), "clone must contain 'git': {cmd}");

    // branch
    let cmd = GitCommandBuilder::build_branch_command(data, "list", Some(data), true);
    assert!(cmd.contains("git"), "branch must contain 'git': {cmd}");

    // checkout
    let cmd = GitCommandBuilder::build_checkout_command(data, data, true);
    assert!(cmd.contains("git"), "checkout must contain 'git': {cmd}");
});
