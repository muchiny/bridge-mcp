#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::windows_event::{
    validate_log_name, WindowsEventCommandBuilder,
};

fuzz_target!(|data: (u32, &str)| {
    let (count, text) = data;

    // validator
    let _ = validate_log_name(text);

    // query
    let cmd = WindowsEventCommandBuilder::build_query_command(text, count, Some(text));
    assert!(cmd.contains("Get-WinEvent"), "query must contain 'Get-WinEvent': {cmd}");

    // query without after
    let cmd = WindowsEventCommandBuilder::build_query_command(text, count, None);
    assert!(cmd.contains("Get-WinEvent"), "query (no after) must contain 'Get-WinEvent': {cmd}");

    // sources
    let cmd = WindowsEventCommandBuilder::build_sources_command();
    assert!(cmd.contains("Get-WinEvent"), "sources must contain 'Get-WinEvent': {cmd}");

    // tail
    let cmd = WindowsEventCommandBuilder::build_tail_command(text, count);
    assert!(cmd.contains("Get-WinEvent"), "tail must contain 'Get-WinEvent': {cmd}");

    // export
    let cmd = WindowsEventCommandBuilder::build_export_command(text, text);
    assert!(
        cmd.contains("wevtutil"),
        "export must contain 'wevtutil': {cmd}"
    );
});
