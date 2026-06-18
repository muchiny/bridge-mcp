#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::domain::use_cases::process::ProcessCommandBuilder;

fuzz_target!(|data: (u32, &str)| {
    let (pid, text) = data;

    // validator
    let _ = ProcessCommandBuilder::validate_signal(text);

    // list
    let _ = ProcessCommandBuilder::build_list_command(Some(text), Some(text), Some(text));

    // kill (may fail for pid 0/1 or bad signal)
    let _ = ProcessCommandBuilder::build_kill_command(pid, Some(text));

    // top
    let _ = ProcessCommandBuilder::build_top_command(Some(text), Some(text), Some(20));
});
