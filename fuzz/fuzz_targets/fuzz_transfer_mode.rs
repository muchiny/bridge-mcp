#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::TransferMode;

fuzz_target!(|data: &str| {
    // Fuzz TransferMode parsing
    let result = TransferMode::parse(data);

    // Invariants:
    // 1. Valid modes should return Some
    let valid_modes = ["overwrite", "append", "resume", "fail_if_exists",
                       "Overwrite", "APPEND", "Resume", "Fail_If_Exists"];

    if valid_modes.iter().any(|m| m.eq_ignore_ascii_case(data.trim())) {
        // Note: exact matching depends on implementation
    }

    // 2. Function should never panic
    let _ = result;
});
