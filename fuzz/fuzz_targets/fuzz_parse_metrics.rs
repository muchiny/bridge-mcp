#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::{parse_cpu, parse_disk, parse_load, parse_memory};

fuzz_target!(|data: &str| {
    // Fuzz all metrics parsing functions
    // These parse output from system commands and should handle malformed input gracefully

    // 1. CPU metrics parsing (from /proc/stat or similar)
    let _cpu = parse_cpu(data);
    // Should return None for invalid input, never panic

    // 2. Memory metrics parsing (from /proc/meminfo or similar)
    let _memory = parse_memory(data);
    // Should return None for invalid input, never panic

    // 3. Disk metrics parsing (from df output)
    let _disk = parse_disk(data);
    // Should return None for invalid input, never panic

    // 4. Load metrics parsing (from /proc/loadavg or similar)
    let _load = parse_load(data);
    // Should return None for invalid input, never panic

    // All functions should handle arbitrary input without panicking
    // (implicit test - if we reach here, no panic occurred)
});
