#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::HostConfig;

fuzz_target!(|data: &[u8]| {
    // Fuzz host configuration parsing
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        let _result: Result<HostConfig, _> = serde_saphyr::from_str(yaml_str);
    }

    // Also try JSON format
    let _result: Result<HostConfig, _> = serde_json::from_slice(data);

    // Should never panic
});
