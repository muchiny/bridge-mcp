#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::SecurityConfig;

fuzz_target!(|data: &[u8]| {
    // Fuzz security configuration parsing
    // This is critical as malformed config could disable security

    if let Ok(yaml_str) = std::str::from_utf8(data) {
        let _result: Result<SecurityConfig, _> = serde_saphyr::from_str(yaml_str);
    }

    // Also try JSON
    let _result: Result<SecurityConfig, _> = serde_json::from_slice(data);

    // Should never panic
});
