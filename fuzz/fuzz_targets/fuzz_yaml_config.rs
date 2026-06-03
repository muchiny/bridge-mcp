#![no_main]

use libfuzzer_sys::fuzz_target;
use bridge_mcp::Config;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as YAML config
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        // Attempt to deserialize as Config
        let _result: Result<Config, _> = serde_saphyr::from_str(yaml_str);
        // Whether it succeeds or fails, it should never panic
    }
});
