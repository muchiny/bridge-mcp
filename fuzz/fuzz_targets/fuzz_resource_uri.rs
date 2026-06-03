#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::ResourcesReadParams;

fuzz_target!(|data: &[u8]| {
    let _: Result<ResourcesReadParams, _> = serde_json::from_slice(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<ResourcesReadParams, _> = serde_json::from_str(s);
    }
});
