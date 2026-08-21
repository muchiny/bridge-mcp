#![no_main]
use libfuzzer_sys::fuzz_target;
// `TaskResultParams` is gone: MCP 2026-07-28 has no `tasks/result` method,
// so there is no such params shape left to fuzz.
// `TaskListParams` is gone too: `tasks/list` was removed deliberately so a
// server cannot leak one caller's task ids to another.
use bridge_mcp::{TaskCancelParams, TaskGetParams, TaskRequest};

fuzz_target!(|data: &[u8]| {
    let _: Result<TaskGetParams, _> = serde_json::from_slice(data);
    let _: Result<TaskCancelParams, _> = serde_json::from_slice(data);
    let _: Result<TaskRequest, _> = serde_json::from_slice(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<TaskGetParams, _> = serde_json::from_str(s);
        let _: Result<TaskCancelParams, _> = serde_json::from_str(s);
        let _: Result<TaskRequest, _> = serde_json::from_str(s);
    }
});
