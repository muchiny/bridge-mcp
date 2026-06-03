#![no_main]
use libfuzzer_sys::fuzz_target;
use bridge_mcp::{
    TaskCancelParams, TaskGetParams, TaskListParams, TaskRequest, TaskResultParams,
};

fuzz_target!(|data: &[u8]| {
    let _: Result<TaskGetParams, _> = serde_json::from_slice(data);
    let _: Result<TaskResultParams, _> = serde_json::from_slice(data);
    let _: Result<TaskCancelParams, _> = serde_json::from_slice(data);
    let _: Result<TaskListParams, _> = serde_json::from_slice(data);
    let _: Result<TaskRequest, _> = serde_json::from_slice(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<TaskGetParams, _> = serde_json::from_str(s);
        let _: Result<TaskResultParams, _> = serde_json::from_str(s);
        let _: Result<TaskCancelParams, _> = serde_json::from_str(s);
        let _: Result<TaskListParams, _> = serde_json::from_str(s);
        let _: Result<TaskRequest, _> = serde_json::from_str(s);
    }
});
