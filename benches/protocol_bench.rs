//! Benchmarks for MCP JSON-RPC protocol parsing and serialization
//!
//! Run with: `cargo bench --bench protocol_bench`

use bridge_mcp::mcp::protocol::{JsonRpcRequest, JsonRpcResponse, ToolCallParams};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};
use std::hint::black_box;

fn create_initialize_request() -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "claude-code",
                "version": "1.0.0"
            }
        }
    }))
    .unwrap()
}

fn create_tools_list_request() -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }))
    .unwrap()
}

fn create_tools_call_request() -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "ssh_exec",
            "arguments": {
                "host": "production-server",
                "command": "docker ps --format '{{.Names}}\\t{{.Status}}'"
            }
        }
    }))
    .unwrap()
}

fn create_success_response() -> JsonRpcResponse {
    JsonRpcResponse::success(
        Some(Value::Number(42.into())),
        json!({
            "content": [{
                "type": "text",
                "text": "CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES\nabc123   nginx   \"nginx -g 'daemon off;'\"   2 hours ago   Up 2 hours   80/tcp   web"
            }],
            "isError": false
        }),
    )
}

fn benchmark_request_parsing(c: &mut Criterion) {
    let init_req = create_initialize_request();
    let list_req = create_tools_list_request();
    let call_req = create_tools_call_request();

    c.bench_function("protocol: parse initialize request", |b| {
        b.iter(|| serde_json::from_str::<JsonRpcRequest>(black_box(&init_req)).unwrap());
    });

    c.bench_function("protocol: parse tools/list request", |b| {
        b.iter(|| serde_json::from_str::<JsonRpcRequest>(black_box(&list_req)).unwrap());
    });

    c.bench_function("protocol: parse tools/call request", |b| {
        b.iter(|| serde_json::from_str::<JsonRpcRequest>(black_box(&call_req)).unwrap());
    });
}

fn benchmark_params_extraction(c: &mut Criterion) {
    let call_req = create_tools_call_request();
    let parsed: JsonRpcRequest = serde_json::from_str(&call_req).unwrap();
    let params_value = parsed.params.unwrap();

    c.bench_function("protocol: extract ToolCallParams from Value", |b| {
        b.iter(|| serde_json::from_value::<ToolCallParams>(black_box(params_value.clone())));
    });
}

fn benchmark_response_serialization(c: &mut Criterion) {
    let response = create_success_response();

    c.bench_function("protocol: serialize success response", |b| {
        b.iter(|| serde_json::to_string(black_box(&response)).unwrap());
    });

    let error_response = JsonRpcResponse::error(
        Some(Value::Number(1.into())),
        bridge_mcp::mcp::protocol::JsonRpcError::internal_error("Connection refused"),
    );

    c.bench_function("protocol: serialize error response", |b| {
        b.iter(|| serde_json::to_string(black_box(&error_response)).unwrap());
    });
}

criterion_group!(
    benches,
    benchmark_request_parsing,
    benchmark_params_extraction,
    benchmark_response_serialization,
);
criterion_main!(benches);
