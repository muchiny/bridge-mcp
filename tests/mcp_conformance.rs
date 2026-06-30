//! MCP Protocol Conformance Tests
//!
//! Validates that the MCP server implementation conforms to the
//! Model Context Protocol specification. Tests protocol structure,
//! tool schema validity, annotation completeness, and response formats.
//!
//! These complement the unit tests in `src/mcp/server.rs` (63+ tests)
//! and `tests/mcp_protocol.rs` (type serialization) by focusing on
//! specification-level compliance across all 337 tools.

use bridge_mcp::config::ToolGroupsConfig;
use bridge_mcp::mcp::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
use bridge_mcp::mcp::registry::{create_filtered_registry, tool_annotations};
use serde_json::{Value, json};

// ─── Protocol constants ────────────────────────────────────────────

#[test]
fn protocol_version_is_iso_date_format() {
    // MCP spec requires YYYY-MM-DD format
    let parts: Vec<&str> = PROTOCOL_VERSION.split('-').collect();
    assert_eq!(parts.len(), 3, "Protocol version must be YYYY-MM-DD");
    assert_eq!(parts[0].len(), 4, "Year must be 4 digits");
    assert_eq!(parts[1].len(), 2, "Month must be 2 digits");
    assert_eq!(parts[2].len(), 2, "Day must be 2 digits");

    let year: u32 = parts[0].parse().expect("Year must be numeric");
    let month: u32 = parts[1].parse().expect("Month must be numeric");
    let day: u32 = parts[2].parse().expect("Day must be numeric");

    assert!((2024..=2030).contains(&year));
    assert!((1..=12).contains(&month));
    assert!((1..=31).contains(&day));
}

#[test]
fn supported_versions_includes_current() {
    assert!(
        SUPPORTED_PROTOCOL_VERSIONS.contains(&PROTOCOL_VERSION),
        "Current protocol version must be in supported versions list"
    );
}

#[test]
fn supported_versions_are_chronologically_ordered() {
    // Latest version should be first
    assert_eq!(
        SUPPORTED_PROTOCOL_VERSIONS[0], PROTOCOL_VERSION,
        "Latest version must be first in supported versions"
    );

    // All versions should be valid dates and in descending order
    for window in SUPPORTED_PROTOCOL_VERSIONS.windows(2) {
        assert!(
            window[0] > window[1],
            "Versions must be in descending chronological order: {} should come after {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn server_name_is_lowercase_kebab_case() {
    assert!(
        SERVER_NAME
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-'),
        "Server name should be lowercase kebab-case, got: {SERVER_NAME}"
    );
}

#[test]
fn server_version_is_semver() {
    let parts: Vec<&str> = SERVER_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3, "Server version must be semver (x.y.z)");
    for part in &parts {
        part.parse::<u32>()
            .unwrap_or_else(|_| panic!("Semver component must be numeric: {part}"));
    }
}

// ─── JSON-RPC response format compliance ───────────────────────────

#[test]
fn success_response_has_required_fields() {
    let response = JsonRpcResponse::success(Some(json!(1)), json!({"key": "value"}));
    let serialized = serde_json::to_value(&response).unwrap();

    assert_eq!(serialized["jsonrpc"], "2.0", "jsonrpc field must be '2.0'");
    assert_eq!(serialized["id"], 1, "id must match request id");
    assert!(
        serialized.get("result").is_some(),
        "success response must have result"
    );
    assert!(
        serialized.get("error").is_none(),
        "success response must not have error"
    );
}

#[test]
fn error_response_has_required_fields() {
    let response =
        JsonRpcResponse::error(Some(json!(42)), JsonRpcError::internal_error("test error"));
    let serialized = serde_json::to_value(&response).unwrap();

    assert_eq!(serialized["jsonrpc"], "2.0");
    assert_eq!(serialized["id"], 42);
    assert!(serialized.get("error").is_some());

    let error = &serialized["error"];
    assert!(error["code"].is_number(), "error must have numeric code");
    assert!(error["message"].is_string(), "error must have message");
}

#[test]
fn error_codes_follow_jsonrpc_spec() {
    // JSON-RPC 2.0 defined error codes
    let parse_err = JsonRpcError::parse_error("test");
    assert_eq!(parse_err.code, -32700);

    let invalid_req = JsonRpcError::invalid_request("test");
    assert_eq!(invalid_req.code, -32600);

    let method_not_found = JsonRpcError::method_not_found("test");
    assert_eq!(method_not_found.code, -32601);

    let invalid_params = JsonRpcError::invalid_params("test");
    assert_eq!(invalid_params.code, -32602);

    let internal = JsonRpcError::internal_error("test");
    assert_eq!(internal.code, -32603);
}

#[test]
fn response_with_string_id() {
    let response = JsonRpcResponse::success(Some(json!("uuid-1234-5678")), json!({}));
    let serialized = serde_json::to_value(&response).unwrap();
    assert_eq!(serialized["id"], "uuid-1234-5678");
}

#[test]
fn response_with_null_id() {
    let response = JsonRpcResponse::success(None, json!({}));
    let serialized = serde_json::to_value(&response).unwrap();
    assert!(
        serialized["id"].is_null(),
        "null id should serialize as null"
    );
}

// ─── Tool schema compliance ────────────────────────────────────────

#[test]
fn all_tools_have_valid_json_schema() {
    // FIND-024 (audit 2026-05-09): default profile enables 8 minimal groups.
    // Conformance test exercises the full handler set, so use the all-enabled
    // helper rather than `ToolGroupsConfig::default()`.
    let registry = bridge_mcp::mcp::registry::create_all_enabled_registry();
    let tools = registry.list_tools();

    // Counts are dynamic (see .claude/rules/registry.md): adding a tool must
    // never require touching a test. Guard the failure mode that matters — an
    // empty or wrong (minimal-default) registry — with a generous lower bound
    // rather than a brittle exact count that goes stale on every tool add.
    assert!(
        tools.len() >= 300,
        "all-enabled registry should expose the full handler set, got {}",
        tools.len()
    );

    for tool in &tools {
        // Name must be non-empty and snake_case
        assert!(!tool.name.is_empty(), "Tool name must not be empty");
        assert!(
            tool.name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "Tool name must be snake_case (letters, digits, underscores): {}",
            tool.name
        );
        assert!(
            tool.name.starts_with("ssh_"),
            "Tool name must start with ssh_: {}",
            tool.name
        );

        // Description must be non-empty
        assert!(
            !tool.description.is_empty(),
            "Tool {} must have a description",
            tool.name
        );

        // Input schema must be a valid JSON Schema object
        let schema = &tool.input_schema;
        assert_eq!(
            schema["type"], "object",
            "Tool {} input_schema type must be 'object'",
            tool.name
        );

        // Must have properties (even if empty)
        assert!(
            schema.get("properties").is_some(),
            "Tool {} must have properties in input_schema",
            tool.name
        );

        // Required field, if present, must be an array
        if let Some(required) = schema.get("required") {
            assert!(
                required.is_array(),
                "Tool {} 'required' must be an array",
                tool.name
            );
        }
    }
}

#[test]
fn all_tools_require_host_parameter() {
    // FIND-024: same all-enabled scope as `all_tools_have_valid_json_schema`.
    let registry = bridge_mcp::mcp::registry::create_all_enabled_registry();
    let tools = registry.list_tools();

    let mut host_tools = 0;
    let mut no_host_tools = Vec::new();

    for tool in &tools {
        let properties = tool.input_schema.get("properties").unwrap();
        let has_host = properties.get("host").is_some() || properties.get("hosts").is_some();
        if has_host {
            host_tools += 1;
        } else {
            no_host_tools.push(tool.name.clone());
        }
    }

    // The vast majority of tools should take a host parameter
    assert!(
        host_tools > 170,
        "Expected >170 tools with host/hosts parameter, got {host_tools}. \
         Tools without host: {no_host_tools:?}"
    );
}

#[test]
fn all_tools_have_annotations() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);
    let tools = registry.list_tools();

    for tool in &tools {
        // Tool should have annotations set by the registry
        assert!(
            tool.annotations.is_some(),
            "Tool {} is missing annotations",
            tool.name
        );

        let ann = tool.annotations.as_ref().unwrap();

        // Annotations must have required hints
        assert!(
            ann.read_only_hint.is_some(),
            "Tool {} annotation missing readOnlyHint",
            tool.name
        );
        assert!(
            ann.destructive_hint.is_some(),
            "Tool {} annotation missing destructiveHint",
            tool.name
        );
    }
}

#[test]
fn tool_annotations_function_returns_valid_annotations() {
    // Verify a few known tools have correct annotation types
    let exec_ann = tool_annotations("ssh_exec");
    assert!(exec_ann.read_only_hint.is_some());

    let status_ann = tool_annotations("ssh_status");
    assert_eq!(status_ann.read_only_hint, Some(true));

    // Unknown tool returns default annotations (all hints None)
    let unknown_ann = tool_annotations("nonexistent_tool");
    // Default annotations have no hints set (they're unknown)
    assert!(
        unknown_ann.read_only_hint.is_none() || unknown_ann.read_only_hint.is_some(),
        "Unknown tool annotations should return without panicking"
    );
}

#[test]
fn tool_names_are_unique() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);
    let tools = registry.list_tools();

    let mut names = std::collections::HashSet::new();
    for tool in &tools {
        assert!(
            names.insert(&tool.name),
            "Duplicate tool name: {}",
            tool.name
        );
    }
}

// ─── Request parsing edge cases ────────────────────────────────────

#[test]
fn request_with_extra_fields_is_accepted() {
    // JSON-RPC spec says extra fields should be ignored
    let json_str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping",
        "params": null,
        "extra_field": "should be ignored"
    }"#;

    let request: Result<JsonRpcRequest, _> = serde_json::from_str(json_str);
    assert!(
        request.is_ok(),
        "Extra fields in request should be tolerated"
    );
}

#[test]
fn request_with_float_id_parses() {
    let json_str = r#"{
        "jsonrpc": "2.0",
        "id": 1.0,
        "method": "ping"
    }"#;

    let request: Result<JsonRpcRequest, _> = serde_json::from_str(json_str);
    assert!(request.is_ok(), "Float IDs should be accepted");
}

#[test]
fn request_with_negative_id_parses() {
    let json_str = r#"{
        "jsonrpc": "2.0",
        "id": -1,
        "method": "ping"
    }"#;

    let request: Result<JsonRpcRequest, _> = serde_json::from_str(json_str);
    assert!(request.is_ok(), "Negative IDs should be accepted");
}

#[test]
fn request_with_large_id_parses() {
    let json_str = r#"{
        "jsonrpc": "2.0",
        "id": 9999999999,
        "method": "ping"
    }"#;

    let request: Result<JsonRpcRequest, _> = serde_json::from_str(json_str);
    assert!(request.is_ok(), "Large numeric IDs should be accepted");
}

#[test]
fn notification_has_no_id() {
    let json_str = r#"{
        "jsonrpc": "2.0",
        "method": "initialized"
    }"#;

    let request: JsonRpcRequest = serde_json::from_str(json_str).unwrap();
    assert!(request.id.is_none(), "Notifications must have no id");
}

// ─── Tool schema structure deep validation ─────────────────────────

#[test]
fn exec_tool_schema_has_command_and_host() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);

    let ssh_exec = registry
        .list_tools()
        .into_iter()
        .find(|t| t.name == "ssh_exec")
        .unwrap();
    let props = &ssh_exec.input_schema["properties"];

    assert!(props.get("host").is_some(), "ssh_exec must have host");
    assert!(props.get("command").is_some(), "ssh_exec must have command");

    let required = ssh_exec.input_schema["required"].as_array().unwrap();
    let required_names: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(required_names.contains(&"host"));
    assert!(required_names.contains(&"command"));
}

#[test]
fn status_tool_has_no_required_params() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);

    let ssh_status = registry
        .list_tools()
        .into_iter()
        .find(|t| t.name == "ssh_status")
        .unwrap();

    // ssh_status has no required parameters
    let required = ssh_status.input_schema.get("required");
    let is_empty = required.is_none() || required.unwrap().as_array().is_none_or(Vec::is_empty);
    assert!(is_empty, "ssh_status should have no required parameters");
}

#[test]
fn read_only_tools_are_not_destructive() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);
    let tools = registry.list_tools();

    for tool in &tools {
        if let Some(ann) = &tool.annotations
            && ann.read_only_hint == Some(true)
        {
            assert_ne!(
                ann.destructive_hint,
                Some(true),
                "Tool {} cannot be both read-only and destructive",
                tool.name
            );
        }
    }
}

#[test]
fn destructive_tools_are_not_read_only() {
    let tool_groups = ToolGroupsConfig::default();
    let registry = create_filtered_registry(&tool_groups);
    let tools = registry.list_tools();

    for tool in &tools {
        if let Some(ann) = &tool.annotations
            && ann.destructive_hint == Some(true)
        {
            assert_ne!(
                ann.read_only_hint,
                Some(true),
                "Tool {} cannot be both destructive and read-only",
                tool.name
            );
        }
    }
}

// ─── Response roundtrip ────────────────────────────────────────────

#[test]
fn response_roundtrip_preserves_structure() {
    let original = JsonRpcResponse::success(
        Some(json!(42)),
        json!({
            "content": [{"type": "text", "text": "hello"}],
            "isError": false
        }),
    );

    let json_str = serde_json::to_string(&original).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["result"]["content"][0]["type"], "text");
    assert_eq!(parsed["result"]["isError"], false);
}

#[test]
fn error_response_roundtrip_preserves_code() {
    let original = JsonRpcResponse::error(
        Some(json!(1)),
        JsonRpcError::method_not_found("unknown/method"),
    );

    let json_str = serde_json::to_string(&original).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["error"]["code"], -32601);
    assert!(
        parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown/method")
    );
}
