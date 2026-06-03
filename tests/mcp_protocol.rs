//! Integration tests for MCP protocol types and parsing
//!
//! These tests verify that the protocol types serialize/deserialize correctly
//! and that the response builders produce valid JSON-RPC responses.

use bridge_mcp::mcp::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ToolCallResult, ToolContent,
};
use serde_json::{Value, json};

// =============================================================================
// Request Parsing Tests
// =============================================================================

mod request_parsing {
    use super::*;

    #[test]
    fn test_parse_valid_request() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ssh_exec", "arguments": {"host": "server1"}}
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json_str).unwrap();

        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.id, Some(json!(1)));
        assert_eq!(request.method, "tools/call");
        assert!(request.params.is_some());
    }

    #[test]
    fn test_parse_request_without_params() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json_str).unwrap();

        assert_eq!(request.method, "tools/list");
        assert!(request.params.is_none());
    }

    #[test]
    fn test_parse_notification_without_id() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 5}
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json_str).unwrap();

        assert!(request.id.is_none());
        assert_eq!(request.method, "notifications/cancelled");
    }

    #[test]
    fn test_parse_request_with_string_id() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": "request-uuid-123",
            "method": "ping"
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json_str).unwrap();

        assert_eq!(request.id, Some(json!("request-uuid-123")));
    }

    #[test]
    fn test_parse_invalid_json_fails() {
        let json_str = r"{ invalid json }";

        let result = serde_json::from_str::<JsonRpcRequest>(json_str);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_method_fails() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": 1
        }"#;

        let result = serde_json::from_str::<JsonRpcRequest>(json_str);

        assert!(result.is_err());
    }
}

// =============================================================================
// Response Builder Tests
// =============================================================================

mod response_builders {
    use super::*;

    #[test]
    fn test_success_response_structure() {
        let response = JsonRpcResponse::success(Some(json!(1)), json!({"data": "value"}));

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(1)));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_error_response_structure() {
        let error = JsonRpcError::method_not_found("unknown/method");
        let response = JsonRpcResponse::error(Some(json!(1)), error);

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(1)));
        assert!(response.result.is_none());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_success_response_serializes_correctly() {
        let response = JsonRpcResponse::success(Some(json!(42)), json!({"status": "ok"}));
        let serialized = serde_json::to_value(&response).unwrap();

        assert_eq!(serialized["jsonrpc"], "2.0");
        assert_eq!(serialized["id"], 42);
        assert_eq!(serialized["result"]["status"], "ok");
        assert!(serialized.get("error").is_none());
    }

    #[test]
    fn test_error_response_serializes_correctly() {
        let error = JsonRpcError::invalid_params("Missing host parameter");
        let response = JsonRpcResponse::error(Some(json!(1)), error);
        let serialized = serde_json::to_value(&response).unwrap();

        assert_eq!(serialized["jsonrpc"], "2.0");
        assert_eq!(serialized["id"], 1);
        assert_eq!(serialized["error"]["code"], -32602);
        assert!(
            serialized["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Missing host")
        );
        assert!(serialized.get("result").is_none());
    }
}

// =============================================================================
// Error Code Tests
// =============================================================================

mod error_codes {
    use super::*;

    const PARSE_ERROR: i32 = -32700;
    const INVALID_REQUEST: i32 = -32600;
    const METHOD_NOT_FOUND: i32 = -32601;
    const INVALID_PARAMS: i32 = -32602;

    #[test]
    fn test_parse_error_has_correct_code() {
        let error = JsonRpcError::parse_error("Invalid JSON");

        assert_eq!(error.code, PARSE_ERROR);
        assert!(error.message.contains("Invalid JSON"));
    }

    #[test]
    fn test_invalid_request_has_correct_code() {
        let error = JsonRpcError::invalid_request("Missing jsonrpc field");

        assert_eq!(error.code, INVALID_REQUEST);
    }

    #[test]
    fn test_method_not_found_has_correct_code() {
        let error = JsonRpcError::method_not_found("tools/unknown");

        assert_eq!(error.code, METHOD_NOT_FOUND);
        assert!(error.message.contains("tools/unknown"));
    }

    #[test]
    fn test_invalid_params_has_correct_code() {
        let error = JsonRpcError::invalid_params("host is required");

        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("host is required"));
    }
}

// =============================================================================
// Tool Call Result Tests
// =============================================================================

mod tool_call_results {
    use super::*;

    #[test]
    fn test_text_result_structure() {
        let result = ToolCallResult::text("Command output here".to_string());

        assert!(!result.content.is_empty());
        assert!(result.is_error.is_none());

        match &result.content[0] {
            ToolContent::Text { text } => {
                assert_eq!(text, "Command output here");
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[test]
    fn test_error_result_structure() {
        let result = ToolCallResult::error("Connection failed".to_string());

        assert!(!result.content.is_empty());
        assert_eq!(result.is_error, Some(true));

        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Connection failed"));
            }
            _ => panic!("Expected Text content"),
        }
    }

    #[test]
    fn test_text_result_serializes_correctly() {
        let result = ToolCallResult::text("Hello".to_string());
        let serialized = serde_json::to_value(&result).unwrap();

        assert!(serialized["content"].is_array());
        let content = serialized["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "Hello");
    }

    #[test]
    fn test_error_result_serializes_with_is_error_flag() {
        let result = ToolCallResult::error("Error message".to_string());
        let serialized = serde_json::to_value(&result).unwrap();

        assert_eq!(serialized["isError"], true);
    }
}

// =============================================================================
// Roundtrip Tests (Parse -> Serialize -> Parse)
// =============================================================================

mod roundtrip {
    use super::*;

    #[test]
    fn test_response_roundtrip() {
        let original = JsonRpcResponse::success(Some(json!(123)), json!({"key": "value"}));
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized["jsonrpc"], "2.0");
        assert_eq!(deserialized["id"], 123);
        assert_eq!(deserialized["result"]["key"], "value");
    }

    #[test]
    fn test_tool_result_roundtrip() {
        let original = ToolCallResult::text("Test output".to_string());
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();

        assert!(deserialized["content"].is_array());
        assert_eq!(deserialized["content"][0]["text"], "Test output");
    }
}
