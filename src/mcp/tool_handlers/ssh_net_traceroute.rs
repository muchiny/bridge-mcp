//! Handler for the `ssh_net_traceroute` tool.
//!
//! Traces the network route from a remote host to a target destination.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshNetTracerouteArgs {
    /// Target host name.
    host: String,
    /// Target destination for traceroute.
    target: String,
    /// Maximum number of hops.
    max_hops: Option<u32>,
    /// Wait time per probe in seconds.
    wait: Option<u32>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetTracerouteArgs);

#[mcp_standard_tool(
    name = "ssh_net_traceroute",
    group = "network",
    annotation = "read_only"
)]
pub struct NetTracerouteTool;

impl StandardTool for NetTracerouteTool {
    type Args = SshNetTracerouteArgs;

    const NAME: &'static str = "ssh_net_traceroute";

    const DESCRIPTION: &'static str = "Trace the network route from a Linux host to a target using `traceroute`. \
        Validates the target (hostname/IP, no shell metacharacters), caps hops at max_hops (default 30). \
        Use ssh_net_ping for simple reachability; use this to diagnose routing hops and latency per hop.";

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "required": ["host", "target"],
    "properties": {
        "host": {
            "type": "string",
            "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
        },
        "target": {
            "type": "string",
            "description": "Target hostname or IP address for traceroute"
        },
        "max_hops": {
            "type": "integer",
            "description": "Maximum number of hops (default: 30)",
            "maximum": 64
        },
        "wait": {
            "type": "integer",
            "description": "Wait time per probe in seconds",
            "maximum": 10
        },
        "timeout_seconds": {
            "type": "integer",
            "description": "Override command timeout in seconds"
        },
        "max_output": {
            "type": "integer",
            "description": "Maximum output characters (truncates if exceeded)"
        },
        "save_output": {
            "type": "string",
            "description": "Path to save full output to a local file"
        }
    }
}"#;

    fn build_command(args: &SshNetTracerouteArgs, _host_config: &HostConfig) -> Result<String> {
        NetworkCommandBuilder::build_traceroute_command(&args.target, args.max_hops, args.wait)
    }
}

/// Handler for the `ssh_net_traceroute` tool.
pub type SshNetTracerouteHandler = StandardToolHandler<NetTracerouteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetTracerouteHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_traceroute");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
        assert!(required.contains(&serde_json::Value::String("target".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetTracerouteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("max_hops"));
        assert!(props.contains_key("wait"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetTracerouteHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetTracerouteHandler::new();
        let args = serde_json::json!({"host": "nonexistent", "target": "example.com"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::UnknownHost { ref host } if host == "nonexistent"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "host": "myhost",
            "target": "example.com",
            "max_hops": 20,
            "wait": 3,
            "timeout_seconds": 60,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetTracerouteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert_eq!(args.max_hops, Some(20));
        assert_eq!(args.wait, Some(3));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost", "target": "example.com"});
        let args: SshNetTracerouteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert!(args.max_hops.is_none());
        assert!(args.wait.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost", "target": "example.com"});
        let args: SshNetTracerouteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
        assert!(debug_str.contains("example.com"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345, "target": "example.com"});
        let result = serde_json::from_value::<SshNetTracerouteArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshNetTracerouteArgs {
            host: "s".to_string(),
            target: "example.com".to_string(),
            max_hops: None,
            wait: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetTracerouteTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("traceroute"));
        assert!(cmd.contains("example.com"));
    }

    #[test]
    fn test_build_command_with_max_hops() {
        let args = SshNetTracerouteArgs {
            host: "s".to_string(),
            target: "10.0.0.1".to_string(),
            max_hops: Some(15),
            wait: Some(3),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetTracerouteTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("10.0.0.1"));
        assert!(cmd.contains("15"));
    }
}
