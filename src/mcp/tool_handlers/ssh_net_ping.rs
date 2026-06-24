//! Handler for the `ssh_net_ping` tool.
//!
//! Pings a target host from a remote host to test network connectivity.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshNetPingArgs {
    /// Target host name.
    host: String,
    /// Target to ping.
    target: String,
    /// Number of ping packets to send.
    count: Option<u32>,
    /// Timeout per ping packet in seconds.
    timeout: Option<u32>,
    /// Source interface for ping.
    interface: Option<String>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetPingArgs);

#[mcp_standard_tool(name = "ssh_net_ping", group = "network", annotation = "read_only")]
pub struct NetPingTool;

impl StandardTool for NetPingTool {
    type Args = SshNetPingArgs;

    const NAME: &'static str = "ssh_net_ping";

    const DESCRIPTION: &'static str = "Ping a target from a Linux host using the `ping` CLI to test reachability. \
        Validates the target (hostname/IP only, no shell metacharacters), sends 4 packets by default, \
        and returns RTT statistics and packet loss. \
        For Windows hosts use ssh_win_net_ping instead.";

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
            "description": "Target hostname or IP address to ping"
        },
        "count": {
            "type": "integer",
            "description": "Number of ping packets to send (default: 4)",
            "maximum": 100
        },
        "timeout": {
            "type": "integer",
            "description": "Timeout per ping packet in seconds",
            "maximum": 60
        },
        "interface": {
            "type": "string",
            "description": "Source interface for ping"
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

    fn build_command(args: &SshNetPingArgs, _host_config: &HostConfig) -> Result<String> {
        NetworkCommandBuilder::build_ping_command(
            &args.target,
            args.count,
            args.timeout,
            args.interface.as_deref(),
        )
    }
}

/// Handler for the `ssh_net_ping` tool.
pub type SshNetPingHandler = StandardToolHandler<NetPingTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetPingHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_ping");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
        assert!(required.contains(&serde_json::Value::String("target".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetPingHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout"));
        assert!(props.contains_key("interface"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetPingHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetPingHandler::new();
        let args = serde_json::json!({"host": "nonexistent", "target": "8.8.8.8"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::UnknownHost { ref host } if host == "nonexistent"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "host": "myhost",
            "target": "8.8.8.8",
            "count": 10,
            "timeout": 5,
            "interface": "eth0",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert_eq!(args.count, Some(10));
        assert_eq!(args.timeout, Some(5));
        assert_eq!(args.interface.as_deref(), Some("eth0"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost", "target": "8.8.8.8"});
        let args: SshNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert!(args.count.is_none());
        assert!(args.timeout.is_none());
        assert!(args.interface.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost", "target": "8.8.8.8"});
        let args: SshNetPingArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
        assert!(debug_str.contains("8.8.8.8"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345, "target": "8.8.8.8"});
        let result = serde_json::from_value::<SshNetPingArgs>(json);
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
        let args = SshNetPingArgs {
            host: "s".to_string(),
            target: "8.8.8.8".to_string(),
            count: None,
            timeout: None,
            interface: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetPingTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ping"));
        assert!(cmd.contains("8.8.8.8"));
    }

    #[test]
    fn test_build_command_with_count_interface() {
        let args = SshNetPingArgs {
            host: "s".to_string(),
            target: "10.0.0.1".to_string(),
            count: Some(10),
            timeout: Some(5),
            interface: Some("eth0".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetPingTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("10.0.0.1"));
        assert!(cmd.contains("10"));
    }
}
