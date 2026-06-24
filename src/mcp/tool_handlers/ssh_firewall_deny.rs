//! Handler for the `ssh_firewall_deny` tool.
//!
//! Adds a firewall deny/block rule on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::firewall::{FirewallCommandBuilder, validate_port};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshFirewallDenyArgs {
    /// Target host name from configuration.
    host: String,
    /// Port number or range to deny (e.g., "80", "8080:8090").
    port: String,
    /// Protocol (tcp/udp). Defaults to tcp.
    protocol: Option<String>,
    /// Source IP or CIDR to restrict the rule to.
    source: Option<String>,
    /// Override auto-detected firewall tool (ufw/firewall-cmd/iptables).
    firewall_tool: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshFirewallDenyArgs);

#[mcp_standard_tool(
    name = "ssh_firewall_deny",
    group = "firewall",
    annotation = "destructive"
)]
pub struct FirewallDenyTool;

impl StandardTool for FirewallDenyTool {
    type Args = SshFirewallDenyArgs;

    const NAME: &'static str = "ssh_firewall_deny";

    const DESCRIPTION: &'static str = "Add a firewall deny/block rule on a remote Linux host (ufw/firewall-cmd/iptables). \
        Prefer this over ssh_exec as it auto-detects the firewall tool and validates parameters. \
        Blocks incoming traffic on a port, optionally restricted to a source IP/CIDR. \
        Use ssh_firewall_list to verify the rule afterward; to remove a rule later, use \
        ssh_exec with the appropriate backend command (e.g., 'ufw delete deny <port>/tcp' or \
        'iptables -D INPUT ...'). For Windows hosts, use ssh_win_firewall_deny instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port number, range, or service name to deny (e.g., '80', '8080:8090', 'ssh', 'http'). Service names are resolved via /etc/services on the remote host; ufw also has its own built-in service database."
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol to block. Defaults to tcp",
                        "enum": ["tcp", "udp"],
                        "default": "tcp"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source IP or CIDR to restrict the rule to"
                    },
                    "firewall_tool": {
                        "type": "string",
                        "description": "Override auto-detected firewall tool",
                        "enum": ["ufw", "firewall-cmd", "iptables"]
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1,
                        "maximum": 3600
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "port"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshFirewallDenyArgs, _host_config: &HostConfig) -> Result<String> {
        FirewallCommandBuilder::build_deny_command(
            args.firewall_tool.as_deref(),
            &args.port,
            args.protocol.as_deref(),
            args.source.as_deref(),
        )
    }

    fn validate(args: &SshFirewallDenyArgs, _host_config: &HostConfig) -> Result<()> {
        validate_port(&args.port)?;
        Ok(())
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Add firewall DENY rule for port `{}` on host `{}`",
            args.port, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_firewall_deny` tool.
pub type SshFirewallDenyHandler = StandardToolHandler<FirewallDenyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFirewallDenyHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshFirewallDenyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "port": "80"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshFirewallDenyHandler::new();
        assert_eq!(handler.name(), "ssh_firewall_deny");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_firewall_deny");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("port")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "port": "3306",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "firewall_tool": "iptables",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/fw_deny.txt"
        });
        let args: SshFirewallDenyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.port, "3306");
        assert_eq!(args.protocol.as_deref(), Some("tcp"));
        assert_eq!(args.source.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(args.firewall_tool.as_deref(), Some("iptables"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/fw_deny.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "port": "22"});
        let args: SshFirewallDenyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.port, "22");
        assert!(args.protocol.is_none());
        assert!(args.source.is_none());
        assert!(args.firewall_tool.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFirewallDenyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("protocol"));
        assert!(props.contains_key("source"));
        assert!(props.contains_key("firewall_tool"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "port": "80"});
        let args: SshFirewallDenyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFirewallDenyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFirewallDenyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "port": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let args = SshFirewallDenyArgs {
            host: "s".to_string(),
            port: "22".to_string(),
            protocol: None,
            source: None,
            firewall_tool: Some("ufw".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FirewallDenyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("22"));
        assert!(cmd.contains("deny"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let args = SshFirewallDenyArgs {
            host: "s".to_string(),
            port: "8080".to_string(),
            protocol: Some("udp".to_string()),
            source: Some("192.168.1.0/24".to_string()),
            firewall_tool: Some("ufw".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FirewallDenyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("8080"));
        assert!(cmd.contains("udp"));
    }
}
