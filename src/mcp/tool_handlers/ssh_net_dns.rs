//! Handler for the `ssh_net_dns` tool.
//!
//! Performs DNS lookups from a remote host using `dig`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshNetDnsArgs {
    /// Target host name.
    host: String,
    /// Domain name to look up.
    domain: String,
    /// DNS record type (A, AAAA, MX, TXT, CNAME, NS, etc.).
    record_type: Option<String>,
    /// DNS server to query.
    server: Option<String>,
    /// Return short (concise) output.
    short: Option<bool>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetDnsArgs);

#[mcp_standard_tool(name = "ssh_net_dns", group = "network", annotation = "read_only")]
pub struct NetDnsTool;

impl StandardTool for NetDnsTool {
    type Args = SshNetDnsArgs;

    const NAME: &'static str = "ssh_net_dns";

    const DESCRIPTION: &'static str = "Perform DNS lookups from a Linux host using `dig`. \
        Supports any record type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV) and optionally \
        a custom DNS server. Use `short=true` for a concise answer-only response. \
        For Windows hosts use ssh_win_net_dns instead.";

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "required": ["host", "domain"],
    "properties": {
        "host": {
            "type": "string",
            "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
        },
        "domain": {
            "type": "string",
            "description": "Domain name to look up"
        },
        "record_type": {
            "type": "string",
            "description": "DNS record type: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc."
        },
        "server": {
            "type": "string",
            "description": "DNS server to query (e.g., 8.8.8.8)"
        },
        "short": {
            "type": "boolean",
            "description": "Return short (concise) output"
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

    fn build_command(args: &SshNetDnsArgs, _host_config: &HostConfig) -> Result<String> {
        NetworkCommandBuilder::build_dns_command(
            &args.domain,
            args.record_type.as_deref(),
            args.server.as_deref(),
            args.short.unwrap_or(false),
        )
    }
}

/// Handler for the `ssh_net_dns` tool.
pub type SshNetDnsHandler = StandardToolHandler<NetDnsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetDnsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_dns");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
        assert!(required.contains(&serde_json::Value::String("domain".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetDnsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("record_type"));
        assert!(props.contains_key("server"));
        assert!(props.contains_key("short"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetDnsHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetDnsHandler::new();
        let args = serde_json::json!({"host": "nonexistent", "domain": "example.com"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::UnknownHost { ref host } if host == "nonexistent"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "host": "myhost",
            "domain": "example.com",
            "record_type": "MX",
            "server": "8.8.8.8",
            "short": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetDnsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.domain, "example.com");
        assert_eq!(args.record_type.as_deref(), Some("MX"));
        assert_eq!(args.server.as_deref(), Some("8.8.8.8"));
        assert_eq!(args.short, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost", "domain": "example.com"});
        let args: SshNetDnsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.domain, "example.com");
        assert!(args.record_type.is_none());
        assert!(args.server.is_none());
        assert!(args.short.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost", "domain": "example.com"});
        let args: SshNetDnsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
        assert!(debug_str.contains("example.com"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345, "domain": "example.com"});
        let result = serde_json::from_value::<SshNetDnsArgs>(json);
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
        let args = SshNetDnsArgs {
            host: "s".to_string(),
            domain: "example.com".to_string(),
            record_type: None,
            server: None,
            short: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetDnsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("example.com"));
    }

    #[test]
    fn test_build_command_with_type_server() {
        let args = SshNetDnsArgs {
            host: "s".to_string(),
            domain: "example.com".to_string(),
            record_type: Some("MX".to_string()),
            server: Some("8.8.8.8".to_string()),
            short: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = NetDnsTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("example.com"));
        assert!(cmd.contains("MX"));
    }
}
