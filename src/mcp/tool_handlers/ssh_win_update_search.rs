//! Handler for the `ssh_win_update_search` tool.
//!
//! Searches for Windows updates matching a title pattern.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_update::WindowsUpdateCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshWinUpdateSearchArgs {
    host: String,
    query: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinUpdateSearchArgs);

#[mcp_standard_tool(
    name = "ssh_win_update_search",
    group = "windows_updates",
    annotation = "read_only"
)]
pub struct WinUpdateSearchTool;

impl StandardTool for WinUpdateSearchTool {
    type Args = SshWinUpdateSearchArgs;

    const NAME: &'static str = "ssh_win_update_search";

    const DESCRIPTION: &'static str = "Search pending Windows updates whose title contains the given keyword (wildcard \
        applied automatically: query becomes *query*). Returns KB, Title, and Size columns. \
        Use instead of ssh_win_update_list when you only want updates matching a specific category \
        (e.g., \"Cumulative\", \"Security\", \".NET\"). To install a found update use \
        ssh_win_update_install with the KB ID. Requires the PSWindowsUpdate module on the remote host.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "query"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "query": {
                "type": "string",
                "description": "Keyword to search for in update titles — wildcards (*query*) are added automatically. Examples: \"Cumulative\", \"Security\", \".NET\", \"Defender\""
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinUpdateSearchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsUpdateCommandBuilder::build_search_command(
            &args.query,
        ))
    }
}

/// Handler for the `ssh_win_update_search` tool.
pub type SshWinUpdateSearchHandler = StandardToolHandler<WinUpdateSearchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinUpdateSearchHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinUpdateSearchHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "query": "Cumulative"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinUpdateSearchHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_update_search");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("query")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "query": "Cumulative",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "Cumulative");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "query": "Security"});
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "Security");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinUpdateSearchHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "query": "test"});
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinUpdateSearchArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "query": "Cumulative"});
        let result = serde_json::from_value::<SshWinUpdateSearchArgs>(json);
        assert!(result.is_err());
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
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
        let args: SshWinUpdateSearchArgs =
            serde_json::from_value(json!({"host": "s", "query": "Security"})).unwrap();
        let host = test_host_config();
        let cmd = WinUpdateSearchTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn win_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "winhost".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Windows,
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
            },
        );
        hosts
    }
    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshWinUpdateSearchHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(
                Some(json!({"host": "winhost", "query": "IsInstalled=0"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
