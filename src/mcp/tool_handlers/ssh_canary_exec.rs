//! SSH Canary Exec Tool Handler
//!
//! Executes a command on a single canary host first with an optional health
//! check, returning the result so Claude can decide whether to proceed with
//! the remaining hosts via `ssh_exec_multi`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::orchestration::OrchestrationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshCanaryExecArgs {
    host: String,
    #[serde(default)]
    #[allow(dead_code)]
    hosts: Option<String>,
    command: String,
    #[serde(default)]
    health_check: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshCanaryExecArgs);

#[mcp_standard_tool(
    name = "ssh_canary_exec",
    group = "orchestration",
    annotation = "mutating"
)]
pub struct CanaryExecTool;

impl StandardTool for CanaryExecTool {
    type Args = SshCanaryExecArgs;

    const NAME: &'static str = "ssh_canary_exec";

    const DESCRIPTION: &'static str = "Execute a command on a ONE canary host and return its \
        result so you (the AI) can decide whether to proceed with the remaining hosts. Use this \
        as the FIRST step of a multi-host operation: run here, inspect the output, then call \
        ssh_exec_multi on the rest. 'hosts' is a memo field only — this tool runs solely on \
        'host'. For a sequential one-at-a-time rolling wave across all hosts use ssh_rolling_exec \
        instead. For read-only fleet comparison (no mutations) use ssh_fleet_diff instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Canary host alias from config.yaml to execute on first"
            },
            "hosts": {
                "type": "string",
                "description": "Memo field: comma-separated remaining host aliases you plan to target after the canary succeeds. Not executed by this tool — pass them to ssh_exec_multi in your next call."
            },
            "command": {
                "type": "string",
                "description": "The command to execute on the canary host"
            },
            "health_check": {
                "type": "string",
                "description": "Optional health check command to run after the main command"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the remote host (absolute path)"
            }
        },
        "required": ["host", "command"]
    }"#;

    fn build_command(args: &SshCanaryExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(OrchestrationCommandBuilder::build_canary_command(
            &args.command,
            args.health_check.as_deref(),
        ))
    }
}

pub type SshCanaryExecHandler = StandardToolHandler<CanaryExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCanaryExecHandler::new();
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
        let handler = SshCanaryExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "command": "echo hi"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshCanaryExecHandler::new();
        assert_eq!(handler.name(), "ssh_canary_exec");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "canary1",
            "hosts": "web2,web3,web4",
            "command": "apt upgrade -y",
            "health_check": "curl -f http://localhost/health",
            "timeout_seconds": 120
        });
        let args: SshCanaryExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "canary1");
        assert_eq!(args.hosts.as_deref(), Some("web2,web3,web4"));
        assert_eq!(args.command, "apt upgrade -y");
        assert_eq!(
            args.health_check.as_deref(),
            Some("curl -f http://localhost/health")
        );
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1", "command": "echo hello"});
        let args: SshCanaryExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.command, "echo hello");
        assert!(args.hosts.is_none());
        assert!(args.health_check.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        use crate::config::{HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
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
        };
        let args = SshCanaryExecArgs {
            host: "canary1".to_string(),
            hosts: Some("web2,web3".to_string()),
            command: "deploy.sh".to_string(),
            health_check: Some("curl localhost".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CanaryExecTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("deploy.sh"));
        assert!(cmd.contains("curl localhost"));
        assert!(cmd.contains("|| true"));
    }
}
