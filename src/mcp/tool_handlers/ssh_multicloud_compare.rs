//! Handler for the `ssh_multicloud_compare` tool.
//!
//! Compares instances between two cloud providers via a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::multicloud::MulticloudCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshMulticloudCompareArgs {
    /// Target host name from configuration.
    host: String,
    /// First cloud provider: aws, gcp, or azure.
    provider1: String,
    /// Second cloud provider: aws, gcp, or azure.
    provider2: String,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshMulticloudCompareArgs);

#[mcp_standard_tool(
    name = "ssh_multicloud_compare",
    group = "multicloud",
    annotation = "read_only"
)]
pub struct MulticloudCompareTool;

impl StandardTool for MulticloudCompareTool {
    type Args = SshMulticloudCompareArgs;

    const NAME: &'static str = "ssh_multicloud_compare";

    const DESCRIPTION: &'static str = "Fetch and display instance lists from two cloud providers \
        side by side for manual comparison. Requires 'provider1' and 'provider2' (each one of: \
        aws, gcp, azure); both are required and validated — unsupported values are rejected. \
        Output is two labelled sections ('=== aws ===', '=== gcp ===', etc.) each containing \
        the raw JSON from 'aws ec2 describe-instances', 'gcloud compute instances list', or \
        'az vm list'. Use jq_filter to extract comparable fields (e.g. \
        '.Reservations[].Instances[].InstanceId' for AWS). For a snapshot of all three \
        providers at once use ssh_multicloud_sync (no provider params required). For a single \
        provider use ssh_multicloud_list.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "provider1": {
                        "type": "string",
                        "description": "First cloud provider: aws, gcp, or azure",
                        "enum": ["aws", "gcp", "azure"]
                    },
                    "provider2": {
                        "type": "string",
                        "description": "Second cloud provider: aws, gcp, or azure",
                        "enum": ["aws", "gcp", "azure"]
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
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
                "required": ["host", "provider1", "provider2"]
            }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn validate(args: &SshMulticloudCompareArgs, _host_config: &HostConfig) -> Result<()> {
        MulticloudCommandBuilder::validate_provider(&args.provider1)?;
        MulticloudCommandBuilder::validate_provider(&args.provider2)?;
        Ok(())
    }

    fn build_command(args: &SshMulticloudCompareArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(MulticloudCommandBuilder::build_multicloud_compare_command(
            &args.provider1,
            &args.provider2,
        ))
    }
}

/// Handler for the `ssh_multicloud_compare` tool.
pub type SshMulticloudCompareHandler = StandardToolHandler<MulticloudCompareTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMulticloudCompareHandler::new();
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
        let handler = SshMulticloudCompareHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "provider1": "aws", "provider2": "gcp"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshMulticloudCompareHandler::new();
        assert_eq!(handler.name(), "ssh_multicloud_compare");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_multicloud_compare");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("provider1")));
        assert!(required.contains(&json!("provider2")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "provider1": "aws",
            "provider2": "azure",
            "timeout_seconds": 120,
            "max_output": 100_000,
            "save_output": "/tmp/compare.json"
        });
        let args: SshMulticloudCompareArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.provider1, "aws");
        assert_eq!(args.provider2, "azure");
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(100_000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/compare.json"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "provider1": "aws", "provider2": "gcp"});
        let args: SshMulticloudCompareArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.provider1, "aws");
        assert_eq!(args.provider2, "gcp");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshMulticloudCompareHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "provider1": "aws", "provider2": "gcp"});
        let args: SshMulticloudCompareArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshMulticloudCompareArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshMulticloudCompareHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "provider1": "aws", "provider2": "gcp"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_has_type_object() {
        let handler = SshMulticloudCompareHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshMulticloudCompareHandler::new();
        assert!(handler.description().len() > 10);
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: AuthConfig::Agent,
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
            },
        );
        hosts
    }

    fn permissive_ctx(mock_out: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::SessionConfig;
        use crate::config::{Config, LimitsConfig, SecurityConfig, SecurityMode};
        use crate::domain::CommandHistory;
        use crate::domain::ExecuteCommandUseCase;
        use crate::domain::TunnelManager;
        use crate::domain::history::HistoryConfig;
        use crate::ports::ExecutorRouter;
        use crate::security::AuditLogger;
        use crate::security::RateLimiter;
        use crate::security::{CommandValidator, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let sec = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: sec.clone(),
            limits: LimitsConfig::default(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&sec));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));
        crate::ports::ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(mock_out)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            pending_requests: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshMulticloudCompareHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "provider1": "aws", "provider2": "gcp"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
