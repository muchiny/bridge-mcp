//! Handler for the `ssh_pkg_list` tool.
//!
//! Lists installed packages on a remote host with optional filtering.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::package::PackageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshPkgListArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter packages by name pattern.
    filter: Option<String>,
    /// Override auto-detected package manager (apt/dnf/yum/apk).
    pkg_manager: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPkgListArgs);

#[mcp_standard_tool(name = "ssh_pkg_list", group = "package", annotation = "read_only")]
pub struct PkgListTool;

impl StandardTool for PkgListTool {
    type Args = SshPkgListArgs;

    const NAME: &'static str = "ssh_pkg_list";

    const DESCRIPTION: &'static str = "List installed packages on a remote Linux host. Prefer this over ssh_exec as it \
        auto-detects the package manager (apt/dnf/yum/apk) and provides consistent output. \
        Use `filter` to narrow results by package name pattern. To check whether a specific \
        package is installed, call this tool with `filter=<name>`. To find packages available \
        for installation (not yet installed), use ssh_pkg_search instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Filter packages by name pattern"
                    },
                    "pkg_manager": {
                        "type": "string",
                        "description": "Override auto-detected package manager; common values: apt, dnf, yum, apk; full binary paths like /usr/bin/apt are also accepted"
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
                        "description": "Save full output to a file path on the remote host (untruncated)"
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshPkgListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PackageCommandBuilder::build_list_command(
            args.pkg_manager.as_deref(),
            args.filter.as_deref(),
        ))
    }
}

/// Handler for the `ssh_pkg_list` tool.
pub type SshPkgListHandler = StandardToolHandler<PkgListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPkgListHandler::new();
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
        let handler = SshPkgListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPkgListHandler::new();
        assert_eq!(handler.name(), "ssh_pkg_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pkg_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "filter": "nginx",
            "pkg_manager": "apt",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/pkgs.txt"
        });
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.filter.as_deref(), Some("nginx"));
        assert_eq!(args.pkg_manager.as_deref(), Some("apt"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/pkgs.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.filter.is_none());
        assert!(args.pkg_manager.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPkgListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("pkg_manager"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPkgListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPkgListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification};

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
        let args: SshPkgListArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = PkgListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshPkgListArgs = serde_json::from_value(json!({
            "host": "s",
            "filter": "nginx",
            "pkg_manager": "apt"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = PkgListTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("nginx") || cmd.contains("grep"));
        assert!(cmd.contains("apt") || cmd.contains("dpkg"));
    }

    // ============== Full Pipeline Test ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
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
            },
        );
        hosts
    }

    /// Creates a test context with permissive security (empty blacklist)
    /// because `build_list_command` always includes `2>/dev/null` which
    /// is blocked by the default blacklist pattern `(?i)>\s*/dev/`.
    fn create_permissive_mock_ctx(
        hosts: std::collections::HashMap<String, crate::config::HostConfig>,
        output: crate::ssh::CommandOutput,
    ) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::{CommandHistory, ExecuteCommandUseCase, HistoryConfig, TunnelManager};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use std::sync::Arc;

        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: vec![],
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts,
            security: security.clone(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&security));
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
            connection_pool: Arc::new(ExecutorRouter::mock(output)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(crate::ssh::SessionManager::new(
                crate::config::SessionConfig::default(),
            )),
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
        let handler = SshPkgListHandler::new();
        let ctx = create_permissive_mock_ctx(
            server1_hosts(),
            mock_output(
                "PACKAGE          VERSION          ARCH\nnginx            1.18.0-6         amd64\nopenssl          3.0.2-0          amd64\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1", "pkg_manager": "apt"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
