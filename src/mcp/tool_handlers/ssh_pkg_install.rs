//! Handler for the `ssh_pkg_install` tool.
//!
//! Installs a package on a remote host using the detected or specified package manager.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::package::{PackageCommandBuilder, validate_package_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshPkgInstallArgs {
    /// Target host name from configuration.
    host: String,
    /// Package name to install.
    package: String,
    /// Override auto-detected package manager (apt/dnf/yum/apk).
    pkg_manager: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPkgInstallArgs);

#[mcp_standard_tool(name = "ssh_pkg_install", group = "package", annotation = "mutating")]
pub struct PkgInstallTool;

impl StandardTool for PkgInstallTool {
    type Args = SshPkgInstallArgs;

    const NAME: &'static str = "ssh_pkg_install";

    const DESCRIPTION: &'static str = "Install a package on a remote Linux host. Prefer this over ssh_exec as it \
        auto-detects the package manager (apt/dnf/yum/apk) and runs non-interactively. \
        Requires root or sudo permissions on the host. Use ssh_pkg_search first to verify the \
        package name exists in the repo, and ssh_pkg_list to confirm it is not already \
        installed. To remove a package use ssh_pkg_remove instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "package": {
                        "type": "string",
                        "description": "Package name to install"
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
                "required": ["host", "package"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshPkgInstallArgs, _host_config: &HostConfig) -> Result<()> {
        validate_package_name(&args.package)?;
        Ok(())
    }

    fn build_command(args: &SshPkgInstallArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PackageCommandBuilder::build_install_command(
            args.pkg_manager.as_deref(),
            &args.package,
        ))
    }
}

/// Handler for the `ssh_pkg_install` tool.
pub type SshPkgInstallHandler = StandardToolHandler<PkgInstallTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPkgInstallHandler::new();
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
        let handler = SshPkgInstallHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "package": "nginx"})),
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
        let handler = SshPkgInstallHandler::new();
        assert_eq!(handler.name(), "ssh_pkg_install");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pkg_install");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("package")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "package": "nginx",
            "pkg_manager": "apt",
            "timeout_seconds": 120,
            "max_output": 5000,
            "save_output": "/tmp/install.txt"
        });
        let args: SshPkgInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.package, "nginx");
        assert_eq!(args.pkg_manager.as_deref(), Some("apt"));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/install.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "package": "curl"});
        let args: SshPkgInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.package, "curl");
        assert!(args.pkg_manager.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPkgInstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("pkg_manager"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "package": "nginx"});
        let args: SshPkgInstallArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPkgInstallArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPkgInstallHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "package": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

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
        let args: SshPkgInstallArgs =
            serde_json::from_value(json!({"host": "s", "package": "nginx"})).unwrap();
        let host = test_host_config();
        let cmd = PkgInstallTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("nginx"));
    }

    #[test]
    fn test_build_command_with_pkg_manager() {
        let args: SshPkgInstallArgs = serde_json::from_value(json!({
            "host": "s", "package": "nginx", "pkg_manager": "apt"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = PkgInstallTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("apt"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshPkgInstallArgs =
            serde_json::from_value(json!({"host": "s", "package": "nginx"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "Reading package lists...\nInstalling nginx\n";
        let result = PkgInstallTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshPkgInstallArgs =
            serde_json::from_value(json!({"host": "s", "package": "nginx"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = PkgInstallTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
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
        let handler = SshPkgInstallHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(Some(json!({"host": "server1", "package": "nginx"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
