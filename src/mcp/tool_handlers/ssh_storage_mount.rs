//! Handler for the `ssh_storage_mount` tool.
//!
//! Mounts a filesystem on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::storage::StorageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshStorageMountArgs {
    /// Target host name from configuration.
    host: String,
    /// Device to mount (e.g., /dev/sdb1).
    device: String,
    /// Mount point path (e.g., /mnt/data).
    mount_point: String,
    /// Filesystem type (e.g., ext4, xfs, nfs).
    #[serde(default)]
    fs_type: Option<String>,
    /// Mount options (e.g., ro,noexec).
    #[serde(default)]
    options: Option<String>,
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

impl_common_args!(SshStorageMountArgs);

#[mcp_standard_tool(name = "ssh_storage_mount", group = "storage", annotation = "mutating")]
pub struct StorageMountTool;

impl StandardTool for StorageMountTool {
    type Args = SshStorageMountArgs;

    const NAME: &'static str = "ssh_storage_mount";

    const DESCRIPTION: &'static str = "Mount a filesystem on a remote host (runs mount on the \
        remote). Requires device (e.g. /dev/sdb1 or //server/share) and mount_point; optionally \
        specify fs_type (e.g. ext4, xfs, nfs, cifs) and options (e.g. ro,noexec,nosuid). Discover \
        available block devices and partition names with ssh_storage_lsblk first. To unmount use \
        ssh_storage_umount; to make the mount persistent add it to /etc/fstab (visible via \
        ssh_storage_fstab).";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "device": {
                        "type": "string",
                        "description": "Device to mount (e.g., /dev/sdb1, //server/share)"
                    },
                    "mount_point": {
                        "type": "string",
                        "description": "Mount point path (e.g., /mnt/data)"
                    },
                    "fs_type": {
                        "type": "string",
                        "description": "Filesystem type (e.g., ext4, xfs, nfs, cifs)"
                    },
                    "options": {
                        "type": "string",
                        "description": "Mount options (e.g., ro,noexec,nosuid)"
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
                "required": ["host", "device", "mount_point"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshStorageMountArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(StorageCommandBuilder::build_mount_command(
            &args.device,
            &args.mount_point,
            args.fs_type.as_deref(),
            args.options.as_deref(),
        ))
    }
}

/// Handler for the `ssh_storage_mount` tool.
pub type SshStorageMountHandler = StandardToolHandler<StorageMountTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshStorageMountHandler::new();
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
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "device": "/dev/sdb1", "mount_point": "/mnt/data"})),
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
        let handler = SshStorageMountHandler::new();
        assert_eq!(handler.name(), "ssh_storage_mount");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_storage_mount");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("device")));
        assert!(required.contains(&json!("mount_point")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "device": "/dev/sdb1",
            "mount_point": "/mnt/data",
            "fs_type": "ext4",
            "options": "ro,noexec",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/mount.txt"
        });
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device, "/dev/sdb1");
        assert_eq!(args.mount_point, "/mnt/data");
        assert_eq!(args.fs_type.as_deref(), Some("ext4"));
        assert_eq!(args.options.as_deref(), Some("ro,noexec"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/mount.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "device": "/dev/sdb1", "mount_point": "/mnt/data"});
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device, "/dev/sdb1");
        assert_eq!(args.mount_point, "/mnt/data");
        assert!(args.fs_type.is_none());
        assert!(args.options.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "device": "/dev/sdb1"})),
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
    fn test_schema_optional_fields() {
        let handler = SshStorageMountHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("fs_type"));
        assert!(props.contains_key("options"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "device": "/dev/sdb1", "mount_point": "/mnt/data"});
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshStorageMountArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "device": "/dev/sdb1", "mount_point": "/mnt/data"})),
                &ctx,
            )
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
        let args: SshStorageMountArgs = serde_json::from_value(json!({
            "host": "s", "device": "/dev/sdb1", "mount_point": "/mnt/data"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = StorageMountTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("mount"));
        assert!(cmd.contains("/dev/sdb1"));
        assert!(cmd.contains("/mnt/data"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshStorageMountArgs = serde_json::from_value(json!({
            "host": "s", "device": "/dev/sdb1", "mount_point": "/mnt/data",
            "fs_type": "ext4", "options": "ro,noexec"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = StorageMountTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("ext4"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshStorageMountArgs = serde_json::from_value(json!({
            "host": "s", "device": "/dev/sdb1", "mount_point": "/mnt/data"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "mount: /dev/sdb1 on /mnt/data\n";
        let result = StorageMountTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshStorageMountArgs = serde_json::from_value(json!({
            "host": "s", "device": "/dev/sdb1", "mount_point": "/mnt/data"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = StorageMountTool::post_process(result, &args, "", &dr);
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

    fn pipeline_ctx(output: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::{Config, SecurityConfig, SecurityMode};
        use crate::domain::TunnelManager;
        use crate::domain::{CommandHistory, ExecuteCommandUseCase};
        use crate::ports::ExecutorRouter;
        use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let security = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: security.clone(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&security));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(
            &crate::domain::history::HistoryConfig::default(),
        ));
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
            session_manager: Arc::new(SessionManager::new(crate::config::SessionConfig::default())),
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
        let handler = SshStorageMountHandler::new();
        let ctx = pipeline_ctx(mock_output("mount: /dev/sdb1 mounted on /mnt/data"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "device": "/dev/sdb1", "mount_point": "/mnt/data"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert!(!result.content.is_empty());
    }
}
