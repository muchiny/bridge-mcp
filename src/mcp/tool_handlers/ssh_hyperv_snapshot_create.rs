//! Handler for the `ssh_hyperv_snapshot_create` tool.
//!
//! Creates a Hyper-V VM snapshot (checkpoint) via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::hyperv::{
    HyperVCommandBuilder, validate_snapshot_name, validate_vm_name,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHypervSnapshotCreateArgs {
    host: String,
    vm_name: String,
    snapshot_name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHypervSnapshotCreateArgs);

#[mcp_standard_tool(
    name = "ssh_hyperv_snapshot_create",
    group = "hyperv",
    annotation = "mutating"
)]
pub struct HypervSnapshotCreateTool;

impl StandardTool for HypervSnapshotCreateTool {
    type Args = SshHypervSnapshotCreateArgs;

    const NAME: &'static str = "ssh_hyperv_snapshot_create";

    const DESCRIPTION: &'static str = "Create a named checkpoint (snapshot) of a Hyper-V virtual machine (runs Checkpoint-VM), \
        enabling rollback before upgrades or configuration changes. Both `vm_name` and \
        `snapshot_name` are required and have no short aliases — use those exact parameter names. \
        Use `ssh_hyperv_vm_list` to discover VM names and `ssh_hyperv_snapshot_list` to view \
        existing checkpoints before creating a new one. Requires appropriate permissions on the \
        Hyper-V host.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "vm_name", "snapshot_name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be a Windows host (use ssh_status to list hosts)"
            },
            "vm_name": {
                "type": "string",
                "description": "Name of the Hyper-V virtual machine"
            },
            "snapshot_name": {
                "type": "string",
                "description": "Name for the new snapshot (checkpoint)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(
        args: &SshHypervSnapshotCreateArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(HyperVCommandBuilder::snapshot_create(
            &args.vm_name,
            &args.snapshot_name,
        ))
    }

    fn validate(args: &SshHypervSnapshotCreateArgs, _host_config: &HostConfig) -> Result<()> {
        validate_vm_name(&args.vm_name)?;
        validate_snapshot_name(&args.snapshot_name)?;
        Ok(())
    }
}

/// Handler for the `ssh_hyperv_snapshot_create` tool.
pub type SshHypervSnapshotCreateHandler = StandardToolHandler<HypervSnapshotCreateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHypervSnapshotCreateHandler::new();
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
        let handler = SshHypervSnapshotCreateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "vm_name": "MyVM",
                    "snapshot_name": "snap1"
                })),
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
        let handler = SshHypervSnapshotCreateHandler::new();
        assert_eq!(handler.name(), "ssh_hyperv_snapshot_create");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_name")));
        assert!(required.contains(&json!("snapshot_name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "winhost",
            "vm_name": "MyVM",
            "snapshot_name": "before-upgrade",
            "timeout_seconds": 60,
            "max_output": 5000
        });
        let args: SshHypervSnapshotCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert_eq!(args.snapshot_name, "before-upgrade");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "winhost",
            "vm_name": "MyVM",
            "snapshot_name": "snap1"
        });
        let args: SshHypervSnapshotCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert_eq!(args.snapshot_name, "snap1");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHypervSnapshotCreateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "winhost", "vm_name": "MyVM"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "h",
            "vm_name": "vm",
            "snapshot_name": "s"
        });
        let args: SshHypervSnapshotCreateArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshHypervSnapshotCreateArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({
            "host": 123,
            "vm_name": "MyVM",
            "snapshot_name": "snap1"
        });
        let result = serde_json::from_value::<SshHypervSnapshotCreateArgs>(json);
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
        let args: SshHypervSnapshotCreateArgs = serde_json::from_value(
            json!({"host": "s", "vm_name": "TestVM", "snapshot_name": "snap1"}),
        )
        .unwrap();
        let host = test_host_config();
        let cmd = HypervSnapshotCreateTool::build_command(&args, &host).unwrap();
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
        let handler = SshHypervSnapshotCreateHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(
                Some(json!({"host": "winhost", "vm_name": "TestVM", "snapshot_name": "snap1"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
