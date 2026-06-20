//! Handler for the `ssh_hyperv_vm_stop` tool.
//!
//! Stops a Hyper-V virtual machine on a Windows host via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::hyperv::{HyperVCommandBuilder, validate_vm_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshHypervVmStopArgs {
    host: String,
    #[serde(alias = "name")]
    vm_name: String,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHypervVmStopArgs);

#[mcp_standard_tool(
    name = "ssh_hyperv_vm_stop",
    group = "hyperv",
    annotation = "destructive"
)]
pub struct HypervVmStopTool;

impl StandardTool for HypervVmStopTool {
    type Args = SshHypervVmStopArgs;

    const NAME: &'static str = "ssh_hyperv_vm_stop";

    const DESCRIPTION: &'static str = "Stop a Hyper-V virtual machine on a Windows host. By default performs a graceful \
        shutdown. Use force=true for immediate power-off (TurnOff). Shows VM state after \
        stopping.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "vm_name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be a Windows host (use ssh_status to list hosts)"
            },
            "vm_name": {
                "type": "string",
                "description": "Name of the Hyper-V virtual machine to stop"
            },
            "force": {
                "type": "boolean",
                "description": "Force immediate power-off via TurnOff — equivalent to pulling the power cord; in-flight writes are not flushed and running workloads may lose data. Default false (graceful shutdown via the integration services)."
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
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshHypervVmStopArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(HyperVCommandBuilder::vm_stop(&args.vm_name, args.force))
    }

    fn validate(args: &SshHypervVmStopArgs, _host_config: &HostConfig) -> Result<()> {
        validate_vm_name(&args.vm_name)?;
        Ok(())
    }

    /// Confirm destructive operation via `elicitation/create` before
    /// running the underlying command. Falls back to a no-op when the
    /// client does not advertise the elicitation capability — the
    /// global `security.require_elicitation_on_destructive` gate still
    /// applies in that case.
    async fn pre_execute(args: &Self::Args, ctx: &ToolContext) -> Result<Option<ToolCallResult>> {
        let summary = format!(
            "Stop Hyper-V VM `{}` (force=`{}`) on host `{}`",
            args.vm_name, args.force, args.host,
        );
        match ctx.elicit_confirm(Self::NAME, &summary).await? {
            Some(false) => Ok(Some(ToolCallResult::error(
                "User declined destructive operation".to_string(),
            ))),
            _ => Ok(None),
        }
    }
}

/// Handler for the `ssh_hyperv_vm_stop` tool.
pub type SshHypervVmStopHandler = StandardToolHandler<HypervVmStopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHypervVmStopHandler::new();
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
        let handler = SshHypervVmStopHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "name": "MyVM"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshHypervVmStopHandler::new();
        assert_eq!(handler.name(), "ssh_hyperv_vm_stop");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "winhost",
            "name": "MyVM",
            "force": true,
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshHypervVmStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert!(args.force);
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "winhost", "name": "MyVM"});
        let args: SshHypervVmStopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert!(!args.force);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_args_force_default_false() {
        let json = json!({"host": "winhost", "name": "MyVM"});
        let args: SshHypervVmStopArgs = serde_json::from_value(json).unwrap();
        assert!(!args.force);
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHypervVmStopHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "winhost"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHypervVmStopHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("force"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "vm"});
        let args: SshHypervVmStopArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshHypervVmStopArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "MyVM"});
        let result = serde_json::from_value::<SshHypervVmStopArgs>(json);
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
        let args: SshHypervVmStopArgs =
            serde_json::from_value(json!({"host": "s", "name": "TestVM"})).unwrap();
        let host = test_host_config();
        let cmd = HypervVmStopTool::build_command(&args, &host).unwrap();
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
        let handler = SshHypervVmStopHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "name": "TestVM"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
