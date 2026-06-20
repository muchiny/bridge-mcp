//! Handler for the `ssh_hyperv_snapshot_list` tool.
//!
//! Lists Hyper-V VM snapshots (checkpoints) via `PowerShell`.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::hyperv::{HyperVCommandBuilder, validate_vm_name};
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshHypervSnapshotListArgs {
    host: String,
    vm_name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshHypervSnapshotListArgs);

#[mcp_standard_tool(
    name = "ssh_hyperv_snapshot_list",
    group = "hyperv",
    annotation = "read_only"
)]
pub struct HypervSnapshotListTool;

impl StandardTool for HypervSnapshotListTool {
    type Args = SshHypervSnapshotListArgs;

    const NAME: &'static str = "ssh_hyperv_snapshot_list";

    const DESCRIPTION: &'static str = "List all snapshots (checkpoints) of a Hyper-V virtual machine (runs Get-VMSnapshot). \
        Returns name, creation time, snapshot type, and parent checkpoint for each entry. \
        Use `ssh_hyperv_vm_list` first to discover VM names. To create a new checkpoint use \
        `ssh_hyperv_snapshot_create`. Note: `vm_name` is the required parameter name (no alias).";

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
                "description": "Name of the Hyper-V virtual machine"
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
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(
        args: &SshHypervSnapshotListArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(HyperVCommandBuilder::snapshot_list(&args.vm_name))
    }

    fn validate(args: &SshHypervSnapshotListArgs, _host_config: &HostConfig) -> Result<()> {
        validate_vm_name(&args.vm_name)?;
        Ok(())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshHypervSnapshotListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Hyper-V Snapshots");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_hyperv_snapshot_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_hyperv_snapshot_list` tool.
pub type SshHypervSnapshotListHandler = StandardToolHandler<HypervSnapshotListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHypervSnapshotListHandler::new();
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
        let handler = SshHypervSnapshotListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "vm_name": "MyVM"})),
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
        let handler = SshHypervSnapshotListHandler::new();
        assert_eq!(handler.name(), "ssh_hyperv_snapshot_list");
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
            "vm_name": "MyVM",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "winhost", "vm_name": "MyVM"});
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHypervSnapshotListHandler::new();
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
        let handler = SshHypervSnapshotListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "vm_name": "vm"});
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshHypervSnapshotListArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "vm_name": "MyVM"});
        let result = serde_json::from_value::<SshHypervSnapshotListArgs>(json);
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
        let args: SshHypervSnapshotListArgs =
            serde_json::from_value(json!({"host": "s", "vm_name": "TestVM"})).unwrap();
        let host = test_host_config();
        let cmd = HypervSnapshotListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshHypervSnapshotListArgs =
            serde_json::from_value(json!({"host": "s", "vm_name": "TestVM"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "Col1\tCol2\nval1\tval2\n";
        let result = HypervSnapshotListTool::post_process(result, &args, output, &dr);
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
        let handler = SshHypervSnapshotListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "vm_name": "TestVM"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
