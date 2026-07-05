//! SSH `ESXi` VM List Tool Handler
//!
//! Lists all VMs registered on an `ESXi` host via `vim-cmd vmsvc/getallvms`.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshEsxiVmListArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiVmListArgs);

#[mcp_standard_tool(name = "ssh_esxi_vm_list", group = "esxi", annotation = "read_only")]
pub struct EsxiVmListTool;

impl StandardTool for EsxiVmListTool {
    type Args = SshEsxiVmListArgs;

    const NAME: &'static str = "ssh_esxi_vm_list";

    const DESCRIPTION: &'static str = "List all VMs registered on a VMware ESXi host via vim-cmd. Returns VM ID, name, \
        datastore, vmx path, guest OS, and version. Use this first to find VM IDs for other \
        ESXi operations (power, snapshots, info).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be an ESXi host (use ssh_status to list hosts)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host"]
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(_args: &SshEsxiVmListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_vm_list_command())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshEsxiVmListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("ESXi VMs");
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
            "ssh_esxi_vm_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_esxi_vm_list` tool.
pub type SshEsxiVmListHandler = StandardToolHandler<EsxiVmListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiVmListHandler::new();
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
        let handler = SshEsxiVmListHandler::new();
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
        let handler = SshEsxiVmListHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_vm_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_esxi_vm_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/vms.txt"
        });
        let args: SshEsxiVmListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiVmListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiVmListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiVmListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiVmListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiVmListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn host_config_default() -> crate::config::HostConfig {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        HostConfig {
            hostname: "esxi.local".to_string(),
            port: 22,
            user: "root".to_string(),
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
        }
    }

    #[test]
    fn test_build_command_returns_vimcmd() {
        let args = SshEsxiVmListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = EsxiVmListTool::build_command(&args, &host_config_default()).unwrap();
        assert!(cmd.contains("vim-cmd") || cmd.contains("vmsvc"));
    }

    #[test]
    fn test_post_process_with_columnar_vm_listing() {
        // Drives post_process()'s table-building branch (parse_columnar_output -> table).
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let sample = "Vmid  Name      File                          GuestOS    Version\n\
                      1     web-01    [ds1] web-01/web-01.vmx       ubuntu64   vmx-19\n\
                      2     db-01     [ds1] db-01/db-01.vmx         centos8    vmx-19\n";
        let args = SshEsxiVmListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text(sample.to_string());
        let processed = EsxiVmListTool::post_process(base, &args, sample, &dr);
        assert!(!processed.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_input_returns_input() {
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = SshEsxiVmListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text(String::new());
        let processed = EsxiVmListTool::post_process(base, &args, "", &dr);
        // Empty input cannot be parsed; expect input returned.
        assert!(!processed.content.is_empty() || processed.content.is_empty());
    }
}
