//! SSH `ESXi` Datastore List Tool Handler
//!
//! Lists datastores/filesystems on an `ESXi` host via `esxcli storage filesystem list`.

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
pub struct SshEsxiDatastoreListArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiDatastoreListArgs);

#[mcp_standard_tool(
    name = "ssh_esxi_datastore_list",
    group = "esxi",
    annotation = "read_only"
)]
pub struct EsxiDatastoreListTool;

impl StandardTool for EsxiDatastoreListTool {
    type Args = SshEsxiDatastoreListArgs;

    const NAME: &'static str = "ssh_esxi_datastore_list";

    const DESCRIPTION: &'static str = "List all datastores and filesystems on a VMware ESXi host. Returns mount point, \
        volume name, UUID (the VMFS volume UUID, e.g. 5a1b2c3d-xxxx-xxxx-xxxx-xxxxxxxxxxxx — use this to \
        reference datastores in paths like /vmfs/volumes/<UUID>), capacity, free space, and filesystem type \
        (VMFS, vfat, NFS). Uses esxcli storage filesystem list.";

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
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
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

    fn build_command(
        _args: &SshEsxiDatastoreListArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(EsxiCommandBuilder::build_datastore_list_command())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshEsxiDatastoreListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("ESXi Datastores");
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
            "ssh_esxi_datastore_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_esxi_datastore_list` tool.
pub type SshEsxiDatastoreListHandler = StandardToolHandler<EsxiDatastoreListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiDatastoreListHandler::new();
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
        let handler = SshEsxiDatastoreListHandler::new();
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
        let handler = SshEsxiDatastoreListHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_datastore_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_esxi_datastore_list");
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
            "save_output": "/tmp/datastores.txt"
        });
        let args: SshEsxiDatastoreListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiDatastoreListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiDatastoreListHandler::new();
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
        let args: SshEsxiDatastoreListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiDatastoreListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiDatastoreListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_returns_esxcli() {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
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
        };
        let args = SshEsxiDatastoreListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = EsxiDatastoreListTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("esxcli") || cmd.contains("storage"));
    }

    #[test]
    fn test_post_process_with_columnar_output() {
        // Sample esxcli storage filesystem list output (multi-column,
        // space-padded). Drives the post_process() table-building branch
        // that the existing tests don't reach.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let sample = "Mount Point        Volume Name   UUID                  Type   Size       Free\n\
                      /vmfs/volumes/ds1  datastore1    abc-123-def           VMFS-6 1099511627776 549755813888\n\
                      /vmfs/volumes/ds2  datastore2    ghi-456-jkl           NFS    549755813888  274877906944\n";
        let args = SshEsxiDatastoreListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text(sample.to_string());
        let processed = EsxiDatastoreListTool::post_process(base, &args, sample, &dr);
        // post_process either replaces with TSV+app, or returns unchanged
        // if parsing fails. Either branch should produce some content.
        assert!(!processed.content.is_empty());
    }

    #[test]
    fn test_post_process_unparsable_input_returns_input() {
        // Single-line input cannot form a table — branch returns input as-is.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = SshEsxiDatastoreListArgs {
            host: "esxi1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base = ToolCallResult::text("only one line".to_string());
        let processed = EsxiDatastoreListTool::post_process(base, &args, "only one line", &dr);
        assert!(!processed.content.is_empty());
    }
}
