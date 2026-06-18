//! SSH `ESXi` Network List Tool Handler
//!
//! Lists network information on an `ESXi` host via `esxcli network`.
//! Supports components: interface, vswitch, nic, all.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshEsxiNetworkListArgs {
    host: String,
    #[serde(default)]
    component: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiNetworkListArgs);

#[mcp_standard_tool(
    name = "ssh_esxi_network_list",
    group = "esxi",
    annotation = "read_only"
)]
pub struct EsxiNetworkListTool;

impl StandardTool for EsxiNetworkListTool {
    type Args = SshEsxiNetworkListArgs;

    const NAME: &'static str = "ssh_esxi_network_list";

    const DESCRIPTION: &'static str = "List network information on a VMware ESXi host. Components: interface (vmk adapters), \
        vswitch (virtual switches), nic (physical NICs), or all (default, returns \
        everything). Uses esxcli network commands.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be an ESXi host (use ssh_status to list hosts)"
            },
            "component": {
                "type": "string",
                "description": "Network component to query (default: all)",
                "enum": ["interface", "vswitch", "nic", "all"]
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

    fn validate(args: &SshEsxiNetworkListArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(component) = &args.component {
            EsxiCommandBuilder::validate_network_component(component)?;
        }
        Ok(())
    }

    fn build_command(args: &SshEsxiNetworkListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_network_list_command(
            args.component.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshEsxiNetworkListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("ESXi Networks");
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
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_esxi_network_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_esxi_network_list` tool.
pub type SshEsxiNetworkListHandler = StandardToolHandler<EsxiNetworkListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiNetworkListHandler::new();
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
        let handler = SshEsxiNetworkListHandler::new();
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

    #[tokio::test]
    async fn test_invalid_component() {
        let handler = SshEsxiNetworkListHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "component": "firewall"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("firewall"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiNetworkListHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_network_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_esxi_network_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "component": "nic",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.component, Some("nic".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert!(args.component.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiNetworkListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("component"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiNetworkListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiNetworkListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    /// Build a minimal `HostConfig` for direct `validate`/`build_command` tests.
    fn test_host_config() -> HostConfig {
        use crate::config::{AuthConfig, HostKeyVerification, OsType};
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

    fn args_with_component(component: Option<&str>) -> SshEsxiNetworkListArgs {
        SshEsxiNetworkListArgs {
            host: "esxi1".to_string(),
            component: component.map(str::to_string),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        }
    }

    #[test]
    fn test_args_full_with_save_output() {
        let json = json!({
            "host": "esxi1",
            "component": "all",
            "timeout_seconds": 60,
            "max_output": 0,
            "save_output": "/tmp/net.txt"
        });
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.component, Some("all".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(0));
        assert_eq!(args.save_output, Some("/tmp/net.txt".to_string()));
    }

    #[test]
    fn test_validate_valid_component_ok() {
        let host = test_host_config();
        let args = args_with_component(Some("nic"));
        assert!(EsxiNetworkListTool::validate(&args, &host).is_ok());
    }

    #[test]
    fn test_validate_none_component_ok() {
        // No component => validation branch is skipped entirely.
        let host = test_host_config();
        let args = args_with_component(None);
        assert!(EsxiNetworkListTool::validate(&args, &host).is_ok());
    }

    #[test]
    fn test_validate_invalid_component_denied() {
        let host = test_host_config();
        let args = args_with_component(Some("firewall"));
        match EsxiNetworkListTool::validate(&args, &host).unwrap_err() {
            BridgeError::CommandDenied { reason } => assert!(reason.contains("firewall")),
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_default_all() {
        // None component => "all" branch combining the three esxcli queries.
        let host = test_host_config();
        let args = args_with_component(None);
        let cmd = EsxiNetworkListTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("esxcli network ip interface list"));
        assert!(cmd.contains("esxcli network vswitch standard list"));
        assert!(cmd.contains("esxcli network nic list"));
    }

    #[test]
    fn test_build_command_interface_only() {
        let host = test_host_config();
        let args = args_with_component(Some("interface"));
        let cmd = EsxiNetworkListTool::build_command(&args, &host).unwrap();
        assert_eq!(cmd, "esxcli network ip interface list");
    }

    #[test]
    fn test_build_command_nic_only() {
        let host = test_host_config();
        let args = args_with_component(Some("nic"));
        let cmd = EsxiNetworkListTool::build_command(&args, &host).unwrap();
        assert_eq!(cmd, "esxcli network nic list");
    }

    #[test]
    fn test_post_process_with_columnar_output() {
        // Multi-column, space-padded sample drives the table-building branch
        // that the standard execute() tests never reach.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let sample = "Name    MAC Address        MTU   Link\n\
                      vmnic0  00:11:22:33:44:55  1500  Up\n\
                      vmnic1  00:11:22:33:44:66  1500  Down\n";
        let args = args_with_component(None);
        let base = ToolCallResult::text(sample.to_string());
        let processed = EsxiNetworkListTool::post_process(base, &args, sample, &dr);
        assert!(!processed.content.is_empty());
    }

    #[test]
    fn test_post_process_unparsable_input_returns_input() {
        // Single non-empty line cannot form a header+row table; parse returns
        // None and post_process returns the original result unchanged.
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let args = args_with_component(None);
        let base = ToolCallResult::text("only one line".to_string());
        let processed = EsxiNetworkListTool::post_process(base, &args, "only one line", &dr);
        assert!(!processed.content.is_empty());
    }
}
