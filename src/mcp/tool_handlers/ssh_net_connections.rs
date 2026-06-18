//! Handler for the `ssh_net_connections` tool.
//!
//! Lists active network connections on a remote host using `ss`.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshNetConnectionsArgs {
    /// Target host name.
    host: String,
    /// Filter by protocol (tcp/udp).
    protocol: Option<String>,
    /// Filter by connection state.
    state: Option<String>,
    /// Show only listening ports.
    listening: Option<bool>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetConnectionsArgs);

#[mcp_standard_tool(
    name = "ssh_net_connections",
    group = "network",
    annotation = "read_only"
)]
pub struct NetConnectionsTool;

impl StandardTool for NetConnectionsTool {
    type Args = SshNetConnectionsArgs;

    const NAME: &'static str = "ssh_net_connections";

    const DESCRIPTION: &'static str = "List active network connections on a remote host. Prefer this over ssh_exec as it \
        provides structured filtering by protocol, state, and listening mode. Returns \
        connection details including local/remote addresses and process info.";

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "required": ["host"],
    "properties": {
        "host": {
            "type": "string",
            "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
        },
        "protocol": {
            "type": "string",
            "description": "Filter by protocol",
            "enum": ["tcp", "udp"]
        },
        "state": {
            "type": "string",
            "description": "Filter by connection state (e.g., established, listening, time-wait)"
        },
        "listening": {
            "type": "boolean",
            "description": "Show only listening ports"
        },
        "timeout_seconds": {
            "type": "integer",
            "description": "Override command timeout in seconds"
        },
        "max_output": {
            "type": "integer",
            "description": "Maximum output characters (truncates if exceeded)"
        },
        "save_output": {
            "type": "string",
            "description": "Path to save full output to a local file"
        }
    }
}"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshNetConnectionsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkCommandBuilder::build_connections_command(
            args.protocol.as_deref(),
            args.state.as_deref(),
            args.listening.unwrap_or(false),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshNetConnectionsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // Parse the `ss` output positionally: its real header packs `Process`
        // directly onto `Peer Address:Port` (no gap) and right-aligns the data,
        // so the space-gutter parser sliced header names mid-word and produced
        // garbled column keys ("send-q loca", "address:portp"). The `Process`
        // column (greedy last) keeps its embedded spaces, e.g. users:(("...")).
        //
        // Only the default `ss -tunap` (both protocols) emits a leading `Netid`
        // column; every single-protocol or listening variant (`-tlnp`, `-tnap`,
        // `-ulnp`, `-unap`) drops it. `build_connections_command` picks the
        // variant from exactly these two args, so mirror that here.
        let has_netid = args.protocol.is_none() && !args.listening.unwrap_or(false);
        let cols: &[&str] = if has_netid {
            &[
                "netid",
                "state",
                "recv-q",
                "send-q",
                "local_address",
                "peer_address",
                "process",
            ]
        } else {
            &[
                "state",
                "recv-q",
                "send-q",
                "local_address",
                "peer_address",
                "process",
            ]
        };
        let Some(parsed) = super::utils::parse_fixed_columns(output, cols, true, false) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Network Connections");
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
            "ssh_net_connections",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_net_connections` tool.
pub type SshNetConnectionsHandler = StandardToolHandler<NetConnectionsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetConnectionsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_connections");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetConnectionsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("protocol"));
        assert!(props.contains_key("state"));
        assert!(props.contains_key("listening"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetConnectionsHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetConnectionsHandler::new();
        let args = serde_json::json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::UnknownHost { ref host } if host == "nonexistent"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "host": "myhost",
            "protocol": "tcp",
            "state": "established",
            "listening": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.protocol.as_deref(), Some("tcp"));
        assert_eq!(args.state.as_deref(), Some("established"));
        assert_eq!(args.listening, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.protocol.is_none());
        assert!(args.state.is_none());
        assert!(args.listening.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345});
        let result = serde_json::from_value::<SshNetConnectionsArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command & post_process Tests ==============

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
        let args: SshNetConnectionsArgs =
            serde_json::from_value(serde_json::json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = NetConnectionsTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("ss"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshNetConnectionsArgs = serde_json::from_value(serde_json::json!({
            "host": "s",
            "protocol": "tcp",
            "state": "established",
            "listening": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = NetConnectionsTool::build_command(&args, &host).unwrap();
        // listening+tcp -> ss -tlnp
        assert!(cmd.contains("tlnp"));
        assert!(cmd.contains("established"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshNetConnectionsArgs =
            serde_json::from_value(serde_json::json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "STATE   LOCAL              PEER\nESTAB   127.0.0.1:22       192.168.1.1:54321\nLISTEN  0.0.0.0:80         *:*\n";
        let result = NetConnectionsTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshNetConnectionsArgs =
            serde_json::from_value(serde_json::json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = NetConnectionsTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
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

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshNetConnectionsHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                // Real `ss` layout: header present, `Process` glued onto Peer.
                "Netid State  Recv-Q Send-Q   Local Address:Port  Peer Address:PortProcess\ntcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=753,fd=3))\n",
            ),
        );
        let result = handler
            .execute(Some(serde_json::json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content
        assert!(result.content.len() >= 2);
        let sc = result.structured_content.expect("structured_content");
        let rows = sc
            .get("rows")
            .and_then(|r| r.as_array())
            .expect("rows array");
        assert_eq!(rows.len(), 1, "rows: {sc}");
        assert_eq!(rows[0].get("netid").and_then(|v| v.as_str()), Some("tcp"));
        assert_eq!(
            rows[0].get("local_address").and_then(|v| v.as_str()),
            Some("0.0.0.0:22")
        );
    }

    #[test]
    fn test_post_process_real_ss_clean_columns() {
        // Regression: the real `ss -tunlp` header packs `Process` directly onto
        // `Peer Address:Port` and right-aligns data, so the space-gutter parser
        // sliced header names mid-word and produced garbled column keys
        // ("send-q loca", "address:portp"). The fixed schema keeps clean keys
        // and the greedy `process` column keeps its embedded spaces.
        let output = "Netid State  Recv-Q Send-Q               Local Address:Port  Peer Address:PortProcess\n\
udp   UNCONN 0      0                          0.0.0.0:53         0.0.0.0:*    \n\
tcp   LISTEN 0      128                        0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=753,fd=3))\n";
        let args: SshNetConnectionsArgs =
            serde_json::from_value(serde_json::json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = NetConnectionsTool::post_process(
            crate::ports::protocol::ToolCallResult::text("raw"),
            &args,
            output,
            &dr,
        );
        let s = serde_json::to_string(&result).unwrap();
        // Clean positional column keys present...
        assert!(s.contains("local_address"), "missing clean key: {s}");
        assert!(s.contains("peer_address"));
        // ...garbled gutter-sliced keys gone.
        assert!(!s.contains("send-q loca"), "garbled key leaked: {s}");
        assert!(!s.contains("address:portp"), "garbled key leaked: {s}");
        // Greedy process column captured with its embedded spaces/quotes.
        assert!(
            s.contains("sshd") && s.contains("pid=753"),
            "process lost: {s}"
        );
    }

    #[test]
    fn test_post_process_listening_variant_has_no_netid() {
        // `ss -tlnp` (listening / single-protocol) drops the leading `Netid`
        // column. The schema must shift accordingly or every value lands one
        // column off (state read as netid, process split across peer/process).
        let output = "State  Recv-Q Send-Q  Local Address:Port  Peer Address:PortProcess\n\
LISTEN 0      128         0.0.0.0:22          0.0.0.0:*    users:((\"sshd\",pid=753,fd=3))\n";
        let args: SshNetConnectionsArgs =
            serde_json::from_value(serde_json::json!({"host": "s", "listening": true})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = NetConnectionsTool::post_process(
            crate::ports::protocol::ToolCallResult::text("raw"),
            &args,
            output,
            &dr,
        );
        // post_process sets the App (structured_content is filled later by the
        // pipeline); read the App data directly.
        let sc = result
            .content
            .iter()
            .find_map(|c| match c {
                crate::mcp::protocol::ToolContent::App { app } => Some(app.data.clone()),
                _ => None,
            })
            .expect("app content");
        // No netid column in this variant.
        assert!(
            !sc.to_string().contains("netid"),
            "netid leaked into listening variant: {sc}"
        );
        let rows = sc.get("rows").and_then(|r| r.as_array()).expect("rows");
        assert_eq!(
            rows[0].get("state").and_then(|v| v.as_str()),
            Some("LISTEN")
        );
        assert_eq!(
            rows[0].get("local_address").and_then(|v| v.as_str()),
            Some("0.0.0.0:22")
        );
        // Process not split off into peer_address.
        assert_eq!(
            rows[0].get("peer_address").and_then(|v| v.as_str()),
            Some("0.0.0.0:*")
        );
        assert!(
            rows[0]
                .get("process")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("sshd")
        );
    }
}
