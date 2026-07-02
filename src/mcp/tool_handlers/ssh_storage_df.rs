//! Handler for the `ssh_storage_df` tool.
//!
//! Shows disk space usage on a remote host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::storage::StorageCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshStorageDfArgs {
    /// Target host name from configuration.
    host: String,
    /// Optional path to check disk usage for.
    #[serde(default)]
    path: Option<String>,
    /// Show inode usage instead of block usage.
    #[serde(default)]
    inodes: Option<bool>,
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

impl_common_args!(SshStorageDfArgs);

#[mcp_standard_tool(name = "ssh_storage_df", group = "storage", annotation = "read_only")]
pub struct StorageDfTool;

impl StandardTool for StorageDfTool {
    type Args = SshStorageDfArgs;

    const NAME: &'static str = "ssh_storage_df";

    const DESCRIPTION: &'static str = "Show disk space usage (df -hT) on a remote host. Reports \
        filesystem type, size, used, available space, and mount point for each filesystem. Set \
        inodes=true to report inode counts instead of blocks. Use this when you need free-space \
        percentages per mount; use ssh_storage_lsblk to see physical block devices and partitions, \
        ssh_storage_lvm for LVM volume details, or ssh_storage_fstab for persistent mount \
        configuration.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional path to check disk usage for a specific filesystem"
                    },
                    "inodes": {
                        "type": "boolean",
                        "description": "Show inode usage instead of block usage"
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
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshStorageDfArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(StorageCommandBuilder::build_df_command(
            args.path.as_deref(),
            args.inodes.unwrap_or(false),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshStorageDfArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // `df -hT` is whitespace-separated with right-aligned numeric
        // columns, which the generic ≥2-space-gutter parser splits wrongly
        // (e.g. headers `used a` / `vail u`). Parse it with a fixed
        // 7-column schema instead. Falls back to the generic parser only
        // if the df-specific parse can't find a header.
        let Some(parsed) =
            parse_df_output(output).or_else(|| super::utils::parse_columnar_output(output))
        else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Disk Usage");
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
            "ssh_storage_df",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Parse `df -hT` (and `df -hT -i`) output into a `ParsedTable`.
///
/// Both variants have a fixed 7-column layout: `Filesystem Type <3 size or
/// inode columns> Use%/IUse% Mounted-on`. The first six columns never
/// contain whitespace; the mount point (last column) may, so everything
/// after the sixth field is joined back together. The two-word header
/// `Mounted on` is collapsed to a single `mounted on` column. Returns
/// `None` when the output has no header line, so the caller can fall back
/// to the generic parser.
fn parse_df_output(output: &str) -> Option<super::utils::ParsedTable> {
    let mut lines = output.lines().filter(|l| !l.trim().is_empty());
    let header_line = lines.next()?;
    let header_fields: Vec<&str> = header_line.split_whitespace().collect();
    // Need at least: Filesystem Type c3 c4 c5 Use% Mounted on = 8 tokens.
    if header_fields.len() < 8 {
        return None;
    }
    // First six headers are single tokens; the remainder ("Mounted on")
    // becomes one column.
    let mut headers: Vec<String> = header_fields[..6]
        .iter()
        .map(|h| h.to_lowercase())
        .collect();
    headers.push(header_fields[6..].join(" ").to_lowercase());

    let rows: Vec<Vec<String>> = lines
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 7 {
                return None;
            }
            let mut row: Vec<String> = fields[..6].iter().map(|s| (*s).to_string()).collect();
            row.push(fields[6..].join(" "));
            Some(row)
        })
        .collect();

    Some(super::utils::ParsedTable { headers, rows })
}

/// Handler for the `ssh_storage_df` tool.
pub type SshStorageDfHandler = StandardToolHandler<StorageDfTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    // Real `df -hT` output from a Raspberry Pi (LC_ALL=C). The generic
    // ≥2-space-gutter parser mangled this into `used a` / `vail u`
    // headers; parse_df_output must keep the 7 columns intact.
    const DF_HT_SAMPLE: &str = "\
Filesystem     Type     Size  Used Avail Use% Mounted on
udev           devtmpfs  3.8G     0  3.8G   0% /dev
tmpfs          tmpfs     1.6G  166M  1.5G  11% /run
/dev/nvme0n1p2 ext4      917G  674G  197G  78% /
/dev/nvme0n1p1 vfat      510M   91M  420M  18% /boot/firmware";

    #[test]
    fn test_parse_df_output_columns_intact() {
        let parsed = parse_df_output(DF_HT_SAMPLE).expect("df output should parse");
        assert_eq!(
            parsed.headers,
            vec![
                "filesystem",
                "type",
                "size",
                "used",
                "avail",
                "use%",
                "mounted on"
            ]
        );
        assert_eq!(parsed.rows.len(), 4);
        // Root filesystem row, fields intact and aligned.
        let root = parsed
            .rows
            .iter()
            .find(|r| r[6] == "/")
            .expect("root mount row");
        assert_eq!(root[0], "/dev/nvme0n1p2");
        assert_eq!(root[1], "ext4");
        assert_eq!(root[2], "917G");
        assert_eq!(root[5], "78%");
    }

    #[test]
    fn test_parse_df_output_column_selection() {
        let parsed = parse_df_output(DF_HT_SAMPLE).unwrap();
        let cols = vec![
            "Filesystem".to_string(),
            "Use%".to_string(),
            "Mounted on".to_string(),
        ];
        let reduced = parsed.select_columns(&cols);
        assert_eq!(reduced.headers, vec!["filesystem", "use%", "mounted on"]);
        assert_eq!(reduced.rows.len(), 4);
        assert_eq!(reduced.rows[0].len(), 3);
    }

    #[test]
    fn test_parse_df_output_rejects_non_df() {
        // Too few header tokens -> None, so caller falls back to generic parser.
        assert!(parse_df_output("just one line of text").is_none());
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshStorageDfHandler::new();
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
        let handler = SshStorageDfHandler::new();
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
        let handler = SshStorageDfHandler::new();
        assert_eq!(handler.name(), "ssh_storage_df");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_storage_df");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var",
            "inodes": true,
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/df.txt"
        });
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path.as_deref(), Some("/var"));
        assert_eq!(args.inodes, Some(true));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/df.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.path.is_none());
        assert!(args.inodes.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshStorageDfHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("inodes"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshStorageDfArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshStorageDfHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command & post_process Tests ==============

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
        let args: SshStorageDfArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = StorageDfTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("df"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshStorageDfArgs = serde_json::from_value(json!({
            "host": "s",
            "path": "/var",
            "inodes": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = StorageDfTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("/var") || cmd.contains("df"));
        assert!(cmd.contains("-i") || cmd.contains("inode"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshStorageDfArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "FILESYSTEM  SIZE  USED  AVAIL  USE%  MOUNTED ON\n/dev/sda1    50G   20G    28G   42%  /\ntmpfs         4G     0     4G    0%  /tmp\n";
        let result = StorageDfTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshStorageDfArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = StorageDfTool::post_process(result, &args, "", &dr);
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
                os_type: crate::config::OsType::default(),
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
        let handler = SshStorageDfHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       41284928 6173696  33000440  16% /\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content
        assert!(result.content.len() >= 2);
        assert!(result.structured_content.is_some());
    }
}
