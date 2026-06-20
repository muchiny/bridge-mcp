//! Handler for the `ssh_process_list` tool.
//!
//! Lists running processes on a remote host with optional filtering and sorting.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshProcessListArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter processes by user.
    user: Option<String>,
    /// Sort field: %cpu, %mem, rss, vsz.
    sort_by: Option<String>,
    /// Filter processes by name pattern.
    filter: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessListArgs);

#[mcp_standard_tool(name = "ssh_process_list", group = "process", annotation = "read_only")]
pub struct ProcessListTool;

impl StandardTool for ProcessListTool {
    type Args = SshProcessListArgs;

    const NAME: &'static str = "ssh_process_list";

    const DESCRIPTION: &'static str = "List running processes on a Linux host. Prefer this over ssh_exec as it provides \
        structured filtering by user or process name with safe parameter handling. Sort by \
        CPU or memory usage. Returns PID, user, CPU%, memory%, and command. Use \
        ssh_process_top when you only want the N heaviest consumers; use ssh_process_kill \
        to send signals to specific processes. For Windows hosts use ssh_win_process_list instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "user": {
                        "type": "string",
                        "description": "Filter processes by user"
                    },
                    "sort_by": {
                        "type": "string",
                        "description": "ps --sort field (e.g. %cpu, %mem, rss, vsz); passed directly to ps so any valid ps sort key is accepted"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Filter processes by name pattern"
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
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshProcessListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ProcessCommandBuilder::build_list_command(
            args.user.as_deref(),
            args.sort_by.as_deref(),
            args.filter.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshProcessListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // `build_list_command` emits a fixed, known column order that depends on
        // whether a user filter is set. Parse positionally against that schema:
        // the space-gutter heuristic in `parse_columnar_output` merges columns on
        // real `ps aux` output (an 8-char user and a 7-digit PID share a single
        // space, below its ≥2-space boundary threshold), which collapsed the
        // table to 3 columns and dropped every row. See utils::parse_fixed_columns.
        let cols: &[&str] = if args.user.is_some() {
            &[
                "pid", "ppid", "%cpu", "%mem", "vsz", "rss", "tty", "stat", "start", "time",
                "command",
            ]
        } else {
            &[
                "user", "pid", "%cpu", "%mem", "vsz", "rss", "tty", "stat", "start", "time",
                "command",
            ]
        };
        let Some(parsed) = super::utils::parse_fixed_columns(output, cols, true, false) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Processes")
            .column("user", "User")
            .column("pid", "PID")
            .column("cpu", "%CPU")
            .column("mem", "%MEM")
            .column("command", "Command");

        let user_idx = parsed.headers.iter().position(|h| h == "user");
        let pid_idx = parsed.headers.iter().position(|h| h == "pid");
        let cpu_idx = parsed.headers.iter().position(|h| h == "%cpu");
        let mem_idx = parsed.headers.iter().position(|h| h == "%mem");
        let cmd_idx = parsed.headers.iter().position(|h| h == "command");

        for row in &parsed.rows {
            if row.iter().all(String::is_empty) {
                continue;
            }
            let get = |idx: Option<usize>| idx.and_then(|i| row.get(i)).map_or("", String::as_str);
            // The user-filter schema (`ps -u U -o ...`) omits the USER column;
            // fall back to the requested user, who owns every returned process.
            let user = match user_idx {
                Some(i) => row.get(i).map_or("", String::as_str),
                None => args.user.as_deref().unwrap_or(""),
            };
            tbl = tbl.row(json!({
                "user": user,
                "pid": get(pid_idx),
                "cpu": get(cpu_idx),
                "mem": get(mem_idx),
                "command": get(cmd_idx),
            }));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_process_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_process_list` tool.
pub type SshProcessListHandler = StandardToolHandler<ProcessListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
        assert_eq!(handler.name(), "ssh_process_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "user": "root",
            "sort_by": "%cpu",
            "filter": "nginx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/procs.txt"
        });
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.sort_by.as_deref(), Some("%cpu"));
        assert_eq!(args.filter.as_deref(), Some("nginx"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/procs.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.user.is_none());
        assert!(args.sort_by.is_none());
        assert!(args.filter.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("sort_by"));
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ProcessListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("ps"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s",
            "user": "root",
            "sort_by": "%cpu",
            "filter": "nginx"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ProcessListTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("root"));
        assert!(cmd.contains("cpu") || cmd.contains("sort"));
        assert!(cmd.contains("nginx") || cmd.contains("grep"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "USER     PID   %CPU  %MEM  COMMAND\nroot       1    0.0   0.1  /sbin/init\nnginx    123    1.2   0.5  nginx: worker\n";
        let result = ProcessListTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = ProcessListTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_real_ps_aux_app_rows_populated() {
        // Regression: real `ps aux` with an 8-char user (`message+`) AND a
        // 7-digit PID (`2411977`) collapsed the space-gutter parser to 3 merged
        // columns, so `position("user")` missed and every App row was dropped.
        let output = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
root           1  0.0  0.1  26336 16336 ?        Ss   May25  15:49 /usr/lib/systemd/systemd --system\n\
message+     564  0.0  0.0   9232  6016 ?        Ss   May25   6:50 /usr/bin/dbus-daemon --system\n\
muchini  2411977  0.0  0.0   2772  1664 ?        S    22:06   0:00 sshd-session\n";
        let args: SshProcessListArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = ProcessListTool::post_process(
            crate::ports::protocol::ToolCallResult::text("raw"),
            &args,
            output,
            &dr,
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(
            serialized.contains("message+"),
            "App rows dropped: {serialized}"
        );
        assert!(serialized.contains("2411977"), "7-digit PID row missing");
        assert!(serialized.contains("/usr/lib/systemd/systemd --system"));
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
        let handler = SshProcessListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 225516  9264 ?        Ss   Jan01   0:15 /sbin/init\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content
        assert!(result.content.len() >= 2);
        // End-to-end (the MCP path): structured_content is auto-populated from
        // the App and MUST carry the parsed row, not an empty array.
        let sc = result
            .structured_content
            .expect("structured_content present");
        let rows = sc
            .get("rows")
            .and_then(|r| r.as_array())
            .expect("rows array");
        assert_eq!(rows.len(), 1, "structured rows empty/wrong: {sc}");
    }
}
