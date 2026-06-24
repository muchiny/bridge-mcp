//! Handler for the `ssh_user_list` tool.
//!
//! Lists users on a remote Linux host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshUserListArgs {
    /// Target host name from configuration.
    host: String,
    /// Include system accounts (UID < 1000).
    #[serde(default)]
    system: Option<bool>,
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

impl_common_args!(SshUserListArgs);

#[mcp_standard_tool(
    name = "ssh_user_list",
    group = "user_management",
    annotation = "read_only"
)]
pub struct UserListTool;

impl StandardTool for UserListTool {
    type Args = SshUserListArgs;

    const NAME: &'static str = "ssh_user_list";

    const DESCRIPTION: &'static str = "List users on a remote Linux host (reads /etc/passwd via \
        awk). By default shows only regular users (UID >= 1000); set system=true to include all \
        system accounts. Returns a table with USER, UID, GID, HOME, SHELL columns — use this to \
        discover usernames before calling ssh_user_info, ssh_user_modify, or ssh_user_delete. \
        For Active Directory user accounts on Windows hosts use ssh_ad_user_list instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "system": {
                "type": "boolean",
                "description": "Include system accounts (UID < 1000). Default: false"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshUserListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_list_command(
            args.system.unwrap_or(false),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshUserListArgs,
        output: &str,
        _dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() < 2 {
            return result;
        }
        let mut tbl = table("Users")
            .column("user", "User")
            .column("uid", "UID")
            .column("gid", "GID")
            .column("home", "Home")
            .column("shell", "Shell");
        for line in &lines[1..] {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 {
                tbl = tbl.row(json!({
                    "user": cols[0],
                    "uid": cols[1],
                    "gid": cols[2],
                    "home": cols[3],
                    "shell": cols[4],
                }));
            }
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_user_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(output).with_app(tbl.build())
    }
}

/// Handler for the `ssh_user_list` tool.
pub type SshUserListHandler = StandardToolHandler<UserListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserListHandler::new();
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
        let handler = SshUserListHandler::new();
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
        let handler = SshUserListHandler::new();
        assert_eq!(handler.name(), "ssh_user_list");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
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
        let args: SshUserListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = UserListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        // Default: system=false, should filter UID >= 1000
        assert!(cmd.contains("awk") || cmd.contains("getent") || cmd.contains("passwd"));
    }

    #[test]
    fn test_build_command_with_system() {
        let args: SshUserListArgs = serde_json::from_value(json!({
            "host": "s",
            "system": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = UserListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "USER\tUID\tGID\tHOME\tSHELL\nroot\t0\t0\t/root\t/bin/bash\njohn\t1000\t1000\t/home/john\t/bin/bash\n";
        let result = UserListTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "";
        let result = UserListTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_single_line() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshUserListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        // Only header, no data rows — should return original result
        let output = "USER\tUID\tGID\tHOME\tSHELL\n";
        let result = UserListTool::post_process(result, &args, output, &dr);
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
        let handler = SshUserListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "USER\tUID\tGID\tHOME\tSHELL\nroot\t0\t0\t/root\t/bin/bash\ntestuser\t1000\t1000\t/home/testuser\t/bin/bash\n",
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
