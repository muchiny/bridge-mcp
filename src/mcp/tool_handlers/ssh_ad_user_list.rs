//! Handler for the `ssh_ad_user_list` tool.
//!
//! List Active Directory users with display name, enabled status, and last logon date.
//! Optionally filter by name pattern. Requires the AD `PowerShell` module.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::active_directory::ActiveDirectoryCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAdUserListArgs {
    host: String,
    filter: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAdUserListArgs);

#[mcp_standard_tool(
    name = "ssh_ad_user_list",
    group = "active_directory",
    annotation = "read_only"
)]
pub struct AdUserListTool;

impl StandardTool for AdUserListTool {
    type Args = SshAdUserListArgs;

    const NAME: &'static str = "ssh_ad_user_list";

    const DESCRIPTION: &'static str = "List Active Directory users with display name, enabled status, and last logon date. \
        Optionally filter by name pattern. Requires the AD PowerShell module.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml — must be a Windows host (use ssh_status to list hosts)"
            },
            "filter": {
                "type": "string",
                "description": "Filter users by name pattern (case-insensitive substring match)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshAdUserListArgs, _host_config: &HostConfig) -> Result<String> {
        ActiveDirectoryCommandBuilder::build_user_list_command(args.filter.as_deref())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshAdUserListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("AD Users");
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
            "ssh_ad_user_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_ad_user_list` tool.
pub type SshAdUserListHandler = StandardToolHandler<AdUserListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAdUserListHandler::new();
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
        let handler = SshAdUserListHandler::new();
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
        let handler = SshAdUserListHandler::new();
        assert_eq!(handler.name(), "ssh_ad_user_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ad_user_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "windc01",
            "filter": "john",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/users.txt"
        });
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.filter, Some("john".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/users.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "windc01"});
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert!(args.filter.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAdUserListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "windc01"});
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAdUserListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAdUserListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let args: SshAdUserListArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let host = test_host_config();
        let cmd = AdUserListTool::build_command(&args, &host).unwrap();
        // Was `assert!(!cmd.is_empty())`, which `cargo mutants` walked
        // straight through: `Ok("xyzzy".into())` is not empty either, so
        // nothing proved this handler reaches the real builder at all.
        // That matters more than a score here -- `build_command` is the
        // only place the filter validation is wired to the tool.
        assert!(cmd.starts_with("Get-ADUser -Filter *"), "{cmd}");
        assert!(cmd.contains("Sort-Object SamAccountName"), "{cmd}");
    }

    /// The filter reaches `build_user_list_command`, which validates it.
    ///
    /// Before the fix the filter was `ps_escape`d into a PowerShell
    /// DOUBLE-quoted string, where `$` and the backtick are expanded and
    /// the single quotes are inert -- so `$(...)` in a filter was evaluated
    /// by the remote shell. This handler was the one AD tool that never
    /// called `validate_ad_identity`; its two siblings did.
    #[test]
    fn test_build_command_refuses_a_hostile_filter() {
        let host = test_host_config();
        for hostile in ["$(hostname)", "a'b", "x\"y", "`n"] {
            let args: SshAdUserListArgs =
                serde_json::from_value(json!({"host": "s", "filter": hostile})).unwrap();
            assert!(
                AdUserListTool::build_command(&args, &host).is_err(),
                "filter {hostile:?} must be refused"
            );
        }
    }

    #[test]
    fn test_build_command_accepts_a_plain_filter() {
        let host = test_host_config();
        let args: SshAdUserListArgs =
            serde_json::from_value(json!({"host": "s", "filter": "john.doe"})).unwrap();
        let cmd = AdUserListTool::build_command(&args, &host).unwrap();
        // One pair of quotes, not two: the template quotes the value and
        // the builder no longer adds a second pair of its own.
        assert!(cmd.contains("Name -like '*john.doe*'"), "{cmd}");
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshAdUserListArgs = serde_json::from_value(json!({"host": "s"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "Col1\tCol2\nval1\tval2\n";
        let result = AdUserListTool::post_process(result, &args, output, &dr);
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
        let handler = SshAdUserListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
