//! Handler for the `ssh_timer_info` tool.
//!
//! Show detailed information about a systemd timer on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::systemd_timers::TimerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTimerInfoArgs {
    host: String,
    timer: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshTimerInfoArgs);

#[mcp_standard_tool(
    name = "ssh_timer_info",
    group = "systemd_timers",
    annotation = "read_only"
)]
pub struct TimerInfoTool;

impl StandardTool for TimerInfoTool {
    type Args = SshTimerInfoArgs;

    const NAME: &'static str = "ssh_timer_info";

    const DESCRIPTION: &'static str = "Show detailed information about a specific systemd timer \
        on a remote host (Linux/systemd only). Runs both `systemctl show` and `systemctl status` \
        to report the timer's OnCalendar/OnBootSec schedule expression, next and last trigger \
        timestamps, associated service unit, and active state. Discover available timer names with \
        ssh_timer_list first. To enable or disable the timer use ssh_timer_enable / \
        ssh_timer_disable; to fire it immediately use ssh_timer_trigger. On Windows hosts use \
        ssh_schtask_info instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "timer"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "timer": {
                "type": "string",
                "description": "Name of the systemd timer (e.g., apt-daily.timer, logrotate.timer)"
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
                "description": "Save full output to this file path on the remote host"
            }
        }
    }"#;

    fn build_command(args: &SshTimerInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TimerCommandBuilder::build_info_command(&args.timer))
    }
}

/// Handler for the `ssh_timer_info` tool.
pub type SshTimerInfoHandler = StandardToolHandler<TimerInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTimerInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshTimerInfoHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "timer": "apt-daily.timer"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshTimerInfoHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_timer_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("timer")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "timer": "apt-daily.timer",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "timer": "apt-daily.timer"});
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTimerInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "timer": "t"});
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshTimerInfoArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "timer": "apt-daily.timer"});
        let result = serde_json::from_value::<SshTimerInfoArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command Tests ==============

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
        let args: SshTimerInfoArgs = serde_json::from_value(json!({
            "host": "s",
            "timer": "apt-daily.timer"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = TimerInfoTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("apt-daily"));
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
        let handler = SshTimerInfoHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "Id=apt-daily.timer\nDescription=Daily apt download\nNextElapseUSecMonotonic=86400000000",
            ),
        );
        let result = handler
            .execute(
                Some(json!({"host": "server1", "timer": "apt-daily.timer"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
