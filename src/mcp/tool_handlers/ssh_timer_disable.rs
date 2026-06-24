//! Handler for the `ssh_timer_disable` tool.
//!
//! Disable a systemd timer on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::systemd_timers::TimerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshTimerDisableArgs {
    host: String,
    timer: String,
    #[serde(default)]
    now: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshTimerDisableArgs);

#[mcp_standard_tool(
    name = "ssh_timer_disable",
    group = "systemd_timers",
    annotation = "mutating"
)]
pub struct TimerDisableTool;

impl StandardTool for TimerDisableTool {
    type Args = SshTimerDisableArgs;

    const NAME: &'static str = "ssh_timer_disable";

    const DESCRIPTION: &'static str = "Disable a systemd timer on a remote host (Linux/systemd \
        only) so it no longer starts automatically at boot or on its configured schedule. Set \
        now=true to also stop the timer unit immediately (equivalent to `systemctl disable --now`). \
        Use ssh_timer_list to discover timer names and confirm the timer is enabled before \
        disabling. To reverse use ssh_timer_enable. On Windows hosts use ssh_schtask_disable \
        instead.";

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
                "description": "Name of the systemd timer to disable (e.g., apt-daily.timer)"
            },
            "now": {
                "type": "boolean",
                "description": "Also stop the timer immediately (default: false)"
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

    fn build_command(args: &SshTimerDisableArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TimerCommandBuilder::build_disable_command(
            &args.timer,
            args.now.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_timer_disable` tool.
pub type SshTimerDisableHandler = StandardToolHandler<TimerDisableTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTimerDisableHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshTimerDisableHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "timer": "apt-daily.timer"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshTimerDisableHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_timer_disable");
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
            "now": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshTimerDisableArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert_eq!(args.now, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "timer": "apt-daily.timer"});
        let args: SshTimerDisableArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert!(args.now.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTimerDisableHandler::new();
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
        let args: SshTimerDisableArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshTimerDisableArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "timer": "apt-daily.timer"});
        let result = serde_json::from_value::<SshTimerDisableArgs>(json);
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
        let args: SshTimerDisableArgs = serde_json::from_value(json!({
            "host": "s",
            "timer": "apt-daily.timer"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = TimerDisableTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("disable"));
        assert!(cmd.contains("apt-daily"));
    }

    #[test]
    fn test_build_command_with_now() {
        let args: SshTimerDisableArgs = serde_json::from_value(json!({
            "host": "s",
            "timer": "apt-daily.timer",
            "now": true
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = TimerDisableTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("--now") || cmd.contains("stop"));
    }
}
