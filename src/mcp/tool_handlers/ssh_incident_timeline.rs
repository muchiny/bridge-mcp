//! Handler for the `ssh_incident_timeline` tool.
//!
//! Constructs an incident timeline from multiple log sources on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::incident::IncidentCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshIncidentTimelineArgs {
    /// Target host name from configuration.
    host: String,
    /// Start time for the timeline (e.g., "1 hour ago", "2024-01-01 00:00:00").
    #[serde(default)]
    since: Option<String>,
    /// End time for the timeline.
    #[serde(default)]
    until: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshIncidentTimelineArgs);

#[mcp_standard_tool(
    name = "ssh_incident_timeline",
    group = "incident",
    annotation = "read_only"
)]
pub struct IncidentTimelineTool;

impl StandardTool for IncidentTimelineTool {
    type Args = SshIncidentTimelineArgs;

    const NAME: &'static str = "ssh_incident_timeline";

    const DESCRIPTION: &'static str = "Construct an incident timeline on a remote host by \
        correlating multiple log sources. Collects journalctl errors (priority err and above), \
        failed systemd units, recent logins, kernel messages (dmesg), and recently modified \
        files under /var/log (*.log files newer than the 'since' timestamp, or last 1 hour if \
        'since' is omitted). Omitting 'since' scans the entire journal and can produce very \
        large output — strongly recommended to bound the query (e.g., '2 hours ago'). \
        'until' defaults to now. For targeted service correlation use ssh_incident_correlate; \
        for automated symptom-based triage use ssh_incident_triage.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "since": {
                        "type": "string",
                        "description": "Start time (e.g., '1 hour ago', '2024-01-01 00:00:00'). Defaults to no time bound if omitted — strongly recommended during incidents to bound the query (e.g., '2 hours ago') to avoid very large output."
                    },
                    "until": {
                        "type": "string",
                        "description": "End time (e.g., '2024-01-01 12:00:00'). Defaults to now if omitted."
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

    fn build_command(args: &SshIncidentTimelineArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(IncidentCommandBuilder::build_incident_timeline_command(
            args.since.as_deref(),
            args.until.as_deref(),
        ))
    }
}

/// Handler for the `ssh_incident_timeline` tool.
pub type SshIncidentTimelineHandler = StandardToolHandler<IncidentTimelineTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIncidentTimelineHandler::new();
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
        let handler = SshIncidentTimelineHandler::new();
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
        let handler = SshIncidentTimelineHandler::new();
        assert_eq!(handler.name(), "ssh_incident_timeline");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_incident_timeline");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "since": "1 hour ago",
            "until": "now",
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/timeline.txt"
        });
        let args: SshIncidentTimelineArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.since.as_deref(), Some("1 hour ago"));
        assert_eq!(args.until.as_deref(), Some("now"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/timeline.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshIncidentTimelineArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.since.is_none());
        assert!(args.until.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshIncidentTimelineHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("since"));
        assert!(props.contains_key("until"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshIncidentTimelineArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshIncidentTimelineArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshIncidentTimelineHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
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
    fn test_build_command_no_args() {
        let args = SshIncidentTimelineArgs {
            host: "s".to_string(),
            since: None,
            until: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = IncidentTimelineTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("Incident Timeline"));
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("dmesg"));
    }

    #[test]
    fn test_build_command_with_since() {
        let args = SshIncidentTimelineArgs {
            host: "s".to_string(),
            since: Some("1 hour ago".to_string()),
            until: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = IncidentTimelineTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1 hour ago"));
    }
}
