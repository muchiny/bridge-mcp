//! SSH Ansible Run Background Tool Handler
//!
//! Launches an Ansible playbook in the background via nohup with JSON callback,
//! returning a run ID and PID for later monitoring with `ssh_ansible_events`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshAnsibleRunBackgroundArgs {
    host: String,
    playbook: String,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    skip_tags: Option<String>,
    #[serde(default)]
    extra_vars: Option<HashMap<String, String>>,
    #[serde(default)]
    check: Option<bool>,
    #[serde(default)]
    diff: Option<bool>,
    #[serde(default)]
    verbose: Option<u8>,
    #[serde(default)]
    forks: Option<u32>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsibleRunBackgroundArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_run_background",
    group = "ansible",
    annotation = "mutating"
)]
pub struct AnsibleRunBackgroundTool;

impl StandardTool for AnsibleRunBackgroundTool {
    type Args = SshAnsibleRunBackgroundArgs;

    const NAME: &'static str = "ssh_ansible_run_background";

    const DESCRIPTION: &'static str = "Launch an Ansible playbook in the background with JSON \
        callback output. Returns a run_id and PID immediately. The playbook output is written \
        to /tmp/ansible-run-{run_id}.json on the remote host. Use ssh_ansible_events to monitor \
        progress and extract events. Use ssh_ansible_events with check_status=true and \
        pid=<pid> to check if the playbook is still running without a separate ssh_exec call.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "playbook": {
                "type": "string",
                "description": "Path to the Ansible playbook YAML file on the remote host"
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file or comma-separated host list"
            },
            "limit": {
                "type": "string",
                "description": "Limit to subset of hosts"
            },
            "tags": {
                "type": "string",
                "description": "Only run plays/tasks matching these tags"
            },
            "skip_tags": {
                "type": "string",
                "description": "Skip plays/tasks matching these tags"
            },
            "extra_vars": {
                "type": "object",
                "description": "Extra variables as key-value pairs"
            },
            "check": {
                "type": "boolean",
                "description": "Dry-run mode"
            },
            "diff": {
                "type": "boolean",
                "description": "Show file change diffs"
            },
            "verbose": {
                "type": "integer",
                "description": "Verbosity level 0-4",
                "minimum": 0,
                "maximum": 4
            },
            "forks": {
                "type": "integer",
                "description": "Number of parallel processes",
                "minimum": 1
            },
            "become": {
                "type": "boolean",
                "description": "Escalate privileges with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become"
            },
            "working_dir": {
                "type": "string",
                "description": "Directory to cd into before running"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file"
            }
        },
        "required": ["host", "playbook"]
    }"#;

    fn build_command(
        args: &SshAnsibleRunBackgroundArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        let playbook_cmd = AnsibleCommandBuilder::build_playbook_command(
            &args.playbook,
            args.inventory.as_deref(),
            args.limit.as_deref(),
            args.tags.as_deref(),
            args.skip_tags.as_deref(),
            args.extra_vars.as_ref(),
            args.check.unwrap_or(false),
            args.diff.unwrap_or(false),
            args.verbose,
            args.forks,
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
            args.working_dir.as_deref(),
            Some("json"),
        );

        // Generate a unique run ID using date + random
        // Launch in background, capture PID, return JSON with run_id and pid
        Ok(format!(
            r#"RUN_ID=$(date +%Y%m%d%H%M%S)_$$ && \
OUTPUT_FILE="/tmp/ansible-run-$RUN_ID.json" && \
nohup bash -c '{playbook_cmd} > "$OUTPUT_FILE" 2>&1' > /dev/null 2>&1 & \
PID=$! && \
echo '{{"run_id":"'$RUN_ID'","pid":'$PID',"output_file":"'$OUTPUT_FILE'","status":"started"}}'
"#,
            playbook_cmd = playbook_cmd.replace('\'', "'\\''"),
        ))
    }

    fn validate(args: &SshAnsibleRunBackgroundArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_playbook_path(&args.playbook)?;
        Ok(())
    }
}

/// Handler for the `ssh_ansible_run_background` tool.
pub type SshAnsibleRunBackgroundHandler = StandardToolHandler<AnsibleRunBackgroundTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsibleRunBackgroundHandler::new();
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
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "playbook": "site.yml"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_run_background");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("playbook")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml",
            "inventory": "hosts.ini",
            "check": true,
            "become": true
        });
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.check, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "playbook": "site.yml"});
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("become"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "s", "playbook": "p.yml"});
        let args: SshAnsibleRunBackgroundArgs = serde_json::from_value(json).unwrap();
        assert!(format!("{args:?}").contains("SshAnsibleRunBackgroundArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "playbook": "s"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let handler = SshAnsibleRunBackgroundHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "playbook": "../../etc/shadow"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    // ============== build_command Tests ==============

    use crate::config::{HostKeyVerification, OsType};

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
    fn test_build_command_uses_json_callback_and_nohup() {
        let args = SshAnsibleRunBackgroundArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: None,
            limit: None,
            tags: None,
            skip_tags: None,
            extra_vars: None,
            check: None,
            diff: None,
            verbose: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = AnsibleRunBackgroundTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("nohup"));
        assert!(cmd.contains("ANSIBLE_STDOUT_CALLBACK"));
        assert!(cmd.contains("json"));
        assert!(cmd.contains("ansible-run-"));
        assert!(cmd.contains("run_id"));
        assert!(cmd.contains("pid"));
    }
}
