//! SSH Ansible Playbook Tool Handler
//!
//! Runs an Ansible playbook on a remote host via SSH.
//! Supports inventory, tags, extra variables, check mode, and verbosity control.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::protocol::LogLevel;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshAnsiblePlaybookArgs {
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
    callback: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsiblePlaybookArgs);

#[mcp_standard_tool(
    name = "ssh_ansible_playbook",
    group = "ansible",
    annotation = "mutating"
)]
pub struct AnsiblePlaybookTool;

impl StandardTool for AnsiblePlaybookTool {
    type Args = SshAnsiblePlaybookArgs;

    const NAME: &'static str = "ssh_ansible_playbook";

    const DESCRIPTION: &'static str = "Run an Ansible playbook on a remote host via SSH. The playbook file must exist on the \
        remote host. Use check=true for dry-run mode to preview changes without applying. Use \
        ssh_ansible_inventory first to discover available hosts and groups. For quick \
        single-module tasks, prefer ssh_ansible_adhoc instead. Set callback='json' for \
        structured JSON output (works with jq_filter for token-efficient extraction). \
        Set callback='dense' for ultra-compact 1-line-per-task output. Returns \
        ansible-playbook output in the selected format.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
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
            "callback": {
                "type": "string",
                "description": "Ansible stdout callback plugin. Use 'json' for structured JSON output (enables jq_filter), 'dense' for compact 1-line-per-task, 'yaml' for YAML format, 'minimal' for minimal output. Default: Ansible default. Note: 'oneline' was removed from Ansible core >= 2.8 — use 'minimal' instead on modern installs.",
                "enum": ["json", "yaml", "dense", "minimal", "tree", "default", "oneline", "debug", "null"]
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
        "required": ["host", "playbook"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshAnsiblePlaybookArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_playbook_command(
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
            args.callback.as_deref(),
        ))
    }

    /// Parse the ansible-playbook output and emit a structured
    /// `notifications/message` per `PLAY [...]` and `TASK [...]` line so
    /// the client can render a live timeline of the run. Failed tasks
    /// (`fatal:` prefix) are logged at Error; others at Info. The raw
    /// result is returned unchanged — this hook is purely additive
    /// observability.
    async fn enrich(
        result: ToolCallResult,
        _args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let Some(logger) = ctx.mcp_logger.as_ref() else {
            return Ok(result);
        };
        for line in output.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("PLAY [") || trimmed.starts_with("PLAY RECAP") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "play", "line": trimmed}),
                );
            } else if trimmed.starts_with("TASK [") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "task", "line": trimmed}),
                );
            } else if trimmed.starts_with("fatal:") || trimmed.starts_with("FAILED!") {
                logger.log(
                    LogLevel::Error,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "fatal", "line": trimmed}),
                );
            } else if trimmed.starts_with("changed:") {
                logger.log(
                    LogLevel::Info,
                    "ssh_ansible_playbook",
                    serde_json::json!({"phase": "changed", "line": trimmed}),
                );
            }
        }
        Ok(result)
    }

    fn validate(args: &SshAnsiblePlaybookArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_playbook_path(&args.playbook)?;
        if let Some(ref cb) = args.callback {
            AnsibleCommandBuilder::validate_callback(cb)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_ansible_playbook` tool.
pub type SshAnsiblePlaybookHandler = StandardToolHandler<AnsiblePlaybookTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "playbook": "site.yml"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAnsiblePlaybookHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_playbook");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_playbook");

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
            "limit": "webservers",
            "tags": "deploy",
            "skip_tags": "debug",
            "extra_vars": {"env": "production", "version": "1.2.3"},
            "check": true,
            "diff": true,
            "verbose": 2,
            "forks": 10,
            "become": true,
            "become_user": "root",
            "working_dir": "/opt/ansible",
            "callback": "json",
            "timeout_seconds": 600,
            "max_output": 15000
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.tags, Some("deploy".to_string()));
        assert_eq!(args.skip_tags, Some("debug".to_string()));
        let extra_vars = args.extra_vars.unwrap();
        assert_eq!(extra_vars.get("env"), Some(&"production".to_string()));
        assert_eq!(extra_vars.get("version"), Some(&"1.2.3".to_string()));
        assert_eq!(args.check, Some(true));
        assert_eq!(args.diff, Some(true));
        assert_eq!(args.verbose, Some(2));
        assert_eq!(args.forks, Some(10));
        assert_eq!(args.use_become, Some(true));
        assert_eq!(args.become_user, Some("root".to_string()));
        assert_eq!(args.working_dir, Some("/opt/ansible".to_string()));
        assert_eq!(args.callback, Some("json".to_string()));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(15000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
        assert!(args.limit.is_none());
        assert!(args.tags.is_none());
        assert!(args.skip_tags.is_none());
        assert!(args.extra_vars.is_none());
        assert!(args.check.is_none());
        assert!(args.diff.is_none());
        assert!(args.verbose.is_none());
        assert!(args.forks.is_none());
        assert!(args.use_become.is_none());
        assert!(args.become_user.is_none());
        assert!(args.working_dir.is_none());
        assert!(args.callback.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        // Missing playbook field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_playbook_path_traversal_rejected() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "playbook": "../../../etc/shadow"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsiblePlaybookHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("skip_tags"));
        assert!(properties.contains_key("extra_vars"));
        assert!(properties.contains_key("check"));
        assert!(properties.contains_key("diff"));
        assert!(properties.contains_key("verbose"));
        assert!(properties.contains_key("forks"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("become_user"));
        assert!(properties.contains_key("working_dir"));
        assert!(properties.contains_key("callback"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });
        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsiblePlaybookArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "playbook": "site.yml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
    fn test_build_command_defaults() {
        let args = SshAnsiblePlaybookArgs {
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
            callback: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("ansible-playbook"));
        assert!(cmd.contains("'site.yml'"));
    }

    #[test]
    fn test_build_command_with_inventory_limit() {
        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: Some("hosts.ini".to_string()),
            limit: Some("webservers".to_string()),
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
            callback: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains("--limit 'webservers'"));
    }

    #[test]
    fn test_build_command_with_extra_vars() {
        let mut extra_vars = HashMap::new();
        extra_vars.insert("env".to_string(), "production".to_string());

        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "site.yml".to_string(),
            inventory: None,
            limit: None,
            tags: None,
            skip_tags: None,
            extra_vars: Some(extra_vars),
            check: Some(true),
            diff: None,
            verbose: None,
            forks: None,
            use_become: None,
            become_user: None,
            working_dir: None,
            callback: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-e 'env'='production'"));
        assert!(cmd.contains("--check"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let mut extra_vars = HashMap::new();
        extra_vars.insert("version".to_string(), "1.2.3".to_string());

        let args = SshAnsiblePlaybookArgs {
            host: "server1".to_string(),
            playbook: "deploy.yml".to_string(),
            inventory: Some("hosts.ini".to_string()),
            limit: Some("webservers".to_string()),
            tags: Some("deploy".to_string()),
            skip_tags: Some("debug".to_string()),
            extra_vars: Some(extra_vars),
            check: Some(true),
            diff: Some(true),
            verbose: Some(2),
            forks: Some(10),
            use_become: Some(true),
            become_user: Some("root".to_string()),
            working_dir: Some("/opt/ansible".to_string()),
            callback: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };

        let cmd = AnsiblePlaybookTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("cd '/opt/ansible' &&"));
        assert!(cmd.contains("ansible-playbook"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--tags 'deploy'"));
        assert!(cmd.contains("--skip-tags 'debug'"));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("--diff"));
        assert!(cmd.contains("-b"));
        assert!(cmd.contains("--become-user 'root'"));
    }
}
