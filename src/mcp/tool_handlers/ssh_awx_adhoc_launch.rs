//! Handler for the `ssh_awx_adhoc_launch` tool.
//!
//! Launches an AWX ad-hoc command against an inventory by building a `curl`
//! POST command and relaying it via SSH to the configured AWX host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::use_cases::awx::{AwxCommandBuilder, HttpMethod};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// Arguments for the `ssh_awx_adhoc_launch` tool.
#[derive(Debug, Deserialize)]
struct SshAwxAdhocLaunchArgs {
    /// Inventory ID to run the ad-hoc command against.
    inventory: u64,
    /// Credential ID to authenticate against the target hosts.
    credential: u64,
    /// Ansible module to run (e.g. `command`, `shell`, `ping`).
    #[serde(default = "default_module_name")]
    module_name: String,
    /// Arguments passed to the module (sent in the JSON body, never the shell).
    module_args: String,
    /// Limit pattern restricting the host subset.
    #[serde(default)]
    limit: Option<String>,
    /// Verbosity level (0-5).
    #[serde(default)]
    verbosity: Option<u8>,
    /// Whether to run the command with privilege escalation.
    #[serde(default)]
    become_enabled: Option<bool>,
}

/// Default Ansible module for an ad-hoc command.
fn default_module_name() -> String {
    "command".to_string()
}

const SCHEMA: &str = r#"{
    "type": "object",
    "properties": {
        "inventory": {
            "type": "integer",
            "description": "Inventory ID to run the ad-hoc command against",
            "minimum": 1
        },
        "credential": {
            "type": "integer",
            "description": "Credential ID to authenticate against the target hosts",
            "minimum": 1
        },
        "module_name": {
            "type": "string",
            "description": "Ansible module to run (e.g. command, shell, ping)",
            "default": "command"
        },
        "module_args": {
            "type": "string",
            "description": "Arguments passed to the module (sent in the JSON body, never the shell)"
        },
        "limit": {
            "type": "string",
            "description": "Limit pattern restricting the host subset"
        },
        "verbosity": {
            "type": "integer",
            "description": "Verbosity level (0-5)",
            "minimum": 0,
            "maximum": 5
        },
        "become_enabled": {
            "type": "boolean",
            "description": "Whether to run the command with privilege escalation"
        }
    },
    "required": ["inventory", "credential", "module_args"]
}"#;

/// Handler for launching AWX ad-hoc commands.
#[mcp_tool(name = "ssh_awx_adhoc_launch", group = "awx", annotation = "mutating")]
pub struct SshAwxAdhocLaunchHandler;

impl Default for SshAwxAdhocLaunchHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAwxAdhocLaunchHandler {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolHandler for SshAwxAdhocLaunchHandler {
    fn name(&self) -> &'static str {
        "ssh_awx_adhoc_launch"
    }

    fn description(&self) -> &'static str {
        "Launch an AWX ad-hoc command (Ansible module) against an inventory. \
         Returns the ad-hoc command ID and initial status. \
         module_args is sent in the JSON body, never interpolated into the shell."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_awx_adhoc_launch",
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        crate::domain::output_kind::OutputKind::Json
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut raw = args.ok_or_else(|| BridgeError::McpMissingParam {
            param: "arguments".to_string(),
        })?;
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut raw);
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(raw)
            .map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        AwxCommandBuilder::validate_id(args.inventory)?;
        AwxCommandBuilder::validate_id(args.credential)?;

        let awx = ctx.config.awx.as_ref().ok_or_else(|| {
            BridgeError::McpInvalidRequest(
                "AWX not configured. Add 'awx:' section to config.yaml".to_string(),
            )
        })?;

        // Build JSON body with the required fields plus any present optional ones.
        let mut body_map = serde_json::Map::new();
        body_map.insert(
            "inventory".to_string(),
            serde_json::Value::Number(args.inventory.into()),
        );
        body_map.insert(
            "credential".to_string(),
            serde_json::Value::Number(args.credential.into()),
        );
        body_map.insert(
            "module_name".to_string(),
            serde_json::Value::String(args.module_name.clone()),
        );
        body_map.insert(
            "module_args".to_string(),
            serde_json::Value::String(args.module_args.clone()),
        );
        if let Some(ref limit) = args.limit {
            body_map.insert(
                "limit".to_string(),
                serde_json::Value::String(limit.clone()),
            );
        }
        if let Some(verbosity) = args.verbosity {
            body_map.insert(
                "verbosity".to_string(),
                serde_json::Value::Number(verbosity.into()),
            );
        }
        if let Some(become_enabled) = args.become_enabled {
            body_map.insert(
                "become_enabled".to_string(),
                serde_json::Value::Bool(become_enabled),
            );
        }

        let body_str = serde_json::Value::Object(body_map).to_string();

        let cmd = AwxCommandBuilder::build_api_call_checked(
            &awx.url,
            &awx.token,
            "/api/v2/ad_hoc_commands/",
            HttpMethod::Post,
            Some(&body_str),
            awx.verify_ssl,
            &[],
            awx.api_timeout,
        );

        let host = &awx.ssh_host;
        let host_config = ctx
            .config
            .hosts
            .get(host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        let limits = ctx.config.limits.clone();
        let mut conn = ctx
            .connection_pool
            .get_connection_with_jump(host, host_config, &limits, None)
            .await?;
        let output = conn.exec(&cmd, &limits).await?;

        let raw = ctx
            .execute_use_case
            .process_success(host, &cmd, &output.into())
            .stdout;
        let mut stdout = AwxCommandBuilder::parse_checked_response(&raw)?;
        crate::mcp::standard_tool::apply_reduction(
            &mut stdout,
            &dr,
            crate::domain::output_kind::OutputKind::Json,
        )?;
        Ok(ToolCallResult::text(stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAwxAdhocLaunchHandler;
        assert_eq!(handler.name(), "ssh_awx_adhoc_launch");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_awx_adhoc_launch");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("inventory")));
        assert!(required.contains(&json!("credential")));
        assert!(required.contains(&json!("module_args")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "inventory": 7,
            "credential": 3,
            "module_name": "shell",
            "module_args": "uptime",
            "limit": "webservers",
            "verbosity": 2,
            "become_enabled": true
        });
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory, 7);
        assert_eq!(args.credential, 3);
        assert_eq!(args.module_name, "shell");
        assert_eq!(args.module_args, "uptime");
        assert_eq!(args.limit.as_deref(), Some("webservers"));
        assert_eq!(args.verbosity, Some(2));
        assert_eq!(args.become_enabled, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"inventory": 1, "credential": 2, "module_args": "whoami"});
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.inventory, 1);
        assert_eq!(args.credential, 2);
        // module_name defaults to "command".
        assert_eq!(args.module_name, "command");
        assert_eq!(args.module_args, "whoami");
        assert!(args.limit.is_none());
        assert!(args.verbosity.is_none());
        assert!(args.become_enabled.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let schema_json: serde_json::Value =
            serde_json::from_str(SshAwxAdhocLaunchHandler.schema().input_schema).unwrap();
        assert!(schema_json["properties"].is_object());
        assert!(schema_json["properties"]["limit"].is_object());
        assert!(schema_json["properties"]["verbosity"].is_object());
        assert!(schema_json["properties"]["become_enabled"].is_object());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"inventory": 1, "credential": 2, "module_args": "whoami"});
        let args: SshAwxAdhocLaunchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwxAdhocLaunchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "inventory": "not_a_number",
                    "credential": 2,
                    "module_args": "whoami"
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_awx_config() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"inventory": 7, "credential": 3, "module_args": "uptime"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AWX not configured"),
            "Expected AWX not configured error, got: {err_msg}"
        );
    }

    // ============== Task 1.3 extra tests ==============

    #[test]
    fn test_body_contains_module_args() {
        // module_args must be carried in the JSON body as a string field, never
        // interpolated into the shell command.
        let body = serde_json::json!({
            "inventory": 7,
            "credential": 3,
            "module_name": "shell",
            "module_args": "rm -rf /tmp/foo && echo done",
        });
        let body_str = body.to_string();
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/ad_hoc_commands/",
            HttpMethod::Post,
            Some(&body_str),
            true,
            &[],
            30,
        );
        assert!(cmd.contains("-X POST"));
        assert!(cmd.contains("module_args"));
        assert!(cmd.contains("rm -rf /tmp/foo"));
    }

    #[tokio::test]
    async fn test_validate_inventory_zero() {
        let handler = SshAwxAdhocLaunchHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"inventory": 0, "credential": 3, "module_args": "uptime"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }
}
