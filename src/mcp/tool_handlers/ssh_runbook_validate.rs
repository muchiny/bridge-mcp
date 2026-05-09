//! SSH Runbook Validate Tool Handler
//!
//! Validates a runbook YAML definition without executing it.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::domain::runbook::{self, Runbook};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

#[derive(Debug, Deserialize)]
struct Args {
    #[serde(default)]
    runbook_name: Option<String>,
    #[serde(default)]
    yaml_content: Option<String>,
}

#[mcp_tool(
    name = "ssh_runbook_validate",
    group = "runbooks",
    annotation = "read_only"
)]
#[derive(Default)]
pub struct SshRunbookValidateHandler;

impl SshRunbookValidateHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "runbook_name": {
                "type": "string",
                "description": "Name of an existing runbook to validate"
            },
            "yaml_content": {
                "type": "string",
                "description": "Raw YAML content of a runbook to validate"
            }
        }
    }"#;
}

#[async_trait]
impl ToolHandler for SshRunbookValidateHandler {
    fn name(&self) -> &'static str {
        "ssh_runbook_validate"
    }

    fn description(&self) -> &'static str {
        "Validate a runbook definition. Provide either a runbook_name (to validate an existing \
         runbook) or yaml_content (to validate raw YAML). Checks structure, required fields, \
         and step definitions."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, _ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: Args =
            serde_json::from_value(args.unwrap_or_else(|| Value::Object(Map::default())))
                .map_err(|e| BridgeError::McpInvalidRequest(format!("Invalid arguments: {e}")))?;

        let rb = if let Some(ref yaml) = args.yaml_content {
            crate::domain::yaml::parse_yaml::<Runbook>(yaml)
                .map_err(|e| BridgeError::McpInvalidRequest(format!("YAML parse error: {e}")))?
        } else if let Some(ref name) = args.runbook_name {
            let mut all = runbook::builtin_runbooks();
            all.extend(runbook::load_runbooks_from_dir(
                &runbook::default_runbooks_dir(),
            ));
            all.into_iter().find(|r| r.name == *name).ok_or_else(|| {
                BridgeError::McpInvalidRequest(format!("Runbook '{name}' not found"))
            })?
        } else {
            return Err(BridgeError::McpInvalidRequest(
                "Provide either runbook_name or yaml_content".to_string(),
            ));
        };

        match runbook::validate_runbook(&rb) {
            Ok(()) => {
                let mut output = format!("VALID: Runbook '{}' (v{})\n\n", rb.name, rb.version);
                let _ = writeln!(output, "Description: {}", rb.description);
                let _ = writeln!(output, "Steps: {}", rb.steps.len());
                let _ = writeln!(output, "Parameters: {}", rb.params.len());

                let confirm_count = rb.steps.iter().filter(|s| s.confirm).count();
                if confirm_count > 0 {
                    let _ = writeln!(output, "Steps requiring confirmation: {confirm_count}");
                }

                let rollback_count = rb.steps.iter().filter(|s| s.rollback.is_some()).count();
                if rollback_count > 0 {
                    let _ = writeln!(output, "Steps with rollback: {rollback_count}");
                }

                Ok(ToolCallResult::text(output))
            }
            Err(e) => Ok(ToolCallResult::text(format!(
                "INVALID: {e}\n\nRunbook '{}' has validation errors.",
                rb.name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshRunbookValidateHandler;
        assert_eq!(handler.name(), "ssh_runbook_validate");
    }

    #[tokio::test]
    async fn test_validate_builtin() {
        let handler = SshRunbookValidateHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"runbook_name": "disk_full_recovery"})), &ctx)
            .await
            .unwrap();
        let crate::mcp::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text")
        };
        assert!(text.contains("VALID"));
    }

    #[tokio::test]
    async fn test_validate_yaml_content() {
        let handler = SshRunbookValidateHandler;
        let ctx = create_test_context();
        let yaml = r"
name: test_runbook
description: A test
steps:
  - name: step1
    command: echo hello
";
        let result = handler
            .execute(Some(json!({"yaml_content": yaml})), &ctx)
            .await
            .unwrap();
        let crate::mcp::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text")
        };
        assert!(text.contains("VALID"));
    }

    #[tokio::test]
    async fn test_validate_invalid_yaml() {
        let handler = SshRunbookValidateHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"yaml_content": "not: valid: yaml: ["})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_args() {
        let handler = SshRunbookValidateHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({})), &ctx).await;
        assert!(result.is_err());
    }
}
