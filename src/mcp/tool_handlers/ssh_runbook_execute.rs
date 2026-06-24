//! SSH Runbook Execute Tool Handler
//!
//! Resolves a runbook with parameters and returns the execution plan.
//! The plan contains resolved commands ready to be executed step by step
//! via `ssh_exec`, allowing Claude to observe each step and decide next actions.

use std::collections::HashMap;
use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::domain::runbook::{self, RunbookStep, apply_template};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

#[derive(Debug, Deserialize)]
struct Args {
    host: String,
    runbook_name: String,
    #[serde(default)]
    params: HashMap<String, String>,
}

#[mcp_tool(
    name = "ssh_runbook_execute",
    group = "runbooks",
    annotation = "destructive"
)]
#[derive(Default)]
pub struct SshRunbookExecuteHandler;

impl SshRunbookExecuteHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias to execute the runbook on"
            },
            "runbook_name": {
                "type": "string",
                "description": "Name of the runbook to execute; obtain valid names from ssh_runbook_list"
            },
            "params": {
                "type": "object",
                "description": "Template variables to inject into runbook steps, overriding any defaults declared in the runbook YAML. Keys must match the {{ variable }} placeholders used in step commands.",
                "additionalProperties": { "type": "string" }
            }
        },
        "required": ["host", "runbook_name"]
    }"#;
}

#[async_trait]
impl ToolHandler for SshRunbookExecuteHandler {
    fn name(&self) -> &'static str {
        "ssh_runbook_execute"
    }

    fn description(&self) -> &'static str {
        "Resolve a named runbook into an execution plan with all template variables replaced, \
         then execute it step by step on the target host. Returns the ordered list of resolved \
         commands; run each step with ssh_exec and observe its output before proceeding. Steps \
         marked confirm=true require explicit user confirmation before execution. Use \
         ssh_runbook_list first to discover available runbook names and their accepted params; \
         use ssh_runbook_validate to dry-check a runbook definition before running it. Unlike \
         ssh_runbook_validate (read-only), this tool is destructive and should not be called \
         without confirming the execution plan with the user first."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let args: Args =
            serde_json::from_value(args.ok_or_else(|| BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            })?)
            .map_err(|e| BridgeError::McpInvalidRequest(format!("Invalid arguments: {e}")))?;

        // Verify host exists
        ctx.config
            .hosts
            .get(&args.host)
            .ok_or_else(|| BridgeError::UnknownHost {
                host: args.host.clone(),
            })?;

        // Find the runbook
        let mut all_runbooks = runbook::builtin_runbooks();
        let user_dir = runbook::default_runbooks_dir();
        all_runbooks.extend(runbook::load_runbooks_from_dir(&user_dir));

        let rb = all_runbooks
            .iter()
            .find(|r| r.name == args.runbook_name)
            .ok_or_else(|| {
                BridgeError::McpInvalidRequest(format!("Runbook '{}' not found", args.runbook_name))
            })?
            .clone();

        // Build template variables: merge defaults with user params
        let mut vars: HashMap<String, String> = rb
            .params
            .iter()
            .filter_map(|(k, v)| v.default.as_ref().map(|d| (k.clone(), d.clone())))
            .collect();
        vars.extend(args.params);

        // Surface step-by-step resolution to the client so users see the
        // runbook unroll in real time even though the *plan* is built
        // synchronously. Both helpers no-op when the client did not
        // request progress / does not advertise logging support.
        let progress = ctx.progress_reporter(Some(rb.steps.len() as u64));
        let step_count = rb.steps.len();
        for (i, step) in rb.steps.iter().enumerate() {
            let step_num = (i + 1) as u64;
            if let Some(reporter) = progress.as_ref() {
                reporter.report(
                    step_num,
                    Some(&format!("step {step_num}/{step_count}: {}", step.name)),
                );
            }
            if let Some(logger) = ctx.mcp_logger.as_ref() {
                let level = if step.confirm {
                    crate::mcp::protocol::LogLevel::Warning
                } else {
                    crate::mcp::protocol::LogLevel::Info
                };
                logger.log(
                    level,
                    "ssh_runbook_execute",
                    serde_json::json!({
                        "runbook": rb.name,
                        "host": args.host,
                        "step": step_num,
                        "total_steps": step_count,
                        "name": step.name,
                        "confirm": step.confirm,
                        "has_rollback": step.rollback.is_some(),
                    }),
                );
            }
        }

        Ok(ToolCallResult::text(format_execution_plan(
            &rb.name,
            &rb.description,
            &args.host,
            &rb.steps,
            &vars,
        )))
    }
}

fn format_execution_plan(
    name: &str,
    description: &str,
    host: &str,
    steps: &[RunbookStep],
    vars: &HashMap<String, String>,
) -> String {
    let mut output = format!(
        "=== Runbook Execution Plan: {name} ===\n\
         Host: {host}\n\
         Description: {description}\n\
         Steps: {}\n\n\
         Execute each step with ssh_exec on host '{host}':\n\n",
        steps.len()
    );

    for (i, step) in steps.iter().enumerate() {
        let _ = writeln!(output, "--- Step {}: {} ---", i + 1, step.name);

        if let Some(ref cmd) = step.command {
            let resolved = apply_template(cmd, vars);
            let _ = writeln!(output, "Command: {resolved}");
        }

        if let Some(ref cond) = step.condition {
            let resolved = apply_template(cond, vars);
            let _ = writeln!(output, "Condition: {resolved}");
            if let Some(ref on_false) = step.on_false {
                let _ = writeln!(output, "On false: {on_false}");
            }
        }

        if step.confirm {
            output.push_str("WARNING: This step requires user confirmation before execution.\n");
        }

        if let Some(ref save_as) = step.save_as {
            let _ = writeln!(output, "Save output as: {save_as}");
        }

        if let Some(ref rollback) = step.rollback {
            let resolved = apply_template(rollback, vars);
            let _ = writeln!(output, "Rollback command: {resolved}");
        }

        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRunbookExecuteHandler;
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
        let handler = SshRunbookExecuteHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "runbook_name": "disk_full_recovery"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_runbook() {
        let handler = SshRunbookExecuteHandler;
        let ctx = crate::ports::mock::create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "runbook_name": "nonexistent_runbook"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRunbookExecuteHandler;
        assert_eq!(handler.name(), "ssh_runbook_execute");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("runbook_name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "runbook_name": "disk_full_recovery",
            "params": {"threshold_percent": "95"}
        });
        let args: Args = serde_json::from_value(json).unwrap();
        assert_eq!(args.runbook_name, "disk_full_recovery");
        assert_eq!(args.params.get("threshold_percent").unwrap(), "95");
    }

    #[tokio::test]
    async fn test_execution_plan() {
        let handler = SshRunbookExecuteHandler;
        let ctx = crate::ports::mock::create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "runbook_name": "disk_full_recovery",
                    "params": {"threshold_percent": "85"}
                })),
                &ctx,
            )
            .await
            .unwrap();
        let crate::mcp::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text")
        };
        assert!(text.contains("Execution Plan"));
        assert!(text.contains("disk_full_recovery"));
        assert!(text.contains("server1"));
        assert!(text.contains("check_disk_usage"));
        // Check template resolution with custom param
        assert!(text.contains("85"));
    }
}
