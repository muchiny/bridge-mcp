//! SSH Runbook List Tool Handler
//!
//! Lists available runbooks (built-in and user-defined).

use std::fmt::Write;

use async_trait::async_trait;
use serde_json::Value;

use crate::domain::runbook;
use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::mcp_tool;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

#[mcp_tool(
    name = "ssh_runbook_list",
    group = "runbooks",
    annotation = "read_only"
)]
#[derive(Default)]
pub struct SshRunbookListHandler;

impl SshRunbookListHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshRunbookListHandler {
    fn name(&self) -> &'static str {
        "ssh_runbook_list"
    }

    fn description(&self) -> &'static str {
        "List available runbooks (built-in and user-defined). Returns a TSV table with each \
         runbook's name, version, step count, parameter names, and description. Runbooks are \
         YAML-defined multi-step operational procedures for common tasks such as disk cleanup \
         (disk_full_recovery), service restart (service_restart), OOM recovery (oom_recovery), \
         log rotation (log_rotation), and certificate renewal (cert_renewal). Use this tool \
         first to discover runbook names, then pass a name to ssh_runbook_validate to check its \
         definition or to ssh_runbook_execute to resolve and run it."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, _ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut all_runbooks = runbook::builtin_runbooks();

        // Load user-defined runbooks
        let user_dir = runbook::default_runbooks_dir();
        let user_runbooks = runbook::load_runbooks_from_dir(&user_dir);
        all_runbooks.extend(user_runbooks);

        if all_runbooks.is_empty() {
            return Ok(ToolCallResult::text("No runbooks found."));
        }

        // TSV format for token efficiency (Category B)
        let mut output = String::from("NAME\tVERSION\tSTEPS\tPARAMS\tDESCRIPTION\n");
        for rb in &all_runbooks {
            let params = if rb.params.is_empty() {
                String::from("-")
            } else {
                rb.params.keys().cloned().collect::<Vec<_>>().join(",")
            };
            let _ = writeln!(
                output,
                "{}\t{}\t{}\t{}\t{}",
                rb.name,
                rb.version,
                rb.steps.len(),
                params,
                rb.description
            );
        }

        Ok(ToolCallResult::text(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshRunbookListHandler;
        assert_eq!(handler.name(), "ssh_runbook_list");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_execute_returns_builtin_runbooks() {
        let handler = SshRunbookListHandler;
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await.unwrap();
        let text = &result.content[0];
        let crate::mcp::protocol::ToolContent::Text { text: content } = text else {
            panic!("Expected text content")
        };
        assert!(content.contains("disk_full_recovery"));
        assert!(content.contains("service_restart"));
        assert!(content.contains("oom_recovery"));
    }
}
