use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::terraform::TerraformCommandBuilder;
use crate::error::Result;
use crate::mcp::protocol::LogLevel;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshTerraformApplyArgs {
    host: String,
    dir: String,
    auto_approve: Option<bool>,
    vars: Option<Vec<String>>,
    var_file: Option<String>,
    targets: Option<Vec<String>>,
    plan_file: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshTerraformApplyArgs);

#[mcp_standard_tool(
    name = "ssh_terraform_apply",
    group = "terraform",
    annotation = "mutating"
)]
pub struct TerraformApplyTool;

impl StandardTool for TerraformApplyTool {
    type Args = SshTerraformApplyArgs;

    const NAME: &'static str = "ssh_terraform_apply";

    const DESCRIPTION: &'static str = "Apply Terraform infrastructure changes on a remote host — creates, updates, or destroys \
        resources as declared in the configuration. Always run ssh_terraform_plan first to review \
        the changes; pass the saved plan file via plan_file to guarantee the exact same set of \
        changes is applied. Without auto_approve=true the remote Terraform process requires \
        interactive confirmation, which is unavailable over SSH — always set auto_approve=true \
        or supply a plan_file. Emits structured MCP log events per resource action during the \
        apply. Use ssh_terraform_output to read output values after apply; use \
        ssh_terraform_state to inspect resulting state.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "dir": {
                        "type": "string",
                        "description": "Path to Terraform directory"
                    },
                    "auto_approve": {
                        "type": "boolean",
                        "description": "Skip interactive approval prompt (default: false). Required when running over SSH since there is no TTY for interactive confirmation; set true or supply a plan_file."
                    },
                    "vars": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Variable assignments in 'key=value' format, each passed as a separate -var flag (e.g. [\"region=us-east-1\", \"env=prod\"]). Ignored when plan_file is set."
                    },
                    "var_file": {
                        "type": "string",
                        "description": "Path to variable file"
                    },
                    "targets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Resource targets to apply"
                    },
                    "plan_file": {
                        "type": "string",
                        "description": "Path on the remote host to a plan file saved by ssh_terraform_plan (out param). When provided, applies exactly those changes — vars/var_file/targets are ignored."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Command timeout in seconds"
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters"
                    },
                    "save_output": {
                        "type": "string",
                        "description": "File path to save full output"
                    }
                },
                "required": ["host", "dir"]
            }"#;

    fn build_command(args: &SshTerraformApplyArgs, _host_config: &HostConfig) -> Result<String> {
        TerraformCommandBuilder::build_apply_command(
            &args.dir,
            args.auto_approve.unwrap_or(false),
            args.vars.as_deref(),
            args.var_file.as_deref(),
            args.targets.as_deref(),
            args.plan_file.as_deref(),
        )
    }

    /// Parse the `terraform apply` output and emit one log per
    /// resource transition (Plan/Creating/Modifying/Destroying/Apply
    /// complete) so the client can render the apply progress live.
    /// Errors surface at `LogLevel::Error`.
    async fn enrich(
        result: ToolCallResult,
        args: &Self::Args,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let Some(logger) = ctx.mcp_logger.as_ref() else {
            return Ok(result);
        };
        logger.log(
            LogLevel::Info,
            "ssh_terraform_apply",
            serde_json::json!({
                "phase": "start",
                "dir": args.dir,
                "auto_approve": args.auto_approve.unwrap_or(false),
                "targets": args.targets.as_ref().map_or(0, Vec::len),
            }),
        );
        for line in output.lines() {
            let trimmed = line.trim_start();
            // terraform prints `<resource>: Creating...` / `Modifying...`
            // / `Destroying...` / `Creation complete` / `Modifications
            // complete` / `Destruction complete` style lines.
            if trimmed.contains(": Creating...")
                || trimmed.contains(": Modifying...")
                || trimmed.contains(": Destroying...")
            {
                logger.log(
                    LogLevel::Info,
                    "ssh_terraform_apply",
                    serde_json::json!({"phase": "resource_action", "line": trimmed}),
                );
            } else if trimmed.contains(": Creation complete")
                || trimmed.contains(": Modifications complete")
                || trimmed.contains(": Destruction complete")
            {
                logger.log(
                    LogLevel::Info,
                    "ssh_terraform_apply",
                    serde_json::json!({"phase": "resource_done", "line": trimmed}),
                );
            } else if trimmed.starts_with("Apply complete!")
                || trimmed.starts_with("Plan:")
                || trimmed.starts_with("Outputs:")
            {
                logger.log(
                    LogLevel::Info,
                    "ssh_terraform_apply",
                    serde_json::json!({"phase": "summary", "line": trimmed}),
                );
            } else if trimmed.starts_with("Error:")
                || trimmed.starts_with("│ Error:")
                || trimmed.contains("Error applying plan")
            {
                logger.log(
                    LogLevel::Error,
                    "ssh_terraform_apply",
                    serde_json::json!({"phase": "error", "line": trimmed}),
                );
            }
        }
        Ok(result)
    }
}

/// Handler for the `ssh_terraform_apply` tool.
pub type SshTerraformApplyHandler = StandardToolHandler<TerraformApplyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTerraformApplyHandler::new();
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
        let handler = SshTerraformApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "dir": "/opt/terraform"})),
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
        let handler = SshTerraformApplyHandler::new();
        assert_eq!(handler.name(), "ssh_terraform_apply");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_terraform_apply");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("dir")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "dir": "/opt/terraform",
            "auto_approve": true,
            "vars": ["region=us-east-1"],
            "var_file": "prod.tfvars",
            "targets": ["aws_instance.web"],
            "plan_file": "plan.tfplan",
            "timeout_seconds": 600,
            "max_output": 20000,
            "save_output": "/tmp/tf_apply.txt"
        });
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(args.auto_approve, Some(true));
        assert_eq!(
            args.vars.as_deref(),
            Some(&["region=us-east-1".to_string()][..])
        );
        assert_eq!(args.var_file.as_deref(), Some("prod.tfvars"));
        assert_eq!(
            args.targets.as_deref(),
            Some(&["aws_instance.web".to_string()][..])
        );
        assert_eq!(args.plan_file.as_deref(), Some("plan.tfplan"));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(20000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tf_apply.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert!(args.auto_approve.is_none());
        assert!(args.vars.is_none());
        assert!(args.var_file.is_none());
        assert!(args.targets.is_none());
        assert!(args.plan_file.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTerraformApplyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("auto_approve"));
        assert!(properties.contains_key("vars"));
        assert!(properties.contains_key("var_file"));
        assert!(properties.contains_key("targets"));
        assert!(properties.contains_key("plan_file"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTerraformApplyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTerraformApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "dir": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
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
        let args = SshTerraformApplyArgs {
            host: "s".to_string(),
            dir: "/opt/infra".to_string(),
            auto_approve: None,
            vars: None,
            var_file: None,
            targets: None,
            plan_file: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TerraformApplyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("terraform"));
        assert!(cmd.contains("apply"));
        assert!(cmd.contains("/opt/infra"));
    }

    #[test]
    fn test_build_command_auto_approve() {
        let args = SshTerraformApplyArgs {
            host: "s".to_string(),
            dir: "/opt/infra".to_string(),
            auto_approve: Some(true),
            vars: Some(vec!["env=staging".to_string()]),
            var_file: None,
            targets: None,
            plan_file: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TerraformApplyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("apply"));
        assert!(cmd.contains("-auto-approve"));
    }

    #[test]
    fn test_build_command_with_var_file_and_targets() {
        let args = SshTerraformApplyArgs {
            host: "s".to_string(),
            dir: "/opt/infra".to_string(),
            auto_approve: None,
            vars: None,
            var_file: Some("prod.tfvars".to_string()),
            targets: Some(vec![
                "aws_instance.web".to_string(),
                "aws_instance.db".to_string(),
            ]),
            plan_file: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TerraformApplyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("apply"));
        assert!(cmd.contains("prod.tfvars"));
        assert!(cmd.contains("aws_instance.web"));
    }

    #[test]
    fn test_build_command_with_plan_file() {
        let args = SshTerraformApplyArgs {
            host: "s".to_string(),
            dir: "/opt/infra".to_string(),
            auto_approve: None,
            vars: None,
            var_file: None,
            targets: None,
            plan_file: Some("saved.tfplan".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TerraformApplyTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("apply"));
        assert!(cmd.contains("saved.tfplan"));
    }

    #[tokio::test]
    async fn test_enrich_no_logger_returns_input_unchanged() {
        // ctx.mcp_logger is None in test contexts -> early return path.
        let ctx = create_test_context();
        let args = SshTerraformApplyArgs {
            host: "s".to_string(),
            dir: "/opt/infra".to_string(),
            auto_approve: Some(true),
            vars: None,
            var_file: None,
            targets: Some(vec!["x".to_string()]),
            plan_file: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let base =
            ToolCallResult::text("aws_instance.web: Creating...\nApply complete!".to_string());
        let result = TerraformApplyTool::enrich(
            base,
            &args,
            "aws_instance.web: Creating...\nApply complete!",
            &ctx,
        )
        .await
        .unwrap();
        if let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] {
            assert!(text.contains("Apply complete!"));
        }
    }
}
