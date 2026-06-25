//! `ssh_k3s_ctr_images` Tool Handler — manage images via k3s ctr.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_ctr_action, validate_path};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_ctr_images` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sCtrImagesArgs {
    host: String,
    action: String,
    #[serde(default)]
    tarball: Option<String>,
    #[serde(default)]
    k3s_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK3sCtrImagesArgs);

/// Handler marker for `ssh_k3s_ctr_images`.
#[mcp_standard_tool(name = "ssh_k3s_ctr_images", group = "k3s", annotation = "mutating")]
pub struct SshK3sCtrImagesTool;

impl StandardTool for SshK3sCtrImagesTool {
    type Args = SshK3sCtrImagesArgs;
    const NAME: &'static str = "ssh_k3s_ctr_images";
    const DESCRIPTION: &'static str = "Manage container images via `k3s ctr images`. \
        Supports listing (`ls`/`list`) and importing from a tarball (`import`). \
        The `import` action requires a `tarball` path. \
        Use `jq_filter` on `ls` output to reduce token usage.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "action": {"type": "string", "description": "Action to perform: 'ls', 'list', or 'import'."},
            "tarball": {"type": "string", "description": "Absolute path to the tarball to import (required for action='import')."},
            "k3s_bin": {"type": "string", "description": "Custom k3s binary path (default: auto-detect 'k3s')."},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config).", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit).", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host", "action"]
    }"#;

    const OUTPUT_KIND: OutputKind = OutputKind::Auto;

    fn build_command(args: &SshK3sCtrImagesArgs, _host_config: &HostConfig) -> Result<String> {
        validate_ctr_action(&args.action)?;
        if let Some(t) = &args.tarball {
            validate_path(t)?;
        }
        K3sCommandBuilder::build_ctr_images_command(
            args.k3s_bin.as_deref(),
            &args.action,
            args.tarball.as_deref(),
        )
    }
}

/// Handler for `ssh_k3s_ctr_images`.
pub type SshK3sCtrImagesHandler = StandardToolHandler<SshK3sCtrImagesTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

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

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK3sCtrImagesHandler::new();
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
        let handler = SshK3sCtrImagesHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "action": "ls"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK3sCtrImagesHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_ctr_images");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k3s_ctr_images");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "action": "import",
            "tarball": "/tmp/myimage.tar",
            "k3s_bin": "k3s",
            "timeout_seconds": 120,
            "max_output": 50000
        });
        let args: SshK3sCtrImagesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.action, "import");
        assert_eq!(args.tarball, Some("/tmp/myimage.tar".to_string()));
        assert_eq!(args.k3s_bin, Some("k3s".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node", "action": "ls"});
        let args: SshK3sCtrImagesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.action, "ls");
        assert!(args.tarball.is_none());
        assert!(args.k3s_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sCtrImagesHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("tarball"));
        assert!(properties.contains_key("k3s_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node", "action": "ls"});
        let args: SshK3sCtrImagesArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sCtrImagesArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sCtrImagesHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "action": "ls"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ── build_command tests ───────────────────────────────────────────────────

    #[test]
    fn test_build_command_ls() {
        let args = SshK3sCtrImagesArgs {
            host: "k3s".into(),
            action: "ls".into(),
            tarball: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sCtrImagesTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sudo k3s ctr images 'ls'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_import_with_tarball() {
        let args = SshK3sCtrImagesArgs {
            host: "k3s".into(),
            action: "import".into(),
            tarball: Some("/tmp/myimage.tar".into()),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sCtrImagesTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("'import'"), "cmd: {cmd}");
        assert!(cmd.contains("'/tmp/myimage.tar'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_import_without_tarball_rejected() {
        let args = SshK3sCtrImagesArgs {
            host: "k3s".into(),
            action: "import".into(),
            tarball: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(SshK3sCtrImagesTool::build_command(&args, &test_host_config()).is_err());
    }
}
