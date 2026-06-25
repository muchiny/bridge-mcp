//! K3s upgrade — upgrades k3s to a pinned version via the official installer.
//! DESTRUCTIVE: swaps the k3s binary and restarts the service; can break the node.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::K3sCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_upgrade` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sUpgradeArgs {
    host: String,
    version: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK3sUpgradeArgs);

/// Handler marker for the `ssh_k3s_upgrade` tool.
#[mcp_standard_tool(name = "ssh_k3s_upgrade", group = "k3s", annotation = "destructive")]
pub struct K3sUpgradeTool;

impl StandardTool for K3sUpgradeTool {
    type Args = SshK3sUpgradeArgs;
    const NAME: &'static str = "ssh_k3s_upgrade";
    const DESCRIPTION: &'static str = "Upgrade (or downgrade) K3s to a specific pinned \
        version via the official installer (`curl -sfL https://get.k3s.io | sudo ...`). \
        **DESTRUCTIVE**: re-runs the installer, which swaps the k3s binary and restarts \
        the service — a failed upgrade can leave the node in a broken state. \
        `version` is REQUIRED and must be a pinned release tag such as `v1.30.2+k3s1` \
        or a plain semver like `v1.30.2`. Channel names (`latest`, `stable`, `testing`) \
        are rejected as version values to prevent accidental unpinned upgrades; use the \
        `channel` parameter instead if you need channel-based installs. \
        The installer URL `https://get.k3s.io` is a fixed literal — never interpolated.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "version": {"type": "string", "description": "Pinned k3s release tag, e.g. 'v1.30.2+k3s1' or 'v1.30.2'. REQUIRED. Channel names (latest/stable/testing) are rejected here — use the channel param instead."},
            "channel": {"type": "string", "description": "Optional release channel: 'stable', 'latest', or 'testing'. Use only when version is a semver and you want to combine with a channel.", "enum": ["stable", "latest", "testing"]},
            "timeout_seconds": {"type": "integer", "description": "Timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit)", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the MCP server"}
        },
        "required": ["host", "version"]
    }"#;

    fn build_command(args: &SshK3sUpgradeArgs, _host_config: &HostConfig) -> Result<String> {
        K3sCommandBuilder::build_upgrade_command(&args.version, args.channel.as_deref())
    }
}

/// Handler for the `ssh_k3s_upgrade` tool.
pub type SshK3sUpgradeHandler = StandardToolHandler<K3sUpgradeTool>;

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
        let handler = SshK3sUpgradeHandler::new();
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
        let handler = SshK3sUpgradeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nohost", "version": "v1.30.2+k3s1"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nohost"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK3sUpgradeHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_upgrade");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("version")));
    }

    #[test]
    fn test_args_deserialization() {
        let args: SshK3sUpgradeArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "version": "v1.30.2+k3s1",
            "channel": "stable"
        }))
        .unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.version, "v1.30.2+k3s1");
        assert_eq!(args.channel, Some("stable".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let args: SshK3sUpgradeArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "version": "v1.30.2+k3s1"
        }))
        .unwrap();
        assert!(args.channel.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sUpgradeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("channel"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK3sUpgradeArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "version": "v1.30.2+k3s1"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sUpgradeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sUpgradeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "version": "v1.30.2+k3s1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_k3s_version_tag() {
        let args = SshK3sUpgradeArgs {
            host: "s1".into(),
            version: "v1.30.2+k3s1".into(),
            channel: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("https://get.k3s.io"), "cmd: {cmd}");
        assert!(cmd.contains("INSTALL_K3S_VERSION="), "cmd: {cmd}");
        assert!(cmd.contains("v1.30.2"), "cmd: {cmd}");
        assert!(cmd.ends_with("sh -"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_plain_semver() {
        let args = SshK3sUpgradeArgs {
            host: "s1".into(),
            version: "v1.30.2".into(),
            channel: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("v1.30.2"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_channel() {
        let args = SshK3sUpgradeArgs {
            host: "s1".into(),
            version: "v1.30.2+k3s1".into(),
            channel: Some("stable".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sUpgradeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("INSTALL_K3S_CHANNEL="), "cmd: {cmd}");
        assert!(cmd.contains("stable"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_version_rejected() {
        let args = SshK3sUpgradeArgs {
            host: "s1".into(),
            version: "latest".into(),
            channel: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sUpgradeTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_invalid_channel_rejected() {
        let args = SshK3sUpgradeArgs {
            host: "s1".into(),
            version: "v1.30.2+k3s1".into(),
            channel: Some("edge".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sUpgradeTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
