//! `ssh_k3s_etcd_snapshot_save` Tool Handler — trigger a k3s etcd snapshot.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_path, validate_snapshot_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_etcd_snapshot_save` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sEtcdSnapshotSaveArgs {
    host: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    k3s_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK3sEtcdSnapshotSaveArgs);

/// Handler marker for `ssh_k3s_etcd_snapshot_save`.
#[mcp_standard_tool(
    name = "ssh_k3s_etcd_snapshot_save",
    group = "k3s",
    annotation = "mutating"
)]
pub struct SshK3sEtcdSnapshotSaveTool;

impl StandardTool for SshK3sEtcdSnapshotSaveTool {
    type Args = SshK3sEtcdSnapshotSaveArgs;
    const NAME: &'static str = "ssh_k3s_etcd_snapshot_save";
    const DESCRIPTION: &'static str = "Trigger a k3s embedded-etcd snapshot (`k3s etcd-snapshot save`). \
        Saves a point-in-time backup of the cluster state. \
        Use `ssh_k3s_etcd_snapshot_list` to verify the snapshot afterwards.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "name": {"type": "string", "description": "Snapshot name (default: auto-generated timestamp). Charset: [A-Za-z0-9._-], no leading '-'."},
            "dir": {"type": "string", "description": "Absolute path to the output directory (default: /var/lib/rancher/k3s/server/db/snapshots)."},
            "k3s_bin": {"type": "string", "description": "Custom k3s binary path (default: auto-detect 'k3s')."},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config).", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit).", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    fn build_command(
        args: &SshK3sEtcdSnapshotSaveArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        if let Some(n) = &args.name {
            validate_snapshot_name(n)?;
        }
        if let Some(d) = &args.dir {
            validate_path(d)?;
        }
        Ok(K3sCommandBuilder::build_etcd_snapshot_save_command(
            args.k3s_bin.as_deref(),
            args.name.as_deref(),
            args.dir.as_deref(),
        ))
    }
}

/// Handler for `ssh_k3s_etcd_snapshot_save`.
pub type SshK3sEtcdSnapshotSaveHandler = StandardToolHandler<SshK3sEtcdSnapshotSaveTool>;

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
        let handler = SshK3sEtcdSnapshotSaveHandler::new();
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
        let handler = SshK3sEtcdSnapshotSaveHandler::new();
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
        let handler = SshK3sEtcdSnapshotSaveHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_etcd_snapshot_save");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k3s_etcd_snapshot_save");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "name": "my-snapshot",
            "dir": "/var/lib/rancher/k3s/server/db/snapshots",
            "k3s_bin": "k3s",
            "timeout_seconds": 60,
            "max_output": 50000
        });
        let args: SshK3sEtcdSnapshotSaveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(args.name, Some("my-snapshot".to_string()));
        assert_eq!(
            args.dir,
            Some("/var/lib/rancher/k3s/server/db/snapshots".to_string())
        );
        assert_eq!(args.k3s_bin, Some("k3s".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sEtcdSnapshotSaveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.name.is_none());
        assert!(args.dir.is_none());
        assert!(args.k3s_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sEtcdSnapshotSaveHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("dir"));
        assert!(properties.contains_key("k3s_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sEtcdSnapshotSaveArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sEtcdSnapshotSaveArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sEtcdSnapshotSaveHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ── build_command tests ───────────────────────────────────────────────────

    #[test]
    fn test_build_command_minimal() {
        let args = SshK3sEtcdSnapshotSaveArgs {
            host: "k3s".into(),
            name: None,
            dir: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sEtcdSnapshotSaveTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sudo k3s etcd-snapshot save"), "cmd: {cmd}");
        assert!(!cmd.contains("--name"), "cmd: {cmd}");
        assert!(!cmd.contains("--dir"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_name_and_dir() {
        let args = SshK3sEtcdSnapshotSaveArgs {
            host: "k3s".into(),
            name: Some("my-snap".into()),
            dir: Some("/var/lib/rancher/k3s/server/db/snapshots".into()),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sEtcdSnapshotSaveTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--name 'my-snap'"), "cmd: {cmd}");
        assert!(
            cmd.contains("--dir '/var/lib/rancher/k3s/server/db/snapshots'"),
            "cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_command_invalid_name_rejected() {
        let args = SshK3sEtcdSnapshotSaveArgs {
            host: "k3s".into(),
            name: Some("bad/name".into()),
            dir: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        assert!(SshK3sEtcdSnapshotSaveTool::build_command(&args, &test_host_config()).is_err());
    }
}
