//! K3s etcd snapshot restore — rolls cluster back to a snapshot.
//! DESTRUCTIVE: wipes current etcd datastore. Stop k3s service BEFORE running.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::K3sCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_etcd_snapshot_restore` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sEtcdSnapshotRestoreArgs {
    host: String,
    snapshot_path: String,
    #[serde(default)]
    k3s_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK3sEtcdSnapshotRestoreArgs);

/// Handler marker for the `ssh_k3s_etcd_snapshot_restore` tool.
#[mcp_standard_tool(
    name = "ssh_k3s_etcd_snapshot_restore",
    group = "k3s",
    annotation = "destructive"
)]
pub struct K3sEtcdSnapshotRestoreTool;

impl StandardTool for K3sEtcdSnapshotRestoreTool {
    type Args = SshK3sEtcdSnapshotRestoreArgs;
    const NAME: &'static str = "ssh_k3s_etcd_snapshot_restore";
    const DESCRIPTION: &'static str = "Restore K3s embedded etcd from a snapshot \
        (`k3s server --cluster-reset --cluster-reset-restore-path=<path>`). \
        **DESTRUCTIVE and IRREVERSIBLE**: wipes the current etcd datastore and rolls \
        back all cluster state to the snapshot. \
        **REQUIRED prerequisite**: stop k3s first (`ssh_service_stop service=k3s`), \
        then run this tool, then restart k3s. \
        `snapshot_path` must be an absolute path to the snapshot file.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "snapshot_path": {"type": "string", "description": "Absolute path to the etcd snapshot file (e.g. /var/lib/rancher/k3s/server/db/snapshots/on-demand-2026-01-01.db)"},
            "k3s_bin": {"type": "string", "description": "Custom k3s binary path (default: auto-detect 'k3s')"},
            "timeout_seconds": {"type": "integer", "description": "Timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit)", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the MCP server"}
        },
        "required": ["host", "snapshot_path"]
    }"#;

    fn build_command(
        args: &SshK3sEtcdSnapshotRestoreArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        K3sCommandBuilder::build_etcd_snapshot_restore_command(
            args.k3s_bin.as_deref(),
            &args.snapshot_path,
        )
    }
}

/// Handler for the `ssh_k3s_etcd_snapshot_restore` tool.
pub type SshK3sEtcdSnapshotRestoreHandler = StandardToolHandler<K3sEtcdSnapshotRestoreTool>;

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
        let handler = SshK3sEtcdSnapshotRestoreHandler::new();
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
        let handler = SshK3sEtcdSnapshotRestoreHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nohost",
                    "snapshot_path": "/var/lib/rancher/k3s/server/db/snapshots/snap.db"
                })),
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
        let handler = SshK3sEtcdSnapshotRestoreHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_etcd_snapshot_restore");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("snapshot_path")));
    }

    #[test]
    fn test_args_deserialization() {
        let args: SshK3sEtcdSnapshotRestoreArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "snapshot_path": "/var/lib/rancher/k3s/server/db/snapshots/snap.db",
            "k3s_bin": "k3s",
            "timeout_seconds": 120
        }))
        .unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(
            args.snapshot_path,
            "/var/lib/rancher/k3s/server/db/snapshots/snap.db"
        );
        assert_eq!(args.k3s_bin, Some("k3s".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let args: SshK3sEtcdSnapshotRestoreArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "snapshot_path": "/var/lib/rancher/k3s/server/db/snapshots/snap.db"
        }))
        .unwrap();
        assert!(args.k3s_bin.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sEtcdSnapshotRestoreHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("k3s_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK3sEtcdSnapshotRestoreArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "snapshot_path": "/var/snap.db"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sEtcdSnapshotRestoreArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sEtcdSnapshotRestoreHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "snapshot_path": "/var/snap.db"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_restore() {
        let args = SshK3sEtcdSnapshotRestoreArgs {
            host: "s1".into(),
            snapshot_path: "/var/lib/rancher/k3s/server/db/snapshots/snap.db".into(),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sEtcdSnapshotRestoreTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sudo k3s server"), "cmd: {cmd}");
        assert!(cmd.contains("--cluster-reset"), "cmd: {cmd}");
        assert!(cmd.contains("--cluster-reset-restore-path="), "cmd: {cmd}");
        assert!(cmd.contains("snap.db"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_path_rejected() {
        let args = SshK3sEtcdSnapshotRestoreArgs {
            host: "s1".into(),
            snapshot_path: "relative/path/snap.db".into(),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sEtcdSnapshotRestoreTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
