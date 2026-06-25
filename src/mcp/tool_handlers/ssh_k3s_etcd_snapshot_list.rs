//! `ssh_k3s_etcd_snapshot_list` Tool Handler — list k3s etcd snapshots as JSON.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::output_kind::OutputKind;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_path};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_etcd_snapshot_list` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sEtcdSnapshotListArgs {
    host: String,
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

impl_common_args!(SshK3sEtcdSnapshotListArgs);

/// Handler marker for `ssh_k3s_etcd_snapshot_list`.
#[mcp_standard_tool(
    name = "ssh_k3s_etcd_snapshot_list",
    group = "k3s",
    annotation = "read_only"
)]
pub struct SshK3sEtcdSnapshotListTool;

impl StandardTool for SshK3sEtcdSnapshotListTool {
    type Args = SshK3sEtcdSnapshotListArgs;
    const NAME: &'static str = "ssh_k3s_etcd_snapshot_list";
    const DESCRIPTION: &'static str = "List k3s embedded-etcd snapshots as JSON (`k3s etcd-snapshot ls -o json`). \
        Use `jq_filter` to extract specific snapshot metadata. \
        Filter by directory with `dir`.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml (use ssh_status to list hosts)"},
            "dir": {"type": "string", "description": "Absolute path to the snapshots directory to list."},
            "k3s_bin": {"type": "string", "description": "Custom k3s binary path (default: auto-detect 'k3s')."},
            "timeout_seconds": {"type": "integer", "description": "Optional timeout in seconds (default: from config).", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit).", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a local file on the MCP server."}
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: OutputKind = OutputKind::Auto;

    fn build_command(
        args: &SshK3sEtcdSnapshotListArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        if let Some(d) = &args.dir {
            validate_path(d)?;
        }
        Ok(K3sCommandBuilder::build_etcd_snapshot_list_command(
            args.k3s_bin.as_deref(),
            args.dir.as_deref(),
        ))
    }
}

/// Handler for `ssh_k3s_etcd_snapshot_list`.
pub type SshK3sEtcdSnapshotListHandler = StandardToolHandler<SshK3sEtcdSnapshotListTool>;

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
        let handler = SshK3sEtcdSnapshotListHandler::new();
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
        let handler = SshK3sEtcdSnapshotListHandler::new();
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
        let handler = SshK3sEtcdSnapshotListHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_etcd_snapshot_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k3s_etcd_snapshot_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k3s-node",
            "dir": "/var/lib/rancher/k3s/server/db/snapshots",
            "k3s_bin": "k3s",
            "timeout_seconds": 30,
            "max_output": 50000
        });
        let args: SshK3sEtcdSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(
            args.dir,
            Some("/var/lib/rancher/k3s/server/db/snapshots".to_string())
        );
        assert_eq!(args.k3s_bin, Some("k3s".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sEtcdSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k3s-node");
        assert!(args.dir.is_none());
        assert!(args.k3s_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sEtcdSnapshotListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("dir"));
        assert!(properties.contains_key("k3s_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k3s-node"});
        let args: SshK3sEtcdSnapshotListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sEtcdSnapshotListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sEtcdSnapshotListHandler::new();
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
        let args = SshK3sEtcdSnapshotListArgs {
            host: "k3s".into(),
            dir: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sEtcdSnapshotListTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("sudo k3s etcd-snapshot ls -o json"),
            "cmd: {cmd}"
        );
        assert!(!cmd.contains("--dir"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_dir() {
        let args = SshK3sEtcdSnapshotListArgs {
            host: "k3s".into(),
            dir: Some("/var/lib/rancher/k3s/server/db/snapshots".into()),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SshK3sEtcdSnapshotListTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("--dir '/var/lib/rancher/k3s/server/db/snapshots'"),
            "cmd: {cmd}"
        );
    }
}
