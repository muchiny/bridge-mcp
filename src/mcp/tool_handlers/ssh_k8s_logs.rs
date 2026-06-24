//! SSH Kubernetes Logs Tool Handler
//!
//! Fetches logs from a Kubernetes pod via `kubectl` on a remote host.
//! Supports tail, since, previous container, timestamps, and container selection.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshK8sLogsArgs {
    host: String,
    pod: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    tail: Option<u64>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    previous: Option<bool>,
    #[serde(default)]
    timestamps: Option<bool>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK8sLogsArgs);

#[mcp_standard_tool(name = "ssh_k8s_logs", group = "kubernetes", annotation = "read_only")]
pub struct K8sLogsTool;

impl StandardTool for K8sLogsTool {
    type Args = SshK8sLogsArgs;

    const NAME: &'static str = "ssh_k8s_logs";

    const DESCRIPTION: &'static str = "Fetch logs from a Kubernetes pod via kubectl on a remote host. Use ssh_k8s_get with \
        resource 'pods' first to find pod names. Supports tail (last N lines), since \
        (time-based filtering, e.g., '1h'), previous container logs, timestamps, and \
        container selection for multi-container pods. Auto-detects kubectl binary (k8s, k3s, \
        microk8s). Returns log text.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pod": {
                "type": "string",
                "description": "Pod name or resource type/name (e.g. 'my-pod-abc123' or 'deployment/myapp'). Use ssh_k8s_get with resource='pods' to find pod names. Do not pass '-l app=nginx' here; label selectors are not supported in this param."
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "container": {
                "type": "string",
                "description": "Container name for multi-container pods (-c)"
            },
            "tail": {
                "type": "integer",
                "description": "Number of lines from the end to show (--tail=N). Omit to get all available log lines (kubectl default).",
                "minimum": 1
            },
            "since": {
                "type": "string",
                "description": "Only return logs newer than a relative duration (e.g. 1h, 30m, 5s)"
            },
            "previous": {
                "type": "boolean",
                "description": "Show logs from previous terminated container (-p)"
            },
            "timestamps": {
                "type": "boolean",
                "description": "Include timestamps in log output (--timestamps)"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "kubectl binary path or command (default: auto-detect k8s/k3s/microk8s)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "pod"]
    }"#;

    fn build_command(args: &SshK8sLogsArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_logs_command(
            args.kubectl_bin.as_deref(),
            &args.pod,
            args.namespace.as_deref(),
            args.container.as_deref(),
            args.tail,
            args.since.as_deref(),
            args.previous.unwrap_or(false),
            args.timestamps.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_k8s_logs` tool.
pub type SshK8sLogsHandler = StandardToolHandler<K8sLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sLogsHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshK8sLogsHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "nonexistent", "pod": "my-pod"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sLogsHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_logs");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_logs");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pod")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pod": "my-pod",
            "namespace": "production",
            "container": "app",
            "tail": 50,
            "since": "1h",
            "previous": true,
            "timestamps": true,
            "kubectl_bin": "k3s kubectl"
        });

        let args: SshK8sLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pod, "my-pod");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.container, Some("app".to_string()));
        assert_eq!(args.tail, Some(50));
        assert_eq!(args.since, Some("1h".to_string()));
        assert_eq!(args.previous, Some(true));
        assert_eq!(args.timestamps, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pod": "my-pod"});

        let args: SshK8sLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pod, "my-pod");
        assert!(args.namespace.is_none());
        assert!(args.container.is_none());
        assert!(args.tail.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sLogsHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("container"));
        assert!(properties.contains_key("tail"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("previous"));
        assert!(properties.contains_key("timestamps"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pod": "my-pod"});
        let args: SshK8sLogsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sLogsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sLogsHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(Some(json!({"host": 123, "pod": "my-pod"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

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
        let args = SshK8sLogsArgs {
            host: "server1".to_string(),
            pod: "my-pod".to_string(),
            namespace: None,
            container: None,
            tail: None,
            since: None,
            previous: None,
            timestamps: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sLogsTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl logs 'my-pod'");
    }

    #[test]
    fn test_build_command_with_container_tail() {
        let args = SshK8sLogsArgs {
            host: "server1".to_string(),
            pod: "my-pod".to_string(),
            namespace: Some("production".to_string()),
            container: Some("app".to_string()),
            tail: Some(50),
            since: None,
            previous: None,
            timestamps: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sLogsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("kubectl logs 'my-pod'"));
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("-c 'app'"));
        assert!(cmd.contains("--tail=50"));
    }

    #[test]
    fn test_build_command_with_previous_timestamps() {
        let args = SshK8sLogsArgs {
            host: "server1".to_string(),
            pod: "my-pod".to_string(),
            namespace: None,
            container: None,
            tail: None,
            since: Some("1h".to_string()),
            previous: Some(true),
            timestamps: Some(true),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sLogsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--since='1h'"));
        assert!(cmd.contains("-p"));
        assert!(cmd.contains("--timestamps"));
    }

    #[test]
    fn test_build_command_all_opts() {
        let args = SshK8sLogsArgs {
            host: "server1".to_string(),
            pod: "my-pod".to_string(),
            namespace: Some("kube-system".to_string()),
            container: Some("sidecar".to_string()),
            tail: Some(100),
            since: Some("30m".to_string()),
            previous: Some(true),
            timestamps: Some(true),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sLogsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("kubectl logs"));
        assert!(cmd.contains("-n 'kube-system'"));
        assert!(cmd.contains("-c 'sidecar'"));
        assert!(cmd.contains("--tail=100"));
        assert!(cmd.contains("--since='30m'"));
        assert!(cmd.contains("-p"));
        assert!(cmd.contains("--timestamps"));
    }
}
