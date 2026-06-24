//! K8s Pod Health Tool Handler — list non-ready pods with full condition detail.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k8s_triage::K8sTriageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_pod_health` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sPodHealthArgs {
    host: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: bool,
    #[serde(default)]
    label_selector: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sPodHealthArgs);

/// Handler marker for the `ssh_k8s_pod_health` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_pod_health",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sPodHealth;

impl StandardTool for K8sPodHealth {
    type Args = SshK8sPodHealthArgs;
    const NAME: &'static str = "ssh_k8s_pod_health";
    const DESCRIPTION: &'static str = "K8s pod health rollup — returns JSON array of pods that \
        are NOT ready, with per-container state detail (waiting reason, exit code, restart count) \
        and unmet condition messages. Requires jq on the host. Filter with `label_selector` \
        (e.g. `app=nginx`).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list hosts)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace to scope (omit for current context namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "Query all namespaces (-A). Default false."
            },
            "label_selector": {
                "type": "string",
                "description": "Label selector to filter pods (e.g. 'app=nginx', 'tier=backend')"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl/k3s/microk8s)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file on the MCP server."
            }
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sPodHealthArgs, _host_config: &HostConfig) -> Result<String> {
        K8sTriageCommandBuilder::build_pod_health_command(
            args.kubectl_bin.as_deref(),
            args.namespace.as_deref(),
            args.all_namespaces,
            args.label_selector.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_pod_health` tool.
pub type SshK8sPodHealthHandler = StandardToolHandler<K8sPodHealth>;

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
        let handler = SshK8sPodHealthHandler::new();
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
        let handler = SshK8sPodHealthHandler::new();
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
        let handler = SshK8sPodHealthHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_pod_health");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_pod_health");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "k8s-prod",
            "namespace": "default",
            "all_namespaces": false,
            "label_selector": "app=nginx",
            "context": "prod-east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 50000
        });
        let args: SshK8sPodHealthArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-prod");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert!(!args.all_namespaces);
        assert_eq!(args.label_selector, Some("app=nginx".to_string()));
        assert_eq!(args.context, Some("prod-east".to_string()));
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(50000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s-node"});
        let args: SshK8sPodHealthArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-node");
        assert!(args.namespace.is_none());
        assert!(!args.all_namespaces);
        assert!(args.label_selector.is_none());
        assert!(args.context.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sPodHealthHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("label_selector"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s-node"});
        let args: SshK8sPodHealthArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sPodHealthArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sPodHealthHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    #[test]
    fn test_build_command_pod_health_with_label() {
        let args = SshK8sPodHealthArgs {
            host: "s1".into(),
            namespace: None,
            all_namespaces: false,
            label_selector: Some("app=nginx".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPodHealth::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-l 'app=nginx'"), "cmd: {cmd}");
        assert!(cmd.contains("notReadyReasons"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_pod_health_minimal() {
        let args = SshK8sPodHealthArgs {
            host: "s1".into(),
            namespace: Some("staging".into()),
            all_namespaces: false,
            label_selector: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPodHealth::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'staging'"), "cmd: {cmd}");
        assert!(!cmd.contains(" -l "), "cmd: {cmd}");
    }
}
