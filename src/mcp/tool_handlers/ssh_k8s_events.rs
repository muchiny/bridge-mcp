//! K8s Events Tool Handler
//!
//! Lists Kubernetes events sorted by last timestamp via kubectl over SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_events` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sEventsArgs {
    host: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
    #[serde(default)]
    field_selector: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    label_selector: Option<String>,
    #[serde(default)]
    for_kind: Option<String>,
    #[serde(default)]
    for_name: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK8sEventsArgs);

/// Handler marker for the `ssh_k8s_events` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_events",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sEventsTool;

impl StandardTool for K8sEventsTool {
    type Args = SshK8sEventsArgs;

    const NAME: &'static str = "ssh_k8s_events";

    const DESCRIPTION: &'static str = "List Kubernetes events sorted by last timestamp (newest last). Scope with namespace, \
        all_namespaces, or field_selector (e.g. involvedObject.name=my-pod). \
        First-line triage tool.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host alias from config"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace to list events from (omit for current namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "List events across all namespaces (-A)"
            },
            "field_selector": {
                "type": "string",
                "description": "Field selector to scope events, e.g. involvedObject.name=my-pod"
            },
            "output": {
                "type": "string",
                "enum": ["json", "yaml", "wide", "name"],
                "description": "Output format for events"
            },
            "label_selector": {
                "type": "string",
                "description": "Filter events by label selector (e.g. app=nginx)"
            },
            "for_kind": {
                "type": "string",
                "description": "Filter events for a specific resource kind (use with for_name)"
            },
            "for_name": {
                "type": "string",
                "description": "Filter events for a specific resource name (use with for_kind)"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Path to kubectl (default: auto-detect kubectl/k3s/microk8s)"
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
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sEventsArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(out) = args.output.as_deref() {
            KubernetesCommandBuilder::validate_events_output(out)?;
        }
        let for_target = match (args.for_kind.as_deref(), args.for_name.as_deref()) {
            (Some(kind), Some(name)) => {
                KubernetesCommandBuilder::validate_for_target(kind, name)?;
                Some(format!("{kind}/{name}"))
            }
            (None, None) => None,
            _ => {
                return Err(crate::error::BridgeError::CommandDenied {
                    reason: "for_kind and for_name must both be provided together".to_string(),
                });
            }
        };
        Ok(KubernetesCommandBuilder::build_events_command(
            args.kubectl_bin.as_deref(),
            args.namespace.as_deref(),
            args.all_namespaces.unwrap_or(false),
            args.field_selector.as_deref(),
            args.output.as_deref(),
            args.label_selector.as_deref(),
            for_target.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_events` tool.
pub type SshK8sEventsHandler = StandardToolHandler<K8sEventsTool>;

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
        let handler = SshK8sEventsHandler::new();
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
        let handler = SshK8sEventsHandler::new();
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
        let handler = SshK8sEventsHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_events");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_events");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "namespace": "default",
            "all_namespaces": true,
            "field_selector": "involvedObject.name=my-pod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.all_namespaces, Some(true));
        assert_eq!(
            args.field_selector,
            Some("involvedObject.name=my-pod".to_string())
        );
        assert_eq!(args.kubectl_bin, Some("kubectl".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshK8sEventsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.namespace.is_none());
        assert!(args.all_namespaces.is_none());
        assert!(args.field_selector.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sEventsHandler::new();
        let ctx = create_test_context();
        // host is the only required field; omit it entirely
        let result = handler
            .execute(Some(json!({"namespace": "default"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sEventsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("field_selector"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshK8sEventsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sEventsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sEventsHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
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
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: None,
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(!cmd.contains("-n "));
        assert!(!cmd.contains("-A"));
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: Some("kube-system".to_string()),
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-n 'kube-system'"));
    }

    #[test]
    fn test_build_command_all_namespaces() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: None,
            all_namespaces: Some(true),
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-A"));
    }

    #[test]
    fn test_build_command_with_field_selector() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: Some("default".to_string()),
            all_namespaces: None,
            field_selector: Some("involvedObject.name=my-pod".to_string()),
            output: None,
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("get events --sort-by=.lastTimestamp"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("--field-selector 'involvedObject.name=my-pod'"));
    }

    #[test]
    fn test_build_command_rejects_flag_like_namespace() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: Some("--all-namespaces".to_string()),
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let result = K8sEventsTool::build_command(&args, &host_config);
        assert!(
            result.is_err(),
            "expected rejection for flag-like namespace"
        );
    }

    #[test]
    fn test_build_command_with_label_selector() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: None,
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: Some("app=nginx".to_string()),
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("-l 'app=nginx'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_for_target() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: Some("default".to_string()),
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: Some("pod".to_string()),
            for_name: Some("my-pod".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("--for 'pod/my-pod'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_partial_for_target() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: None,
            all_namespaces: None,
            field_selector: None,
            output: None,
            label_selector: None,
            for_kind: Some("pod".to_string()),
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let result = K8sEventsTool::build_command(&args, &host_config);
        assert!(
            result.is_err(),
            "expected error when only for_kind provided"
        );
    }

    #[test]
    fn test_build_command_with_output_format() {
        let args = SshK8sEventsArgs {
            host: "server1".to_string(),
            namespace: None,
            all_namespaces: None,
            field_selector: None,
            output: Some("json".to_string()),
            label_selector: None,
            for_kind: None,
            for_name: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sEventsTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("-o 'json'"), "cmd: {cmd}");
    }
}
