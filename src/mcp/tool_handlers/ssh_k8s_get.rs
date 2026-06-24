//! SSH Kubernetes Get Tool Handler
//!
//! Lists or gets Kubernetes resources via `kubectl` on a remote host.
//! Supports filtering by namespace, labels, field selectors, and output formats.
//! Auto-detects kubectl binary (k8s, k3s, `microk8s`).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshK8sGetArgs {
    host: String,
    resource: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
    #[serde(default)]
    label_selector: Option<String>,
    #[serde(default)]
    field_selector: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    sort_by: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK8sGetArgs);

#[mcp_standard_tool(name = "ssh_k8s_get", group = "kubernetes", annotation = "read_only")]
pub struct K8sGetTool;

impl StandardTool for K8sGetTool {
    type Args = SshK8sGetArgs;

    const NAME: &'static str = "ssh_k8s_get";

    const DESCRIPTION: &'static str = "List or get Kubernetes resources via kubectl on a remote host. Start here to discover \
        resource names and status before using ssh_k8s_describe (detailed prose), \
        ssh_k8s_logs (pod logs), ssh_k8s_exec (run command in pod), or ssh_k8s_delete. \
        Use output='json' or 'yaml' for structured data filterable with jq_filter. Use \
        all_namespaces=true to search cluster-wide. Auto-detects kubectl binary (k8s, k3s, \
        microk8s). Returns kubectl text output.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "resource": {
                "type": "string",
                "description": "Kubernetes resource type (e.g., pods, deployments, services, nodes, configmaps)"
            },
            "name": {
                "type": "string",
                "description": "Specific resource name to get (omit to list all)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "List resources across all namespaces (-A flag)"
            },
            "label_selector": {
                "type": "string",
                "description": "Filter by label selector (e.g., app=nginx, tier in (frontend,backend))"
            },
            "field_selector": {
                "type": "string",
                "description": "Filter by field selector (e.g., status.phase=Running)"
            },
            "output": {
                "type": "string",
                "description": "Output format: wide, json, yaml, name, jsonpath=..., custom-columns=..."
            },
            "sort_by": {
                "type": "string",
                "description": "Sort output by JSONPath expression (e.g., .metadata.creationTimestamp)"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl, k3s kubectl, microk8s kubectl)"
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
        "required": ["host", "resource"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sGetArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_get_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            args.name.as_deref(),
            args.namespace.as_deref(),
            args.all_namespaces.unwrap_or(false),
            args.label_selector.as_deref(),
            args.field_selector.as_deref(),
            args.output.as_deref(),
            args.sort_by.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshK8sGetArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table(format!("Kubernetes {}", args.resource));
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let mut row_map = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                row_map.insert(h.clone(), json!(row.get(i).map_or("", String::as_str)));
            }
            tbl = tbl.row(Value::Object(row_map));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_k8s_get",
            Some(json!({"host": args.host, "resource": args.resource})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_k8s_get` tool.
pub type SshK8sGetHandler = StandardToolHandler<K8sGetTool>;

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
        let handler = SshK8sGetHandler::new();
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
        let handler = SshK8sGetHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "resource": "pods"})),
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
        let handler = SshK8sGetHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_get");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_get");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "pods",
            "name": "my-pod",
            "namespace": "default",
            "all_namespaces": true,
            "label_selector": "app=nginx",
            "field_selector": "status.phase=Running",
            "output": "json",
            "sort_by": ".metadata.creationTimestamp",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshK8sGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "pods");
        assert_eq!(args.name, Some("my-pod".to_string()));
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.all_namespaces, Some(true));
        assert_eq!(args.label_selector, Some("app=nginx".to_string()));
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "resource": "deployments"});
        let args: SshK8sGetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "deployments");
        assert!(args.name.is_none());
        assert!(args.namespace.is_none());
        assert!(args.all_namespaces.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sGetHandler::new();
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
        let handler = SshK8sGetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("label_selector"));
        assert!(properties.contains_key("field_selector"));
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("sort_by"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "pods"});
        let args: SshK8sGetArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sGetArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sGetHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(Some(json!({"host": 123, "resource": "pods"})), &ctx)
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
        let args = SshK8sGetArgs {
            host: "server1".to_string(),
            resource: "pods".to_string(),
            name: None,
            namespace: None,
            all_namespaces: None,
            label_selector: None,
            field_selector: None,
            output: None,
            sort_by: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sGetTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl get 'pods'");
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sGetArgs {
            host: "server1".to_string(),
            resource: "deployments".to_string(),
            name: Some("my-app".to_string()),
            namespace: Some("production".to_string()),
            all_namespaces: None,
            label_selector: None,
            field_selector: None,
            output: None,
            sort_by: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sGetTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("kubectl get"));
        assert!(cmd.contains("'my-app'"));
        assert!(cmd.contains("-n 'production'"));
    }

    #[test]
    fn test_build_command_all_namespaces_labels() {
        let args = SshK8sGetArgs {
            host: "server1".to_string(),
            resource: "pods".to_string(),
            name: None,
            namespace: None,
            all_namespaces: Some(true),
            label_selector: Some("app=nginx".to_string()),
            field_selector: None,
            output: None,
            sort_by: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sGetTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("-A"));
        assert!(cmd.contains("-l 'app=nginx'"));
    }

    #[test]
    fn test_build_command_all_options() {
        let args = SshK8sGetArgs {
            host: "server1".to_string(),
            resource: "services".to_string(),
            name: Some("my-svc".to_string()),
            namespace: Some("default".to_string()),
            all_namespaces: Some(false),
            label_selector: Some("tier=frontend".to_string()),
            field_selector: Some("status.phase=Running".to_string()),
            output: Some("json".to_string()),
            sort_by: Some(".metadata.creationTimestamp".to_string()),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sGetTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.starts_with("kubectl get"));
        assert!(cmd.contains("'my-svc'"));
        assert!(cmd.contains("-n 'default'"));
        assert!(cmd.contains("-l 'tier=frontend'"));
        assert!(cmd.contains("--field-selector 'status.phase=Running'"));
        assert!(cmd.contains("-o 'json'"));
        assert!(cmd.contains("--sort-by='"));
    }

    #[test]
    fn test_build_command_rejects_flag_like_namespace() {
        // Regression: namespace=--all-namespaces was accepted as a literal
        // namespace name, producing "No resources found" silently. The handler
        // must now reject it via validate_namespace before reaching kubectl.
        let args = SshK8sGetArgs {
            host: "server1".to_string(),
            resource: "pods".to_string(),
            name: None,
            namespace: Some("--all-namespaces".to_string()),
            all_namespaces: None,
            label_selector: None,
            field_selector: None,
            output: None,
            sort_by: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let result = K8sGetTool::build_command(&args, &host_config);
        assert!(
            result.is_err(),
            "expected rejection for flag-like namespace"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshK8sGetHandler::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token for server1
        assert!(ctx.rate_limiter.check("server1").is_ok());

        // Use explicit kubectl_bin to avoid auto-detect prefix with &>/dev/null
        // which triggers the blacklist pattern (?i)>\s*/dev/
        let result = handler
            .execute(
                Some(json!({"host": "server1", "resource": "pods", "kubectl_bin": "kubectl"})),
                &ctx,
            )
            .await;

        // Rate limit returns Ok with error content, not Err
        let result = result.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Rate limit exceeded"));
                assert!(text.contains("server1"));
            }
            _ => panic!("Expected Text content"),
        }
    }
}
