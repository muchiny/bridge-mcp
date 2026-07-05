//! SSH Kubernetes Top Tool Handler
//!
//! Displays resource usage (CPU/memory) of pods or nodes via `kubectl` top on a remote host.
//! Requires metrics-server. Auto-detects `kubectl` binary (k8s, k3s, microk8s).

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
pub struct SshK8sTopArgs {
    host: String,
    resource_type: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
    #[serde(default)]
    sort_by: Option<String>,
    #[serde(default)]
    containers: Option<bool>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sTopArgs);

#[mcp_standard_tool(name = "ssh_k8s_top", group = "kubernetes", annotation = "read_only")]
pub struct K8sTopTool;

impl StandardTool for K8sTopTool {
    type Args = SshK8sTopArgs;

    const NAME: &'static str = "ssh_k8s_top";

    const DESCRIPTION: &'static str = "Display real-time CPU and memory usage of pods or nodes via kubectl top on a remote \
        host. Requires metrics-server to be installed in the cluster. Set resource_type to \
        'pods' or 'nodes'. Sort by 'cpu' or 'memory' to find resource-intensive workloads. \
        For host-level metrics (outside k8s), use ssh_metrics instead. Auto-detects kubectl \
        binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "resource_type": {
                "type": "string",
                "enum": ["pods", "nodes"],
                "description": "Resource type to show metrics for"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (for pods only)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "Show pods across all namespaces (-A flag, for pods only)"
            },
            "sort_by": {
                "type": "string",
                "enum": ["cpu", "memory"],
                "description": "Sort output by CPU or memory usage"
            },
            "containers": {
                "type": "boolean",
                "description": "Show container-level metrics (for pods only)"
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
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            }
        },
        "required": ["host", "resource_type"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sTopArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(KubernetesCommandBuilder::build_top_command(
            args.kubectl_bin.as_deref(),
            &args.resource_type,
            args.namespace.as_deref(),
            args.all_namespaces.unwrap_or(false),
            args.sort_by.as_deref(),
            args.containers.unwrap_or(false),
        ))
    }

    fn validate(args: &SshK8sTopArgs, _host_config: &HostConfig) -> Result<()> {
        KubernetesCommandBuilder::validate_top_resource(&args.resource_type)?;
        Ok(())
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshK8sTopArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let title = if args.resource_type == "nodes" {
            "Node Metrics"
        } else {
            "Pod Metrics"
        };
        let mut tbl = table(title);

        // Dynamic columns from parsed headers
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

        let mut refresh_args = json!({"host": &args.host, "resource_type": &args.resource_type});
        if let Some(ns) = &args.namespace {
            refresh_args["namespace"] = json!(ns);
        }
        tbl = tbl.action("refresh", "Refresh", "ssh_k8s_top", Some(refresh_args));
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_k8s_top` tool.
pub type SshK8sTopHandler = StandardToolHandler<K8sTopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
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
        let handler = SshK8sTopHandler::new();
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
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "resource_type": "pods"
                })),
                &ctx,
            )
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
        let handler = SshK8sTopHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_top");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_top");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource_type")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource_type": "pods",
            "namespace": "production",
            "sort_by": "cpu",
            "containers": true,
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 30,
            "max_output": 10000
        });

        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource_type, "pods");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.sort_by, Some("cpu".to_string()));
        assert_eq!(args.containers, Some(true));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "resource_type": "nodes"
        });

        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource_type, "nodes");
        assert!(args.namespace.is_none());
        assert!(args.sort_by.is_none());
        assert!(args.containers.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();

        // Missing resource_type field
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_resource_type() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "resource_type": "deployments"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sTopHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("sort_by"));
        assert!(properties.contains_key("containers"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource_type": "pods"});
        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sTopArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(Some(json!({"host": 123, "resource_type": "pods"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    #[test]
    fn test_build_command_pods() {
        let args = SshK8sTopArgs {
            host: "server1".to_string(),
            resource_type: "pods".to_string(),
            namespace: None,
            all_namespaces: None,
            sort_by: None,
            containers: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sTopTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl top 'pods'");
    }

    #[test]
    fn test_build_command_nodes() {
        let args = SshK8sTopArgs {
            host: "server1".to_string(),
            resource_type: "nodes".to_string(),
            namespace: None,
            all_namespaces: None,
            sort_by: Some("cpu".to_string()),
            containers: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sTopTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("kubectl top 'nodes'"));
        assert!(cmd.contains("--sort-by='cpu'"));
    }

    #[test]
    fn test_build_command_all_namespaces_flag() {
        // Regression: ssh_k8s_top didn't expose -A / --all-namespaces; users
        // had to fall back to ssh_exec. Now supported.
        let args = SshK8sTopArgs {
            host: "server1".to_string(),
            resource_type: "pods".to_string(),
            namespace: None,
            all_namespaces: Some(true),
            sort_by: None,
            containers: None,
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sTopTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "kubectl top 'pods' -A");
    }

    #[test]
    fn test_build_command_with_namespace() {
        let args = SshK8sTopArgs {
            host: "server1".to_string(),
            resource_type: "pods".to_string(),
            namespace: Some("production".to_string()),
            all_namespaces: None,
            sort_by: Some("memory".to_string()),
            containers: Some(true),
            kubectl_bin: Some("kubectl".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let host_config = test_host_config();
        let cmd = K8sTopTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--sort-by='memory'"));
        assert!(cmd.contains("--containers"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshK8sTopArgs =
            serde_json::from_value(json!({"host": "server1", "resource_type": "nodes"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "NAME    CPU(cores)   MEMORY(bytes)\n\
                      node1   100m         200Mi\n\
                      node2   250m         512Mi";
        let result = K8sTopTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshK8sTopArgs =
            serde_json::from_value(json!({"host": "server1", "resource_type": "nodes"})).unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = K8sTopTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }
}
