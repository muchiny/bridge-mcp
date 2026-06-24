//! K8s Create `ConfigMap` Tool Handler

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_create_configmap` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sCreateConfigmapArgs {
    host: String,
    name: String,
    #[serde(default)]
    from_literal: std::collections::HashMap<String, String>,
    #[serde(default)]
    from_file: Vec<String>,
    #[serde(default)]
    from_env_file: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    dry_run: Option<String>,
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

impl_common_args!(SshK8sCreateConfigmapArgs);

/// Handler marker for `ssh_k8s_create_configmap`.
#[mcp_standard_tool(
    name = "ssh_k8s_create_configmap",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct K8sCreateConfigmapTool;

impl StandardTool for K8sCreateConfigmapTool {
    type Args = SshK8sCreateConfigmapArgs;
    const NAME: &'static str = "ssh_k8s_create_configmap";
    const DESCRIPTION: &'static str = "Create a Kubernetes ConfigMap via `kubectl create configmap`. \
        Supports from_literal (key→value map), from_file (file paths on host), and \
        from_env_file (KEY=VALUE env file path). At least one source is required. \
        Not idempotent (errors AlreadyExists on re-run; use dry_run=client to preflight).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "name": {"type": "string", "description": "ConfigMap name (DNS-1123 subdomain)"},
            "from_literal": {"type": "object", "description": "Key-value pairs for configmap (non-secret config data)", "additionalProperties": {"type": "string"}},
            "from_file": {"type": "array", "items": {"type": "string"}, "description": "File paths on host: 'key=/path' or '/path'"},
            "from_env_file": {"type": "string", "description": "Path to KEY=VALUE env file on host"},
            "namespace": {"type": "string", "description": "Kubernetes namespace"},
            "dry_run": {"type": "string", "description": "Dry-run mode: 'client', 'server', or 'none'"},
            "context": {"type": "string", "description": "kubectl context for multi-cluster targeting"},
            "kubectl_bin": {"type": "string", "description": "Custom kubectl binary path"},
            "timeout_seconds": {"type": "integer", "description": "Command timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the bridge host"}
        },
        "required": ["host", "name"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(
        args: &SshK8sCreateConfigmapArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        let from_literal_pairs: Vec<(String, String)> = args
            .from_literal
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        KubernetesCommandBuilder::build_create_configmap_command(
            args.kubectl_bin.as_deref(),
            &args.name,
            &from_literal_pairs,
            &args.from_file,
            args.from_env_file.as_deref(),
            args.namespace.as_deref(),
            args.dry_run.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_create_configmap` tool.
pub type SshK8sCreateConfigmapHandler = StandardToolHandler<K8sCreateConfigmapTool>;

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
        let handler = SshK8sCreateConfigmapHandler::new();
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
        let handler = SshK8sCreateConfigmapHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(
                    json!({"host": "nonexistent", "name": "my-config", "from_literal": {"k": "v"}}),
                ),
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
        let handler = SshK8sCreateConfigmapHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_create_configmap");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "my-config",
            "from_literal": {"key1": "val1"},
            "namespace": "default",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sCreateConfigmapArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "my-config");
        assert_eq!(
            args.from_literal.get("key1").map(String::as_str),
            Some("val1")
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "my-config"});
        let args: SshK8sCreateConfigmapArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.from_literal.is_empty());
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sCreateConfigmapHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("from_literal"));
        assert!(properties.contains_key("from_file"));
        assert!(properties.contains_key("from_env_file"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "name": "my-config"});
        let args: SshK8sCreateConfigmapArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sCreateConfigmapArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sCreateConfigmapHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "name": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_from_literal() {
        let mut from_literal = std::collections::HashMap::new();
        from_literal.insert("key1".to_string(), "value1".to_string());
        let args = SshK8sCreateConfigmapArgs {
            host: "s1".into(),
            name: "my-config".into(),
            from_literal,
            from_file: vec![],
            from_env_file: None,
            namespace: Some("default".into()),
            dry_run: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sCreateConfigmapTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create configmap"), "cmd: {cmd}");
        assert!(cmd.contains("my-config"), "cmd: {cmd}");
        assert!(cmd.contains("--from-literal="), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_empty_sources() {
        let args = SshK8sCreateConfigmapArgs {
            host: "s1".into(),
            name: "my-config".into(),
            from_literal: std::collections::HashMap::new(),
            from_file: vec![],
            from_env_file: None,
            namespace: None,
            dry_run: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sCreateConfigmapTool::build_command(&args, &test_host_config());
        assert!(result.is_err(), "empty sources must be rejected");
    }
}
