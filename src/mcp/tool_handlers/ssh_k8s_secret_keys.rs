//! K8s Secret Keys Tool Handler
//!
//! List key names and base64 lengths from a Kubernetes Secret without
//! ever revealing the values.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_secret_keys` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sSecretKeysArgs {
    host: String,
    name: String,
    #[serde(default)]
    namespace: Option<String>,
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

impl_common_args!(SshK8sSecretKeysArgs);

/// Handler marker for `ssh_k8s_secret_keys`.
#[mcp_standard_tool(
    name = "ssh_k8s_secret_keys",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sSecretKeysTool;

impl StandardTool for K8sSecretKeysTool {
    type Args = SshK8sSecretKeysArgs;
    const NAME: &'static str = "ssh_k8s_secret_keys";
    const DESCRIPTION: &'static str = "List the data keys and base64 lengths from a Kubernetes \
        Secret — NEVER reveals values. Output: one `key\\tbase64-length` line per entry. \
        The length is of the base64-encoded string (not decoded byte length). \
        Use `ssh_k8s_secret_decode` to decode a specific key (requires reveal=true).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "name": {"type": "string", "description": "Secret name to inspect"},
            "namespace": {"type": "string", "description": "Kubernetes namespace"},
            "context": {"type": "string", "description": "kubectl context for multi-cluster targeting"},
            "kubectl_bin": {"type": "string", "description": "Custom kubectl binary path"},
            "timeout_seconds": {"type": "integer", "description": "Command timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file"}
        },
        "required": ["host", "name"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshK8sSecretKeysArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_secret_keys_command(
            args.kubectl_bin.as_deref(),
            &args.name,
            args.namespace.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_secret_keys` tool.
pub type SshK8sSecretKeysHandler = StandardToolHandler<K8sSecretKeysTool>;

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
        let handler = SshK8sSecretKeysHandler::new();
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
        let handler = SshK8sSecretKeysHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "name": "my-secret"})),
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
        let handler = SshK8sSecretKeysHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_secret_keys");
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
            "name": "my-secret",
            "namespace": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sSecretKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "my-secret");
        assert_eq!(args.namespace.as_deref(), Some("prod"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "my-secret"});
        let args: SshK8sSecretKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.namespace.is_none());
        assert!(args.context.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sSecretKeysHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "name": "my-secret"});
        let args: SshK8sSecretKeysArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sSecretKeysArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sSecretKeysHandler::new();
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
    fn test_build_command_emits_go_template() {
        let args = SshK8sSecretKeysArgs {
            host: "s1".into(),
            name: "my-secret".into(),
            namespace: Some("prod".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sSecretKeysTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get secret"), "cmd: {cmd}");
        assert!(cmd.contains("my-secret"), "cmd: {cmd}");
        assert!(cmd.contains("go-template"), "must use go-template: {cmd}");
        // Must NOT contain base64 — no decode step
        assert!(!cmd.contains("base64"), "must not decode values: {cmd}");
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshK8sSecretKeysArgs {
            host: "s1".into(),
            name: "my-secret".into(),
            namespace: None,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sSecretKeysTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }
}
