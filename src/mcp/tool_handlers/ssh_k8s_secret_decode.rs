//! K8s Secret Decode Tool Handler
//!
//! REVEAL-GATED: decodes a single base64 Secret value via `kubectl get secret
//! -o jsonpath | base64 -d`. The `reveal` parameter must be explicitly `true`
//! or the tool returns a `CommandDenied` error without building any command.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_secret_decode` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sSecretDecodeArgs {
    host: String,
    name: String,
    key: String,
    /// Must be `true` to decode and return plaintext. When `false` (default),
    /// the tool refuses with a guidance message before building any command.
    #[serde(default)]
    reveal: bool,
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

impl_common_args!(SshK8sSecretDecodeArgs);

/// Handler marker for `ssh_k8s_secret_decode`.
#[mcp_standard_tool(
    name = "ssh_k8s_secret_decode",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sSecretDecodeTool;

impl StandardTool for K8sSecretDecodeTool {
    type Args = SshK8sSecretDecodeArgs;
    const NAME: &'static str = "ssh_k8s_secret_decode";
    const DESCRIPTION: &'static str = "REVEAL-GATED: Decode a single base64 Secret value via \
        `kubectl get secret -o jsonpath | base64 -d`. \
        Set `reveal=true` to return plaintext — omitting it or passing false returns a \
        guidance error without executing any command. One key only (never a dump-all path). \
        Recommend `save_output=/path` so the decoded value lands in a file rather than the \
        transcript. Use `ssh_k8s_secret_keys` to list keys without revealing values.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "name": {"type": "string", "description": "Secret name"},
            "key": {"type": "string", "description": "Single data key to decode (one key only)"},
            "reveal": {"type": "boolean", "description": "Must be true to return plaintext; false (default) refuses with guidance"},
            "namespace": {"type": "string", "description": "Kubernetes namespace"},
            "context": {"type": "string", "description": "kubectl context for multi-cluster targeting"},
            "kubectl_bin": {"type": "string", "description": "Custom kubectl binary path"},
            "timeout_seconds": {"type": "integer", "description": "Command timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters", "minimum": 0},
            "save_output": {"type": "string", "description": "Save decoded output to a file (recommended for sensitive values)"}
        },
        "required": ["host", "name", "key"]
    }"#;

    // OutputKind: RawText (decoded plaintext, no structured reduction)
    // Trait default is RawText so no const needed.

    fn build_command(args: &SshK8sSecretDecodeArgs, _host_config: &HostConfig) -> Result<String> {
        // REVEAL GATE: refuse before building any command unless explicitly opted in
        if !args.reveal {
            return Err(BridgeError::CommandDenied {
                reason: "set reveal=true to decode plaintext; \
                    use ssh_k8s_secret_keys to list keys without revealing values"
                    .to_string(),
            });
        }

        KubernetesCommandBuilder::build_secret_decode_command(
            args.kubectl_bin.as_deref(),
            &args.name,
            &args.key,
            args.namespace.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_secret_decode` tool.
pub type SshK8sSecretDecodeHandler = StandardToolHandler<K8sSecretDecodeTool>;

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
        let handler = SshK8sSecretDecodeHandler::new();
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
        let handler = SshK8sSecretDecodeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "name": "my-secret", "key": "api_key", "reveal": true})),
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
        let handler = SshK8sSecretDecodeHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_secret_decode");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("name")));
        assert!(required.contains(&json!("key")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "my-secret",
            "key": "api_key",
            "reveal": true,
            "namespace": "prod"
        });
        let args: SshK8sSecretDecodeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "my-secret");
        assert_eq!(args.key, "api_key");
        assert!(args.reveal);
        assert_eq!(args.namespace.as_deref(), Some("prod"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "my-secret", "key": "api_key"});
        let args: SshK8sSecretDecodeArgs = serde_json::from_value(json).unwrap();
        assert!(!args.reveal); // defaults false
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sSecretDecodeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("reveal"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "name": "my-secret", "key": "api_key"});
        let args: SshK8sSecretDecodeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sSecretDecodeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sSecretDecodeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "name": 456, "key": 789})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    /// REVEAL GATE: reveal=false (default) must refuse BEFORE building any command.
    #[test]
    fn test_reveal_gate_default_redacts() {
        let args = SshK8sSecretDecodeArgs {
            host: "s1".into(),
            name: "my-secret".into(),
            key: "api_key".into(),
            reveal: false,
            namespace: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sSecretDecodeTool::build_command(&args, &test_host_config());
        assert!(result.is_err(), "reveal=false must return an error");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(
                    reason.contains("reveal=true"),
                    "error must mention reveal=true: {reason}"
                );
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_reveal_true() {
        let args = SshK8sSecretDecodeArgs {
            host: "s1".into(),
            name: "my-secret".into(),
            key: "api-key".into(),
            reveal: true,
            namespace: Some("prod".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sSecretDecodeTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("get secret"), "cmd: {cmd}");
        assert!(cmd.contains("jsonpath"), "cmd: {cmd}");
        assert!(cmd.contains("base64 -d"), "cmd: {cmd}");
        assert!(cmd.contains("api-key"), "cmd: {cmd}");
    }
}
