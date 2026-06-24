//! K8s Create Secret Tool Handler
//!
//! Create a Kubernetes Secret (generic/Opaque, tls, or docker-registry) via
//! `kubectl create secret`. Secret VALUES are stored as [`RedactedSecret`] so
//! they never appear in `Debug` output or audit logs.

use serde::Deserialize;

use crate::config::{HostConfig, RedactedSecret};
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// A key-value pair where the value is a redacted secret.
///
/// Used for `--from-literal` entries in `ssh_k8s_create_secret`: the key is
/// safe to log but the value must never appear in `Debug`, audit logs, or
/// error messages.
#[derive(Debug, Deserialize)]
pub struct SecretLiteralEntry {
    key: String,
    /// SECURITY: the value is a `RedactedSecret` so that `#[derive(Debug)]`
    /// on the containing struct does NOT print the plaintext. The single
    /// audited plaintext boundary is `value.as_str()` inside `build_command`.
    value: RedactedSecret,
}

/// Arguments for the `ssh_k8s_create_secret` tool.
///
/// Note: `from_literal` uses `Vec<SecretLiteralEntry>` (not a bare
/// `HashMap<String, String>`) so that secret values are wrapped in
/// `RedactedSecret` and are structurally incapable of leaking through
/// `format!("{args:?}")`.
#[derive(Debug, Deserialize)]
pub struct SshK8sCreateSecretArgs {
    host: String,
    name: String,
    #[serde(default)]
    secret_type: Option<String>,
    /// Secret key→value pairs. Values are redacted in Debug.
    #[serde(default)]
    from_literal: Vec<SecretLiteralEntry>,
    #[serde(default)]
    from_file: Vec<String>,
    #[serde(default)]
    from_env_file: Option<String>,
    #[serde(default)]
    tls_cert: Option<String>,
    #[serde(default)]
    tls_key: Option<String>,
    #[serde(default)]
    docker_server: Option<String>,
    #[serde(default)]
    docker_username: Option<String>,
    /// Docker registry password. Stored as `RedactedSecret` so it is never
    /// visible in `Debug` output or audit logs.
    #[serde(default)]
    docker_password: Option<RedactedSecret>,
    #[serde(default)]
    docker_email: Option<String>,
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

impl_common_args!(SshK8sCreateSecretArgs);

/// Handler marker for `ssh_k8s_create_secret`.
#[mcp_standard_tool(
    name = "ssh_k8s_create_secret",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct K8sCreateSecretTool;

impl StandardTool for K8sCreateSecretTool {
    type Args = SshK8sCreateSecretArgs;
    const NAME: &'static str = "ssh_k8s_create_secret";
    const DESCRIPTION: &'static str = "Create a Kubernetes Secret via `kubectl create secret`. \
        Supports `generic`/`Opaque` (from_literal, from_file, from_env_file), `tls` \
        (tls_cert + tls_key paths on host), and `docker-registry` types. \
        Secret VALUES are never logged — they appear in the host process argv \
        (air-gapped acceptable); prefer from_file/from_env_file for higher \
        sensitivity. Use `dry_run=client` to preflight. Not idempotent (errors \
        AlreadyExists on re-run).";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "name": {"type": "string", "description": "Secret name (DNS-1123 subdomain)"},
            "secret_type": {"type": "string", "description": "Secret type: 'Opaque'/'generic' (default), 'tls', or 'docker-registry'"},
            "from_literal": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "value": {"type": "string"}
                    },
                    "required": ["key", "value"]
                },
                "description": "Key-value pairs for generic secret (values are secret, never logged)"
            },
            "from_file": {"type": "array", "items": {"type": "string"}, "description": "File paths on host: 'key=/path' or '/path'"},
            "from_env_file": {"type": "string", "description": "Path to KEY=VALUE env file on host (contents treated as secret)"},
            "tls_cert": {"type": "string", "description": "Path to PEM cert on host (required for tls type)"},
            "tls_key": {"type": "string", "description": "Path to PEM private key on host (required for tls type)"},
            "docker_server": {"type": "string", "description": "Registry URL (required for docker-registry type)"},
            "docker_username": {"type": "string", "description": "Registry username (required for docker-registry type)"},
            "docker_password": {"type": "string", "description": "Registry password (required for docker-registry type; never logged)"},
            "docker_email": {"type": "string", "description": "Registry email (optional, docker-registry only)"},
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

    fn build_command(args: &SshK8sCreateSecretArgs, _host_config: &HostConfig) -> Result<String> {
        let secret_type = args.secret_type.as_deref().unwrap_or("generic");

        // Convert from_literal: extract plaintext at the single audited boundary
        let from_literal_pairs: Vec<(String, String)> = args
            .from_literal
            .iter()
            .map(|e| (e.key.clone(), e.value.as_str().to_owned()))
            .collect();

        KubernetesCommandBuilder::build_create_secret_command(
            args.kubectl_bin.as_deref(),
            &args.name,
            secret_type,
            &from_literal_pairs,
            &args.from_file,
            args.from_env_file.as_deref(),
            args.tls_cert.as_deref(),
            args.tls_key.as_deref(),
            args.docker_server.as_deref(),
            args.docker_username.as_deref(),
            args.docker_password.as_ref().map(RedactedSecret::as_str),
            args.docker_email.as_deref(),
            args.namespace.as_deref(),
            args.dry_run.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_create_secret` tool.
pub type SshK8sCreateSecretHandler = StandardToolHandler<K8sCreateSecretTool>;

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
        let handler = SshK8sCreateSecretHandler::new();
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
        let handler = SshK8sCreateSecretHandler::new();
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
        let handler = SshK8sCreateSecretHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_create_secret");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_create_secret");
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
            "secret_type": "generic",
            "from_literal": [{"key": "api_key", "value": "s3cr3t"}],
            "namespace": "default",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 30
        });
        let args: SshK8sCreateSecretArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "my-secret");
        assert_eq!(args.secret_type.as_deref(), Some("generic"));
        assert_eq!(args.from_literal.len(), 1);
        assert_eq!(args.from_literal[0].key, "api_key");
        // value accessible via as_str() — never via Debug
        assert_eq!(args.from_literal[0].value.as_str(), "s3cr3t");
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "my-secret"});
        let args: SshK8sCreateSecretArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "my-secret");
        assert!(args.secret_type.is_none());
        assert!(args.from_literal.is_empty());
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sCreateSecretHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("secret_type"));
        assert!(properties.contains_key("from_literal"));
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("save_output"));
    }

    /// SECURITY: secret values stored as `RedactedSecret` must NOT appear in
    /// `Debug` output of the `Args` struct.
    #[test]
    fn test_args_debug_does_not_leak_secret_values() {
        let args = SshK8sCreateSecretArgs {
            host: "myhost".to_string(),
            name: "my-secret".to_string(),
            secret_type: Some("generic".to_string()),
            from_literal: vec![SecretLiteralEntry {
                key: "password".to_string(),
                value: RedactedSecret::from("hunter2-super-secret"),
            }],
            from_file: vec![],
            from_env_file: None,
            tls_cert: None,
            tls_key: None,
            docker_server: None,
            docker_username: None,
            docker_password: Some(RedactedSecret::from("docker-pw-secret")),
            docker_email: None,
            namespace: None,
            dry_run: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let debug_str = format!("{args:?}");
        assert!(
            !debug_str.contains("hunter2-super-secret"),
            "secret value leaked in Debug: {debug_str}"
        );
        assert!(
            !debug_str.contains("docker-pw-secret"),
            "docker_password leaked in Debug: {debug_str}"
        );
        assert!(
            debug_str.contains("[REDACTED]"),
            "expected [REDACTED] in: {debug_str}"
        );
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "name": "my-secret"});
        let args: SshK8sCreateSecretArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sCreateSecretArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sCreateSecretHandler::new();
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
    fn test_build_command_generic_secret() {
        let args = SshK8sCreateSecretArgs {
            host: "s1".into(),
            name: "my-secret".into(),
            secret_type: Some("generic".into()),
            from_literal: vec![SecretLiteralEntry {
                key: "api_key".to_string(),
                value: RedactedSecret::from("s3cr3t"),
            }],
            from_file: vec![],
            from_env_file: None,
            tls_cert: None,
            tls_key: None,
            docker_server: None,
            docker_username: None,
            docker_password: None,
            docker_email: None,
            namespace: Some("default".into()),
            dry_run: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sCreateSecretTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create secret generic"), "cmd: {cmd}");
        assert!(cmd.contains("my-secret"), "cmd: {cmd}");
        assert!(cmd.contains("--from-literal="), "cmd: {cmd}");
        assert!(cmd.contains("-n 'default'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_tls_secret() {
        let args = SshK8sCreateSecretArgs {
            host: "s1".into(),
            name: "tls-secret".into(),
            secret_type: Some("tls".into()),
            from_literal: vec![],
            from_file: vec![],
            from_env_file: None,
            tls_cert: Some("/etc/certs/tls.crt".into()),
            tls_key: Some("/etc/certs/tls.key".into()),
            docker_server: None,
            docker_username: None,
            docker_password: None,
            docker_email: None,
            namespace: None,
            dry_run: None,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sCreateSecretTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create secret tls"), "cmd: {cmd}");
        assert!(cmd.contains("--cert="), "cmd: {cmd}");
        assert!(cmd.contains("--key="), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }
}
