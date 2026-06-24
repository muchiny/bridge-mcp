//! K8s RBAC Diagnose Tool Handler
//!
//! Composite SA diagnostic: prints identity, can-i list, and granting bindings.
//! Read-only.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_sa_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_rbac_diagnose` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sRbacDiagnoseArgs {
    host: String,
    service_account: String,
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

impl_common_args!(SshK8sRbacDiagnoseArgs);

/// Handler marker for the `ssh_k8s_rbac_diagnose` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_rbac_diagnose",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sRbacDiagnoseTool;

impl StandardTool for K8sRbacDiagnoseTool {
    type Args = SshK8sRbacDiagnoseArgs;
    const NAME: &'static str = "ssh_k8s_rbac_diagnose";
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;
    const DESCRIPTION: &'static str = "Composite RBAC diagnostic for a service account: \
        returns a JSON object with fields `serviceaccount` (SA identity string), \
        `can_i_list` (array of effective permissions from `kubectl auth can-i --list --as`), \
        and `granting_bindings` (array of `{namespace,kind,name,roleRefKind,roleRefName}` \
        objects for bindings that reference this SA). \
        Read-only. Use `namespace` to specify the SA's namespace (default: `default`). \
        Requires `jq` on the remote host.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "service_account": {
                "type": "string",
                "description": "Name of the service account to diagnose"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace of the service account (default: 'default')"
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file"
            }
        },
        "required": ["host", "service_account"]
    }"#;

    fn build_command(args: &SshK8sRbacDiagnoseArgs, _host_config: &HostConfig) -> Result<String> {
        validate_sa_name(&args.service_account)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_rbac_diagnose_command(
            args.kubectl_bin.as_deref(),
            &args.service_account,
            args.namespace.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_rbac_diagnose` tool.
pub type SshK8sRbacDiagnoseHandler = StandardToolHandler<K8sRbacDiagnoseTool>;

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
        let handler = SshK8sRbacDiagnoseHandler::new();
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
        let handler = SshK8sRbacDiagnoseHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "service_account": "my-sa"})),
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
        let handler = SshK8sRbacDiagnoseHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_rbac_diagnose");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_rbac_diagnose");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("service_account")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "service_account": "ci-deployer",
            "namespace": "ci",
            "context": "east",
            "kubectl_bin": "kubectl"
        });
        let args: SshK8sRbacDiagnoseArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "ci-deployer");
        assert_eq!(args.namespace, Some("ci".to_string()));
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "service_account": "default"});
        let args: SshK8sRbacDiagnoseArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service_account, "default");
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sRbacDiagnoseHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sRbacDiagnoseArgs = serde_json::from_value(json!({
            "host": "server1", "service_account": "default"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sRbacDiagnoseArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sRbacDiagnoseHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "service_account": "default"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_rbac_diagnose_basic() {
        let args = SshK8sRbacDiagnoseArgs {
            host: "s1".into(),
            service_account: "ci-deployer".into(),
            namespace: Some("ci".into()),
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sRbacDiagnoseTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("system:serviceaccount"), "cmd: {cmd}");
        assert!(cmd.contains("auth can-i --list"), "cmd: {cmd}");
        assert!(cmd.contains("rolebindings"), "cmd: {cmd}");
        assert!(cmd.contains("east"), "context: cmd: {cmd}");
        // Must have jq guard and emit a JSON object with the expected fields
        assert!(
            cmd.contains("command -v jq >/dev/null 2>&1"),
            "jq guard missing: cmd: {cmd}"
        );
        assert!(
            cmd.contains("\"serviceaccount\""),
            "serviceaccount field in JSON: cmd: {cmd}"
        );
        assert!(
            cmd.contains("\"can_i_list\""),
            "can_i_list field in JSON: cmd: {cmd}"
        );
        assert!(
            cmd.contains("\"granting_bindings\""),
            "granting_bindings field in JSON: cmd: {cmd}"
        );
        assert!(
            cmd.contains("jq -n"),
            "jq -n (JSON object assembly) stage missing: cmd: {cmd}"
        );
    }

    #[test]
    fn test_build_command_rbac_diagnose_default_namespace() {
        let args = SshK8sRbacDiagnoseArgs {
            host: "s1".into(),
            service_account: "my-sa".into(),
            namespace: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sRbacDiagnoseTool::build_command(&args, &test_host_config()).unwrap();
        assert!(
            cmd.contains("default"),
            "should have default namespace: cmd: {cmd}"
        );
        // JSON output must still be present
        assert!(cmd.contains("jq -n"), "JSON object stage: cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_sa_name() {
        let args = SshK8sRbacDiagnoseArgs {
            host: "s1".into(),
            service_account: "SA-UPPERCASE".into(), // invalid: uppercase
            namespace: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sRbacDiagnoseTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
