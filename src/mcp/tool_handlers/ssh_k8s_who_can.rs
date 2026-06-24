//! K8s Who Can Tool Handler
//!
//! Reverse-scan RBAC bindings to find all principals that can perform
//! a verb on a resource. Read-only composite pipeline.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{KubernetesCommandBuilder, validate_rbac_token};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_who_can` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sWhoCanArgs {
    host: String,
    verb: String,
    resource: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: bool,
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

impl_common_args!(SshK8sWhoCanArgs);

/// Handler marker for the `ssh_k8s_who_can` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_who_can",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sWhoCanTool;

impl StandardTool for K8sWhoCanTool {
    type Args = SshK8sWhoCanArgs;
    const NAME: &'static str = "ssh_k8s_who_can";
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;
    const DESCRIPTION: &'static str = "Reverse-scan all RBAC RoleBindings and ClusterRoleBindings \
        to find every principal (user, group, or service account) that can perform `<verb>` on \
        `<resource>`. Read-only; outputs a JSON array of objects with fields \
        `namespace`, `kind`, `name`, `roleRefKind`, `roleRefName`. \
        Useful for auditing blast radius before granting access or identifying over-privileged \
        principals. Use `all_namespaces=true` to scan the whole cluster. \
        Heuristic (grep over RBAC rules) — may over-report; use `ssh_k8s_auth_can_i` for an \
        authoritative yes/no.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "verb": {
                "type": "string",
                "description": "The verb to check (e.g. 'get', 'create', 'delete', '*')"
            },
            "resource": {
                "type": "string",
                "description": "The resource type to check (e.g. 'pods', 'secrets', '*')"
            },
            "namespace": {
                "type": "string",
                "description": "Scope the scan to a single namespace"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "Scan all namespaces (overrides namespace)",
                "default": false
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
        "required": ["host", "verb", "resource"]
    }"#;

    fn build_command(args: &SshK8sWhoCanArgs, _host_config: &HostConfig) -> Result<String> {
        validate_rbac_token(&args.verb)?;
        validate_rbac_token(&args.resource)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        Ok(KubernetesCommandBuilder::build_who_can_command(
            args.kubectl_bin.as_deref(),
            &args.verb,
            &args.resource,
            args.namespace.as_deref(),
            args.all_namespaces,
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_who_can` tool.
pub type SshK8sWhoCanHandler = StandardToolHandler<K8sWhoCanTool>;

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
        let handler = SshK8sWhoCanHandler::new();
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
        let handler = SshK8sWhoCanHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "verb": "get", "resource": "pods"})),
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
        let handler = SshK8sWhoCanHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_who_can");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_who_can");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("verb")));
        assert!(required.contains(&json!("resource")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "verb": "get",
            "resource": "pods",
            "namespace": "prod",
            "all_namespaces": false,
            "context": "east",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60
        });
        let args: SshK8sWhoCanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.verb, "get");
        assert_eq!(args.resource, "pods");
        assert_eq!(args.namespace, Some("prod".to_string()));
        assert!(!args.all_namespaces);
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "verb": "create", "resource": "secrets"});
        let args: SshK8sWhoCanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.verb, "create");
        assert_eq!(args.resource, "secrets");
        assert!(args.namespace.is_none());
        assert!(!args.all_namespaces);
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sWhoCanHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("context"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sWhoCanArgs = serde_json::from_value(json!({
            "host": "server1", "verb": "get", "resource": "pods"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sWhoCanArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sWhoCanHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "verb": "get", "resource": "pods"})),
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
    fn test_build_command_who_can_basic() {
        let args = SshK8sWhoCanArgs {
            host: "s1".into(),
            verb: "get".into(),
            resource: "pods".into(),
            namespace: Some("prod".into()),
            all_namespaces: false,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sWhoCanTool::build_command(&args, &test_host_config()).unwrap();
        // Should contain key elements of the composite pipeline
        assert!(cmd.contains("rolebindings"), "cmd: {cmd}");
        assert!(cmd.contains("clusterrolebindings"), "cmd: {cmd}");
        assert!(cmd.contains("get"), "cmd: {cmd}");
        // Must have jq guard and emit JSON array via jq -s
        assert!(
            cmd.contains("command -v jq >/dev/null 2>&1"),
            "jq guard missing: cmd: {cmd}"
        );
        assert!(
            cmd.contains("jq -s '.'"),
            "JSON array stage missing: cmd: {cmd}"
        );
        // Must include JSON field names in the awk stage (backslash-escaped inside raw string)
        assert!(cmd.contains("namespace"), "namespace field: cmd: {cmd}");
        assert!(cmd.contains("roleRefKind"), "roleRefKind field: cmd: {cmd}");
    }

    #[test]
    fn test_build_command_who_can_all_namespaces() {
        let args = SshK8sWhoCanArgs {
            host: "s1".into(),
            verb: "delete".into(),
            resource: "secrets".into(),
            namespace: None,
            all_namespaces: true,
            context: Some("east".into()),
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sWhoCanTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-A"), "all_namespaces flag: cmd: {cmd}");
        assert!(cmd.contains("east"), "context: cmd: {cmd}");
        // JSON output stage must still be present
        assert!(cmd.contains("jq -s '.'"), "JSON stage: cmd: {cmd}");
    }

    #[test]
    fn test_description_has_heuristic_caveat() {
        let handler = SshK8sWhoCanHandler::new();
        let desc = handler.description();
        assert!(
            desc.contains("Heuristic") || desc.contains("heuristic"),
            "description must warn about heuristic nature: {desc}"
        );
        assert!(
            desc.contains("ssh_k8s_auth_can_i"),
            "description must reference authoritative tool: {desc}"
        );
    }

    #[test]
    fn test_build_command_invalid_verb() {
        let args = SshK8sWhoCanArgs {
            host: "s1".into(),
            verb: "get; rm -rf /".into(), // shell injection attempt
            resource: "pods".into(),
            namespace: None,
            all_namespaces: false,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sWhoCanTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
