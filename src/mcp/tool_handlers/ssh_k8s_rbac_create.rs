//! K8s RBAC Create Tool Handler
//!
//! Create Kubernetes RBAC resources (Role, ClusterRole, RoleBinding,
//! ClusterRoleBinding, ServiceAccount) via `kubectl create`. Mutating.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{
    KubernetesCommandBuilder, validate_rbac_kind, validate_sa_name,
};
use crate::error::{BridgeError, Result};
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_rbac_create` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sRbacCreateArgs {
    host: String,
    kind: String,
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    verbs: Option<Vec<String>>,
    #[serde(default)]
    resources: Option<Vec<String>>,
    #[serde(default)]
    resource_names: Option<Vec<String>>,
    #[serde(default)]
    clusterrole: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    serviceaccount: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    output: Option<String>,
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

impl_common_args!(SshK8sRbacCreateArgs);

/// Handler marker for the `ssh_k8s_rbac_create` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_rbac_create",
    group = "kubernetes",
    annotation = "mutating"
)]
pub struct K8sRbacCreateTool;

impl StandardTool for K8sRbacCreateTool {
    type Args = SshK8sRbacCreateArgs;
    const NAME: &'static str = "ssh_k8s_rbac_create";
    const DESCRIPTION: &'static str = "Create a Kubernetes RBAC resource via `kubectl create`. \
        Supports `kind`: role, clusterrole, rolebinding, clusterrolebinding, serviceaccount. \
        For roles: supply `verbs` and `resources`. \
        For bindings: supply exactly one of `clusterrole`/`role` and one of \
        `serviceaccount`/`user`/`group`. \
        Use `dry_run=true` to preview without applying. Mutating.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "kind": {
                "type": "string",
                "description": "RBAC resource kind to create",
                "enum": ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"]
            },
            "name": {
                "type": "string",
                "description": "Name of the RBAC resource to create"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace for namespaced resources (role, rolebinding, serviceaccount)"
            },
            "verbs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Allowed verbs for role/clusterrole (e.g. ['get','list','watch'])"
            },
            "resources": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Target resources for role/clusterrole (e.g. ['pods','services'])"
            },
            "resource_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific resource names to restrict the role to"
            },
            "clusterrole": {
                "type": "string",
                "description": "ClusterRole to bind (for rolebinding/clusterrolebinding)"
            },
            "role": {
                "type": "string",
                "description": "Role to bind (for rolebinding)"
            },
            "serviceaccount": {
                "type": "string",
                "description": "Service account subject in 'namespace:name' format"
            },
            "user": {
                "type": "string",
                "description": "User subject for the binding"
            },
            "group": {
                "type": "string",
                "description": "Group subject for the binding"
            },
            "dry_run": {
                "type": "boolean",
                "description": "Preview the resource without applying (--dry-run=client -o yaml)",
                "default": false
            },
            "output": {
                "type": "string",
                "description": "Output format when dry_run=true (default: yaml)",
                "enum": ["yaml", "json"]
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
        "required": ["host", "kind", "name"]
    }"#;

    fn build_command(args: &SshK8sRbacCreateArgs, _host_config: &HostConfig) -> Result<String> {
        validate_rbac_kind(
            &args.kind,
            &["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"],
        )?;
        validate_sa_name(&args.name)?;
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        if let Some(ctx) = args.context.as_deref() {
            crate::domain::use_cases::kubernetes::validate_context(ctx)?;
        }
        // Guard: at most one of {serviceaccount, user, group}
        let subject_count = [
            args.serviceaccount.is_some(),
            args.user.is_some(),
            args.group.is_some(),
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        if subject_count > 1 {
            return Err(BridgeError::CommandDenied {
                reason: "at most one of serviceaccount/user/group may be specified".to_string(),
            });
        }
        // Guard: at most one of {role, clusterrole}
        if args.clusterrole.is_some() && args.role.is_some() {
            return Err(BridgeError::CommandDenied {
                reason: "at most one of role/clusterrole may be specified".to_string(),
            });
        }
        Ok(KubernetesCommandBuilder::build_rbac_create_command(
            args.kubectl_bin.as_deref(),
            &args.kind,
            &args.name,
            args.namespace.as_deref(),
            args.verbs.as_deref(),
            args.resources.as_deref(),
            args.resource_names.as_deref(),
            args.clusterrole.as_deref(),
            args.role.as_deref(),
            args.serviceaccount.as_deref(),
            args.user.as_deref(),
            args.group.as_deref(),
            args.dry_run,
            args.output.as_deref(),
            args.context.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_rbac_create` tool.
pub type SshK8sRbacCreateHandler = StandardToolHandler<K8sRbacCreateTool>;

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
        let handler = SshK8sRbacCreateHandler::new();
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
        let handler = SshK8sRbacCreateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "kind": "role", "name": "my-role"})),
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
        let handler = SshK8sRbacCreateHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_rbac_create");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_rbac_create");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("kind")));
        assert!(required.contains(&json!("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "kind": "role",
            "name": "my-role",
            "namespace": "prod",
            "verbs": ["get", "list"],
            "resources": ["pods"],
            "dry_run": true,
            "context": "east"
        });
        let args: SshK8sRbacCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.kind, "role");
        assert_eq!(args.name, "my-role");
        assert_eq!(args.namespace, Some("prod".to_string()));
        assert_eq!(args.verbs, Some(vec!["get".to_string(), "list".to_string()]));
        assert_eq!(args.resources, Some(vec!["pods".to_string()]));
        assert!(args.dry_run);
        assert_eq!(args.context, Some("east".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "kind": "serviceaccount", "name": "my-sa"});
        let args: SshK8sRbacCreateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.kind, "serviceaccount");
        assert_eq!(args.name, "my-sa");
        assert!(!args.dry_run);
        assert!(args.namespace.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sRbacCreateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("verbs"));
        assert!(properties.contains_key("resources"));
        assert!(properties.contains_key("resource_names"));
        assert!(properties.contains_key("clusterrole"));
        assert!(properties.contains_key("role"));
        assert!(properties.contains_key("serviceaccount"));
        assert!(properties.contains_key("user"));
        assert!(properties.contains_key("group"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("context"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK8sRbacCreateArgs = serde_json::from_value(json!({
            "host": "server1", "kind": "role", "name": "my-role"
        }))
        .unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sRbacCreateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sRbacCreateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "kind": "role", "name": "r"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_role_with_verbs_and_resources() {
        let args = SshK8sRbacCreateArgs {
            host: "s1".into(),
            kind: "role".into(),
            name: "pod-reader".into(),
            namespace: Some("prod".into()),
            verbs: Some(vec!["get".into(), "list".into()]),
            resources: Some(vec!["pods".into()]),
            resource_names: None,
            clusterrole: None,
            role: None,
            serviceaccount: None,
            user: None,
            group: None,
            dry_run: false,
            output: None,
            context: Some("east".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sRbacCreateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create") && cmd.contains("role"), "cmd: {cmd}");
        assert!(cmd.contains("pod-reader"), "cmd: {cmd}");
        assert!(cmd.contains("-n"), "cmd: {cmd}");
        assert!(cmd.contains("prod"), "cmd: {cmd}");
        assert!(cmd.contains("--verb="), "cmd: {cmd}");
        assert!(cmd.contains("--resource="), "cmd: {cmd}");
        assert!(cmd.contains("--context=east"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rolebinding() {
        let args = SshK8sRbacCreateArgs {
            host: "s1".into(),
            kind: "rolebinding".into(),
            name: "ci-binding".into(),
            namespace: Some("ci".into()),
            verbs: None,
            resources: None,
            resource_names: None,
            clusterrole: Some("pod-reader".into()),
            role: None,
            serviceaccount: Some("ci:deployer".into()),
            user: None,
            group: None,
            dry_run: false,
            output: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sRbacCreateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("create") && cmd.contains("rolebinding"), "cmd: {cmd}");
        assert!(cmd.contains("ci-binding"), "cmd: {cmd}");
        assert!(cmd.contains("--clusterrole"), "cmd: {cmd}");
        assert!(cmd.contains("--serviceaccount"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_multiple_subjects_fails() {
        let args = SshK8sRbacCreateArgs {
            host: "s1".into(),
            kind: "rolebinding".into(),
            name: "binding".into(),
            namespace: None,
            verbs: None,
            resources: None,
            resource_names: None,
            clusterrole: Some("admin".into()),
            role: None,
            serviceaccount: Some("default:sa".into()),
            user: Some("alice".into()),
            group: None,
            dry_run: false,
            output: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sRbacCreateTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("serviceaccount"), "reason: {reason}");
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_invalid_kind() {
        let args = SshK8sRbacCreateArgs {
            host: "s1".into(),
            kind: "deployment".into(), // invalid kind
            name: "my-deploy".into(),
            namespace: None,
            verbs: None,
            resources: None,
            resource_names: None,
            clusterrole: None,
            role: None,
            serviceaccount: None,
            user: None,
            group: None,
            dry_run: false,
            output: None,
            context: None,
            kubectl_bin: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sRbacCreateTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
