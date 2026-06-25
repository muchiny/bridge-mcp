//! K3s certificate rotation — regenerates TLS certificates for k3s services.
//! DESTRUCTIVE: a failed rotate can lock the API server. Cluster must be restarted after.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::k3s::{K3sCommandBuilder, validate_cert_service};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k3s_cert_rotate` tool.
#[derive(Debug, Deserialize)]
pub struct SshK3sCertRotateArgs {
    host: String,
    #[serde(default)]
    service: Option<Vec<String>>,
    #[serde(default)]
    k3s_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK3sCertRotateArgs);

/// Handler marker for the `ssh_k3s_cert_rotate` tool.
#[mcp_standard_tool(
    name = "ssh_k3s_cert_rotate",
    group = "k3s",
    annotation = "destructive"
)]
pub struct K3sCertRotateTool;

impl StandardTool for K3sCertRotateTool {
    type Args = SshK3sCertRotateArgs;
    const NAME: &'static str = "ssh_k3s_cert_rotate";
    const DESCRIPTION: &'static str = "Rotate TLS certificates for K3s services \
        (`k3s certificate rotate`). \
        **DESTRUCTIVE**: regenerates certificates — a botched rotate can lock the \
        API server and require manual recovery. The cluster must be restarted after \
        rotation for new certs to take effect. \
        Omit `service` to rotate all certificates. Provide `service` to limit \
        rotation to specific services (e.g. `[\"etcd\", \"api-server\"]`). \
        Allowed services: admin, api-server, controller-manager, scheduler, \
        k3s-controller, k3s-server, cloud-controller, etcd, auth-proxy, kubelet, \
        kube-proxy, k3s-server-load-balancer.";
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Host alias from config.yaml"},
            "service": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of k3s cert services to rotate. Omit to rotate all. Allowed: admin, api-server, controller-manager, scheduler, k3s-controller, k3s-server, cloud-controller, etcd, auth-proxy, kubelet, kube-proxy, k3s-server-load-balancer"
            },
            "k3s_bin": {"type": "string", "description": "Custom k3s binary path (default: auto-detect 'k3s')"},
            "timeout_seconds": {"type": "integer", "description": "Timeout in seconds", "minimum": 1, "maximum": 3600},
            "max_output": {"type": "integer", "description": "Max output characters (0 = no limit)", "minimum": 0},
            "save_output": {"type": "string", "description": "Save full output to a file on the MCP server"}
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshK3sCertRotateArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(services) = args.service.as_deref() {
            for svc in services {
                validate_cert_service(svc)?;
            }
        }
        Ok(K3sCommandBuilder::build_cert_rotate_command(
            args.k3s_bin.as_deref(),
            args.service.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k3s_cert_rotate` tool.
pub type SshK3sCertRotateHandler = StandardToolHandler<K3sCertRotateTool>;

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
        let handler = SshK3sCertRotateHandler::new();
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
        let handler = SshK3sCertRotateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": "nohost"})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nohost"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK3sCertRotateHandler::new();
        assert_eq!(handler.name(), "ssh_k3s_cert_rotate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(!required.contains(&json!("service")));
    }

    #[test]
    fn test_args_deserialization_with_services() {
        let args: SshK3sCertRotateArgs = serde_json::from_value(json!({
            "host": "k3s-node",
            "service": ["etcd", "api-server"],
            "k3s_bin": "k3s"
        }))
        .unwrap();
        assert_eq!(args.host, "k3s-node");
        assert_eq!(
            args.service,
            Some(vec!["etcd".to_string(), "api-server".to_string()])
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let args: SshK3sCertRotateArgs =
            serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        assert!(args.service.is_none());
        assert!(args.k3s_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK3sCertRotateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("service"));
        assert!(props.contains_key("k3s_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let args: SshK3sCertRotateArgs =
            serde_json::from_value(json!({"host": "k3s-node"})).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK3sCertRotateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK3sCertRotateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_no_service_rotates_all() {
        let args = SshK3sCertRotateArgs {
            host: "s1".into(),
            service: None,
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sCertRotateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("sudo k3s certificate rotate"), "cmd: {cmd}");
        assert!(!cmd.contains("--service"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_valid_services() {
        let args = SshK3sCertRotateArgs {
            host: "s1".into(),
            service: Some(vec!["etcd".into(), "api-server".into()]),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K3sCertRotateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--service"), "cmd: {cmd}");
        assert!(cmd.contains("etcd"), "cmd: {cmd}");
        assert!(cmd.contains("api-server"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_invalid_service_rejected() {
        let args = SshK3sCertRotateArgs {
            host: "s1".into(),
            service: Some(vec!["invalid-service".into()]),
            k3s_bin: Some("k3s".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K3sCertRotateTool::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }
}
