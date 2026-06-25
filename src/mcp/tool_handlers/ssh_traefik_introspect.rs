//! SSH Traefik API Introspect Tool Handler
//!
//! Discovers the Traefik pod by label, starts a bounded port-forward,
//! queries `/api<path>`, then unconditionally kills the background
//! process and cleans up the tmp log file. Never hangs.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_traefik_introspect` tool.
#[derive(Debug, Deserialize)]
pub struct SshTraefikIntrospectArgs {
    host: String,
    /// Traefik API path to query (default: /rawdata).
    #[serde(default = "default_api_path")]
    api_path: String,
    /// Kubernetes namespace where Traefik is deployed (default: kube-system).
    #[serde(default)]
    namespace: Option<String>,
    /// Traefik API port (default: 8080).
    #[serde(default = "default_api_port")]
    api_port: u16,
    /// Wait seconds for port-forward to be ready (default: 5, max: 30).
    #[serde(default = "default_wait_secs")]
    wait_secs: u64,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

fn default_api_path() -> String {
    "/rawdata".to_string()
}

fn default_api_port() -> u16 {
    8080
}

fn default_wait_secs() -> u64 {
    5
}

impl_common_args!(SshTraefikIntrospectArgs);

/// Handler marker for the `ssh_traefik_introspect` tool.
#[mcp_standard_tool(
    name = "ssh_traefik_introspect",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct TraefikIntrospect;

impl StandardTool for TraefikIntrospect {
    type Args = SshTraefikIntrospectArgs;
    const NAME: &'static str = "ssh_traefik_introspect";
    const DESCRIPTION: &'static str = "Introspect the Traefik API by discovering the Traefik pod, \
        starting a bounded port-forward, and querying /api<path>. Self-terminating: always kills \
        the port-forward and cleans up. Useful for inspecting routes, middlewares, and services \
        in K3s clusters using Traefik as the ingress controller.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "api_path": {
                "type": "string",
                "description": "Traefik API path to query (default: /rawdata). Examples: /rawdata, /routers, /services, /middlewares"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace where Traefik is deployed (default: kube-system)"
            },
            "api_port": {
                "type": "integer",
                "description": "Traefik API port (default: 8080)",
                "minimum": 1,
                "maximum": 65535
            },
            "wait_secs": {
                "type": "integer",
                "description": "Wait seconds for port-forward to be ready (default: 5, max: 30)",
                "minimum": 1,
                "maximum": 30
            },
            "context": {
                "type": "string",
                "description": "kubectl context for multi-cluster targeting"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl/k3s/microk8s)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "SSH command timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (0 = no limit). Truncated output yields an output_id for ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a file on the MCP server."
            }
        },
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshTraefikIntrospectArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_traefik_introspect_command(
            args.kubectl_bin.as_deref(),
            &args.api_path,
            args.namespace.as_deref(),
            args.api_port,
            args.wait_secs,
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_traefik_introspect` tool.
pub type SshTraefikIntrospectHandler = StandardToolHandler<TraefikIntrospect>;

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

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "k8s-host",
            "api_path": "/routers",
            "namespace": "kube-system",
            "api_port": 9000,
            "wait_secs": 10,
            "context": "prod",
            "kubectl_bin": "kubectl"
        });
        let args: SshTraefikIntrospectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.api_path, "/routers");
        assert_eq!(args.api_port, 9000);
        assert_eq!(args.wait_secs, 10);
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s"});
        let args: SshTraefikIntrospectArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert_eq!(args.api_path, "/rawdata"); // default
        assert_eq!(args.api_port, 8080); // default
        assert_eq!(args.wait_secs, 5); // default
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s"});
        let args: SshTraefikIntrospectArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshTraefikIntrospectArgs"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTraefikIntrospectHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("api_path"));
        assert!(props.contains_key("namespace"));
        assert!(props.contains_key("api_port"));
        assert!(props.contains_key("wait_secs"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTraefikIntrospectHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_build_command_basic() {
        let args = SshTraefikIntrospectArgs {
            host: "k8s".into(),
            api_path: "/rawdata".into(),
            namespace: None,
            api_port: 8080,
            wait_secs: 5,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TraefikIntrospect::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("app.kubernetes.io/name=traefik"), "cmd: {cmd}");
        assert!(cmd.contains("port-forward"), "cmd: {cmd}");
        assert!(cmd.contains("kill $PF"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/tpf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_invalid_path() {
        let args = SshTraefikIntrospectArgs {
            host: "k8s".into(),
            api_path: "/../etc/passwd".into(),
            namespace: None,
            api_port: 8080,
            wait_secs: 5,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = TraefikIntrospect::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_invalid_namespace() {
        let args = SshTraefikIntrospectArgs {
            host: "k8s".into(),
            api_path: "/rawdata".into(),
            namespace: Some("--all-namespaces".into()),
            api_port: 8080,
            wait_secs: 5,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = TraefikIntrospect::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_with_context() {
        let args = SshTraefikIntrospectArgs {
            host: "k8s".into(),
            api_path: "/rawdata".into(),
            namespace: None,
            api_port: 8080,
            wait_secs: 5,
            context: Some("prod".into()),
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TraefikIntrospect::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--context=prod"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_includes_kubectl_prefix() {
        let args = SshTraefikIntrospectArgs {
            host: "k8s".into(),
            api_path: "/rawdata".into(),
            namespace: None,
            api_port: 8080,
            wait_secs: 5,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = TraefikIntrospect::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("K='kubectl'"), "cmd: {cmd}");
    }
}
