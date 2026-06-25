//! SSH Kubernetes Port-Forward Tool Handler
//!
//! Runs a **bounded** `kubectl port-forward` session, optionally probes the
//! forwarded endpoint, then unconditionally terminates the background process.
//! The forward NEVER hangs: it is always killed and cleaned up within
//! `wait_secs` + probe time (capped at 30 s + ~5 s curl timeout).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

/// Arguments for the `ssh_k8s_port_forward` tool.
#[derive(Debug, Deserialize)]
pub struct SshK8sPortForwardArgs {
    host: String,
    /// Resource target: `svc/<name>`, `pod/<name>`, `deployment/<name>`.
    target: String,
    /// Port mapping: `<local>:<remote>` or bare `<port>`.
    ports: String,
    /// Optional HTTP path to probe after the forward is up (e.g. `/healthz`).
    #[serde(default)]
    probe_path: Option<String>,
    /// Bounded wait window in seconds (1–30). Default 5.
    #[serde(default = "default_wait_secs")]
    wait_secs: u64,
    #[serde(default)]
    namespace: Option<String>,
    /// Bind address for the local side (default `127.0.0.1`).
    #[serde(default)]
    address: Option<String>,
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

fn default_wait_secs() -> u64 {
    5
}

impl_common_args!(SshK8sPortForwardArgs);

/// Handler marker for the `ssh_k8s_port_forward` tool.
#[mcp_standard_tool(
    name = "ssh_k8s_port_forward",
    group = "kubernetes",
    annotation = "read_only"
)]
pub struct K8sPortForward;

impl StandardTool for K8sPortForward {
    type Args = SshK8sPortForwardArgs;
    const NAME: &'static str = "ssh_k8s_port_forward";
    const DESCRIPTION: &'static str = "Run a **bounded** kubectl port-forward to a Kubernetes service or pod, \
        optionally probe the forwarded endpoint via curl, then unconditionally tear down \
        the port-forward. The background process is always killed within wait_secs (max 30 s). \
        Use probe_path (e.g. '/healthz') to get an HTTP status code from the forwarded port. \
        Never leaves a hanging port-forward.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Resource to forward: svc/<name>, pod/<name>, deployment/<name>"
            },
            "ports": {
                "type": "string",
                "description": "Port mapping: <local>:<remote> (e.g. 8080:80) or bare port"
            },
            "probe_path": {
                "type": "string",
                "description": "HTTP path to curl after the forward is up (e.g. /healthz, /metrics)"
            },
            "wait_secs": {
                "type": "integer",
                "description": "Bounded wait window in seconds before teardown (1–30, default 5)",
                "minimum": 1,
                "maximum": 30
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "address": {
                "type": "string",
                "description": "Bind address for local side (default: 127.0.0.1)"
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
        "required": ["host", "target", "ports"]
    }"#;

    // port-forward output is freeform text — use RawText (omit the const entirely
    // since OutputKind::Auto is the default; no OutputKind constant emitted)
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::RawText;

    fn build_command(args: &SshK8sPortForwardArgs, _host_config: &HostConfig) -> Result<String> {
        KubernetesCommandBuilder::build_port_forward_command(
            args.kubectl_bin.as_deref(),
            &args.target,
            &args.ports,
            args.probe_path.as_deref(),
            args.wait_secs,
            args.namespace.as_deref(),
            args.address.as_deref(),
            args.context.as_deref(),
        )
    }
}

/// Handler for the `ssh_k8s_port_forward` tool.
pub type SshK8sPortForwardHandler = StandardToolHandler<K8sPortForward>;

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

    // --- deserialization ---

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "k8s-host",
            "target": "svc/myapp",
            "ports": "8080:80",
            "probe_path": "/healthz",
            "wait_secs": 10,
            "namespace": "default",
            "address": "127.0.0.1",
            "context": "prod",
            "kubectl_bin": "kubectl",
            "timeout_seconds": 60,
            "max_output": 40000
        });
        let args: SshK8sPortForwardArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s-host");
        assert_eq!(args.target, "svc/myapp");
        assert_eq!(args.ports, "8080:80");
        assert_eq!(args.probe_path, Some("/healthz".to_string()));
        assert_eq!(args.wait_secs, 10);
        assert_eq!(args.namespace, Some("default".to_string()));
        assert_eq!(args.context, Some("prod".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "k8s", "target": "svc/web", "ports": "8080:80"});
        let args: SshK8sPortForwardArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "k8s");
        assert_eq!(args.wait_secs, 5, "default wait_secs should be 5");
        assert!(args.probe_path.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "k8s", "target": "svc/web", "ports": "9090"});
        let args: SshK8sPortForwardArgs = serde_json::from_value(json).unwrap();
        let s = format!("{args:?}");
        assert!(s.contains("SshK8sPortForwardArgs"));
    }

    // --- schema ---

    #[test]
    fn test_schema_has_required_fields() {
        let handler = SshK8sPortForwardHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"host"));
        assert!(required_strs.contains(&"target"));
        assert!(required_strs.contains(&"ports"));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sPortForwardHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("probe_path"));
        assert!(props.contains_key("wait_secs"));
        assert!(props.contains_key("namespace"));
        assert!(props.contains_key("context"));
        assert!(props.contains_key("kubectl_bin"));
        assert!(props.contains_key("address"));
    }

    // --- invalid JSON type ---

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sPortForwardHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "target": "svc/web", "ports": "8080:80"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // --- build_command ---

    #[test]
    fn test_build_command_basic() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/myapp".into(),
            ports: "8080:80".into(),
            probe_path: None,
            wait_secs: 5,
            namespace: None,
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPortForward::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("kubectl port-forward"), "cmd: {cmd}");
        assert!(cmd.contains("'svc/myapp'"), "cmd: {cmd}");
        assert!(cmd.contains("'8080:80'"), "cmd: {cmd}");
        assert!(cmd.contains("sleep '5'"), "cmd: {cmd}");
        assert!(cmd.contains("kill $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("wait $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/pf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_probe() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/api".into(),
            ports: "8080:80".into(),
            probe_path: Some("/healthz".into()),
            wait_secs: 10,
            namespace: Some("production".into()),
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPortForward::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("curl"), "cmd: {cmd}");
        assert!(cmd.contains("/healthz"), "cmd: {cmd}");
        assert!(cmd.contains("-n 'production'"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_rejects_zero_wait() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/web".into(),
            ports: "8080:80".into(),
            probe_path: None,
            wait_secs: 0,
            namespace: None,
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sPortForward::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_wait_above_30() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/web".into(),
            ports: "8080:80".into(),
            probe_path: None,
            wait_secs: 31,
            namespace: None,
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sPortForward::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_rejects_invalid_probe_path() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/web".into(),
            ports: "8080:80".into(),
            probe_path: Some("/../evil".into()),
            wait_secs: 5,
            namespace: None,
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = K8sPortForward::build_command(&args, &test_host_config());
        assert!(result.is_err());
    }

    #[test]
    fn test_build_command_always_self_terminates() {
        // Verify the auto-teardown is present even without a probe
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "pod/mypod-abc".into(),
            ports: "9090".into(),
            probe_path: None,
            wait_secs: 3,
            namespace: None,
            address: None,
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPortForward::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("kill $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("wait $PF 2>/dev/null"), "cmd: {cmd}");
        assert!(cmd.contains("rm -f /tmp/pf.$$"), "cmd: {cmd}");
    }

    #[test]
    fn test_build_command_with_address() {
        let args = SshK8sPortForwardArgs {
            host: "k8s".into(),
            target: "svc/myapp".into(),
            ports: "8080:80".into(),
            probe_path: None,
            wait_secs: 5,
            namespace: None,
            address: Some("0.0.0.0".into()),
            context: None,
            kubectl_bin: Some("kubectl".into()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = K8sPortForward::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("--address '0.0.0.0'"), "cmd: {cmd}");
    }
}
