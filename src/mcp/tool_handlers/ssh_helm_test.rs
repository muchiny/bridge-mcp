//! SSH Helm Test Tool Handler
//!
//! Runs Helm chart tests for a deployed release on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::{HelmCommandBuilder, KubernetesCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshHelmTestArgs {
    host: String,
    release: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    logs: Option<bool>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    kubeconfig: Option<String>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmTestArgs);

#[mcp_standard_tool(name = "ssh_helm_test", group = "kubernetes", annotation = "mutating")]
pub struct HelmTestTool;

impl StandardTool for HelmTestTool {
    type Args = SshHelmTestArgs;

    const NAME: &'static str = "ssh_helm_test";

    const DESCRIPTION: &'static str = "Run Helm chart tests for a deployed release on a remote host. \
        Executes the test hooks defined in the chart. Use logs to stream test pod logs. \
        Use filter to run specific tests by name. \
        Note: tests may create or modify resources (test pods). \
        Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "release": {
                "type": "string",
                "description": "Helm release name to test"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "logs": {
                "type": "boolean",
                "description": "Dump test pod logs after tests complete"
            },
            "timeout": {
                "type": "string",
                "description": "Time to wait for tests to complete (e.g. 5m0s)"
            },
            "filter": {
                "type": "string",
                "description": "Run only tests matching this name filter"
            },
            "kubeconfig": {
                "type": "string",
                "description": "Path to kubeconfig file (e.g., /etc/rancher/k3s/k3s.yaml for K3s)"
            },
            "helm_bin": {
                "type": "string",
                "description": "Custom helm binary path (default: auto-detect)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            }
        },
        "required": ["host", "release"]
    }"#;

    fn build_command(args: &SshHelmTestArgs, _host_config: &HostConfig) -> Result<String> {
        if let Some(ns) = args.namespace.as_deref() {
            KubernetesCommandBuilder::validate_namespace(ns)?;
        }
        Ok(HelmCommandBuilder::build_test_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            args.namespace.as_deref(),
            args.logs.unwrap_or(false),
            args.timeout.as_deref(),
            args.filter.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_test` tool.
pub type SshHelmTestHandler = StandardToolHandler<HelmTestTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmTestHandler::new();
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
        let handler = SshHelmTestHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "release": "myapp"})),
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
        let handler = SshHelmTestHandler::new();
        assert_eq!(handler.name(), "ssh_helm_test");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_test");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("release")));
    }

    #[test]
    fn test_args_deserialization() {
        let json_val = json!({
            "host": "server1",
            "release": "myapp",
            "namespace": "production",
            "logs": true,
            "timeout": "10m0s",
            "filter": "connectivity",
            "kubeconfig": "/etc/rancher/k3s/k3s.yaml",
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 600,
            "max_output": 10000
        });
        let args: SshHelmTestArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "myapp");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.logs, Some(true));
        assert_eq!(args.timeout, Some("10m0s".to_string()));
        assert_eq!(args.filter, Some("connectivity".to_string()));
        assert_eq!(
            args.kubeconfig,
            Some("/etc/rancher/k3s/k3s.yaml".to_string())
        );
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json_val = json!({"host": "server1", "release": "myapp"});
        let args: SshHelmTestArgs = serde_json::from_value(json_val).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "myapp");
        assert!(args.namespace.is_none());
        assert!(args.logs.is_none());
        assert!(args.timeout.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("logs"));
        assert!(properties.contains_key("timeout"));
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("kubeconfig"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json_val = json!({"host": "server1", "release": "myapp"});
        let args: SshHelmTestArgs = serde_json::from_value(json_val).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmTestArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmTestHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "release": "myapp"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    use crate::config::{HostKeyVerification, OsType};

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
    fn test_build_command_basic() {
        let args = SshHelmTestArgs {
            host: "server1".to_string(),
            release: "myapp".to_string(),
            namespace: None,
            logs: None,
            timeout: None,
            filter: None,
            kubeconfig: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmTestTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("helm test 'myapp'"));
    }

    #[test]
    fn test_build_command_with_logs_and_namespace() {
        let args = SshHelmTestArgs {
            host: "server1".to_string(),
            release: "myapp".to_string(),
            namespace: Some("production".to_string()),
            logs: Some(true),
            timeout: Some("5m0s".to_string()),
            filter: None,
            kubeconfig: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = HelmTestTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-n 'production'"));
        assert!(cmd.contains("--logs"));
        assert!(cmd.contains("--timeout '5m0s'"));
    }

    #[test]
    fn test_build_command_rejects_bad_namespace() {
        let args = SshHelmTestArgs {
            host: "server1".to_string(),
            release: "myapp".to_string(),
            namespace: Some("--all-namespaces".to_string()),
            logs: None,
            timeout: None,
            filter: None,
            kubeconfig: None,
            helm_bin: Some("helm".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let result = HelmTestTool::build_command(&args, &test_host_config());
        assert!(
            result.is_err(),
            "expected error for flag-like namespace value"
        );
    }
}
