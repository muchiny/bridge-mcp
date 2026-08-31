//! Handler for the `ssh_reg_export` tool.
//!
//! Exports a Windows Registry key to a `.reg` file via `reg.exe`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_registry::{
    WindowsRegistryCommandBuilder, validate_file_path,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRegExportArgs {
    host: String,
    key: String,
    file: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRegExportArgs);

#[mcp_standard_tool(
    name = "ssh_reg_export",
    group = "windows_registry",
    annotation = "mutating"
)]
pub struct RegExportTool;

impl StandardTool for RegExportTool {
    type Args = SshRegExportArgs;

    const NAME: &'static str = "ssh_reg_export";

    const DESCRIPTION: &'static str = "Export a Windows Registry key to a `.reg` file on the remote host. The file can be \
        used for backup or to import on another machine.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "key", "file"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "key": {
                "type": "string",
                "description": "Registry key to export (e.g., HKLM\\SOFTWARE\\MyApp)"
            },
            "file": {
                "type": "string",
                "description": "Destination file path on the remote host (e.g., C:\\backup\\myapp.reg)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshRegExportArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsRegistryCommandBuilder::export_key(
            &args.key, &args.file,
        ))
    }

    fn validate(args: &SshRegExportArgs, _host_config: &HostConfig) -> Result<()> {
        validate_file_path(&args.file)?;
        Ok(())
    }
}

/// Handler for the `ssh_reg_export` tool.
pub type SshRegExportHandler = StandardToolHandler<RegExportTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRegExportHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshRegExportHandler::new();
        let ctx = create_test_context();
        let args = json!({
            "host": "nonexistent",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup.reg"
        });
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRegExportHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_reg_export");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("key")));
        assert!(required.iter().any(|v| v.as_str() == Some("file")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup\\myapp.reg",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.key, "HKLM\\SOFTWARE\\MyApp");
        assert_eq!(args.file, "C:\\backup\\myapp.reg");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "myhost",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup.reg"
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.key, "HKLM\\SOFTWARE\\MyApp");
        assert_eq!(args.file, "C:\\backup.reg");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRegExportHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "h",
            "key": "HKLM\\SOFTWARE",
            "file": "C:\\out.reg"
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshRegExportArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({
            "host": 123,
            "key": "HKLM\\SOFTWARE",
            "file": "C:\\out.reg"
        });
        let result = serde_json::from_value::<SshRegExportArgs>(json);
        assert!(result.is_err());
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
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
    fn test_build_command_defaults() {
        let args: SshRegExportArgs = serde_json::from_value(
            json!({"host": "s", "key": "HKLM:\\SOFTWARE\\Test", "file": "C:\\out.reg"}),
        )
        .unwrap();
        let host = test_host_config();
        let cmd = RegExportTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn win_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "winhost".to_string(),
            HostConfig {
                hostname: "10.0.0.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Windows,
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
            },
        );
        hosts
    }
    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshRegExportHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            win_hosts(),
            mock_output("mock-output-ok"),
        );
        let result = handler
            .execute(Some(json!({"host": "winhost", "key": "HKLM:\\SOFTWARE\\Test", "file": "C:\\export.reg"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }
}
