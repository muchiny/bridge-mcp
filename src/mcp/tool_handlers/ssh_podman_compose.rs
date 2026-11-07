//! SSH Podman Compose Tool Handler
//!
//! Runs podman compose commands on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::podman::PodmanCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPodmanComposeArgs {
    host: String,
    action: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPodmanComposeArgs);

#[mcp_standard_tool(
    name = "ssh_podman_compose",
    group = "podman",
    annotation = "destructive"
)]
pub struct PodmanComposeTool;

impl StandardTool for PodmanComposeTool {
    type Args = SshPodmanComposeArgs;

    const NAME: &'static str = "ssh_podman_compose";

    const DESCRIPTION: &'static str = "Run `podman compose` commands on a remote host to manage \
        multi-container stacks. Pass the subcommand as action (e.g. 'up -d', 'down', 'ps', \
        'logs --tail 100', 'restart', 'pull'): a subcommand, then only its known flags and \
        service names, separated by spaces, no quoting. Output files, env files and \
        'logs -f' are refused. Can remove containers and volumes (down -v, rm). Specify file if the compose file is not the default \
        (compose.yaml or docker-compose.yml in the working directory); file is a local path on \
        the host (letters, digits, '/', '.', '_', '-'; a relative path with a directory part \
        starts with './'): URLs, Git and OCI references and 'host:path' forms are refused. \
        Remote Git and OCI includes named inside a compose file are not loaded (the compose \
        remote loaders are switched off). For viewing individual \
        container logs use ssh_podman_logs. For Docker Compose stacks use ssh_docker_compose \
        instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "action": {
                "type": "string",
                "description": "Compose subcommand with its flags and service names, separated by spaces, no quotes or backslashes (e.g. 'up -d', 'down', 'ps', 'logs --tail 100 web'). Only a short list of flags per subcommand is accepted; output/file flags and 'logs -f' are refused."
            },
            "file": {
                "type": "string",
                "description": "Local path of the compose file on the remote host, made of letters, digits, '/', '.', '_' and '-' (absolute, or relative to the working directory; a relative path with a directory part starts with './'). URLs, Git/OCI references and 'host:path' forms are refused. Default: compose.yaml or docker-compose.yml in current directory"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 40000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "action"]
    }"#;

    fn validate(args: &SshPodmanComposeArgs, _host_config: &HostConfig) -> Result<()> {
        PodmanCommandBuilder::validate_compose_action(&args.action)?;
        if let Some(file) = &args.file {
            PodmanCommandBuilder::validate_compose_file(file)?;
        }
        Ok(())
    }

    fn build_command(args: &SshPodmanComposeArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PodmanCommandBuilder::build_compose_command(
            &args.action,
            args.file.as_deref(),
        ))
    }
}

/// Handler for the `ssh_podman_compose` tool.
pub type SshPodmanComposeHandler = StandardToolHandler<PodmanComposeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPodmanComposeHandler::new();
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
        let handler = SshPodmanComposeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "action": "ps"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPodmanComposeHandler::new();
        assert_eq!(handler.name(), "ssh_podman_compose");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
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
            os_type: crate::config::OsType::default(),
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
            ansible: None,
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args: SshPodmanComposeArgs =
            serde_json::from_value(json!({"host": "s", "action": "ps"})).unwrap();
        let host = test_host_config();
        let cmd = PodmanComposeTool::build_command(&args, &host).unwrap();
        assert_ne!(cmd, "");
        assert!(cmd.contains("podman"));
    }

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        use crate::config::{AuthConfig, HostConfig, HostKeyVerification, OsType};
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: AuthConfig::Agent,
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
                ansible: None,
            },
        );
        hosts
    }

    fn permissive_ctx(mock_out: crate::ssh::CommandOutput) -> crate::ports::ToolContext {
        use crate::config::SessionConfig;
        use crate::config::{Config, LimitsConfig, SecurityConfig, SecurityMode};
        use crate::domain::CommandHistory;
        use crate::domain::ExecuteCommandUseCase;
        use crate::domain::TunnelManager;
        use crate::domain::history::HistoryConfig;
        use crate::ports::ExecutorRouter;
        use crate::security::AuditLogger;
        use crate::security::RateLimiter;
        use crate::security::{CommandValidator, Sanitizer};
        use crate::ssh::SessionManager;
        use std::sync::Arc;
        let sec = SecurityConfig {
            mode: SecurityMode::Permissive,
            blacklist: Vec::new(),
            ..SecurityConfig::default()
        };
        let config = Config {
            hosts: server1_hosts(),
            security: sec.clone(),
            limits: LimitsConfig::default(),
            ..Config::default()
        };
        let validator = Arc::new(CommandValidator::new(&sec));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));
        crate::ports::ToolContext {
            mrtr: crate::ports::MrtrSlot::default(),
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ExecutorRouter::mock(mock_out)),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
            roots: Vec::new(),
            session_recorder: None,
            metrics: None,
            cancel_token: None,
            notification_tx: None,
            progress_token: None,
            client_supports_elicitation: false,
            client_supports_sampling: false,
            mcp_logger: None,
        }
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshPodmanComposeHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(Some(json!({"host": "server1", "action": "ps"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    #[tokio::test]
    async fn test_action_with_shell_or_unknown_subcommand_is_refused() {
        for action in ["ps; id", "exec web sh", "-f x up", "x"] {
            let handler = SshPodmanComposeHandler::new();
            let ctx = crate::ports::mock::create_test_context_with_host();
            let err = handler
                .execute(Some(json!({"host": "server1", "action": action})), &ctx)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("Compose action"),
                "{action}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_option_and_quote_actions_are_refused() {
        for action in [
            "config -o /home/deploy/.ssh/authorized_keys",
            "up --env-file /etc/x",
            "logs -f",
            "logs 'web'",
        ] {
            let handler = SshPodmanComposeHandler::new();
            let ctx = crate::ports::mock::create_test_context_with_host();
            let err = handler
                .execute(Some(json!({"host": "server1", "action": action})), &ctx)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("Compose action"),
                "{action}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_listed_flags_still_run() {
        let handler = SshPodmanComposeHandler::new();
        let ctx = permissive_ctx(mock_output("ok"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "action": "logs --tail 50 web"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    #[tokio::test]
    async fn test_logs_since_and_up_wait_run_but_bad_times_are_refused() {
        for action in [
            "logs --since 10m web",
            "logs --since 2026-11-05T10:00:00Z --until 2026-11-05T11:00:00Z",
            "up -d --wait",
        ] {
            let handler = SshPodmanComposeHandler::new();
            let ctx = permissive_ctx(mock_output("ok"));
            let result = handler
                .execute(Some(json!({"host": "server1", "action": action})), &ctx)
                .await
                .unwrap();
            assert!(
                result.is_error.is_none() || result.is_error == Some(false),
                "{action}"
            );
        }
        for action in ["logs --since -1h", "logs --since 1h;id", "logs --since"] {
            let handler = SshPodmanComposeHandler::new();
            let ctx = crate::ports::mock::create_test_context_with_host();
            let err = handler
                .execute(Some(json!({"host": "server1", "action": action})), &ctx)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("Compose action"),
                "{action}: {err}"
            );
        }
    }

    #[test]
    fn test_registered_annotation_is_destructive() {
        let kind = inventory::iter::<crate::mcp::registry::ToolRegistryEntry>()
            .find(|e| e.name == "ssh_podman_compose")
            .map(|e| e.annotation_kind);
        assert_eq!(
            kind,
            Some(crate::mcp::registry::ToolAnnotationKind::Destructive)
        );
    }

    #[test]
    fn test_validate_refuses_output_flag_and_keeps_up_d() {
        let host = test_host_config();
        let bad: SshPodmanComposeArgs =
            serde_json::from_value(json!({"host": "s", "action": "config -o /x"})).unwrap();
        assert!(PodmanComposeTool::validate(&bad, &host).is_err());
        let ok: SshPodmanComposeArgs =
            serde_json::from_value(json!({"host": "s", "action": "up -d web"})).unwrap();
        assert!(PodmanComposeTool::validate(&ok, &host).is_ok());
    }

    #[test]
    fn test_build_command_quotes_each_action_word() {
        let args: SshPodmanComposeArgs =
            serde_json::from_value(json!({"host": "s", "action": "up -d"})).unwrap();
        let cmd = PodmanComposeTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
             podman compose 'up' '-d'"
        );
    }

    #[tokio::test]
    async fn test_remote_compose_file_is_refused() {
        for file in [
            "https://example.com/org/repo.git",
            "git@example.com:org/repo.git",
            "oci://registry.example.com/stack:latest",
            "github.com/org/repo",
            "example.com:compose.yml",
            "-",
            "",
        ] {
            let handler = SshPodmanComposeHandler::new();
            let ctx = crate::ports::mock::create_test_context_with_host();
            let args = json!({"host": "server1", "action": "up -d", "file": file});
            let err = handler.execute(Some(args), &ctx).await.unwrap_err();
            let BridgeError::CommandDenied { reason } = &err else {
                panic!("{file:?}: {err:?}");
            };
            assert!(reason.contains("'file'"), "{file:?}: {reason}");
        }
    }

    #[tokio::test]
    async fn test_local_compose_file_still_runs() {
        let handler = SshPodmanComposeHandler::new();
        let ctx = permissive_ctx(mock_output("ok"));
        let args = json!({"host": "server1", "action": "up -d", "file": "./deploy/compose.yml"});
        let result = handler.execute(Some(args), &ctx).await.unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    #[test]
    fn test_build_command_golden_with_file() {
        for (file, want) in [
            (
                "docker-compose.prod.yml",
                "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
                 podman compose -f 'docker-compose.prod.yml' 'up' '-d'",
            ),
            (
                "/srv/stack/compose.yaml",
                "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
                 podman compose -f '/srv/stack/compose.yaml' 'up' '-d'",
            ),
            (
                "./deploy/compose.yml",
                "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
                 podman compose -f './deploy/compose.yml' 'up' '-d'",
            ),
        ] {
            let args: SshPodmanComposeArgs =
                serde_json::from_value(json!({"host": "s", "action": "up -d", "file": file}))
                    .unwrap();
            let host = test_host_config();
            assert!(PodmanComposeTool::validate(&args, &host).is_ok(), "{file}");
            assert_eq!(
                PodmanComposeTool::build_command(&args, &host).unwrap(),
                want
            );
        }
    }
}
