//! SSH Docker Exec Tool Handler
//!
//! Executes a command inside a running Docker container on a remote host
//! via `docker exec`. Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::domain::use_cases::shell::{refuse_option_like, refuse_sensitive_env_name};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::mcp::standard_tool::{
    StandardTool, StandardToolHandler, impl_common_args, validate_free_form_command,
};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshDockerExecArgs {
    host: String,
    container: String,
    command: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    env: Option<Vec<String>>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerExecArgs);

#[mcp_standard_tool(name = "ssh_docker_exec", group = "docker", annotation = "mutating")]
pub struct DockerExecTool;

impl StandardTool for DockerExecTool {
    type Args = SshDockerExecArgs;

    const NAME: &'static str = "ssh_docker_exec";

    const DESCRIPTION: &'static str = "Execute a command inside a running Docker container on a remote host. Use \
        ssh_docker_ps first to find container names. Supports custom user, working directory, \
        and environment variables. Auto-detects docker or podman. Returns command \
        stdout/stderr.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to execute the command in"
            },
            "command": {
                "type": "string",
                "description": "Command to execute inside the container (e.g., 'ls -la /app', 'cat /etc/hostname')"
            },
            "user": {
                "type": "string",
                "description": "Run command as this user inside the container (e.g., 'root', 'www-data')"
            },
            "workdir": {
                "type": "string",
                "description": "Working directory inside the container"
            },
            "env": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Environment variables to set (format: KEY=VALUE)"
            },
            "docker_bin": {
                "type": "string",
                "description": "Custom docker binary path (default: auto-detect docker or podman)"
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
        "required": ["host", "container", "command"]
    }"#;

    fn validate(args: &SshDockerExecArgs, _host_config: &HostConfig) -> Result<()> {
        refuse_option_like("container", &args.container)?;
        for entry in args.env.iter().flatten() {
            validate_env_entry(entry)?;
        }
        // `sh -c` reads a command string that starts with `-` as its own options.
        refuse_option_like("command", &args.command)
    }

    /// `command` is a free-form script from the request, so it faces the same
    /// whitelist as `ssh_exec`, not only the blacklist `validate_builtin`
    /// applies to builder-produced commands.
    fn pre_execute(
        args: &SshDockerExecArgs,
        ctx: &ToolContext,
    ) -> impl std::future::Future<Output = Result<Option<ToolCallResult>>> + Send {
        let script = command_with_env(args.workdir.as_deref(), args.env.as_deref(), &args.command);
        std::future::ready(
            validate_free_form_command(ctx, Self::NAME, &args.host, &script).map(|()| None),
        )
    }

    fn build_command(args: &SshDockerExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_exec_command(
            args.docker_bin.as_deref(),
            &args.container,
            &args.command,
            args.user.as_deref(),
            args.workdir.as_deref(),
            args.env.as_deref(),
        ))
    }
}

/// The text the whitelist judges: `cd -- DIR &&` for a `workdir` (it changes
/// which file a relative path names), the `env` entries as the assignments a
/// shell line would carry (`NAME=VALUE command`), then the command. An entry
/// changes what the command does (`RSYNC_RSH`, `KUBE_EDITOR`), so a
/// whitelist entry for the bare command does not approve it. `docker exec -e`
/// sets the entries for the whole command and its `sh`, not only for the
/// first simple command the line shows them on.
fn command_with_env(workdir: Option<&str>, env: Option<&[String]>, command: &str) -> String {
    let mut words: Vec<String> = workdir
        .map(|dir| {
            format!(
                "cd -- {} &&",
                crate::domain::use_cases::shell::posix_word(dir)
            )
        })
        .into_iter()
        .collect();
    words.extend(
        env.unwrap_or_default()
            .iter()
            .map(|entry| match entry.split_once('=') {
                Some((name, value)) => {
                    format!(
                        "{name}={}",
                        crate::domain::use_cases::shell::posix_word(value)
                    )
                }
                None => crate::domain::use_cases::shell::posix_word(entry),
            }),
    );
    words.push(command.to_string());
    words.join(" ")
}

/// Check one `env` entry (`NAME=VALUE`).
///
/// `docker exec -e` accepts any name, so an entry could set a variable that
/// changes which program or library the container runs, or how its shell
/// starts (`BASH_FUNC_echo%%`, `LD_PRELOAD`, `PATH`, `SHELLOPTS`), and run
/// something the whitelist never saw. The name must be a plain identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`) and not one of those variables. An entry
/// without `=` would copy the variable from the remote login environment, so
/// it is refused too.
fn validate_env_entry(entry: &str) -> Result<()> {
    let Some((name, _value)) = entry.split_once('=') else {
        return Err(BridgeError::CommandDenied {
            reason: "'env' entries must be NAME=VALUE".to_string(),
        });
    };
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(BridgeError::CommandDenied {
            reason: format!("'env' variable name '{name}' must match [A-Za-z_][A-Za-z0-9_]*"),
        });
    }
    refuse_sensitive_env_name("env", name)
}

/// Handler for the `ssh_docker_exec` tool.
pub type SshDockerExecHandler = StandardToolHandler<DockerExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[test]
    fn the_whitelist_sees_env_entries_before_the_command() {
        assert_eq!(
            command_with_env(None, None, "rsync -a /d/ b:/s/"),
            "rsync -a /d/ b:/s/"
        );
        assert_eq!(
            command_with_env(Some("/tmp/x y"), None, "./healthcheck.sh"),
            "cd -- '/tmp/x y' && ./healthcheck.sh"
        );
        assert_eq!(
            command_with_env(
                None,
                Some(&["RSYNC_RSH=sh -c 'id' x".to_string(), "DEBUG=1".to_string()]),
                "rsync -a /d/ b:/s/"
            ),
            r"RSYNC_RSH='sh -c '\''id'\'' x' DEBUG=1 rsync -a /d/ b:/s/"
        );
    }

    #[tokio::test]
    async fn an_env_entry_needs_its_own_whitelist_match() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^rsync -a /d/ b:/s/$"]);
        let args = |env: serde_json::Value| -> SshDockerExecArgs {
            serde_json::from_value(json!({
                "host": "server1", "container": "app", "command": "rsync -a /d/ b:/s/", "env": env
            }))
            .unwrap()
        };
        assert!(
            DockerExecTool::pre_execute(&args(json!([])), &ctx)
                .await
                .is_ok()
        );
        assert!(
            DockerExecTool::pre_execute(&args(json!(["RSYNC_RSH=sh -c id x"])), &ctx)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerExecHandler::new();
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
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "app", "command": "ls"})),
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
        let handler = SshDockerExecHandler::new();
        assert_eq!(handler.name(), "ssh_docker_exec");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "container": "app",
            "command": "ls -la /app",
            "user": "root",
            "workdir": "/app",
            "env": ["FOO=bar", "DEBUG=1"],
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "app");
        assert_eq!(args.command, "ls -la /app");
        assert_eq!(args.user, Some("root".to_string()));
        assert_eq!(
            args.env,
            Some(vec!["FOO=bar".to_string(), "DEBUG=1".to_string()])
        );
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "app", "command": "ls"});
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "app");
        assert_eq!(args.command, "ls");
        assert!(args.user.is_none());
        assert!(args.workdir.is_none());
        assert!(args.env.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "container": "app"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerExecHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("user"));
        assert!(properties.contains_key("workdir"));
        assert!(properties.contains_key("env"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "s1", "container": "app", "command": "ls"});
        let args: SshDockerExecArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerExecArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "container": "app", "command": "ls"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

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
    fn test_build_command_defaults() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("docker exec"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("ls"));
    }

    #[test]
    fn test_build_command_with_user_workdir() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: Some("root".to_string()),
            workdir: Some("/app".to_string()),
            env: None,
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("root"));
        assert!(cmd.contains("/app"));
    }

    #[test]
    fn test_build_command_with_env() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: Some(vec!["FOO=bar".to_string()]),
            docker_bin: Some("docker".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("FOO=bar"));
    }

    #[test]
    fn test_build_command_custom_bin() {
        let args = SshDockerExecArgs {
            host: "server1".to_string(),
            container: "nginx".to_string(),
            command: "ls".to_string(),
            user: None,
            workdir: None,
            env: None,
            docker_bin: Some("podman".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DockerExecTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("podman"));
    }

    #[tokio::test]
    async fn test_container_starting_with_dash_is_refused() {
        let handler = SshDockerExecHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_host();
        let err = handler
            .execute(
                Some(json!({"host": "server1", "container": "-x", "command": "ls"})),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("'container' must not start with '-'"),
            "{err}"
        );
    }

    #[test]
    fn test_env_entries_that_change_what_runs_are_refused() {
        for entry in [
            "BASH_FUNC_echo%%=() { cat /run/secrets/db_password; }",
            "BASH_FUNC_echo=x",
            "SHELLOPTS=xtrace",
            "PS4=$(id)",
            "LD_PRELOAD=/x.so",
            "path=/x",
            "PATH=/tmp",
            "BASH_ENV=/tmp/x",
            "IFS=x",
            "1BAD=x",
            "=x",
            "A B=x",
            "NOEQUALS",
            "",
        ] {
            let args: SshDockerExecArgs = serde_json::from_value(
                json!({"host": "h", "container": "c", "command": "echo ok", "env": [entry]}),
            )
            .unwrap();
            let result = DockerExecTool::validate(&args, &test_host_config());
            assert!(
                matches!(result, Err(BridgeError::CommandDenied { .. })),
                "{entry}: {result:?}"
            );
        }
    }

    #[test]
    fn test_ordinary_env_entries_pass() {
        let args: SshDockerExecArgs = serde_json::from_value(json!({
            "host": "h", "container": "c", "command": "echo ok",
            "env": ["FOO=bar", "DEBUG=1", "_X9=a=b", "EMPTY=", "MY_PATH=/x"]
        }))
        .unwrap();
        DockerExecTool::validate(&args, &test_host_config()).unwrap();
        let none: SshDockerExecArgs =
            serde_json::from_value(json!({"host": "h", "container": "c", "command": "ls"}))
                .unwrap();
        DockerExecTool::validate(&none, &test_host_config()).unwrap();
    }

    #[tokio::test]
    async fn test_command_outside_whitelist_is_denied() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let args: SshDockerExecArgs =
            serde_json::from_value(json!({"host": "server1", "container": "c", "command": "id"}))
                .unwrap();
        let result = DockerExecTool::pre_execute(&args, &ctx).await;
        assert!(
            matches!(result, Err(BridgeError::CommandDenied { .. })),
            "command must be whitelist-checked, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_whitelisted_command_is_allowed() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let args: SshDockerExecArgs = serde_json::from_value(
            json!({"host": "server1", "container": "c", "command": "echo ok"}),
        )
        .unwrap();
        let result = DockerExecTool::pre_execute(&args, &ctx).await;
        assert!(result.is_ok(), "got: {result:?}");
    }

    #[tokio::test]
    async fn a_command_starting_with_a_dash_is_refused() {
        let ctx = crate::ports::mock::create_test_context_with_host();
        let err = SshDockerExecHandler::new()
            .execute(
                Some(json!({"host": "server1", "container": "c", "command": "-s"})),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("'command' must not start with '-'"),
            "{err}"
        );
    }
}
