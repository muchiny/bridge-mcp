//! Handler for the `ssh_aws_cli` tool.
//!
//! Executes AWS CLI commands on a remote host, with the AWS identity of that
//! host (environment, `~/.aws`, instance role). The endpoint and the
//! credentials are never chosen by the caller: `args` takes an allow-list of
//! options, the services and operations that print or issue a credential are
//! refused, and the tool neither reads nor writes files of the host (a word
//! that is not an option must be an `s3://` location).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::cloud::CloudCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAwsCliArgs {
    /// Target host name from configuration.
    host: String,
    /// AWS service name (e.g. s3, ec2, iam).
    service: String,
    /// AWS CLI subcommand (e.g. describe-instances, list-buckets).
    subcommand: String,
    /// Additional arguments: whitespace-separated words, quotes group. Options
    /// come from an allow-list, spelled in full.
    #[serde(default)]
    args: Option<String>,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAwsCliArgs);

#[mcp_standard_tool(name = "ssh_aws_cli", group = "cloud", annotation = "destructive")]
pub struct AwsCliTool;

impl StandardTool for AwsCliTool {
    type Args = SshAwsCliArgs;

    const NAME: &'static str = "ssh_aws_cli";

    const DESCRIPTION: &'static str = "Execute AWS CLI commands on a remote host. Runs \
        'aws SERVICE SUBCOMMAND [ARGS] --output json' via SSH with the AWS identity and the \
        endpoint configured on that host — the --output json flag is appended automatically; \
        do NOT pass --output in args or jq_filter will fail on non-JSON text output. ARGS is \
        split into words (quotes group); options must be written in full and come from a \
        fixed list of resource selectors and paging options (--region, --query, --filters, \
        --instance-ids, --bucket, --prefix, --max-items, --no-paginate, ...; a refused call \
        lists them all). Options that choose the endpoint, profile, certificate checks or \
        request signing (--endpoint-url, --profile, --ca-bundle, --no-verify-ssl, \
        --no-sign-request, --debug, ...) and parameter values read from a file or URL \
        (file://, http://) are refused, as are the services configure, sso, sso-oidc, login, \
        logout and history and the operations that print or issue a credential (sts \
        get-session-token and assume-role, ecr get-login-password, eks get-token, s3 \
        presign, iam create-access-key, rds generate-db-auth-token, ...). The tool does not \
        read or write files of the host: a word of ARGS that is not an option or the value \
        of one must be an s3:// location (s3 cp and mv work between buckets), and the \
        operations that write an output file (s3api get-object, lambda invoke, ...) are \
        refused; use ssh_exec for transfers to or from the host. Use this only when \
        no specialized tool covers the operation: for read-only instance metadata use \
        ssh_cloud_metadata or ssh_cloud_tags, for cost data use ssh_cloud_cost (AWS only), \
        and for multi-cloud instance listing or comparison across AWS, GCP, and Azure prefer \
        ssh_multicloud_list or ssh_multicloud_compare.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "service": {
                        "type": "string",
                        "description": "AWS service name (e.g. s3, ec2, iam, lambda)"
                    },
                    "subcommand": {
                        "type": "string",
                        "description": "AWS CLI subcommand (e.g. describe-instances, list-buckets)"
                    },
                    "args": {
                        "type": "string",
                        "description": "Additional arguments, split into words (quotes group), e.g. '--region us-east-1 --instance-ids i-123' or \"--query 'Reservations[].Instances[].InstanceId'\". Options must be written in full and come from a fixed list of resource selectors and paging options; options that choose the endpoint, profile, certificate checks or request signing are refused. A word that is not an option or the value of one must be an s3:// location: files of the host are never read or written (use ssh_exec for transfers). Do NOT include --output here; --output json is appended automatically and overriding it will break jq_filter."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "service", "subcommand"]
            }"#;
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Json;

    fn validate(args: &SshAwsCliArgs, _host_config: &HostConfig) -> Result<()> {
        CloudCommandBuilder::validate_aws_service(&args.service)?;
        CloudCommandBuilder::validate_subcommand(&args.subcommand)?;
        CloudCommandBuilder::validate_aws_operation(&args.service, &args.subcommand)?;
        if let Some(extra) = args.args.as_deref() {
            CloudCommandBuilder::validate_aws_args(extra)?;
        }
        Ok(())
    }

    fn build_command(args: &SshAwsCliArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CloudCommandBuilder::build_aws_cli_command(
            &args.service,
            &args.subcommand,
            args.args.as_deref(),
        ))
    }
}

/// Handler for the `ssh_aws_cli` tool.
pub type SshAwsCliHandler = StandardToolHandler<AwsCliTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAwsCliHandler::new();
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
        let handler = SshAwsCliHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "service": "s3", "subcommand": "ls"})),
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
        let handler = SshAwsCliHandler::new();
        assert_eq!(handler.name(), "ssh_aws_cli");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_aws_cli");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("service")));
        assert!(required.contains(&json!("subcommand")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "service": "ec2",
            "subcommand": "describe-instances",
            "args": "--region us-east-1",
            "timeout_seconds": 30,
            "max_output": 10000,
            "save_output": "/tmp/aws.json"
        });
        let args: SshAwsCliArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service, "ec2");
        assert_eq!(args.subcommand, "describe-instances");
        assert_eq!(args.args.as_deref(), Some("--region us-east-1"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/aws.json"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "service": "s3", "subcommand": "ls"});
        let args: SshAwsCliArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service, "s3");
        assert_eq!(args.subcommand, "ls");
        assert!(args.args.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAwsCliHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("args"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "service": "s3", "subcommand": "ls"});
        let args: SshAwsCliArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAwsCliArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAwsCliHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "service": "s3", "subcommand": "ls"})),
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
    fn test_schema_has_type_object() {
        let handler = SshAwsCliHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshAwsCliHandler::new();
        assert!(handler.description().len() > 10);
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
        let handler = SshAwsCliHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        let result = handler
            .execute(
                Some(json!({"host": "server1", "service": "s3", "subcommand": "ls"})),
                &ctx,
            )
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
    }

    // ============== The host's identity and endpoint stay the host's ==============

    fn host_config() -> crate::config::HostConfig {
        server1_hosts().remove("server1").expect("server1")
    }

    fn call_args(service: &str, subcommand: &str, extra: Option<&str>) -> SshAwsCliArgs {
        let mut value = json!({"host": "server1", "service": service, "subcommand": subcommand});
        if let (Some(map), Some(extra)) = (value.as_object_mut(), extra) {
            map.insert("args".to_string(), json!(extra));
        }
        serde_json::from_value(value).expect("deserialize")
    }

    fn command_for(service: &str, subcommand: &str, extra: Option<&str>) -> String {
        let args = call_args(service, subcommand, extra);
        AwsCliTool::validate(&args, &host_config())
            .unwrap_or_else(|e| panic!("{service} {subcommand} {extra:?}: {e:?}"));
        AwsCliTool::build_command(&args, &host_config()).unwrap()
    }

    fn refusal_for(service: &str, subcommand: &str, extra: Option<&str>) -> String {
        let args = call_args(service, subcommand, extra);
        match AwsCliTool::validate(&args, &host_config()) {
            Err(BridgeError::CommandDenied { reason }) => reason,
            other => panic!("{service} {subcommand} {extra:?}: expected CommandDenied: {other:?}"),
        }
    }

    #[test]
    fn test_command_strings() {
        assert_eq!(
            command_for("s3", "ls", None),
            "aws 's3' 'ls' --output json 2>&1"
        );
        assert_eq!(
            command_for(
                "ec2",
                "describe-instances",
                Some("--region us-east-1 --instance-ids i-123")
            ),
            "aws 'ec2' 'describe-instances' '--region' 'us-east-1' '--instance-ids' 'i-123' \
             --output json 2>&1"
        );
        assert_eq!(
            command_for("sts", "get-caller-identity", Some("--query Account")),
            "aws 'sts' 'get-caller-identity' '--query' 'Account' --output json 2>&1"
        );
    }

    #[test]
    fn test_refuses_the_options_that_choose_the_destination_or_the_credentials() {
        for extra in [
            "--endpoint-url=http://rogue.example",
            "--endpoint-url http://rogue.example",
            "--endpoint=http://rogue.example",
            "--end=http://rogue.example",
            "--profile other",
            "--prof=other",
            "--ca-bundle /tmp/ca.pem",
            "--no-verify-ssl",
            "--no-sign-request",
            "--debug",
            "--region us-east-1 --endpoint-url=http://rogue.example",
        ] {
            let reason = refusal_for("ec2", "describe-instances", Some(extra));
            assert!(reason.contains("'args'"), "{extra}: {reason}");
            assert!(reason.contains("global option"), "{extra}: {reason}");
        }
    }

    #[test]
    fn test_s3_locations_are_accepted_and_quoted_one_word_each() {
        assert_eq!(
            command_for("s3", "ls", Some("s3://b/")),
            "aws 's3' 'ls' 's3://b/' --output json 2>&1"
        );
        assert_eq!(
            command_for("s3", "cp", Some("s3://a/k s3://b/k")),
            "aws 's3' 'cp' 's3://a/k' 's3://b/k' --output json 2>&1"
        );
        assert_eq!(
            command_for("s3", "rm", Some("--recursive s3://b/p/")),
            "aws 's3' 'rm' '--recursive' 's3://b/p/' --output json 2>&1"
        );
        assert_eq!(
            command_for(
                "s3",
                "ls",
                Some("--recursive --human-readable --summarize s3://b")
            ),
            "aws 's3' 'ls' '--recursive' '--human-readable' '--summarize' 's3://b' \
             --output json 2>&1"
        );
    }

    #[test]
    fn test_refuses_the_files_of_the_host() {
        for (service, subcommand, extra) in [
            ("s3", "cp", "/srv/x s3://b/k"),
            ("s3", "cp", "s3://b/k /srv/x"),
            ("s3", "cp", "--recursive /srv/d s3://b/"),
            ("s3", "mv", "s3://b/k /srv/x"),
            ("s3", "sync", "s3://b/ /srv/d"),
        ] {
            let reason = refusal_for(service, subcommand, Some(extra));
            assert!(reason.starts_with("'args'"), "{extra}: {reason}");
            assert!(
                reason.contains("does not read or write files of the host"),
                "{extra}: {reason}"
            );
            assert!(reason.contains("ssh_exec"), "{extra}: {reason}");
        }
        // The operations that write the `outfile` positional are refused
        // whatever the arguments.
        for (service, subcommand, extra) in [
            ("s3api", "get-object", "--bucket b --key k /srv/x"),
            ("s3api", "get-object", "--bucket b --key k"),
            ("s3api", "get-object-torrent", "--bucket b --key k /srv/x"),
            ("lambda", "invoke", "--function-name f /srv/out"),
            ("cloudfront", "get-function", "--name f /srv/out"),
            ("iotwireless", "get-position-estimate", "/srv/out"),
            ("apigateway", "get-api-keys", ""),
            ("apigateway", "get-api-keys", "--include"),
            ("apigateway", "get-api-key", "--include"),
        ] {
            let reason = refusal_for(service, subcommand, Some(extra));
            assert!(
                reason.contains("'subcommand'"),
                "{service} {subcommand}: {reason}"
            );
            assert!(
                reason.contains("ssh_exec"),
                "{service} {subcommand}: {reason}"
            );
        }
    }

    #[test]
    fn test_refuses_the_identity_services_and_the_credential_operations() {
        for service in ["configure", "sso", "sso-oidc", "login", "logout", "history"] {
            let reason = refusal_for(service, "get", None);
            assert!(reason.contains("'service'"), "{service}: {reason}");
        }
        for (service, subcommand) in [
            ("sts", "get-session-token"),
            ("sts", "get-federation-token"),
            ("sts", "assume-role"),
            ("ecr", "get-login-password"),
            ("ecr-public", "get-login-password"),
            ("codeartifact", "get-authorization-token"),
            ("eks", "get-token"),
            ("iam", "create-access-key"),
            ("s3", "presign"),
            ("rds", "generate-db-auth-token"),
        ] {
            let reason = refusal_for(service, subcommand, None);
            assert!(
                reason.contains("'subcommand'"),
                "{service} {subcommand}: {reason}"
            );
        }
    }

    #[test]
    fn test_refuses_parameters_loaded_from_a_file_or_a_url() {
        for extra in [
            "--instance-ids file:///srv/x",
            "--name fileb:///srv/x",
            "--name http://198.51.100.7/x",
        ] {
            let reason = refusal_for("ec2", "describe-instances", Some(extra));
            assert!(reason.contains("file://"), "{extra}: {reason}");
        }
    }

    #[tokio::test]
    async fn test_a_refused_call_sends_no_command() {
        let handler = SshAwsCliHandler::new();
        let ctx = permissive_ctx(mock_output("mock output"));
        for call in [
            json!({"host": "server1", "service": "ec2", "subcommand": "describe-instances",
                   "args": "--end=http://rogue.example"}),
            json!({"host": "server1", "service": "s3", "subcommand": "cp",
                   "args": "s3://b/k /srv/x"}),
            json!({"host": "server1", "service": "lambda", "subcommand": "invoke",
                   "args": "--function-name f /srv/out"}),
            json!({"host": "server1", "service": "configure", "subcommand": "get"}),
            json!({"host": "server1", "service": "eks", "subcommand": "get-token"}),
        ] {
            let result = handler.execute(Some(call.clone()), &ctx).await;
            assert!(
                matches!(result, Err(BridgeError::CommandDenied { .. })),
                "{call}: {result:?}"
            );
        }
        let calls = ctx.connection_pool.mock_calls();
        assert!(calls.is_empty(), "a refused call sent {calls:?}");
    }

    #[tokio::test]
    async fn test_an_allowed_call_runs_with_one_quoted_word_per_argument() {
        let handler = SshAwsCliHandler::new();
        let ctx = permissive_ctx(mock_output("{}"));
        handler
            .execute(
                Some(json!({"host": "server1", "service": "ec2",
                            "subcommand": "describe-instances",
                            "args": "--region us-east-1 --query 'Reservations[0]'"})),
                &ctx,
            )
            .await
            .unwrap();
        let calls = ctx.connection_pool.mock_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            "export LC_ALL=C; aws 'ec2' 'describe-instances' '--region' 'us-east-1' \
             '--query' 'Reservations[0]' --output json 2>&1"
        );
    }

    #[test]
    fn test_description_and_schema_state_the_rule() {
        let handler = SshAwsCliHandler::new();
        let description = handler.description();
        for needle in [
            "AWS identity",
            "--endpoint-url",
            "configure",
            "get-session-token",
        ] {
            assert!(description.contains(needle), "{needle}");
        }
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let args_doc = schema_json["properties"]["args"]["description"]
            .as_str()
            .unwrap();
        assert!(args_doc.contains("fixed list"), "{args_doc}");
    }
}
