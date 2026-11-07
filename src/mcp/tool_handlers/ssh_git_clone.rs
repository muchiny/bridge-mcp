//! SSH Git Clone Tool Handler
//!
//! Clones a Git repository on a remote host via `git clone`.
//!
//! The URL is the caller's choice. Credentials keyed by host (a credential
//! helper, a `~/.netrc` `machine` entry, `http.<url>.extraHeader`) are used
//! for the server they name; an unscoped `http.extraHeader` and the
//! `GIT_SSL_CERT` / `GIT_SSL_KEY` client certificate variables of the host
//! are not sent. An unscoped `http.sslCert` / `http.sslKey`, a credential
//! helper that answers for any host and a `~/.netrc` `default` entry are
//! presented to the URL (see `domain::use_cases::git`).
//!
//! `destination` must be an absolute path none of whose components starts with
//! `.`, and when it is absent the directory name that git derives from the URL
//! must not start with `.` (nor be empty), and the URL must hold no whitespace
//! or control byte (git rewrites those in the name it derives): the clone would
//! otherwise create or fill hidden configuration directories of the SSH user
//! (`~/.ssh`, `~/.config`, ...). The rule refuses a superset of what git would
//! create, and does not cover everything: see `domain::use_cases::git`.
//!
//! The tool is annotated `destructive`, so the confirmation policy
//! (`security.require_elicitation_on_destructive`) asks before a clone: it
//! fills a directory with files chosen by whoever controls the repository.
//! Git runs with `-c safe.bareRepository=explicit` (Git 2.38 and later; an
//! older git ignores it).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshGitCloneArgs {
    host: String,
    url: String,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    depth: Option<u32>,
    #[serde(default)]
    single_branch: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitCloneArgs);

#[mcp_standard_tool(name = "ssh_git_clone", group = "git", annotation = "destructive")]
pub struct GitCloneTool;

impl StandardTool for GitCloneTool {
    type Args = SshGitCloneArgs;

    const NAME: &'static str = "ssh_git_clone";

    const DESCRIPTION: &'static str = "Clone a Git repository on a remote host. Supports shallow clones (--depth), branch \
        selection (--branch), and single-branch mode. The URL can be HTTPS or SSH. An unscoped \
        http.extraHeader and the GIT_SSL_CERT / GIT_SSL_KEY client certificate variables of \
        the host are not sent; credentials keyed by host (credential helper, ~/.netrc machine \
        entry, http.<url>.extraHeader) still apply. An unscoped http.sslCert / http.sslKey in \
        the host's git config, a credential helper that answers for any host and a ~/.netrc \
        default entry are presented to the URL: operators avoid them on hosts exposed to \
        these tools. `destination` must be an absolute path with no component starting with '.' \
        (a hidden directory such as ~/.ssh or ~/.config is refused); when it is omitted, the \
        directory name git derives from the URL must not start with '.' (and the URL must hold \
        no whitespace or control character in that case). Git runs with \
        safe.bareRepository=explicit. The tool asks for confirmation (destructive).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "url": {
                "type": "string",
                "description": "Repository URL to clone (HTTPS or SSH)"
            },
            "destination": {
                "type": "string",
                "description": "Target directory on the remote host: an absolute path (starting with '/', '~' is not expanded) with no component starting with '.'. Default: the name git derives from the URL, which must not start with '.' (the URL must then hold no whitespace or control character). For a hidden target such as ~/.dotfiles, use ssh_exec."
            },
            "branch": {
                "type": "string",
                "description": "Branch to clone (maps to --branch, default: default branch)"
            },
            "depth": {
                "type": "integer",
                "description": "Create a shallow clone with N commits (maps to --depth)",
                "minimum": 1
            },
            "single_branch": {
                "type": "boolean",
                "description": "Clone only the specified branch (default: false)"
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
        "required": ["host", "url"]
    }"#;

    fn validate(args: &SshGitCloneArgs, _host_config: &HostConfig) -> Result<()> {
        GitCommandBuilder::validate_not_option("url", Some(args.url.as_str()))?;
        GitCommandBuilder::validate_not_option("branch", args.branch.as_deref())?;
        GitCommandBuilder::validate_clone_destination(args.destination.as_deref(), &args.url)
    }

    fn build_command(args: &SshGitCloneArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_clone_command(
            &args.url,
            args.destination.as_deref(),
            args.branch.as_deref(),
            args.depth,
            args.single_branch.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_git_clone` tool.
pub type SshGitCloneHandler = StandardToolHandler<GitCloneTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitCloneHandler::new();
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
        let handler = SshGitCloneHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "url": "https://github.com/user/repo.git"})),
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
        let handler = SshGitCloneHandler::new();
        assert_eq!(handler.name(), "ssh_git_clone");
        assert_ne!(handler.description(), "");
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_clone");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("url")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "url": "https://github.com/user/repo.git",
            "destination": "/opt/myrepo",
            "branch": "develop",
            "depth": 1,
            "single_branch": true
        });
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.url, "https://github.com/user/repo.git");
        assert_eq!(args.destination, Some("/opt/myrepo".to_string()));
        assert_eq!(args.depth, Some(1));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "url": "https://github.com/user/repo.git"});
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.destination.is_none());
        assert!(args.depth.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitCloneHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("destination"));
        assert!(properties.contains_key("branch"));
        assert!(properties.contains_key("depth"));
        assert!(properties.contains_key("single_branch"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "url": "https://github.com/user/repo.git"});
        let args: SshGitCloneArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitCloneArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitCloneHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "url": "https://github.com/user/repo.git"})),
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
            ansible: None,
        }
    }

    #[test]
    fn test_description_states_the_residual_credential_sources() {
        for needle in ["GIT_SSL_CERT", "http.sslCert", "any host", "~/.netrc"] {
            assert!(GitCloneTool::DESCRIPTION.contains(needle), "{needle}");
        }
    }

    #[test]
    fn test_build_command_golden() {
        let args: SshGitCloneArgs = serde_json::from_value(json!({
            "host": "s", "url": "https://git.example.org/o/r.git", "destination": "/opt/r",
            "branch": "main", "depth": 1, "single_branch": true
        }))
        .unwrap();
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone --branch 'main' \
             --depth 1 --single-branch -- 'https://git.example.org/o/r.git' '/opt/r'"
        );
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshGitCloneArgs {
            host: "s".to_string(),
            url: "https://github.com/user/repo.git".to_string(),
            destination: None,
            branch: None,
            depth: None,
            single_branch: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone \
             -- 'https://github.com/user/repo.git'"
        );
    }

    #[test]
    fn test_build_command_with_branch_depth() {
        let args = SshGitCloneArgs {
            host: "s".to_string(),
            url: "git@github.com:user/repo.git".to_string(),
            destination: Some("/opt/repo".to_string()),
            branch: Some("develop".to_string()),
            depth: Some(1),
            single_branch: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone --branch 'develop' \
             --depth 1 --single-branch -- 'git@github.com:user/repo.git' '/opt/repo'"
        );
    }

    #[test]
    fn test_validate_refuses_option_shaped_url_and_branch() {
        for key in ["url", "branch"] {
            let mut v = json!({"host": "s", "url": "ssh://x/y"});
            v[key] = json!("--upload-pack=touch /tmp/p");
            let args: SshGitCloneArgs = serde_json::from_value(v).unwrap();
            let err = GitCloneTool::validate(&args, &test_host_config()).unwrap_err();
            assert!(err.to_string().contains(&format!("'{key}'")), "{err}");
        }
    }

    fn clone_args(destination: Option<&str>, url: &str) -> SshGitCloneArgs {
        let mut v = json!({"host": "s", "url": url});
        if let Some(d) = destination {
            v["destination"] = json!(d);
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn test_description_and_schema_state_the_destination_rule() {
        for needle in [
            "absolute path",
            "no component starting with '.'",
            "derives from the URL must not start with '.'",
            "whitespace or control character",
            "asks for confirmation (destructive)",
            "safe.bareRepository=explicit",
        ] {
            assert!(GitCloneTool::DESCRIPTION.contains(needle), "{needle}");
        }
        let schema: serde_json::Value = serde_json::from_str(GitCloneTool::SCHEMA).unwrap();
        let text = schema["properties"]["destination"]["description"]
            .as_str()
            .unwrap();
        for needle in [
            "absolute path",
            "'~' is not expanded",
            "no component starting with '.'",
            "must not start with '.'",
            "ssh_exec",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
    }

    #[test]
    fn test_validate_accepts_an_absolute_destination_and_visible_derived_names() {
        let host = test_host_config();
        for (destination, url) in [
            (Some("/srv/repos/name"), "https://git.example.org/o/r.git"),
            (Some("/opt/r"), "ssh://x/y"),
            (None, "https://git.example.org/o/r.git"),
            (None, "git@github.com:user/repo.git"),
            (Some("/srv/x"), "https://git.example.org/o/.cfg"),
        ] {
            GitCloneTool::validate(&clone_args(destination, url), &host)
                .unwrap_or_else(|e| panic!("{destination:?} {url}: {e}"));
        }
    }

    #[test]
    fn test_validate_refuses_a_relative_destination() {
        let host = test_host_config();
        for destination in ["rel", "~/x", "", "./x"] {
            let err = GitCloneTool::validate(&clone_args(Some(destination), "ssh://x/y"), &host)
                .unwrap_err();
            assert!(
                matches!(err, BridgeError::CommandDenied { .. }),
                "{destination:?}: {err:?}"
            );
            assert_eq!(
                err.to_string(),
                "Command denied: 'destination' must be an absolute path (start with '/'): a \
                 relative path is resolved against the SSH user's home directory and '~' is \
                 not expanded. Use the full path, for example /srv/repos/name",
                "{destination:?}"
            );
        }
    }

    #[test]
    fn test_validate_refuses_a_hidden_destination_component() {
        let host = test_host_config();
        for (destination, component) in [
            ("/home/u/.ssh", ".ssh"),
            ("/home/u/.config/git", ".config"),
            ("/a/../b", ".."),
            ("/a/./b", "."),
        ] {
            let err = GitCloneTool::validate(&clone_args(Some(destination), "ssh://x/y"), &host)
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "Command denied: 'destination' must not contain a component starting with \
                     '.' ('{component}'): the clone would create or fill hidden configuration \
                     directories (~/.ssh, ~/.config, ...). Choose a path without hidden \
                     components; for a hidden target, use ssh_exec"
                ),
                "{destination:?}"
            );
        }
    }

    #[test]
    fn test_validate_refuses_a_hidden_name_derived_from_the_url() {
        let host = test_host_config();
        for (url, derived) in [("https://h/r/.cfg", ".cfg"), ("host:.x", ".x")] {
            let err = GitCloneTool::validate(&clone_args(None, url), &host).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "Command denied: 'destination' is not set and the directory git derives \
                     from 'url' ('{derived}') starts with '.': the clone would create a hidden \
                     directory. Set 'destination' to an absolute path, for example \
                     /srv/repos/name"
                ),
                "{url:?}"
            );
        }
    }

    #[test]
    fn test_validate_refuses_the_urls_git_turns_into_a_hidden_name() {
        // git 2.56 creates `.ssh` for each of these (see `domain::use_cases::git`).
        let host = test_host_config();
        for url in [
            "https://attacker.example/.ssh/ ",
            "https://attacker.example/.ssh/\t",
            "https://attacker.example/\u{1}.ssh",
            "https://x@.ssh",
        ] {
            let err = GitCloneTool::validate(&clone_args(None, url), &host).unwrap_err();
            assert!(
                matches!(err, BridgeError::CommandDenied { .. }),
                "{url:?}: {err:?}"
            );
            assert!(
                err.to_string().contains("'destination' is not set"),
                "{err}"
            );
            // With a visible destination the same URLs are fine.
            GitCloneTool::validate(&clone_args(Some("/srv/x"), url), &host)
                .unwrap_or_else(|e| panic!("{url:?}: {e}"));
        }
    }

    #[test]
    fn test_build_command_destination_after_double_dash() {
        let args: SshGitCloneArgs = serde_json::from_value(
            json!({"host": "s", "url": "ssh://x/y", "destination": "--config=a=b"}),
        )
        .unwrap();
        let cmd = GitCloneTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("-- 'ssh://x/y' '--config=a=b'"), "{cmd}");
    }
}
