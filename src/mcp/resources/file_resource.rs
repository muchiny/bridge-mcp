//! File Resource Handler
//!
//! Reads remote files via SSH `cat` command.
//! URI format: `file://{host}/{path}`
//!
//! For binary or large files, use `ssh_download` instead.

use async_trait::async_trait;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::mcp::tool_handlers::utils::shell_escape;
use crate::ports::{ResourceHandler, ToolContext};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Max path length to prevent abuse
const MAX_PATH_LEN: usize = 1024;

/// Resource handler for remote files
pub struct FileResourceHandler;

/// Parsed file URI components.
///
/// `path` is the value that reaches [`file_read_command`] — the ONE thing a
/// fuzz target must be handed rather than re-derive from the URI text. Every
/// oracle in this project that re-derived a parser's output from its input has
/// been wrong at least once; the parser is the authority on what it kept.
#[doc(hidden)]
pub struct FileUri {
    pub host: String,
    pub path: String,
}

/// Parse a file URI into its components.
///
/// Format: `file://{host}/{path}`
///
/// Note that this does NOT split a query string off the path, unlike
/// [`parse_log_uri`](crate::parse_log_uri): `file://h/a?b=c` reads a file
/// literally named `/a?b=c`. That asymmetry is deliberate — there is no
/// parameter for a `cat` to take — and it is why a fuzz oracle shared between
/// the two schemes would be red on healthy code.
///
/// # Errors
///
/// Returns [`BridgeError::McpInvalidRequest`] when the URI does not start with
/// `file://`, carries no `/` after the host, has an empty host, or yields a
/// path over `MAX_PATH_LEN`.
#[doc(hidden)]
pub fn parse_file_uri(uri: &str) -> Result<FileUri> {
    let rest = uri
        .strip_prefix("file://")
        .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Invalid file URI: {uri}")))?;

    let (host, path) = rest.split_once('/').ok_or_else(|| {
        BridgeError::McpInvalidRequest("file URI must include a path".to_string())
    })?;

    if host.is_empty() {
        return Err(BridgeError::McpInvalidRequest(
            "file URI host is empty".to_string(),
        ));
    }

    let full_path = format!("/{path}");

    if full_path.len() > MAX_PATH_LEN {
        return Err(BridgeError::McpInvalidRequest("Path too long".to_string()));
    }

    Ok(FileUri {
        host: host.to_string(),
        path: full_path,
    })
}

/// Build the `cat` command that reads `path`.
///
/// Extracted from `FileResourceHandler::read` so a fuzz target can reach the
/// command WITHOUT a `ToolContext`: `read` needs one, whose mock is
/// `#[cfg(test)]`, opens a real SSH connection, and never hands back the
/// command it built. Production calls this same function, so the target
/// measures the string that actually runs rather than a copy of it that could
/// drift.
///
/// `path` is interpolated through [`shell_escape`]; that call is the whole
/// safety property, and `fuzz_resource_uri` exists to assert it.
#[doc(hidden)]
#[must_use]
pub fn file_read_command(path: &str) -> String {
    format!("cat {}", shell_escape(path))
}

/// Guess MIME type from file extension
fn guess_mime(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("json") => "application/json",
        Some("yaml" | "yml") => "text/yaml",
        Some("xml") => "application/xml",
        Some("html" | "htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("csv") => "text/csv",
        Some("toml") => "text/toml",
        Some("sh" | "bash" | "zsh") => "text/x-shellscript",
        Some("py") => "text/x-python",
        Some("rs") => "text/x-rust",
        _ => "text/plain",
    }
}

#[async_trait]
impl ResourceHandler for FileResourceHandler {
    fn scheme(&self) -> &'static str {
        "file"
    }

    fn description(&self) -> &'static str {
        "Read remote files via SSH (file://{host}/{path})"
    }

    fn path_template(&self) -> Option<&'static str> {
        // MINOR (fix round 1, audit 2026-08-19): `{path}` is RFC 6570
        // *simple* expansion (section 3.2.2), which percent-encodes
        // reserved characters -- a conformant expander given
        // path="etc/hosts" would produce "etc%2Fhosts", which
        // `parse_file_uri`'s `split_once('/')` cannot route to a nested
        // path. `{+path}` is *reserved* expansion (section 3.2.3): slashes
        // pass through unencoded, matching what this template actually
        // needs.
        Some("{+path}")
    }

    async fn list(&self, _ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        // File resources are template-based; no concrete listing.
        Ok(Vec::new())
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let parsed = parse_file_uri(uri)?;

        let host_config =
            ctx.config
                .hosts
                .get(&parsed.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: parsed.host.clone(),
                })?;

        // `cat`/`tail` with a POSIX-quoted path: anywhere else the quoting
        // does not hold and the URI's path would become a command.
        if let Some(reason) =
            crate::mcp::tool_handlers::utils::posix_only_refusal(host_config, "file:// resource")
        {
            ctx.execute_use_case
                .log_denied("file://", &parsed.host, "", &reason);
            return Err(BridgeError::McpInvalidRequest(reason));
        }

        // A resource read reads a file like `ssh_file_read`, so the client's
        // workspace roots bound it the same way when they are known.
        // `resources/read` itself asks no `roots/list` today, so `ctx.roots`
        // is empty on that path and this check passes: it applies to a
        // caller that fills them.
        if let Err(e) = ctx.validate_root_scope(&parsed.path) {
            ctx.execute_use_case
                .log_denied("file://", &parsed.host, "", &e.to_string());
            return Err(e);
        }

        // Use cat to read file content
        let command = file_read_command(&parsed.path);

        // Validate command, audited like a tool's free-form command.
        crate::mcp::standard_tool::validate_free_form_command(
            ctx,
            "file://",
            &parsed.host,
            &command,
        )?;

        // Check rate limit
        if ctx.rate_limiter.check(&parsed.host).is_err() {
            return Err(BridgeError::RateLimitExceeded {
                host: parsed.host.clone(),
            });
        }

        let limits = ctx.config.limits.clone();
        let retry_config = limits.retry_config();

        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jc| (jump_name.as_str(), jc))
        });

        let output = with_retry_if(
            &retry_config,
            "file_resource",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&parsed.host, host_config, &limits, jump_host)
                    .await?;

                match conn.exec(&command, &limits).await {
                    Ok(out) => Ok(out),
                    Err(e) => {
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            is_retryable_error,
        )
        .await?;

        // Sanitized, audited and recorded like any tool output: a resource is
        // not a side door around the secret filters.
        let output: crate::ports::CommandOutput = output.into();
        let response =
            ctx.execute_use_case
                .process_success("file://", &parsed.host, &command, &output, &[]);

        if output.exit_code != 0 {
            return Err(BridgeError::FileTransfer {
                reason: format!(
                    "Failed to read file '{}': {}",
                    parsed.path,
                    response.stderr.trim()
                ),
            });
        }

        let mime = guess_mime(&parsed.path);

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some(mime.to_string()),
            text: Some(response.stdout),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme() {
        let handler = FileResourceHandler;
        assert_eq!(handler.scheme(), "file");
        assert_ne!(handler.description(), "");
    }

    #[test]
    fn test_parse_file_uri_basic() {
        let parsed = parse_file_uri("file://server1/etc/nginx/nginx.conf").unwrap();
        assert_eq!(parsed.host, "server1");
        assert_eq!(parsed.path, "/etc/nginx/nginx.conf");
    }

    #[test]
    fn test_parse_file_uri_nested_path() {
        let parsed = parse_file_uri("file://web1/var/log/app/error.log").unwrap();
        assert_eq!(parsed.host, "web1");
        assert_eq!(parsed.path, "/var/log/app/error.log");
    }

    #[test]
    fn test_parse_file_uri_invalid_scheme() {
        let result = parse_file_uri("log://server1/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_file_uri_no_path() {
        let result = parse_file_uri("file://server1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_file_uri_empty_host() {
        let result = parse_file_uri("file:///etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_guess_mime() {
        assert_eq!(guess_mime("/etc/config.json"), "application/json");
        assert_eq!(guess_mime("/app/config.yaml"), "text/yaml");
        assert_eq!(guess_mime("/app/config.yml"), "text/yaml");
        assert_eq!(guess_mime("/var/log/syslog"), "text/plain");
        assert_eq!(guess_mime("/app/main.rs"), "text/x-rust");
        assert_eq!(guess_mime("/app/script.sh"), "text/x-shellscript");
    }

    use crate::mcp::tool_handlers::utils::guard_test_support::context_with_target;

    /// The reason the resource refused `target`, which it must do before
    /// dialing it (the timeout turns a missing guard into a failure).
    async fn refusal(ctx: &crate::ports::ToolContext) -> String {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            FileResourceHandler.read("file://target/etc/hosts", ctx),
        )
        .await
        .expect("the resource must refuse without dialing the host");
        let reason = match result {
            Err(BridgeError::McpInvalidRequest(reason)) => reason,
            other => panic!("expected McpInvalidRequest, got: {other:?}"),
        };
        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].event_type, "command_denied");
        assert_eq!(events[0].tool_name.as_deref(), Some("file://"));
        assert_eq!(events[0].host, "target");
        reason
    }

    /// The path is POSIX-quoted for `cat`/`tail`; on a Windows host that
    /// quoting does not hold and the URI's path would become a command.
    #[tokio::test]
    async fn test_read_refuses_a_windows_host() {
        let reason = refusal(&context_with_target("windows", "")).await;
        assert!(reason.contains("Windows"), "{reason}");
    }

    #[tokio::test]
    async fn test_read_refuses_a_host_whose_shell_is_powershell() {
        let reason = refusal(&context_with_target("linux", r#","shell":"powershell""#)).await;
        assert!(reason.contains("PowerShell"), "{reason}");
    }

    #[tokio::test]
    async fn test_list_returns_empty() {
        let handler = FileResourceHandler;
        let ctx = crate::ports::mock::create_test_context();

        let resources = handler.list(&ctx).await.unwrap();
        assert!(resources.is_empty());
    }

    #[test]
    fn test_parse_file_uri_path_too_long() {
        let long_path = "a".repeat(MAX_PATH_LEN + 10);
        let uri = format!("file://server1/{long_path}");
        let result = parse_file_uri(&uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_guess_mime_all_extensions() {
        assert_eq!(guess_mime("/app/index.html"), "text/html");
        assert_eq!(guess_mime("/app/index.htm"), "text/html");
        assert_eq!(guess_mime("/app/style.css"), "text/css");
        assert_eq!(guess_mime("/app/script.js"), "application/javascript");
        assert_eq!(guess_mime("/app/data.csv"), "text/csv");
        assert_eq!(guess_mime("/app/config.toml"), "text/toml");
        assert_eq!(guess_mime("/app/data.xml"), "application/xml");
        assert_eq!(guess_mime("/app/script.bash"), "text/x-shellscript");
        assert_eq!(guess_mime("/app/script.zsh"), "text/x-shellscript");
        assert_eq!(guess_mime("/app/main.py"), "text/x-python");
        assert_eq!(guess_mime("/app/unknown.xyz"), "text/plain");
    }

    /// The `cat` line, spelled out.
    ///
    /// `cargo mutants` replaced the whole body with `"xyzzy".into()` and every
    /// test in this file stayed green: extracting the builder out of `read`
    /// gave the fuzz target something to call, and left the unit suite with
    /// nothing asserting what it produces. The fuzzer covers it nightly; this
    /// covers it on every PR.
    #[test]
    fn the_cat_command_is_the_path_quoted_and_nothing_else() {
        assert_eq!(file_read_command("/etc/hosts"), "cat '/etc/hosts'");
    }

    /// The escape is the safety property, so it is asserted on a path that
    /// needs it rather than on one that does not.
    #[test]
    fn a_hostile_path_is_one_quoted_word_to_cat() {
        assert_eq!(
            file_read_command("/tmp/a'; id #"),
            r"cat '/tmp/a'\''; id #'",
            "a `;` reaching the shell here is a command injection, not a filename"
        );
    }

    /// A context whose Linux host `target` answers every command with
    /// `stdout`, in permissive mode so the read command passes validation.
    fn reading_context(stdout: &str) -> crate::ports::ToolContext {
        let mut config = (*context_with_target("linux", "").config).clone();
        config.security.mode = crate::config::SecurityMode::Permissive;
        crate::ports::mock::create_test_context_with_config_and_mock_executor(
            config,
            crate::ssh::CommandOutput {
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
                duration_ms: 1,
            },
        )
    }

    /// The content goes through the sanitizer and leaves an audit event, like
    /// the output of any tool.
    #[tokio::test]
    async fn test_read_sanitizes_and_audits_the_content() {
        let ctx = reading_context("password=secret123\n");
        let content = FileResourceHandler
            .read("file://target/etc/hosts", &ctx)
            .await
            .expect("the read succeeds");
        let text = content[0].text.as_deref().unwrap_or_default();
        assert!(!text.contains("secret123"), "{text}");
        assert!(text.contains("[REDACTED]"), "{text}");
        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].tool_name.as_deref(), Some("file://"));
        assert_eq!(events[0].host, "target");
    }

    /// A path outside the client's workspace roots is refused and audited.
    #[tokio::test]
    async fn test_read_refuses_a_path_outside_the_roots() {
        let mut ctx = reading_context("x");
        ctx.roots = vec![crate::mcp::protocol::RootEntry {
            uri: "file:///srv".to_string(),
            name: None,
        }];
        let result = FileResourceHandler
            .read("file://target/etc/hosts", &ctx)
            .await;
        assert!(result.is_err(), "{result:?}");
        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].event_type, "command_denied");
        assert!(
            ctx.connection_pool.mock_calls().is_empty(),
            "nothing was sent"
        );
    }

    /// A read the whitelist refuses leaves an audit event, like a refused
    /// tool command.
    #[tokio::test]
    async fn a_read_the_whitelist_refuses_is_audited() {
        let ctx = crate::ports::mock::create_test_context_with_whitelist(&["^echo"]);
        let result = FileResourceHandler
            .read("file://server1/etc/hosts", &ctx)
            .await;
        assert!(
            matches!(result, Err(BridgeError::CommandDenied { .. })),
            "{result:?}"
        );
        let events = ctx.audit_logger.drain_for_test();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].event_type, "command_denied");
        assert_eq!(events[0].tool_name.as_deref(), Some("file://"));
        assert_eq!(events[0].host, "server1");
        assert!(events[0].command.contains("/etc/hosts"), "{events:?}");
    }
}
