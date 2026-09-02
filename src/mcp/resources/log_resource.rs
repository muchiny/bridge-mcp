//! Log Resource Handler
//!
//! Reads remote log files via `tail`.
//! URI format: `log://{host}/{path}?lines={n}`

use async_trait::async_trait;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::mcp::tool_handlers::utils::shell_escape;
use crate::ports::{ResourceHandler, ToolContext};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Default number of lines to tail
const DEFAULT_LINES: u64 = 100;

/// Max file path length to prevent abuse
const MAX_PATH_LEN: usize = 1024;

/// Resource handler for remote log files
pub struct LogResourceHandler;

/// Parsed log URI components.
///
/// `path` and `lines` are the two values that reach [`log_tail_command`] — the
/// things a fuzz target must be handed rather than re-derive from the URI
/// text, since the parser is the authority on what it kept.
#[doc(hidden)]
pub struct LogUri {
    pub host: String,
    pub path: String,
    pub lines: u64,
}

/// Parse a log URI into its components.
///
/// Format: `log://{host}/{path}?lines={n}`
///
/// Unlike [`parse_file_uri`](crate::parse_file_uri), this DOES cut the path at
/// the first `?`, because `lines` is a real parameter here. The two schemes
/// therefore disagree about `h/a?b=c`, which is why a fuzz oracle shared
/// between them would be red on healthy code.
///
/// # Errors
///
/// Returns [`BridgeError::McpInvalidRequest`] when the URI does not start with
/// `log://`, carries no `/` after the host, has an empty host, or yields a
/// path over `MAX_PATH_LEN`.
#[doc(hidden)]
pub fn parse_log_uri(uri: &str) -> Result<LogUri> {
    let rest = uri
        .strip_prefix("log://")
        .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Invalid log URI: {uri}")))?;

    // Split host from path
    let (host, path_with_query) = rest
        .split_once('/')
        .ok_or_else(|| BridgeError::McpInvalidRequest("log URI must include a path".to_string()))?;

    if host.is_empty() {
        return Err(BridgeError::McpInvalidRequest(
            "log URI host is empty".to_string(),
        ));
    }

    // Split path from query string
    let (path, lines) = if let Some((path, query)) = path_with_query.split_once('?') {
        let lines = query
            .split('&')
            .find_map(|param| {
                let (key, val) = param.split_once('=')?;
                if key == "lines" {
                    val.parse::<u64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(DEFAULT_LINES);
        (path, lines)
    } else {
        (path_with_query, DEFAULT_LINES)
    };

    let full_path = format!("/{path}");

    if full_path.len() > MAX_PATH_LEN {
        return Err(BridgeError::McpInvalidRequest("Path too long".to_string()));
    }

    Ok(LogUri {
        host: host.to_string(),
        path: full_path,
        lines,
    })
}

/// Build the `tail` command that reads the last `lines` lines of `path`.
///
/// Extracted from `LogResourceHandler::read` for the same reason as
/// [`file_read_command`](crate::file_read_command): `read` needs a
/// `ToolContext` whose mock is `#[cfg(test)]`, opens a real SSH connection,
/// and never hands back the command it built. Production calls this function,
/// so a fuzz target measures the string that actually runs.
///
/// `lines` is a `u64` and cannot carry shell syntax; `path` can, and is
/// interpolated through [`shell_escape`]. That call is the whole safety
/// property, and `fuzz_resource_uri` exists to assert it.
#[doc(hidden)]
#[must_use]
pub fn log_tail_command(lines: u64, path: &str) -> String {
    format!("tail -n {lines} {}", shell_escape(path))
}

#[async_trait]
impl ResourceHandler for LogResourceHandler {
    fn scheme(&self) -> &'static str {
        "log"
    }

    fn description(&self) -> &'static str {
        "Tail remote log files (log://{host}/{path}?lines=N)"
    }

    fn path_template(&self) -> Option<&'static str> {
        // MINOR (fix round 1, audit 2026-08-19): see the matching comment
        // in `file_resource.rs` -- `{+path}` (RFC 6570 reserved expansion)
        // passes slashes through unencoded, unlike `{path}` (simple
        // expansion), which is required for a nested path to round-trip.
        Some("{+path}")
    }

    async fn list(&self, _ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        // Log resources are template-based; no concrete listing.
        Ok(Vec::new())
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let parsed = parse_log_uri(uri)?;

        let host_config =
            ctx.config
                .hosts
                .get(&parsed.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: parsed.host.clone(),
                })?;

        // Build tail command
        let command = log_tail_command(parsed.lines, &parsed.path);

        // Validate command
        ctx.execute_use_case.validate(&command)?;

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
            "log_resource",
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

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(output.stdout),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme() {
        let handler = LogResourceHandler;
        assert_eq!(handler.scheme(), "log");
        assert!(!handler.description().is_empty());
    }

    #[test]
    fn test_parse_log_uri_basic() {
        let parsed = parse_log_uri("log://server1/var/log/syslog").unwrap();
        assert_eq!(parsed.host, "server1");
        assert_eq!(parsed.path, "/var/log/syslog");
        assert_eq!(parsed.lines, DEFAULT_LINES);
    }

    #[test]
    fn test_parse_log_uri_with_lines() {
        let parsed = parse_log_uri("log://server1/var/log/syslog?lines=50").unwrap();
        assert_eq!(parsed.host, "server1");
        assert_eq!(parsed.path, "/var/log/syslog");
        assert_eq!(parsed.lines, 50);
    }

    #[test]
    fn test_parse_log_uri_invalid_scheme() {
        let result = parse_log_uri("file://server1/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_log_uri_no_path() {
        let result = parse_log_uri("log://server1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_log_uri_empty_host() {
        let result = parse_log_uri("log:///var/log/syslog");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_returns_empty() {
        let handler = LogResourceHandler;
        let ctx = crate::ports::mock::create_test_context();

        let resources = handler.list(&ctx).await.unwrap();
        assert!(resources.is_empty());
    }

    #[test]
    fn test_parse_log_uri_path_too_long() {
        let long_path = "a".repeat(MAX_PATH_LEN + 10);
        let uri = format!("log://server1/{long_path}");
        let result = parse_log_uri(&uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_log_uri_with_extra_query_params() {
        let parsed = parse_log_uri("log://server1/var/log/syslog?lines=25&follow=true").unwrap();
        assert_eq!(parsed.lines, 25);
        assert_eq!(parsed.path, "/var/log/syslog");
    }

    #[test]
    fn test_parse_log_uri_invalid_lines_value() {
        // Non-numeric lines should fall back to default
        let parsed = parse_log_uri("log://server1/var/log/syslog?lines=abc").unwrap();
        assert_eq!(parsed.lines, DEFAULT_LINES);
    }

    #[test]
    fn test_parse_log_uri_nested_path() {
        // Nested path segments must be preserved verbatim under the leading slash
        let parsed = parse_log_uri("log://web1/var/log/nginx/access.log").unwrap();
        assert_eq!(parsed.host, "web1");
        assert_eq!(parsed.path, "/var/log/nginx/access.log");
        assert_eq!(parsed.lines, DEFAULT_LINES);
    }

    #[test]
    fn test_parse_log_uri_query_without_lines_param() {
        // Query string present but no `lines=` key → default lines
        let parsed = parse_log_uri("log://server1/var/log/syslog?follow=true").unwrap();
        assert_eq!(parsed.lines, DEFAULT_LINES);
        assert_eq!(parsed.path, "/var/log/syslog");
    }

    #[test]
    fn test_parse_log_uri_lines_zero() {
        // Zero is a valid u64 and must not be coerced to the default
        let parsed = parse_log_uri("log://server1/var/log/syslog?lines=0").unwrap();
        assert_eq!(parsed.lines, 0);
    }

    #[test]
    fn test_parse_log_uri_root_path() {
        // A trailing slash with an empty segment resolves to the root "/"
        let parsed = parse_log_uri("log://server1/").unwrap();
        assert_eq!(parsed.host, "server1");
        assert_eq!(parsed.path, "/");
        assert_eq!(parsed.lines, DEFAULT_LINES);
    }

    #[test]
    fn test_parse_log_uri_path_at_max_boundary() {
        // full_path = "/" + path, so a path of MAX_PATH_LEN-1 yields exactly MAX_PATH_LEN
        let path = "a".repeat(MAX_PATH_LEN - 1);
        let uri = format!("log://server1/{path}");
        let parsed = parse_log_uri(&uri).unwrap();
        assert_eq!(parsed.path.len(), MAX_PATH_LEN);
    }

    #[test]
    fn test_parse_log_uri_path_one_over_boundary() {
        // full_path length MAX_PATH_LEN + 1 must be rejected
        let path = "a".repeat(MAX_PATH_LEN);
        let uri = format!("log://server1/{path}");
        assert!(parse_log_uri(&uri).is_err());
    }

    #[test]
    fn test_description_mentions_uri_template() {
        let handler = LogResourceHandler;
        assert!(handler.description().contains("log://"));
    }

    #[tokio::test]
    async fn test_read_rejects_invalid_uri() {
        let handler = LogResourceHandler;
        let ctx = crate::ports::mock::create_test_context();
        let result = handler.read("file://server1/etc/passwd", &ctx).await;
        assert!(matches!(result, Err(BridgeError::McpInvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_read_unknown_host() {
        let handler = LogResourceHandler;
        let ctx = crate::ports::mock::create_test_context();
        // URI parses fine but no such host is configured
        let result = handler.read("log://ghost/var/log/syslog", &ctx).await;
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "ghost"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }
}
