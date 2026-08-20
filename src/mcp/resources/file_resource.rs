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

/// Parsed file URI components
struct FileUri {
    host: String,
    path: String,
}

/// Parse a file URI into its components.
///
/// Format: `file://{host}/{path}`
fn parse_file_uri(uri: &str) -> Result<FileUri> {
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
        Some("{path}")
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

        // Use cat to read file content
        let command = format!("cat {}", shell_escape(&parsed.path));

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

        if output.exit_code != 0 {
            return Err(BridgeError::FileTransfer {
                reason: format!(
                    "Failed to read file '{}': {}",
                    parsed.path,
                    output.stderr.trim()
                ),
            });
        }

        let mime = guess_mime(&parsed.path);

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some(mime.to_string()),
            text: Some(output.stdout),
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
        assert!(!handler.description().is_empty());
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
}
