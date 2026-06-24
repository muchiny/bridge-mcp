//! AWX Command Builder
//!
//! Builds `curl` commands for AWX REST API calls, relayed through SSH
//! to reach AWX instances in air-gapped environments.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Percent-encode a query-string component per RFC 3986 (unreserved set kept
/// verbatim, everything else `%XX`).
///
/// Applied to query keys and values in [`AwxCommandBuilder::build_api_call`] so
/// a filter value containing `&`, `=`, space, `#` or `+` cannot corrupt the
/// query or inject an extra AWX parameter (HTTP parameter injection).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Extract a human-readable error message from an AWX JSON error body.
///
/// AWX surfaces errors as `{"detail": "..."}` (auth/404) or as field maps like
/// `{"<field>": ["msg", ...]}` / `{"__all__": ["msg"]}` (400 validation). Falls
/// back to the trimmed body (capped) when the shape is unrecognized.
fn extract_detail(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(d) = v.get("detail").and_then(serde_json::Value::as_str) {
            return d.to_string();
        }
        if let Some(obj) = v.as_object() {
            let mut parts = Vec::new();
            for (k, val) in obj {
                match val {
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                parts.push(format!("{k}: {s}"));
                            }
                        }
                    }
                    serde_json::Value::String(s) => parts.push(format!("{k}: {s}")),
                    _ => {}
                }
            }
            if !parts.is_empty() {
                return parts.join("; ");
            }
        }
    }
    let trimmed = body.trim();
    let capped: String = trimmed.chars().take(300).collect();
    if trimmed.chars().count() > 300 {
        format!("{capped}…")
    } else {
        capped
    }
}

/// HTTP methods for AWX API calls.
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

impl HttpMethod {
    /// Returns the curl flag for this method.
    fn as_curl_flag(self) -> &'static str {
        match self {
            Self::Get => "-X GET",
            Self::Post => "-X POST",
            Self::Delete => "-X DELETE",
        }
    }
}

/// Builds curl commands for AWX REST API calls.
pub struct AwxCommandBuilder;

impl AwxCommandBuilder {
    /// Build a curl command for an AWX API call.
    ///
    /// The token is included in the Authorization header but masked in
    /// audit logs via the security sanitizer.
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of AWX (e.g., `https://awx.internal`)
    /// * `token` - AWX API `OAuth2` token
    /// * `endpoint` - API endpoint (e.g., `/api/v2/jobs/123/`)
    /// * `method` - HTTP method
    /// * `body` - Optional JSON body for POST requests
    /// * `verify_ssl` - Whether to verify SSL certificates
    /// * `query_params` - Query string parameters
    /// * `timeout` - Request timeout in seconds
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_api_call(
        url: &str,
        token: &str,
        endpoint: &str,
        method: HttpMethod,
        body: Option<&str>,
        verify_ssl: bool,
        query_params: &[(&str, &str)],
        timeout: u32,
    ) -> String {
        let mut cmd = String::from("curl -s");

        // Method
        let _ = write!(cmd, " {}", method.as_curl_flag());

        // SSL verification
        if !verify_ssl {
            cmd.push_str(" -k");
        }

        // Timeout
        let _ = write!(cmd, " --max-time {timeout}");

        // Auth header
        let _ = write!(cmd, " -H 'Authorization: Bearer {}'", shell_escape(token));

        // Content-Type for POST
        if body.is_some() {
            cmd.push_str(" -H 'Content-Type: application/json'");
        }

        // Body
        if let Some(b) = body {
            let _ = write!(cmd, " -d {}", shell_escape(b));
        }

        // Build full URL with query params
        let mut full_url = format!("{}{}", url.trim_end_matches('/'), endpoint);
        if !query_params.is_empty() {
            full_url.push('?');
            for (i, (key, value)) in query_params.iter().enumerate() {
                if i > 0 {
                    full_url.push('&');
                }
                let _ = write!(
                    full_url,
                    "{}={}",
                    percent_encode(key),
                    percent_encode(value)
                );
            }
        }

        let _ = write!(cmd, " {}", shell_escape(&full_url));

        cmd
    }

    /// Marker prefixing the HTTP status that [`Self::build_api_call_checked`]
    /// asks `curl` to append to stdout.
    const STATUS_MARKER: &'static str = "HTTP_STATUS:";

    /// Like [`Self::build_api_call`] but appends a `curl -w` write-out so the
    /// HTTP status code can be recovered from stdout and classified by
    /// [`Self::parse_checked_response`].
    ///
    /// Plain `build_api_call` uses `curl -s`, which exits 0 on any HTTP
    /// response, so a 4xx/5xx would otherwise reach the model as an opaque
    /// success. Use this variant for handlers where a non-2xx must be an error
    /// (launch, relaunch, cancel, approvals, project sync).
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_api_call_checked(
        url: &str,
        token: &str,
        endpoint: &str,
        method: HttpMethod,
        body: Option<&str>,
        verify_ssl: bool,
        query_params: &[(&str, &str)],
        timeout: u32,
    ) -> String {
        let mut cmd = Self::build_api_call(
            url,
            token,
            endpoint,
            method,
            body,
            verify_ssl,
            query_params,
            timeout,
        );
        // `\n` is interpreted by curl (not the shell, inside single quotes), so
        // the status lands on its own trailing line: `<body>\nHTTP_STATUS:200`.
        let _ = write!(cmd, " -w '\\n{}%{{http_code}}'", Self::STATUS_MARKER);
        cmd
    }

    /// Split the `curl -w` status line written by [`Self::build_api_call_checked`]
    /// from the response body.
    ///
    /// Returns the body on a 2xx/3xx status, and a [`BridgeError::AwxApi`]
    /// carrying the status and AWX `detail` message on a status `>= 400`. If the
    /// marker is absent (e.g. curl failed at the transport level before the
    /// write-out), the raw text is returned unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::AwxApi`] when AWX responded with HTTP `>= 400`.
    pub fn parse_checked_response(raw: &str) -> Result<String> {
        let Some(idx) = raw.rfind(Self::STATUS_MARKER) else {
            return Ok(raw.to_string());
        };
        let status: u16 = raw[idx + Self::STATUS_MARKER.len()..]
            .trim()
            .parse()
            .unwrap_or(0);
        // Body is everything before the marker; drop the newline curl inserted.
        let body = raw[..idx].trim_end_matches(['\n', '\r']).to_string();
        if status >= 400 {
            Err(BridgeError::AwxApi {
                status,
                detail: extract_detail(&body),
            })
        } else {
            Ok(body)
        }
    }

    /// Validate an AWX API endpoint path.
    ///
    /// Rejects paths with `..` (directory traversal) and paths not
    /// starting with `/api/`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path is invalid.
    pub fn validate_endpoint(endpoint: &str) -> Result<()> {
        if endpoint.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in API endpoint".to_string(),
            });
        }
        if !endpoint.starts_with("/api/") {
            return Err(BridgeError::CommandDenied {
                reason: "AWX endpoint must start with /api/".to_string(),
            });
        }
        Ok(())
    }

    /// Validate a template/job ID (must be a positive integer).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the ID is not a valid
    /// positive integer.
    pub fn validate_id(id: u64) -> Result<()> {
        if id == 0 {
            return Err(BridgeError::CommandDenied {
                reason: "ID must be a positive integer".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_api_call_get() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "mytoken123",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        assert!(cmd.contains("curl -s"));
        assert!(cmd.contains("-X GET"));
        assert!(cmd.contains("Authorization: Bearer"));
        assert!(cmd.contains("mytoken123"));
        assert!(cmd.contains("https://awx.internal/api/v2/ping/"));
        assert!(cmd.contains("--max-time 30"));
        assert!(!cmd.contains("-k"));
    }

    #[test]
    fn test_build_api_call_post_with_body() {
        let body = r#"{"extra_vars": {"env": "prod"}}"#;
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/job_templates/5/launch/",
            HttpMethod::Post,
            Some(body),
            false,
            &[],
            60,
        );
        assert!(cmd.contains("-X POST"));
        assert!(cmd.contains("-k"));
        assert!(cmd.contains("Content-Type: application/json"));
        assert!(cmd.contains("-d "));
        assert!(cmd.contains("extra_vars"));
    }

    #[test]
    fn test_build_api_call_with_query_params() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/jobs/42/job_events/",
            HttpMethod::Get,
            None,
            true,
            &[("page_size", "20"), ("event", "runner_on_failed")],
            30,
        );
        assert!(cmd.contains("page_size=20"));
        assert!(cmd.contains("event=runner_on_failed"));
        assert!(cmd.contains('?'));
        assert!(cmd.contains('&'));
    }

    #[test]
    fn test_query_param_values_are_url_encoded() {
        // A `search` value containing URL-significant chars must be
        // percent-encoded, otherwise `&` injects a spurious AWX query param and
        // a space breaks the request (HTTP parameter injection / corrupt filter).
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/job_templates/",
            HttpMethod::Get,
            None,
            true,
            &[("search", "deploy prod&order_by=-id")],
            30,
        );
        assert!(
            cmd.contains("search=deploy%20prod%26order_by%3D-id"),
            "query value not percent-encoded: {cmd}"
        );
        // The injected parameter must not survive as a real query parameter.
        assert!(
            !cmd.contains("&order_by=-id"),
            "query parameter injection not prevented: {cmd}"
        );
    }

    #[test]
    fn test_build_api_call_no_trailing_slash_on_url() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal/",
            "tok",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        // Should not double the slash
        assert!(cmd.contains("https://awx.internal/api/v2/ping/"));
        assert!(!cmd.contains("https://awx.internal//api/"));
    }

    #[test]
    fn test_build_api_call_delete() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/jobs/99/cancel/",
            HttpMethod::Delete,
            None,
            true,
            &[],
            30,
        );
        assert!(cmd.contains("-X DELETE"));
    }

    #[test]
    fn test_token_is_shell_escaped() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok'en$(whoami)",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        // Token with single quote should be escaped (quote-break-quote pattern)
        assert!(cmd.contains("tok'\\''en"));
        // $(whoami) is safely inside single quotes — not interpreted by shell
        assert!(cmd.contains("$(whoami)"));
    }

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_endpoint_ok() {
        assert!(AwxCommandBuilder::validate_endpoint("/api/v2/ping/").is_ok());
        assert!(AwxCommandBuilder::validate_endpoint("/api/v2/jobs/123/").is_ok());
    }

    #[test]
    fn test_validate_endpoint_traversal() {
        let result = AwxCommandBuilder::validate_endpoint("/api/../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_endpoint_wrong_prefix() {
        let result = AwxCommandBuilder::validate_endpoint("/etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("/api/"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_id_ok() {
        assert!(AwxCommandBuilder::validate_id(1).is_ok());
        assert!(AwxCommandBuilder::validate_id(42).is_ok());
    }

    #[test]
    fn test_validate_id_zero() {
        assert!(AwxCommandBuilder::validate_id(0).is_err());
    }

    // ============== Checked-response (HTTP status) Tests ==============

    #[test]
    fn test_build_api_call_checked_appends_status_writeout() {
        let cmd = AwxCommandBuilder::build_api_call_checked(
            "https://awx.internal",
            "tok",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        // curl -w must request the HTTP status so the response can be classified.
        assert!(cmd.contains("-w "), "missing -w write-out: {cmd}");
        assert!(
            cmd.contains("HTTP_STATUS:%{http_code}"),
            "missing status marker: {cmd}"
        );
        // Still a valid GET to the endpoint.
        assert!(cmd.contains("https://awx.internal/api/v2/ping/"));
    }

    #[test]
    fn test_parse_checked_response_ok_strips_marker() {
        let raw = "{\"version\":\"23.0.0\"}\nHTTP_STATUS:200";
        let body = AwxCommandBuilder::parse_checked_response(raw).unwrap();
        assert_eq!(body, "{\"version\":\"23.0.0\"}");
        assert!(!body.contains("HTTP_STATUS"));
    }

    #[test]
    fn test_parse_checked_response_201_is_ok() {
        // AWX returns 201 Created on a successful job launch.
        let raw = "{\"job\":42}\nHTTP_STATUS:201";
        let body = AwxCommandBuilder::parse_checked_response(raw).unwrap();
        assert_eq!(body, "{\"job\":42}");
    }

    #[test]
    fn test_parse_checked_response_4xx_is_error_with_detail() {
        let raw = "{\"detail\":\"Not found.\"}\nHTTP_STATUS:404";
        let err = AwxCommandBuilder::parse_checked_response(raw).unwrap_err();
        match err {
            BridgeError::AwxApi { status, detail } => {
                assert_eq!(status, 404);
                assert!(
                    detail.contains("Not found."),
                    "detail not extracted: {detail}"
                );
            }
            other => panic!("expected AwxApi error, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_checked_response_401_is_error() {
        let raw = "{\"detail\":\"Authentication credentials were not provided.\"}\nHTTP_STATUS:401";
        let err = AwxCommandBuilder::parse_checked_response(raw).unwrap_err();
        assert!(matches!(err, BridgeError::AwxApi { status: 401, .. }));
    }

    #[test]
    fn test_parse_checked_response_no_marker_returns_body() {
        // If curl never emitted the marker (e.g. transport-level failure before
        // write-out), fall back to returning the raw body unchanged.
        let raw = "some raw output without a status line";
        let body = AwxCommandBuilder::parse_checked_response(raw).unwrap();
        assert_eq!(body, raw);
    }
}
