//! `ChatOps` Command Builder
//!
//! Builds webhook and notification commands for `ChatOps` integration
//! via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Start of every webhook `curl` command, shared by the two builders.
///
/// `-q` must be the first argument of `curl`: it is then honoured and curl
/// reads neither `~/.curlrc` nor `$CURL_HOME/.curlrc`. The URL is chosen by the
/// caller of the tool, so no setting of the host's curl configuration file
/// (`user`, `header`, `oauth2-bearer`, `netrc`, a client certificate...) may
/// apply to it. The `https_proxy` and `HTTPS_PROXY` environment variables still
/// apply. `--globoff`: without it `[1-100000000]` and `{a,b}` in the URL are
/// expanded into one request per value.
const CURL_POST_JSON: &str = "curl -q -s -X POST --globoff -H 'Content-Type: application/json'";

/// Validate a webhook URL.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the URL does not start with
/// `https://` or is otherwise invalid.
pub fn validate_webhook_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Webhook URL must not be empty".to_string(),
        });
    }
    if !url.starts_with("https://") {
        return Err(BridgeError::CommandDenied {
            reason: "Webhook URL must start with 'https://'".to_string(),
        });
    }
    if url.contains('\n') || url.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Webhook URL must not contain newlines".to_string(),
        });
    }
    if url.len() > 2048 {
        return Err(BridgeError::CommandDenied {
            reason: format!("Webhook URL too long: {} chars (max 2048)", url.len()),
        });
    }
    Ok(())
}

/// Validate a webhook payload.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the payload is empty, exceeds
/// 10000 characters, or starts with `@` (`curl -d @file` reads and sends that
/// file instead of the text).
pub fn validate_payload(payload: &str) -> Result<()> {
    if payload.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Payload must not be empty".to_string(),
        });
    }
    if payload.starts_with('@') {
        return Err(BridgeError::CommandDenied {
            reason: "Payload must not start with '@': curl would read it as a file name"
                .to_string(),
        });
    }
    if payload.len() > 10000 {
        return Err(BridgeError::CommandDenied {
            reason: format!("Payload too long: {} chars (max 10000)", payload.len()),
        });
    }
    Ok(())
}

/// Builds `ChatOps` commands for remote execution.
pub struct ChatOpsCommandBuilder;

impl ChatOpsCommandBuilder {
    /// Build a command to send a webhook POST request.
    ///
    /// curl runs with `-q` (it reads no `~/.curlrc`) and `--globoff` (no
    /// expansion of `[1-100000000]` and `{a,b}` in the URL into one request
    /// per value).
    ///
    /// # Errors
    ///
    /// Returns an error if the URL or payload is invalid.
    pub fn build_webhook_command(url: &str, payload: &str) -> Result<String> {
        validate_webhook_url(url)?;
        validate_payload(payload)?;

        let escaped_url = shell_escape(url);
        let escaped_payload = shell_escape(payload);

        Ok(format!(
            "{CURL_POST_JSON} \
             -d {escaped_payload} {escaped_url} \
             -w '\\nHTTP_STATUS:%{{http_code}}' -o /dev/stdout"
        ))
    }

    /// Build a command to send a notification via webhook.
    ///
    /// Formats the message as a JSON notification payload and sends it
    /// (curl runs with `-q` and `--globoff`, see [`Self::build_webhook_command`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the message or webhook URL is invalid.
    pub fn build_notify_command(message: &str, webhook_url: &str) -> Result<String> {
        validate_webhook_url(webhook_url)?;

        if message.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Notification message must not be empty".to_string(),
            });
        }
        if message.len() > 10000 {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Notification message too long: {} chars (max 10000)",
                    message.len()
                ),
            });
        }

        let escaped_url = shell_escape(webhook_url);
        // The message is a JSON string value: encode it as JSON first, so a
        // quote in it cannot add keys to the payload, then quote it once.
        let json_message = serde_json::Value::String(message.to_string()).to_string();
        let escaped_message = shell_escape(&json_message);

        Ok(format!(
            "HOSTNAME=$(hostname 2>/dev/null || echo 'unknown') && \
             TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date) && \
             PAYLOAD=$(printf '{{\"text\":%s,\"hostname\":\"%s\",\"timestamp\":\"%s\"}}' \
             {escaped_message} \"$HOSTNAME\" \"$TIMESTAMP\") && \
             {CURL_POST_JSON} \
             -d \"$PAYLOAD\" {escaped_url} \
             -w '\\nHTTP_STATUS:%{{http_code}}' -o /dev/stdout"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_webhook_url ──────────────────────────────────

    #[test]
    fn test_validate_webhook_url_valid() {
        assert!(validate_webhook_url("https://hooks.slack.com/services/T/B/X").is_ok());
        assert!(validate_webhook_url("https://example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_empty() {
        let err = validate_webhook_url("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_webhook_url_http() {
        let err = validate_webhook_url("http://example.com/webhook").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("https://"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_webhook_url_newline() {
        assert!(validate_webhook_url("https://example.com\n/evil").is_err());
    }

    #[test]
    fn test_validate_webhook_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(2040));
        assert!(validate_webhook_url(&long_url).is_err());
    }

    // ── validate_payload ──────────────────────────────────────

    #[test]
    fn test_validate_payload_valid() {
        assert!(validate_payload("{\"text\":\"hello\"}").is_ok());
    }

    #[test]
    fn test_validate_payload_empty() {
        assert!(validate_payload("").is_err());
    }

    #[test]
    fn test_validate_payload_too_long() {
        let long = "x".repeat(10001);
        assert!(validate_payload(&long).is_err());
    }

    #[test]
    fn test_validate_payload_max_length_ok() {
        let exact = "x".repeat(10000);
        assert!(validate_payload(&exact).is_ok());
    }

    // ── build_webhook_command ─────────────────────────────────

    #[test]
    fn test_webhook_valid() {
        let cmd = ChatOpsCommandBuilder::build_webhook_command(
            "https://hooks.slack.com/services/T/B/X",
            "{\"text\":\"hello\"}",
        )
        .unwrap();
        assert!(cmd.contains("curl -q -s -X POST"));
        assert!(cmd.contains("Content-Type: application/json"));
        assert!(cmd.contains("hooks.slack.com"));
    }

    #[test]
    fn test_webhook_invalid_url() {
        let result = ChatOpsCommandBuilder::build_webhook_command(
            "http://insecure.com",
            "{\"text\":\"hello\"}",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_invalid_payload() {
        let result = ChatOpsCommandBuilder::build_webhook_command(
            "https://hooks.slack.com/services/T/B/X",
            "",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_shell_injection_url() {
        let cmd = ChatOpsCommandBuilder::build_webhook_command(
            "https://example.com/'; rm -rf /; echo '",
            "{\"text\":\"test\"}",
        )
        .unwrap();
        assert!(cmd.contains("'\\''"));
    }

    #[test]
    fn test_webhook_refuses_a_payload_that_curl_reads_as_a_file() {
        for bad in ["@/etc/passwd", "@-", "@~/.aws/credentials"] {
            let err = ChatOpsCommandBuilder::build_webhook_command(
                "https://hooks.slack.com/services/T/B/X",
                bad,
            )
            .unwrap_err();
            assert!(err.to_string().contains("must not start with '@'"), "{err}");
        }
        // A leading '@' elsewhere is plain text.
        validate_payload("{\"text\":\"@here\"}").unwrap();
    }

    #[test]
    fn test_notify_message_is_a_json_string() {
        let cmd = ChatOpsCommandBuilder::build_notify_command(
            "say \"hi\", \"evil\":\"1",
            "https://hooks.slack.com/services/T/B/X",
        )
        .unwrap();
        assert!(
            cmd.contains("'\"say \\\"hi\\\", \\\"evil\\\":\\\"1\"'"),
            "{cmd}"
        );
        let plain = ChatOpsCommandBuilder::build_notify_command(
            "Server restarted",
            "https://hooks.slack.com/services/T/B/X",
        )
        .unwrap();
        assert!(plain.contains("'\"Server restarted\"'"), "{plain}");
    }

    // ── build_notify_command ──────────────────────────────────

    #[test]
    fn test_notify_valid() {
        let cmd = ChatOpsCommandBuilder::build_notify_command(
            "Server restarted",
            "https://hooks.slack.com/services/T/B/X",
        )
        .unwrap();
        assert!(cmd.contains("curl -q -s -X POST"));
        assert!(cmd.contains("hostname"));
        assert!(cmd.contains("timestamp"));
        assert!(cmd.contains("Server restarted"));
    }

    #[test]
    fn test_notify_empty_message() {
        let result = ChatOpsCommandBuilder::build_notify_command(
            "",
            "https://hooks.slack.com/services/T/B/X",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_notify_invalid_url() {
        let result = ChatOpsCommandBuilder::build_notify_command("hello", "http://insecure.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_notify_message_too_long() {
        let long_msg = "x".repeat(10001);
        let result = ChatOpsCommandBuilder::build_notify_command(
            &long_msg,
            "https://hooks.slack.com/services/T/B/X",
        );
        assert!(result.is_err());
    }

    // ── URL globbing ──────────────────────────────────────────

    #[test]
    fn test_webhook_url_is_not_globbed_by_curl() {
        for url in [
            "https://hooks.example.com/x/[1-100000000]",
            "https://{10.0.0.1,10.0.0.2}/hook",
        ] {
            let cmd = ChatOpsCommandBuilder::build_webhook_command(url, "{}").unwrap();
            assert!(cmd.contains(" --globoff "), "{cmd}");
            assert!(
                cmd.contains(&format!(" '{url}' ")),
                "URL stays one operand: {cmd}"
            );
            let notify = ChatOpsCommandBuilder::build_notify_command("hi", url).unwrap();
            assert!(notify.contains(" --globoff "), "{notify}");
            assert!(notify.contains(&format!(" '{url}' ")), "{notify}");
        }
    }

    #[test]
    fn test_globoff_comes_before_the_url() {
        let cmd =
            ChatOpsCommandBuilder::build_webhook_command("https://example.com/h", "{}").unwrap();
        let flag = cmd.find("--globoff").unwrap();
        let url = cmd.find("'https://example.com/h'").unwrap();
        assert!(flag < url, "{cmd}");
    }

    // ── curl configuration file ───────────────────────────────

    #[test]
    fn test_curl_q_is_the_first_curl_argument() {
        let url = "https://hooks.slack.com/services/T/B/X";
        let webhook = ChatOpsCommandBuilder::build_webhook_command(url, "{}").unwrap();
        assert!(webhook.starts_with("curl -q "), "{webhook}");
        assert_eq!(webhook.matches("curl").count(), 1, "{webhook}");

        // The notification command sets variables first: its one curl is the
        // last link of the `&&` chain, and `-q` is still its first argument.
        let notify = ChatOpsCommandBuilder::build_notify_command("hi", url).unwrap();
        assert!(notify.contains(" && curl -q -s -X POST "), "{notify}");
        assert_eq!(notify.matches("curl").count(), 1, "{notify}");
    }

    #[test]
    fn test_both_builders_share_the_curl_prefix() {
        let url = "https://hooks.slack.com/services/T/B/X";
        let webhook = ChatOpsCommandBuilder::build_webhook_command(url, "{}").unwrap();
        let notify = ChatOpsCommandBuilder::build_notify_command("hi", url).unwrap();
        assert!(webhook.starts_with(CURL_POST_JSON), "{webhook}");
        assert!(
            notify.contains(&format!(" && {CURL_POST_JSON} ")),
            "{notify}"
        );
        assert_eq!(
            CURL_POST_JSON,
            "curl -q -s -X POST --globoff -H 'Content-Type: application/json'"
        );
    }

    #[test]
    fn test_webhook_golden_command() {
        assert_eq!(
            ChatOpsCommandBuilder::build_webhook_command("https://example.com/h", "{\"a\":1}")
                .unwrap(),
            "curl -q -s -X POST --globoff -H 'Content-Type: application/json' \
             -d '{\"a\":1}' 'https://example.com/h' \
             -w '\\nHTTP_STATUS:%{http_code}' -o /dev/stdout"
        );
    }
}
