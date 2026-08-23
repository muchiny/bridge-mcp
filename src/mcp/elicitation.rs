//! MCP Elicitation Service
//!
//! Allows the server to ask the client for user input via `elicitation/create`.
//!
//! Use cases:
//! - SSH host key verification (confirm unknown host key fingerprint)
//! - Password/passphrase input (encrypted SSH key)
//! - Confirmation of destructive operations
//!
//! This module SENDS NOTHING. 2026-07-28 requires `elicitation/create` to be
//! carried by Multi Round-Trip Requests — returned inside an
//! `InputRequiredResult` and answered by a client retry — so what is left here
//! is the pure half: build the request ([`confirm_destructive_request`]), read
//! the answer ([`destructive_confirmation_granted`]), and the `schema`
//! builders both use. The transmission belongs to
//! `McpServer::check_destructive_elicitation`, which returns the request
//! rather than sending it.

use std::fmt::Write as _;

use serde_json::Value;

use super::protocol::ElicitationCreateParams;

/// Pure JSON-Schema builders for elicitation `requested_schema` fields.
///
/// All builders emit draft-2020-12-compatible property fragments:
/// - [`bool_default`] — a boolean with a SEP-1034 `default`.
/// - [`string_enum`] — a single-select enum with an optional SEP-1034 `default`.
/// - [`multi_select_enum`] — an array-of-enum (SEP-1330) for fleet selection,
///   with an optional `default` pre-selection.
///
/// These are property *fragments*: callers wrap them in
/// `{ "type": "object", "properties": { ... }, "required": [...] }`.
mod schema {
    use serde_json::{Value, json};

    /// A boolean property carrying a SEP-1034 `default`.
    #[must_use]
    pub fn bool_default(_name: &str, description: &str, default: bool) -> Value {
        json!({
            "type": "boolean",
            "description": description,
            "default": default
        })
    }

    /// A single-select string enum (SEP-1034 `default` when `default` is `Some`).
    #[must_use]
    #[allow(dead_code)]
    pub fn string_enum(
        _name: &str,
        description: &str,
        choices: &[String],
        default: Option<String>,
    ) -> Value {
        let mut obj = json!({
            "type": "string",
            "description": description,
            "enum": choices
        });
        if let Some(d) = default {
            obj["default"] = Value::String(d);
        }
        obj
    }

    /// A multi-select array-of-enum (SEP-1330) for fleet actions.
    ///
    /// Emits `{"type":"array","items":{"type":"string","enum":[...]},
    /// "uniqueItems":true}` plus an optional `default` pre-selection.
    #[must_use]
    #[allow(dead_code)]
    pub fn multi_select_enum(
        _name: &str,
        description: &str,
        choices: &[String],
        default: Option<Vec<String>>,
    ) -> Value {
        let mut obj = json!({
            "type": "array",
            "description": description,
            "uniqueItems": true,
            "items": {
                "type": "string",
                "enum": choices
            }
        });
        if let Some(d) = default {
            obj["default"] = Value::Array(d.into_iter().map(Value::String).collect());
        }
        obj
    }
}

/// Build the destructive-confirmation `ElicitRequest`, without sending it.
///
/// Pure: it returns the params and nothing else. Under Multi Round-Trip
/// Requests the server does not send this — it embeds it in an
/// `InputRequiredResult` and the client retries the call with the answer — so
/// the construction and the transmission had to come apart. The wording,
/// schema and `confirm` field are carried over unchanged from the
/// `ElicitationService::confirm_destructive_with_plan` this replaced, so an
/// operator sees the same prompt as before.
#[must_use]
pub fn confirm_destructive_request(
    tool_name: &str,
    summary: &str,
    command: Option<String>,
) -> ElicitationCreateParams {
    let mut message = format!("Confirm destructive operation: `{tool_name}`\n\n{summary}\n");
    if let Some(cmd) = command {
        let _ = write!(message, "\n**Command:**\n```sh\n{cmd}\n```\n");
    }
    message.push_str("\nProceed?");

    ElicitationCreateParams {
        mode: crate::mcp::protocol::ElicitationMode::Form,
        message,
        requested_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "confirm": schema::bool_default(
                    "confirm",
                    "Set to true to execute the destructive operation",
                    false
                )
            },
            "required": ["confirm"]
        })),
        url: None,
    }
}

/// Whether an `ElicitResult` for [`confirm_destructive_request`] approves the
/// operation.
///
/// BOTH halves are required: `action == "accept"` says the user engaged with
/// the form rather than dismissing it, and `content.confirm == true` says what
/// they actually put in it. A form can be accepted with the checkbox left
/// false, and reading only the action would take that as consent.
///
/// Everything else — a missing action, a missing `content`, a non-boolean
/// `confirm`, an unrecognised action — is NOT consent.
#[must_use]
pub fn destructive_confirmation_granted(answer: &Value) -> bool {
    if answer.get("action").and_then(Value::as_str) != Some("accept") {
        return false;
    }
    answer
        .get("content")
        .and_then(|c| c.get("confirm"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ============== schema builders ==============

    #[test]
    fn test_schema_bool_default_emits_default_field() {
        let v = schema::bool_default("confirm", "Confirm it", false);
        assert_eq!(v["type"], "boolean");
        assert_eq!(v["default"], false);
        assert_eq!(v["description"], "Confirm it");
    }

    #[test]
    fn test_schema_string_enum_single_select() {
        let v = schema::string_enum(
            "env",
            "Target",
            &["dev".to_string(), "prod".to_string()],
            Some("dev".to_string()),
        );
        assert_eq!(v["type"], "string");
        assert_eq!(v["enum"], json!(["dev", "prod"]));
        assert_eq!(v["default"], "dev");
    }

    #[test]
    fn test_schema_string_enum_omits_default_when_none() {
        let v = schema::string_enum(
            "env",
            "Target",
            &["dev".to_string(), "prod".to_string()],
            None,
        );
        assert!(v.get("default").is_none(), "{v}");
    }

    #[test]
    fn test_schema_multi_select_enum_array_of_enum() {
        let v = schema::multi_select_enum(
            "hosts",
            "Pick hosts",
            &["a".to_string(), "b".to_string()],
            Some(vec!["a".to_string()]),
        );
        assert_eq!(v["type"], "array");
        assert_eq!(v["items"]["enum"], json!(["a", "b"]));
        assert_eq!(v["default"], json!(["a"]));
    }

    #[test]
    fn test_schema_multi_select_omits_default_when_none() {
        let v = schema::multi_select_enum(
            "hosts",
            "Pick hosts",
            &["a".to_string(), "b".to_string()],
            None,
        );
        assert!(v.get("default").is_none(), "{v}");
    }

    // ============== the MRTR confirmation request ==============

    /// The request is built, not sent. Under MRTR it is embedded in an
    /// `InputRequiredResult` and the client answers it on the retry.
    #[test]
    fn the_confirmation_request_is_a_form_naming_the_tool() {
        let p = confirm_destructive_request("ssh_cron_remove", "remove `backup` on `prod`", None);
        assert!(matches!(
            p.mode,
            crate::mcp::protocol::ElicitationMode::Form
        ));
        assert!(p.message.contains("ssh_cron_remove"), "{}", p.message);
        assert!(
            p.message.contains("remove `backup` on `prod`"),
            "{}",
            p.message
        );
        assert!(p.message.ends_with("Proceed?"), "{}", p.message);
        assert!(p.url.is_none());
        let s = p.requested_schema.expect("a form needs a schema");
        assert_eq!(s["required"], json!(["confirm"]));
        assert_eq!(s["properties"]["confirm"]["type"], "boolean");
        // Defaulting to `true` would pre-tick the box that authorises the
        // operation.
        assert_eq!(s["properties"]["confirm"]["default"], false);
    }

    /// The command is shown when there is one, so the operator approves what
    /// will actually run rather than a tool name.
    #[test]
    fn the_confirmation_request_shows_the_command() {
        let p =
            confirm_destructive_request("ssh_exec", "run it", Some("rm -rf /tmp/x".to_string()));
        assert!(p.message.contains("rm -rf /tmp/x"), "{}", p.message);
        assert!(p.message.contains("```sh"), "{}", p.message);
    }

    // ============== reading the answer ==============

    /// The only shape that is consent.
    #[test]
    fn accept_with_confirm_true_is_consent() {
        assert!(destructive_confirmation_granted(&json!({
            "action": "accept", "content": { "confirm": true }
        })));
    }

    /// Everything else is not — including an ACCEPTED form with the box left
    /// unticked, which is the case a check on `action` alone would let run.
    #[test]
    fn nothing_else_is_consent() {
        for answer in [
            json!({ "action": "accept", "content": { "confirm": false } }),
            json!({ "action": "accept", "content": {} }),
            json!({ "action": "accept" }),
            json!({ "action": "decline", "content": { "confirm": true } }),
            json!({ "action": "cancel", "content": { "confirm": true } }),
            json!({ "action": "something-new", "content": { "confirm": true } }),
            json!({ "content": { "confirm": true } }),
            json!({ "action": "accept", "content": { "confirm": "true" } }),
            json!({}),
            json!(null),
        ] {
            assert!(
                !destructive_confirmation_granted(&answer),
                "must not be consent: {answer}"
            );
        }
    }
}
