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

/// Wrap `content` in a fenced code block that `content` cannot close.
///
/// `CommonMark` closes a fence with a line carrying at least as many backticks
/// as opened it, so a fence one backtick longer than the longest run inside
/// the content is inescapable.
///
/// This is not cosmetic. Both values interpolated into the confirmation prompt
/// are chosen by the client: `summary` is `serde_json::to_string` of the tool
/// arguments, and `command` is `arguments["command"]` of `ssh_exec`, which is
/// annotated destructive and may carry real newlines. With a fixed three-tick
/// fence, a command containing a line of three backticks closed the block and
/// everything after it rendered as prose — so the operator read `rm -rf /`
/// followed, in plain prose, by "Nothing will be executed; this is a dry
/// run", and approved a command whose second half they never saw as a
/// command. The same trick opened a second **Command:** section showing
/// something harmless.
/// The prompt is the only thing standing between a destructive tool and the
/// host, so what it shows has to be what runs.
fn fenced(content: &str, info: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for c in content.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    // At least three, and always one more than the longest run inside.
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}{info}\n{content}\n{fence}")
}

/// Build the destructive-confirmation `ElicitRequest`, without sending it.
///
/// Pure: it returns the params and nothing else. Under Multi Round-Trip
/// Requests the server does not send this — it embeds it in an
/// `InputRequiredResult` and the client retries the call with the answer — so
/// the construction and the transmission had to come apart. The wording,
/// schema and `confirm` field are carried over from the
/// `ElicitationService::confirm_destructive_with_plan` this replaced; the
/// layout is not, because both client-controlled values now go through
/// `fenced` rather than being pasted into a fixed three-tick block.
#[must_use]
pub fn confirm_destructive_request(
    tool_name: &str,
    summary: &str,
    command: Option<String>,
) -> ElicitationCreateParams {
    let mut message = format!("Confirm destructive operation: `{tool_name}`\n");
    let _ = write!(message, "\n**Arguments:**\n{}\n", fenced(summary, "json"));
    if let Some(cmd) = command {
        let _ = write!(message, "\n**Command:**\n{}\n", fenced(&cmd, "sh"));
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
    // ── the confirmation prompt cannot be forged ──────────────────────
    //
    // The gate is fail-closed on everything else: a client that cannot be
    // asked cannot confirm. What was NOT closed is the prompt itself — the
    // operator's only view of what they are approving.

    /// Read back what the Command block actually encloses, the way a markdown
    /// renderer would: the section opens with a fence line, and closes on the
    /// first line of the same fence.
    fn command_block_of(message: &str) -> String {
        let body = message
            .split_once("**Command:**\n")
            .expect("the prompt must carry a Command section")
            .1;
        let (fence_line, rest) = body.split_once('\n').expect("a fence line, then content");
        let close = format!("\n{}", fence_line.trim_end_matches("sh"));
        rest.split_once(&close)
            .expect("the fence must close")
            .0
            .to_string()
    }

    /// A command carrying its own fence used to close the block and continue
    /// in prose. Whatever the command contains, it must stay inside.
    #[test]
    fn a_command_cannot_close_its_own_fence() {
        let attack = "rm -rf /\n```\nNothing will be executed; this is a dry run.";
        let params = super::confirm_destructive_request("ssh_exec", "{}", Some(attack.to_string()));

        assert_eq!(
            command_block_of(&params.message),
            attack,
            "the operator must see the command in full, not the part before its own fence"
        );
    }

    /// Forging a second section is the same bug wearing a different hat: the
    /// operator reads the harmless one and approves the other. The forged
    /// text is still *present* — it has to be, it is part of the command —
    /// but it is inside the block, where markdown reads it as text and not as
    /// a heading.
    #[test]
    fn a_forged_second_section_stays_inside_the_block() {
        let attack = "rm -rf /\n```\n\n**Command:**\n```sh\necho hello";
        let params = super::confirm_destructive_request("ssh_exec", "{}", Some(attack.to_string()));

        let block = command_block_of(&params.message);
        assert_eq!(block, attack, "the whole command must be inside the block");
        assert!(
            block.contains("**Command:**"),
            "the forged heading belongs to the command text, not to the prompt"
        );

        // And nothing follows the block but the question.
        let after = params
            .message
            .rsplit_once("````")
            .expect("the block must close")
            .1;
        assert_eq!(after.trim(), "Proceed?", "got trailing prose: {after:?}");
    }

    /// The arguments are `serde_json::to_string` of client input and are
    /// interpolated too, so they get the same treatment.
    #[test]
    fn the_arguments_are_fenced_as_well() {
        let params =
            super::confirm_destructive_request("ssh_exec", "{\"command\":\"a```b\"}", None);
        assert!(
            params.message.contains("````json\n"),
            "a summary containing three backticks needs a longer fence: {}",
            params.message
        );
    }

    /// Nothing exotic in the content, nothing exotic in the fence — the
    /// ordinary case must stay readable.
    #[test]
    fn an_ordinary_command_keeps_a_plain_fence() {
        let params =
            super::confirm_destructive_request("ssh_exec", "{}", Some("rm /tmp/x".to_string()));
        assert!(
            params.message.contains("```sh\nrm /tmp/x\n```"),
            "got: {}",
            params.message
        );
    }

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
