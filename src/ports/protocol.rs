//! MCP Protocol Contract Types
//!
//! These types define the contracts used in port trait signatures
//! (`ToolHandler`, `PromptHandler`, `ResourceHandler`). They live in the
//! ports layer because they are part of the interface definition,
//! not adapter implementation details.
//!
//! The MCP adapter module re-exports these types for backward
//! compatibility via `crate::mcp::protocol`.

use serde::Serialize;
use serde_json::Value;

// ============================================================================
// Tool Annotations (MCP 2025-03-26+)
// ============================================================================

/// MCP Tool Annotations providing behavioral hints to clients.
///
/// Claude Code uses these to decide parallelization (`readOnlyHint`),
/// confirmation dialogs (`destructiveHint`), and retry safety
/// (`idempotentHint`). All fields are optional with spec-defined defaults.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Human-readable title for display in UIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// If true, the tool does not modify its environment.
    /// Clients may execute read-only tools in parallel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,

    /// If true, the tool may perform destructive operations
    /// (deletions, overwrites). Clients may show confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,

    /// If true, calling the tool repeatedly with the same args
    /// has no additional effect. Clients may retry safely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,

    /// If true, the tool may interact with external entities
    /// beyond the MCP server's host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl ToolAnnotations {
    /// Read-only tool: safe for parallel execution, no confirmation needed.
    #[must_use]
    pub fn read_only(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        }
    }

    /// Mutating but non-destructive tool.
    #[must_use]
    pub fn mutating(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(false),
            open_world_hint: Some(true),
        }
    }

    /// Mutating tool whose effect is convergent — repeating the same call
    /// with the same args leaves the system in the same final state
    /// (e.g. `kubectl apply`, `systemctl restart`, `nginx reload`).
    #[must_use]
    pub fn mutating_idempotent(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        }
    }

    /// Destructive tool: triggers confirmation dialogs in clients.
    #[must_use]
    pub fn destructive(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(false),
            destructive_hint: Some(true),
            idempotent_hint: Some(false),
            open_world_hint: Some(true),
        }
    }

    /// Check if all annotation fields are `None` (empty annotations).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.read_only_hint.is_none()
            && self.destructive_hint.is_none()
            && self.idempotent_hint.is_none()
            && self.open_world_hint.is_none()
    }
}

// ============================================================================
// Tool Contract Types
// ============================================================================

/// MCP Tool Call Result
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    /// Machine-readable structured data (MCP 2025-06-18+).
    /// Must conform to the tool's `outputSchema` if defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// The **remote** command's own exit code, when a command ran on the
    /// target host and exited non-zero.
    ///
    /// Whether that *is a failure* is a separate question, and a separate
    /// field. See [`Self::with_remote_exit_code`], which answers yes and sets
    /// `is_error` too, and [`Self::with_remote_exit_code_only`], which
    /// declines to answer because the caller chose the command.
    ///
    /// This is the discriminator `is_error` alone cannot provide.
    /// [`Self::error`] sets `is_error` for bridge-side refusals too — a rate
    /// limit, a denied command, a declined confirmation — so "`is_error` is
    /// true" cannot tell "the bridge refused" from "the target host said no".
    /// The CLI needs that distinction to report a distinct process exit code
    /// (see `EXIT_REMOTE_FAILURE` in `crate::cli::runner`), and announcing a
    /// remote failure on a signal that cannot establish one would be the very
    /// fault this field exists to remove.
    ///
    /// The three states, in full:
    /// * `None` — no claim about a remote exit code. Either nothing ran
    ///   remotely, or the tool counts a non-zero exit as a normal answer
    ///   (`StandardTool::NONZERO_EXIT_IS_ERROR = false`), or the handler
    ///   simply does not report one. **This is what a successful call carries**,
    ///   and what most handlers outside the `StandardTool` pipeline still
    ///   carry — see the note on that pipeline's step 19. The exceptions are
    ///   the handlers that call [`Self::with_remote_exit_code`] or
    ///   [`Self::with_remote_exit_code_only`] themselves, under whatever
    ///   conditions each documents; a handler that does neither is in this
    ///   state. Which of the two constructors a handler uses depends on who
    ///   chose the command, as set out on each of them.
    /// * `Some(0)` — a command ran on the target host and succeeded. A
    ///   coherent statement, and the CLI reads it as success, but nothing in
    ///   the tree emits it: the pipeline only records a code when it is
    ///   non-zero, so `Some(0)` exists as a total contract rather than as a
    ///   reachable state.
    /// * `Some(n)`, `n != 0` — a command ran on the target host and exited
    ///   `n`. `is_error` is `Some(true)` alongside it **only when the tool
    ///   also calls that a failure**. A tool whose command the caller wrote
    ///   (for instance `ssh_exec`; the criterion, not this example, decides)
    ///   reports the code with `is_error` absent, because `grep` matching nothing exits 1 without having
    ///   failed. The CLI still exits `EXIT_REMOTE_FAILURE` (6) either way,
    ///   since it reads this field before `is_error`.
    ///
    /// **Not part of the result body.** `#[serde(skip)]` keeps it out of
    /// every serialized result and out of every `outputSchema`: serde cannot
    /// carry it, and a field there would become a protocol extension of the
    /// result shape. It reaches a client that reads the result off the wire —
    /// the daemon-forwarding CLI path — through `_meta` instead:
    /// `crate::mcp::protocol::tool_result_value` adds
    /// `_meta["io.github.muchiny/remote-exit-code"]` (the constant
    /// `REMOTE_EXIT_CODE_META_KEY`) at serialization time, and
    /// `print_daemon_response` reads it back and applies the same rule as the
    /// direct path. So `ssh_exec host=X command=false` exits 6 either way.
    /// The `MCP summarize=true` round trip carries it through `SealedResult`.
    #[serde(skip)]
    pub remote_exit_code: Option<i32>,
}

/// Content block within a tool result.
///
/// Supports Text (used by all current handlers), plus Image, Audio,
/// and embedded Resource for future use.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ToolContent {
    Text {
        text: String,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    #[serde(rename = "resource")]
    Resource {
        resource: EmbeddedResource,
    },
    /// Interactive app component (MCP Apps, early 2026).
    #[serde(rename = "app")]
    App {
        app: AppContent,
    },
}

// ============================================================================
// MCP Apps Types (Interactive UI Components, early 2026)
// ============================================================================

/// Interactive UI component returned by tools.
///
/// Clients that support MCP Apps render these as rich UI elements
/// (dashboards, tables, forms, charts) directly in the conversation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppContent {
    /// App type: `"dashboard"`, `"table"`, `"form"`, `"chart"`.
    pub app_type: String,
    /// Human-readable title for the component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// App-specific structured data.
    pub data: serde_json::Value,
    /// Optional interactive actions (buttons that invoke tools).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<AppAction>>,
}

/// An interactive action button within an MCP App component.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppAction {
    /// Unique action identifier.
    pub id: String,
    /// Human-readable label for the button.
    pub label: String,
    /// Tool name to invoke when the action is triggered.
    pub tool: String,
    /// Pre-filled arguments for the tool invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
}

/// Embedded resource content within a tool result (MCP 2025-06-18+).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedResource {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

impl ToolCallResult {
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: None,
            structured_content: None,
            remote_exit_code: None,
        }
    }

    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: Some(true),
            structured_content: None,
            // Deliberately `None`: `error` is the bridge's own refusal
            // channel. Claiming a remote exit code here is what would
            // conflate "the bridge said no" with "the host said no".
            remote_exit_code: None,
        }
    }

    /// Add an MCP App component alongside text content.
    #[must_use]
    pub fn with_app(mut self, app: AppContent) -> Self {
        self.content.push(ToolContent::App { app });
        self
    }

    /// Strip non-standard `App` content items for clients that only accept
    /// the MCP-spec types (`text`, `image`, `audio`, `resource`).
    #[must_use]
    pub fn without_apps(mut self) -> Self {
        // Drop interactive App content for spec-only clients. Typed
        // `structured_content` is now produced independently of Apps
        // (GAP #2 decoupling), so it MUST be preserved here.
        self.content
            .retain(|c| !matches!(c, ToolContent::App { .. }));
        self
    }

    /// Set machine-readable structured content for AI consumption.
    ///
    /// The structured content is returned alongside the human-readable text
    /// and allows AI models to parse tool results without text extraction.
    #[must_use]
    pub fn with_structured(mut self, data: serde_json::Value) -> Self {
        self.structured_content = Some(data);
        self
    }

    /// Record that a command ran on the target host and exited `code`.
    ///
    /// For `code != 0` this also sets `is_error`: a remote command that failed
    /// is a failed tool call, which is what an MCP client tests. See
    /// [`Self::remote_exit_code`] for why the two signals are not
    /// interchangeable.
    ///
    /// `code == 0` records the code and leaves `is_error` alone, because a
    /// command that succeeded is not an error. That is deliberate rather than
    /// a half-state — [`Self::remote_exit_code`] documents all three states —
    /// but no caller passes 0 today, since the pipeline records a code only
    /// when it is non-zero.
    #[must_use]
    pub const fn with_remote_exit_code(mut self, code: i32) -> Self {
        self.remote_exit_code = Some(code);
        if code != 0 {
            self.is_error = Some(true);
        }
        self
    }

    /// Comme [`Self::with_remote_exit_code`], mais **sans** poser `is_error`.
    ///
    /// Pour les outils dont l'appelant choisit la commande (c'est ce critère, et
    /// non une liste d'outils, qui décide). Un code non nul y décrit un *fait* de la commande, pas
    /// un *verdict* de l'appel : `grep` qui ne trouve rien sort 1, `diff` qui
    /// voit une différence sort 1, `test` sort 1 pour faux. Poser `is_error`
    /// dirait à un client MCP que son propre `grep` a échoué, sans recours.
    ///
    /// Le code atteint quand même le processus quand l'appel est servi en
    /// direct, parce que `tool_exit_code` (dans `crate::cli::runner`) lit
    /// `remote_exit_code` avant `is_error`. Servi par un daemon, le code
    /// voyage dans `_meta` (voir la doc du champ) et le chemin daemon le relit
    /// de la même façon : 6 des deux côtés.
    #[must_use]
    pub const fn with_remote_exit_code_only(mut self, code: i32) -> Self {
        self.remote_exit_code = Some(code);
        self
    }
}

// ============================================================================
// Prompt Contract Types
// ============================================================================

/// MCP Prompt Argument definition
#[derive(Debug, Clone, Serialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// MCP Prompt Message (part of get response)
#[derive(Debug, Clone, Serialize)]
pub struct PromptMessage {
    pub role: String,
    pub content: PromptContent,
}

/// MCP Prompt Content
#[derive(Debug, Clone, Serialize)]
pub struct PromptContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

impl PromptMessage {
    /// Create a user message
    #[must_use]
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: PromptContent {
                content_type: "text".to_string(),
                text: text.into(),
            },
        }
    }

    /// Create an assistant message
    #[must_use]
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: PromptContent {
                content_type: "text".to_string(),
                text: text.into(),
            },
        }
    }
}

// ============================================================================
// Resource Contract Types
// ============================================================================

/// MCP Resource Definition (returned by resources/list)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Resource Content (returned by resources/read)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

// ============================================================================
// Task Contract Types (MCP 2025-11-25+)
// ============================================================================

/// Task lifecycle status values — the five of MCP 2026-07-28.
///
/// `snake_case`, not `lowercase`: `InputRequired` must reach the wire as
/// `"input_required"`, and `lowercase` would spell it `"inputrequired"`. The
/// other four variants are single words and serialize identically under both
/// renamings, so the switch is invisible to them.
///
/// Note the spelling: `Cancelled`, double-l.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// The request is currently being processed.
    Working,
    /// The server needs input from the client before the task can proceed.
    ///
    /// Nothing in bridge-mcp constructs this variant today, and nothing is
    /// planned to: no tool suspends mid-execution to elicit. It exists so the
    /// type is complete and the wire value is spellable — a client that
    /// negotiated the extension may legitimately expect all five.
    InputRequired,
    /// Completed successfully and results are available. **Includes tool
    /// calls that returned `isError: true`** — those are completions, not
    /// failures.
    Completed,
    /// Failed due to a JSON-RPC error during execution. MUST NOT be used for
    /// non-JSON-RPC errors.
    Failed,
    /// Cancelled before completion.
    Cancelled,
}

/// The bare `Task` object of MCP 2026-07-28 — seven fields, no payload.
///
/// The adapter layer flattens this into `DetailedTask` to add the protocol
/// artefacts (`resultType`, `result`/`error`/`inputRequests`). Keeping the
/// two apart is what stops `ResultType` — a pure wire concept — from leaking
/// into the ports layer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskInfo {
    pub task_id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    pub created_at: String,
    pub last_updated_at: String,
    /// Time-to-live in milliseconds before the task expires; `null` for
    /// unlimited retention.
    ///
    /// REQUIRED and NULLABLE — deliberately no `skip_serializing_if`. The
    /// spec types this `number | null`, so an absent key is not a legal
    /// encoding of "unlimited"; `null` is. bridge-mcp always evicts on TTL
    /// (`TaskEntry::is_expired`), so in practice this is always `Some`, but
    /// the shape must stay spellable.
    ///
    /// 2025-11-25 called this `ttl`. The wire key is now `ttlMs`.
    pub ttl_ms: Option<i64>,
    /// Suggested poll interval in milliseconds.
    ///
    /// OPTIONAL per the spec (may be absent entirely), but bridge-mcp always
    /// emits it: clients "SHOULD respect the `pollIntervalMs` provided in
    /// responses", and omitting it leaves them nothing to pace against.
    ///
    /// 2025-11-25 called this `pollInterval`. The wire key is now
    /// `pollIntervalMs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_remote_exit_code_too_large_for_i32_becomes_one() {
        // `ExecuteCommandResponse::exit_code` est un u32 et le champ un i32.
        // La forme de référence fait `try_from(...).unwrap_or(1)` : un code
        // qu'aucun processus réel ne peut produire doit rester non nul et
        // légitime, pas devenir négatif ni paniquer.
        let code = i32::try_from(u32::MAX).unwrap_or(1);
        assert_eq!(code, 1);
        let r = ToolCallResult::text("x".to_string()).with_remote_exit_code(code);
        assert_eq!(r.remote_exit_code, Some(1));
        assert_eq!(r.is_error, Some(true));
    }

    // ========================================================================
    // ToolAnnotations tests
    // ========================================================================

    #[test]
    fn test_read_only_annotation_fields() {
        let ann = ToolAnnotations::read_only("List files");
        assert_eq!(ann.title.as_deref(), Some("List files"));
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_mutating_annotation_fields() {
        let ann = ToolAnnotations::mutating("Apply config");
        assert_eq!(ann.title.as_deref(), Some("Apply config"));
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(false));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_destructive_annotation_fields() {
        let ann = ToolAnnotations::destructive("Delete resource");
        assert_eq!(ann.title.as_deref(), Some("Delete resource"));
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, Some(false));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_default_annotations_is_empty() {
        let ann = ToolAnnotations::default();
        assert!(ann.is_empty());
    }

    #[test]
    fn test_read_only_not_empty() {
        let ann = ToolAnnotations::read_only("x");
        assert!(!ann.is_empty());
    }

    /// `is_empty` is `title.is_none() && read_only.is_none() &&
    /// destructive.is_none() && idempotent.is_none() &&
    /// open_world.is_none()`. Mutations `&& -> ||` at each `&&`
    /// turn the conjunction at that position into a disjunction —
    /// only catchable by exercising each field *in isolation* (every
    /// other field `None`). The constructor helpers all set all five
    /// fields, so the existing tests miss these mutants.
    #[test]
    fn test_single_field_some_is_not_empty() {
        // title only
        let ann = ToolAnnotations {
            title: Some("t".to_string()),
            ..ToolAnnotations::default()
        };
        assert!(!ann.is_empty(), "title=Some must not be empty");

        // read_only_hint only
        let ann = ToolAnnotations {
            read_only_hint: Some(true),
            ..ToolAnnotations::default()
        };
        assert!(!ann.is_empty(), "read_only_hint=Some must not be empty");

        // destructive_hint only
        let ann = ToolAnnotations {
            destructive_hint: Some(true),
            ..ToolAnnotations::default()
        };
        assert!(!ann.is_empty(), "destructive_hint=Some must not be empty");

        // idempotent_hint only
        let ann = ToolAnnotations {
            idempotent_hint: Some(true),
            ..ToolAnnotations::default()
        };
        assert!(!ann.is_empty(), "idempotent_hint=Some must not be empty");

        // open_world_hint only
        let ann = ToolAnnotations {
            open_world_hint: Some(true),
            ..ToolAnnotations::default()
        };
        assert!(!ann.is_empty(), "open_world_hint=Some must not be empty");
    }

    #[test]
    fn test_annotations_json_serialization_camel_case() {
        let ann = ToolAnnotations::read_only("Test tool");
        let json = serde_json::to_value(&ann).unwrap();

        // Verify camelCase renaming
        assert_eq!(json["title"], "Test tool");
        assert_eq!(json["readOnlyHint"], true);
        assert_eq!(json["destructiveHint"], false);
        assert_eq!(json["idempotentHint"], true);
        assert_eq!(json["openWorldHint"], true);

        // Verify snake_case keys are NOT present
        assert!(json.get("read_only_hint").is_none());
        assert!(json.get("destructive_hint").is_none());
    }

    #[test]
    fn test_annotations_skip_serializing_none() {
        let ann = ToolAnnotations::default();
        let json = serde_json::to_value(&ann).unwrap();
        let obj = json.as_object().unwrap();

        // All fields are None, so JSON object should be empty
        assert!(
            obj.is_empty(),
            "Default annotations should serialize to {{}}"
        );
    }

    // ========================================================================
    // ToolCallResult tests
    // ========================================================================

    #[test]
    fn test_text_result_structure() {
        let result = ToolCallResult::text("ok");
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "ok"),
            _ => panic!("Expected Text content"),
        }
        assert!(result.is_error.is_none());
        assert!(result.structured_content.is_none());
    }

    #[test]
    fn test_error_result_has_is_error_true() {
        let result = ToolCallResult::error("fail");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_text_result_has_no_is_error() {
        let result = ToolCallResult::text("ok");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_text_result_serialization() {
        let result = ToolCallResult::text("hello");
        let json = serde_json::to_value(&result).unwrap();

        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "hello");
        // isError should be absent (None skipped)
        assert!(json.get("isError").is_none());
        // structuredContent should be absent
        assert!(json.get("structuredContent").is_none());
    }

    #[test]
    fn test_error_result_serialization() {
        let result = ToolCallResult::error("something broke");
        let json = serde_json::to_value(&result).unwrap();

        assert_eq!(json["isError"], true);
        assert_eq!(json["content"][0]["text"], "something broke");
    }

    #[test]
    fn test_structured_content_none_skipped() {
        let result = ToolCallResult::text("ok");
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(!json_str.contains("structuredContent"));
    }

    #[test]
    fn test_structured_content_present_when_set() {
        let mut result = ToolCallResult::text("ok");
        result.structured_content = Some(json!({"count": 42}));
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["structuredContent"]["count"], 42);
    }

    #[test]
    fn test_without_apps_preserves_structured_content() {
        use super::AppContent;
        let app = AppContent {
            app_type: "table".to_string(),
            title: Some("t".to_string()),
            data: json!({"rows": []}),
            actions: None,
        };
        let mut result = ToolCallResult::text("tsv").with_app(app);
        result.structured_content = Some(json!({"items": [{"name": "nginx"}]}));
        let stripped = result.without_apps();
        assert!(
            !stripped
                .content
                .iter()
                .any(|c| matches!(c, ToolContent::App { .. })),
            "App content must be stripped"
        );
        assert_eq!(
            stripped.structured_content,
            Some(json!({"items": [{"name": "nginx"}]})),
            "structured_content must NOT be cleared by without_apps"
        );
    }

    // ========================================================================
    // ToolContent tests
    // ========================================================================

    #[test]
    fn test_text_content_serialization() {
        let content = ToolContent::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn test_image_content_serialization() {
        let content = ToolContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "image");
        assert_eq!(json["data"], "base64data");
        assert_eq!(json["mimeType"], "image/png");
    }

    #[test]
    fn test_audio_content_serialization() {
        let content = ToolContent::Audio {
            data: "audiodata".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "audio");
        assert_eq!(json["data"], "audiodata");
        assert_eq!(json["mimeType"], "audio/wav");
    }

    #[test]
    fn test_tool_resource_content_serialization() {
        let content = ToolContent::Resource {
            resource: EmbeddedResource {
                uri: "file:///tmp/test.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("file contents".to_string()),
                blob: None,
            },
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "resource");
        assert_eq!(json["resource"]["uri"], "file:///tmp/test.txt");
        assert_eq!(json["resource"]["mimeType"], "text/plain");
        assert_eq!(json["resource"]["text"], "file contents");
        // blob is None, should be absent
        assert!(json["resource"].get("blob").is_none());
    }

    #[test]
    fn test_embedded_resource_skip_none_fields() {
        let res = EmbeddedResource {
            uri: "test://x".to_string(),
            mime_type: None,
            text: None,
            blob: None,
        };
        let json = serde_json::to_value(&res).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 1); // Only uri
        assert_eq!(json["uri"], "test://x");
    }

    // ========================================================================
    // PromptMessage tests
    // ========================================================================

    #[test]
    fn test_user_message_role() {
        let msg = PromptMessage::user("hello");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.content_type, "text");
        assert_eq!(msg.content.text, "hello");
    }

    #[test]
    fn test_assistant_message_role() {
        let msg = PromptMessage::assistant("response");
        assert_eq!(msg.role, "assistant");
        assert_eq!(msg.content.content_type, "text");
        assert_eq!(msg.content.text, "response");
    }

    #[test]
    fn test_prompt_message_serialization() {
        let msg = PromptMessage::user("check health");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"]["type"], "text");
        assert_eq!(json["content"]["text"], "check health");
    }

    // ========================================================================
    // ResourceDefinition / ResourceContent tests
    // ========================================================================

    #[test]
    fn test_resource_definition_serialization_camel_case() {
        let def = ResourceDefinition {
            uri: "metrics://web1".to_string(),
            name: "web1 metrics".to_string(),
            description: Some("System metrics".to_string()),
            mime_type: Some("application/json".to_string()),
        };
        let json = serde_json::to_value(&def).unwrap();
        assert_eq!(json["uri"], "metrics://web1");
        assert_eq!(json["name"], "web1 metrics");
        assert_eq!(json["description"], "System metrics");
        assert_eq!(json["mimeType"], "application/json");
        // Verify camelCase, not snake_case
        assert!(json.get("mime_type").is_none());
    }

    #[test]
    fn test_resource_definition_skip_none() {
        let def = ResourceDefinition {
            uri: "test://x".to_string(),
            name: "test".to_string(),
            description: None,
            mime_type: None,
        };
        let json = serde_json::to_value(&def).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2); // Only uri + name
        assert!(json.get("description").is_none());
        assert!(json.get("mimeType").is_none());
    }

    #[test]
    fn test_resource_content_serialization() {
        let content = ResourceContent {
            uri: "log://web1/syslog".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("log line 1\nlog line 2".to_string()),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["uri"], "log://web1/syslog");
        assert_eq!(json["mimeType"], "text/plain");
        assert!(json["text"].as_str().unwrap().contains("log line 1"));
    }

    #[test]
    fn test_resource_content_skip_none() {
        let content = ResourceContent {
            uri: "test://x".to_string(),
            mime_type: None,
            text: None,
        };
        let json = serde_json::to_value(&content).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 1); // Only uri
    }

    // ========================================================================
    // TaskStatus / TaskInfo tests
    // ========================================================================

    /// Pins the WIRE spellings, not the Rust symbols: rename the variants
    /// and this test stays green; change `rename_all` and it goes red.
    #[test]
    fn task_status_serializes_the_five_modern_spellings() {
        assert_eq!(
            serde_json::to_value(TaskStatus::Working).unwrap(),
            "working"
        );
        // The underscore is the whole point. Under the pre-3.0.0
        // `rename_all = "lowercase"` this would be `"inputrequired"`.
        assert_eq!(
            serde_json::to_value(TaskStatus::InputRequired).unwrap(),
            "input_required"
        );
        assert_eq!(
            serde_json::to_value(TaskStatus::Completed).unwrap(),
            "completed"
        );
        assert_eq!(serde_json::to_value(TaskStatus::Failed).unwrap(), "failed");
        // Double-l, per the spec's own explicit note.
        assert_eq!(
            serde_json::to_value(TaskStatus::Cancelled).unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn test_task_info_serialization_camel_case() {
        let info = TaskInfo {
            task_id: "abc-123".to_string(),
            status: TaskStatus::Working,
            status_message: Some("In progress".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:01Z".to_string(),
            ttl_ms: Some(60000),
            poll_interval_ms: Some(1000),
        };
        let json = serde_json::to_value(&info).unwrap();

        assert_eq!(json["taskId"], "abc-123");
        assert_eq!(json["status"], "working");
        assert_eq!(json["statusMessage"], "In progress");
        assert_eq!(json["createdAt"], "2025-01-01T00:00:00Z");
        assert_eq!(json["lastUpdatedAt"], "2025-01-01T00:00:01Z");
        assert_eq!(json["ttlMs"], 60000);
        assert_eq!(json["pollIntervalMs"], 1000);

        // snake_case keys must NOT be present
        assert!(json.get("task_id").is_none());
        assert!(json.get("status_message").is_none());
        assert!(json.get("created_at").is_none());
    }

    #[test]
    fn test_task_info_skip_none_status_message() {
        let info = TaskInfo {
            task_id: "x".to_string(),
            status: TaskStatus::Completed,
            status_message: None,
            created_at: "t".to_string(),
            last_updated_at: "t".to_string(),
            ttl_ms: Some(1000),
            poll_interval_ms: Some(500),
        };
        let json_str = serde_json::to_string(&info).unwrap();
        assert!(!json_str.contains("statusMessage"));
    }

    #[test]
    fn the_fact_and_the_verdict_can_be_set_separately() {
        // Soudés : ce que le pipeline veut, et ce que la Task 2 veut.
        let welded = ToolCallResult::text("x".to_string()).with_remote_exit_code(1);
        assert_eq!(welded.remote_exit_code, Some(1));
        assert_eq!(welded.is_error, Some(true), "le pipeline veut le verdict");

        // Séparés : ce que les outils à commande libre veulent. Un `grep` qui
        // ne trouve rien sort 1 et n'est pas un échec de l'appel.
        let fact_only = ToolCallResult::text("x".to_string()).with_remote_exit_code_only(1);
        assert_eq!(fact_only.remote_exit_code, Some(1), "le fait remonte");
        assert_eq!(
            fact_only.is_error, None,
            "le verdict n'est PAS posé : un grep qui ne trouve rien n'est pas un échec"
        );
    }

    /// Le fait ne traverse PAS le corps du résultat sérialisé.
    ///
    /// Le `#[serde(skip)]` porté par `remote_exit_code` est délibéré — voir
    /// la documentation du champ. Le chemin daemon le reçoit par `_meta`
    /// (`tool_result_value`), pas par ce corps : le test existe pour que lever
    /// le `skip` — un changement de forme de tous les résultats et de tous les
    /// `outputSchema` — ne puisse pas se faire sans le voir.
    #[test]
    fn the_fact_never_crosses_the_mcp_wire() {
        let json = serde_json::to_value(
            ToolCallResult::text("x".to_string()).with_remote_exit_code_only(7),
        )
        .expect("un ToolCallResult doit être sérialisable");
        assert!(
            json.get("remoteExitCode").is_none() && json.get("remote_exit_code").is_none(),
            "le code distant ne doit pas apparaître dans la réponse MCP : {json}"
        );
        assert!(
            json.get("isError").is_none(),
            "ni le verdict, que ce constructeur ne pose pas : {json}"
        );
    }
}
