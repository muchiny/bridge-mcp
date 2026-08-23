use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    /// JSON-RPC 2.0 §5 makes `id` REQUIRED on every Response, and Null when
    /// the id of the offending request could not be determined. It therefore
    /// carries NO `skip_serializing_if`: omitting the key entirely produced a
    /// Response object no conforming client can correlate or reject.
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// The `result` member that discriminates a result shape.
    ///
    /// 2026-07-28 makes it a MUST on every result: *"Result responses must
    /// include a `result` field and a `resultType` field to indicate the nature
    /// of the outcome"*, and the changelog states it without qualification —
    /// *"All results must now include a `resultType` field"*.
    ///
    /// The companion sentence, *"Clients MUST treat an absent `resultType` as
    /// `complete` for backward compatibility"*, is a CLIENT-side bridge for
    /// PRE-2026-07-28 servers. A server that declares `2026-07-28` and then
    /// leans on it is asking to be handled by the compatibility path for a
    /// revision it claims not to speak. The reference client refuses exactly
    /// that, and names the reasoning in its own error text: *"missing required
    /// resultType — servers implementing protocol revision 2026-07-28 MUST
    /// include it (the absent-means-complete bridge applies only to
    /// earlier-revision servers)"*.
    const RESULT_TYPE_KEY: &'static str = "resultType";

    /// The `resultType` value stamped on any result that does not set its own.
    ///
    /// Kept as a literal rather than `to_value(ResultType::Complete)` so this
    /// path cannot fail or allocate a `Result` on every response;
    /// `test_stamped_result_type_matches_the_enum` pins the two together.
    const RESULT_TYPE_COMPLETE: &'static str = "complete";

    /// Build a success response, stamping `resultType: "complete"` unless the
    /// result already discriminates itself.
    ///
    /// Centralised here, not at the call sites, because the MUST is universal:
    /// every result-producing path would otherwise have to remember it, and the
    /// one that forgot would stay invisible until a conforming client rejected
    /// it — which is how this was found. The shapes that set their own
    /// discriminator ([`DetailedTask`], the `server/discover` result, the
    /// `subscriptions/listen` teardown) already carry the key and are left
    /// untouched, so this never overwrites a deliberate value.
    ///
    /// A non-object `result` passes through unchanged: it cannot carry a member,
    /// and wrapping it would change a shape the handler chose. No such call site
    /// exists; if one appears, the bug is in that handler.
    #[must_use]
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(Self::stamp_result_type(result)),
            error: None,
        }
    }

    /// Insert the default discriminator into an object result that lacks one.
    fn stamp_result_type(mut result: Value) -> Value {
        if let Value::Object(map) = &mut result {
            map.entry(Self::RESULT_TYPE_KEY)
                .or_insert_with(|| Value::String(Self::RESULT_TYPE_COMPLETE.to_string()));
        }
        result
    }

    #[must_use]
    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Create a success response, falling back to an internal error if serialization fails.
    ///
    /// This is a safer alternative to `success()` that avoids panicking on serialization errors.
    #[must_use]
    pub fn success_or_serialize_error(id: Option<Value>, result: &impl Serialize) -> Self {
        match serde_json::to_value(result) {
            Ok(v) => Self::success(id, v),
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize response");
                Self::error(
                    id,
                    JsonRpcError::internal_error(format!("Serialization error: {e}")),
                )
            }
        }
    }
}

/// Error code used for a request cancelled by the client.
///
/// Borrowed from LSP's `RequestCancelled`; see [`JsonRpcError::cancelled`].
pub const CANCELLED_ERROR_CODE: i32 = -32800;

/// Error code for an HTTP request whose headers do not match its body, or
/// whose required headers are missing or malformed (MCP 2026-07-28).
///
/// PROVENANCE, recorded to the same standard as its neighbour below, because
/// this code carried an uncited assertion in this codebase for one release
/// cycle and that is exactly how invented protocol ships. The published
/// schema defines `export const HEADER_MISMATCH = -32020;` and
/// `HeaderMismatchError`, whose own doc comment makes the status normative at
/// the schema level: *"Returned when a server rejects a request because the
/// values in the HTTP headers do not match the corresponding values in the
/// request body, or because required headers are missing or malformed. For
/// HTTP, the response status code MUST be `400 Bad Request`."*
///
/// It was `-32001` in the draft and was RENUMBERED before GA, together with
/// its two neighbours (`-32003` -> `-32021`, `-32004` -> `-32022`), when the
/// error-code allocation policy partitioned the server-error range. Any SDK
/// or blog post showing `-32001` for this is stale.
///
/// THE SUB-RANGE IS CLOSED WORLD: *"`-32020` to `-32099` — reserved for the
/// MCP specification. Implementations **MUST NOT** emit any code from this
/// sub-range that is not defined by this specification."* For 2026-07-28 the
/// defined set is exactly three — this, [`MISSING_REQUIRED_CLIENT_CAPABILITY`]
/// and `-32022` — and `error_codes_stay_inside_the_defined_set` pins that.
/// Two further codes are BURNED and must never be re-used: `-32002`
/// (resource not found, replaced by `-32602`) and `-32042` (URL elicitation,
/// 2025-11-25 only).
pub const HEADER_MISMATCH: i32 = -32020;

/// Error code for a request needing a client capability the request did not
/// declare (MCP 2026-07-28).
///
/// PROVENANCE, because two normative bodies disagree and one of them is
/// stale: the ext-tasks specification text says `-32003` in all four places
/// it names this error, while SEP-2663 — the proposal that actually landed
/// for 2026-07-28 — says `-32021`. The core schema settles it, defining
/// `MISSING_REQUIRED_CLIENT_CAPABILITY = -32021` and stating that a request
/// requiring an undeclared capability "is signalled instead by
/// `MissingRequiredClientCapabilityError` (-32021)". `-32003` appears nowhere
/// in the core schema, and `-32000..-32019` is the legacy sub-range new
/// implementations "SHOULD NOT use at all". A defensive CLIENT should accept
/// either code; a server must emit this one.
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Attach machine-readable `data` to an error built by one of the
    /// constructors below, none of which populate it.
    ///
    /// JSON-RPC 2.0 §5.1 leaves `data` to the server; a client that has to
    /// regex the English `message` to learn *why* a call failed is coupled to
    /// wording that changes between releases.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    #[must_use]
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
            data: None,
        }
    }

    #[must_use]
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: msg.into(),
            data: None,
        }
    }

    /// MCP 2026-07-28 `UnsupportedProtocolVersionError`.
    ///
    /// Code `-32022` is MCP-assigned: it sits inside JSON-RPC's reserved
    /// `-32768..-32000` band but is not one of the pre-assigned codes.
    ///
    /// `data.supported` carries every revision this server accepts,
    /// most-preferred first, and `data.requested` echoes back what the client
    /// asked for. Both fields are load-bearing — this specific code is how a
    /// dual-era client tells a Modern server from a Legacy one during its
    /// `server/discover` probe.
    ///
    /// Spec: `/specification/2026-07-28/basic/versioning`.
    #[must_use]
    pub fn unsupported_protocol_version(requested: &str) -> Self {
        Self {
            code: -32022,
            message: "Unsupported protocol version".to_string(),
            data: Some(serde_json::json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": requested,
            })),
        }
    }

    /// Request-cancellation error.
    ///
    /// Emitted when a `notifications/cancelled` fires while a request is
    /// still in flight.
    ///
    /// Two corrections to what this comment used to claim: `-32800` is NOT
    /// inside the JSON-RPC implementation-defined server-error range, which
    /// is -32000 to -32099; and it is not an MCP convention either — MCP
    /// defines no cancellation error code. The value is borrowed from the
    /// Language Server Protocol, whose `RequestCancelled` is -32800, because
    /// clients that speak both protocols already recognise it. The code
    /// choice stands; only the justification was wrong.
    ///
    /// Over stdio this envelope is built but never written — see
    /// `McpServer::should_send_response`. It is still produced so the HTTP
    /// transport, which has no cancellation notification path, gets a
    /// terminal answer instead of a dangling request.
    #[must_use]
    pub fn cancelled(reason: Option<String>) -> Self {
        Self {
            code: CANCELLED_ERROR_CODE,
            message: reason.unwrap_or_else(|| "Request cancelled by client".to_string()),
            data: None,
        }
    }

    /// `-32021` — the request needs a client capability it did not declare.
    ///
    /// `data.requiredCapabilities` is REQUIRED and carries "the capabilities
    /// the server requires from the client to process this request", shaped
    /// exactly like the `clientCapabilities` object the client would have had
    /// to send. It is not decoration: it is how a client learns what to
    /// declare in order to retry, without parsing the message.
    ///
    /// The message text is explicitly non-normative in the spec's own
    /// example.
    #[must_use]
    pub fn missing_required_client_capability(required: &Value) -> Self {
        Self {
            code: MISSING_REQUIRED_CLIENT_CAPABILITY,
            message: "Missing required client capability".to_string(),
            data: Some(serde_json::json!({ "requiredCapabilities": required })),
        }
    }

    /// `-32020` — HTTP header validation failed.
    ///
    /// Two distinct conditions share this code, and the caller says which in
    /// `message`: a REQUIRED standard header is missing (`MCP-Protocol-Version`,
    /// `Mcp-Method`, or `Mcp-Name` where it applies), or a present header does
    /// not match the corresponding value in the body.
    ///
    /// The spec enumerates both. Its Server Validation opening sentence covers
    /// only mismatch — *"Servers that process the request body **MUST** reject
    /// requests where the values specified in the headers do not match the
    /// corresponding values in the request body"* — and it is the
    /// failure-conditions list that extends it to absence: *"A required
    /// standard header (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) is
    /// missing."* Reading only the first sentence would leave a missing header
    /// unhandled, which is the whole Legacy-`initialize` case.
    ///
    /// HTTP-only by construction: stdio has no headers, so this code must
    /// never appear on that transport.
    #[must_use]
    pub fn header_mismatch(message: impl Into<String>) -> Self {
        Self {
            code: HEADER_MISMATCH,
            message: message.into(),
            data: None,
        }
    }
}

// ============================================================================
// MCP Protocol Types
// ============================================================================

/// MCP Initialize Request Parameters
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<RootsCapability>,
    #[serde(default)]
    pub sampling: Option<Value>,
    #[serde(default)]
    pub elicitation: Option<Value>,
    #[serde(default)]
    pub extensions: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    // A client that omits only `clientInfo.version` used to fail the whole
    // `InitializeParams` typed deserialize, silently dropping
    // `capabilities` (elicitation, sampling, roots) with it — see
    // `McpServer::handle_initialize`. `version` is metadata we log, not
    // something we validate, so defaulting it to "" keeps the rest of the
    // client's declared capabilities intact instead of discarding them.
    #[serde(default)]
    pub version: String,
}

/// MCP Initialize Response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
    /// Free-form instructions for the connected LLM to understand the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    pub tools: Option<ToolsCapability>,
    pub prompts: Option<PromptsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Completions capability (argument auto-completion).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completions: Option<CompletionsCapability>,
    /// Logging capability: `notifications/message`, and nothing else.
    ///
    /// It did mean "`logging/setLevel` + `notifications/message`". 2026-07-28
    /// deleted `logging/setLevel` — the minimum level rides on each request's
    /// `_meta["io.modelcontextprotocol/logLevel"]` instead of being latched
    /// onto a connection — and this server answers that method `-32601`. The
    /// doc described a method the code refuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingCapability>,
    /// MCP Extensions (2025-11-25+). Map of extension URI to settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    /// Optional icons for client display (SEP-973).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<Icon>>,
    /// Vendor-namespaced build provenance, keyed by [`BUILD_META_KEY`].
    /// Puts the compiled-from revision on the wire so a stale deployment is
    /// visible to a client, not only to whoever ran `make verify-install`.
    /// `#[serde(rename)]` is required: `rename_all = "camelCase"` would emit
    /// `meta`, and the spec field is `_meta`.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// Icon metadata (SEP-973). Used by `Tool`, `Resource`, `Prompt`, and
/// `Implementation` to advertise visual affordances.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Icon {
    /// URI to the icon — `https?://` URL or `data:` URI with base64 image.
    pub src: String,
    /// MIME type override (e.g. `"image/png"`, `"image/svg+xml"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Sizes in `WxH` format (e.g. `["48x48", "96x96"]`) or `["any"]` for
    /// scalable formats. Per spec this is an array, not a single string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizes: Option<Vec<String>>,
    /// Designed-for theme: `"light"` or `"dark"`. Omit when theme-agnostic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
}

/// MCP Tool Definition
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// Behavioral hints for MCP clients (MCP 2025-03-26+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Structured output schema for the tool's return value (MCP 2025-06-18+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Visual affordances for client UIs (SEP-973).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<Icon>>,
    /// Client-specific metadata hints (e.g., `anthropic/maxResultSizeChars`).
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// MCP Tools List Response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsListResult {
    /// `ttlMs` + `cacheScope`, REQUIRED on this result by 2026-07-28.
    #[serde(flatten)]
    pub cache: CacheHints,
    pub tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// MCP Tool Call Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
    /// Client-provided metadata (e.g., `progressToken` for progress notifications).
    #[serde(rename = "_meta", default)]
    pub meta: Option<ToolCallMeta>,
    /// MRTR: the client's answers to a previous `InputRequiredResult`, keyed by
    /// the identifiers the server assigned in `inputRequests`.
    ///
    /// A SIBLING of `_meta` on `params`, not a member of it. The reference
    /// client lifts exactly `["inputResponses", "requestState"]` off `params`,
    /// and the published request-params shape declares both there.
    ///
    /// Renamed explicitly: this struct carries no `rename_all`, so without the
    /// attribute serde would look for `input_responses` and silently find
    /// nothing — the retry would parse fine and arrive with no answers, which
    /// reads as "the client did not confirm".
    #[serde(rename = "inputResponses", default)]
    pub input_responses: Option<serde_json::Map<String, Value>>,
    /// MRTR: the opaque state the server issued, echoed back verbatim.
    #[serde(rename = "requestState", default)]
    pub request_state: Option<String>,
}

/// Client-provided metadata for tool calls.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallMeta {
    /// Token for sending progress notifications back to the client.
    #[serde(rename = "progressToken")]
    pub progress_token: Option<Value>,
    /// Per-request minimum log level for `notifications/message`
    /// (MCP 2026-07-28). Replaces the connection-scoped
    /// `logging/setLevel` method, which Modern deleted. Absent means
    /// `LogLevel::Warning`.
    // SPEC: verify the exact key against
    // https://modelcontextprotocol.io/specification/2026-07-28/basic/index
    // — this literal is the single place the spelling appears.
    #[serde(rename = "io.modelcontextprotocol/loggingLevel", default)]
    pub logging_level: Option<LogLevel>,
}

// Contract types re-exported from ports (canonical location: crate::ports::protocol)
pub use crate::ports::protocol::{
    AppAction, AppContent, EmbeddedResource, TaskInfo, TaskStatus, ToolAnnotations, ToolCallResult,
    ToolContent,
};

// ============================================================================
// MCP Prompts Types
// ============================================================================

pub use crate::ports::protocol::{PromptArgument, PromptContent, PromptMessage};

/// MCP Prompt Definition
#[derive(Debug, Clone, Serialize)]
pub struct PromptDefinition {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// MCP Prompts List Response
#[derive(Debug, Clone, Serialize)]
pub struct PromptsListResult {
    /// `ttlMs` + `cacheScope`, REQUIRED on this result by 2026-07-28.
    #[serde(flatten)]
    pub cache: CacheHints,
    pub prompts: Vec<PromptDefinition>,
}

/// MCP Prompts Get Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct PromptsGetParams {
    pub name: String,
    #[serde(default)]
    pub arguments: std::collections::HashMap<String, String>,
}

// PromptMessage, PromptContent, PromptArgument re-exported above

/// MCP Prompts Get Response
#[derive(Debug, Clone, Serialize)]
pub struct PromptsGetResult {
    pub messages: Vec<PromptMessage>,
}

// ============================================================================
// MCP Resources Types
// ============================================================================

pub use crate::ports::protocol::{ResourceContent, ResourceDefinition};

/// MCP Resources List Response
#[derive(Debug, Clone, Serialize)]
pub struct ResourcesListResult {
    /// `ttlMs` + `cacheScope`, REQUIRED on this result by 2026-07-28.
    #[serde(flatten)]
    pub cache: CacheHints,
    pub resources: Vec<ResourceDefinition>,
}

/// MCP Resources Read Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct ResourcesReadParams {
    pub uri: String,
}

/// MCP Resources Read Response
#[derive(Debug, Clone, Serialize)]
pub struct ResourcesReadResult {
    /// `ttlMs` + `cacheScope`, REQUIRED on this result by 2026-07-28.
    /// [`CacheHints::LIVE_REMOTE`]: this is host payload, not capability
    /// metadata.
    #[serde(flatten)]
    pub cache: CacheHints,
    pub contents: Vec<ResourceContent>,
}

/// MCP Resources Capability
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    pub subscribe: bool,
    pub list_changed: bool,
}

/// MCP Resource Template (returned by resources/templates/list)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplate {
    pub uri_template: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Resource Templates List Response
///
/// Typed rather than a bare `json!` so the cache hints 2026-07-28 REQUIRES on
/// this result cannot be forgotten on one of the two return paths.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplatesListResult {
    /// `ttlMs` + `cacheScope`, REQUIRED on this result by 2026-07-28.
    #[serde(flatten)]
    pub cache: CacheHints,
    pub resource_templates: Vec<ResourceTemplate>,
}

// ============================================================================
// MCP Tasks Types (MCP 2025-11-25+, experimental)
// ============================================================================

// TaskStatus and TaskInfo re-exported from ports::protocol above.

/// Modern (2026-07-28) discriminator telling a client which *shape* of result
/// it is holding — NOT how far along the work is.
///
/// PROVENANCE: the core union is
/// `"complete" | "input_required" | "task" | string`. Two MUSTs bound the two
/// variants spelled here:
///
/// - "Servers **MUST** set `resultType` to `"task"` when returning a
///   `CreateTaskResult` so that clients can distinguish it from a standard
///   result. Servers **MUST NOT** set `resultType` to `"task"` on result types
///   other than `CreateTaskResult`."
/// - On a `tasks/get` response: "The `resultType` field **MUST** be set to
///   `"complete"` on this object as it is the standard result shape for the
///   `tasks/get` request."
///
/// A pre-3.0.0 draft of this enum carried a `Working` variant, reasoning that
/// it should "reuse the spelling `TaskStatus::Working` already puts on the
/// wire". That was the mistake this doc-comment exists to prevent: `"working"`
/// is a `TaskStatus` and never a `ResultType`. The two are orthogonal axes —
/// every `tasks/get` answer carries `resultType: "complete"`, including one
/// reporting `status: "working"`.
///
/// `input_required` IS spelled here now. It was omitted on the reasoning that
/// "bridge-mcp never enters that state", which stopped being true when the
/// destructive-confirmation gate moved to Multi Round-Trip Requests: an
/// `InputRequiredResult` is exactly how the server asks for that confirmation.
///
/// `Serialize` only, on purpose: this server emits `resultType` and never
/// parses one. Adding `Deserialize` would need a catch-all variant, and
/// serde's `#[serde(other)]` is not available on a plain externally-tagged
/// enum.
/// `snake_case`, not `camelCase`. The wire values are `"complete"`, `"task"` and
/// `"input_required"`; the first two are identical under either convention,
/// which is why `camelCase` stood here unchallenged and would have emitted
/// `"inputRequired"` the moment a third variant existed. A client seeing that
/// MUST treat it as invalid — *"A `resultType` of any value unrecognized by
/// the client MUST be considered invalid"* — so the bug would have surfaced as
/// every confirmation being rejected, not as a cosmetic difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultType {
    /// The standard result shape. Carried by every `tasks/get` answer
    /// whatever the task's status, and by the `tasks/cancel` /`tasks/update`
    /// acks.
    Complete,
    /// A task handle returned in lieu of a standard result. Legal on
    /// `CreateTaskResult` and nowhere else.
    Task,
    /// More input is needed before the request can be completed. Legal on
    /// `prompts/get`, `resources/read` and `tools/call`, and *"Servers MUST NOT
    /// send `InputRequiredResult` responses on any other client requests."*
    InputRequired,
}

/// One flat struct covering `CreateTaskResult` and `GetTaskResult`.
///
/// Both are `Result & Task` / `Result & DetailedTask` in 2026-07-28, so one
/// type serves both; only `result_type` and which payload field is populated
/// distinguish them. This replaces the pre-3.0.0 `CreateTaskResult`, whose
/// nested `result.task` object was the 2025-11-25 shape.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailedTask {
    /// [`ResultType::Task`] on the handle returned in lieu of a tool result;
    /// [`ResultType::Complete`] on every `tasks/get` snapshot. Not optional
    /// and never skipped: the spec makes the discriminator a MUST on both,
    /// and an omitted `resultType` is exactly what a client cannot
    /// distinguish from a standard `CallToolResult`.
    pub result_type: ResultType,

    /// The seven `Task` fields, FLATTENED to the root of the result.
    ///
    /// `Result & Task` is flat in 2026-07-28 — `taskId`, `status`, `ttlMs`
    /// and the rest sit directly on `result`, with no enclosing `task`
    /// object. 2025-11-25 nested them; this is the exact reversal.
    ///
    /// The flatten is what lets the domain keep an unpolluted [`TaskInfo`]
    /// while the wire stays flat. Note that `#[serde(flatten)]` is
    /// incompatible with `deny_unknown_fields` — harmless here, since this
    /// type is `Serialize`-only.
    #[serde(flatten)]
    pub task: TaskInfo,

    /// Present iff `status == Completed`: the original `ToolCallResult`,
    /// including ones carrying `isError: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Present iff `status == Failed`: a JSON-RPC error object. Protocol
    /// faults only — a tool that ran and failed is `Completed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,

    /// Present iff `status == InputRequired`. bridge-mcp never enters that
    /// state, so this is always `None`; the field exists so the shape is
    /// complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_requests: Option<Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
}

impl DetailedTask {
    /// The handle returned in lieu of a tool result: `resultType: "task"`,
    /// no payload (the task has not produced one yet).
    #[must_use]
    pub fn handle(task: TaskInfo) -> Self {
        Self {
            result_type: ResultType::Task,
            task,
            result: None,
            error: None,
            input_requests: None,
            meta: None,
        }
    }

    /// A `tasks/get` snapshot: `resultType: "complete"` whatever the status,
    /// because a snapshot IS the standard result shape for that method.
    #[must_use]
    pub fn snapshot(task: TaskInfo) -> Self {
        Self {
            result_type: ResultType::Complete,
            task,
            result: None,
            error: None,
            input_requests: None,
            meta: None,
        }
    }

    /// Attach the completed task's `ToolCallResult`.
    #[must_use]
    pub fn with_result(mut self, result: Value) -> Self {
        self.result = Some(result);
        self
    }

    /// Attach the failed task's JSON-RPC error object.
    #[must_use]
    pub fn with_error(mut self, error: Value) -> Self {
        self.error = Some(error);
        self
    }
}

/// Parameters for `tasks/get`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskGetParams {
    pub task_id: String,
}

/// Parameters for `tasks/update`.
///
/// `inputResponses` is accepted and then ignored — see `handle_tasks_update`
/// for why that is conformant here. It is typed as a raw `Value` rather than
/// a map of `InputResponse`, because parsing a union this server can never
/// have asked for would be modelling a state it cannot enter.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskUpdateParams {
    pub task_id: String,
    #[serde(default)]
    pub input_responses: Option<Value>,
}

/// Parameters for `tasks/cancel`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCancelParams {
    pub task_id: String,
}

// ============================================================================
// MCP Completions Types
// ============================================================================

/// Completions capability for `ServerCapabilities`.
#[derive(Debug, Clone, Serialize)]
pub struct CompletionsCapability {}

/// Reference type for completion requests (tagged by `"type"` field).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum CompletionRef {
    /// Auto-complete a prompt argument.
    #[serde(rename = "ref/prompt")]
    Prompt { name: String },
    /// Auto-complete a resource argument.
    #[serde(rename = "ref/resource")]
    Resource { uri: String },
}

/// Parameters for `completions/complete`.
#[derive(Debug, Clone, Deserialize)]
pub struct CompletionsCompleteParams {
    /// The prompt or resource being completed.
    #[serde(rename = "ref")]
    pub reference: CompletionRef,
    /// The argument being typed.
    pub argument: CompletionArgument,
}

/// A single argument being auto-completed.
#[derive(Debug, Clone, Deserialize)]
pub struct CompletionArgument {
    /// Argument name (e.g. `"host"`).
    pub name: String,
    /// Prefix typed so far (e.g. `"web"`).
    pub value: String,
}

/// Response for `completions/complete`.
#[derive(Debug, Clone, Serialize)]
pub struct CompletionsCompleteResult {
    pub completion: CompletionResult,
}

/// The completion values returned to the client.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionResult {
    pub values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

// ============================================================================
// MCP Logging Types
// ============================================================================

/// Logging capability for `ServerCapabilities`.
#[derive(Debug, Clone, Serialize)]
pub struct LoggingCapability {}

/// MCP log levels ordered by severity (lowest to highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    Alert = 6,
    Emergency = 7,
}

impl LogLevel {
    /// Numeric severity (0 = debug, 7 = emergency).
    #[must_use]
    pub fn severity(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// MCP Elicitation Types
// ============================================================================

/// Parameters for `elicitation/create` (server → client request).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElicitationCreateParams {
    /// Which `ElicitRequest` variant this is.
    ///
    /// The published request params are a union discriminated by `mode`, and
    /// the spec's own MRTR example carries `"mode": "form"` explicitly. It was
    /// absent here, so every request this server built was missing the
    /// discriminator its own union needs.
    pub mode: ElicitationMode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
    /// SEP-1036 URL mode: client opens browser. Required when
    /// [`ElicitationMode::Url`], and meaningless otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// The `ElicitRequest` variant discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationMode {
    /// Ask for structured input against `requestedSchema`.
    Form,
    /// Send the user to a URL.
    Url,
}

/// A result saying the request cannot finish until the client supplies more.
///
/// *"Servers MUST include at least one of `inputRequests` or `requestState` in
/// every `InputRequiredResult` response."* Both are `Option` because either may
/// be omitted individually; [`InputRequiredResult::new`] is the constructor
/// that enforces the "at least one" part, so no call site can build an empty
/// one by accident. The reference client rejects that shape by name.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputRequiredResult {
    /// Always [`ResultType::InputRequired`].
    pub result_type: ResultType,
    /// Server-assigned keys to `ElicitRequest` / `CreateMessageRequest` /
    /// `ListRootsRequest` objects. *"keys are server assigned identifiers and
    /// MUST be unique within the scope of the request"* — a `Map` gives that
    /// for free.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_requests: Option<serde_json::Map<String, Value>>,
    /// Opaque to the client: *"Clients MUST NOT inspect, parse, modify, or make
    /// any assumptions about its contents."*
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_state: Option<String>,
}

impl InputRequiredResult {
    /// Build a result carrying one server-to-client request and the state
    /// needed to recognise the retry.
    #[must_use]
    pub fn new(key: &str, request: Value, request_state: String) -> Self {
        let mut requests = serde_json::Map::new();
        requests.insert(key.to_string(), request);
        Self::with_requests(requests, request_state)
    }

    /// Build a result carrying SEVERAL server-to-client requests at once.
    ///
    /// The spec's own example carries two, and asking for everything the
    /// request needs in one result is what the error-handling section pushes
    /// toward: challenging incrementally "forces multiple authorization
    /// round-trips for a single operation". A confirmation and a `roots/list`
    /// wanted by the same call travel together.
    #[must_use]
    pub fn with_requests(
        input_requests: serde_json::Map<String, Value>,
        request_state: String,
    ) -> Self {
        Self {
            result_type: ResultType::InputRequired,
            input_requests: Some(input_requests),
            request_state: Some(request_state),
        }
    }
}

/// Response from client for `elicitation/create`.
#[derive(Debug, Clone, Deserialize)]
pub struct ElicitationCreateResult {
    /// `"accept"`, `"decline"`, or `"cancel"`.
    pub action: String,
    #[serde(default)]
    pub content: Option<Value>,
}

// ============================================================================
// MCP Sampling Types (with Tools, SEP-1577)
// ============================================================================

/// Parameters for `sampling/createMessage` (server → client request).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingCreateMessageParams {
    pub messages: Vec<SamplingMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<ModelPreferences>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// `"none"`, `"thisServer"`, or `"allServers"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_context: Option<String>,
    pub max_tokens: u32,
    /// Tool definitions for tool-use in sampling (SEP-1577).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<SamplingTool>>,
}

/// A message in a sampling request.
#[derive(Debug, Clone, Serialize)]
pub struct SamplingMessage {
    pub role: String,
    pub content: SamplingContent,
}

/// Build a `CreateMessageRequest` for an `inputRequests` entry.
///
/// Shaped as the `{method, params}` pair MRTR puts in the map, not sent: *"the
/// server ... does not send its own JSON-RPC request. It returns an
/// `InputRequiredResult` containing `inputRequests`."*
///
/// The instruction goes in `systemPrompt` and the data in a single user
/// message, which is the split the thirteen `summarize=true` handlers already
/// used when this was a blocking call.
///
/// Returns a `Value` rather than a typed request because `inputRequests` values
/// are a union of three request types and the map holds them side by side.
#[must_use]
pub fn sampling_request(prompt: &str, content: &str, max_tokens: u32) -> Value {
    let params = SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: SamplingContent::Text {
                text: content.to_string(),
            },
        }],
        model_preferences: None,
        system_prompt: Some(prompt.to_string()),
        include_context: None,
        max_tokens,
        tools: None,
    };
    serde_json::json!({
        "method": "sampling/createMessage",
        "params": serde_json::to_value(&params).unwrap_or_else(|_| serde_json::json!({})),
    })
}

/// The text of a `CreateMessageResult` the client returned.
///
/// `None` when the answer is not a text result — a client may legitimately
/// return other content types, and there is nothing to append then.
#[must_use]
pub fn sampling_answer_text(answer: &Value) -> Option<&str> {
    answer.get("content")?.get("text")?.as_str()
}

/// Content of a sampling message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SamplingContent {
    Text { text: String },
}

/// Model preferences for sampling.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPreferences {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<ModelHint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_priority: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_priority: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence_priority: Option<f64>,
}

/// A model hint for sampling preferences.
#[derive(Debug, Clone, Serialize)]
pub struct ModelHint {
    pub name: String,
}

/// A tool definition for sampling with tools (SEP-1577).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Response from client for `sampling/createMessage`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingCreateMessageResult {
    pub role: String,
    pub content: SamplingContent,
    pub model: String,
    #[serde(default)]
    pub stop_reason: Option<String>,
}

// ============================================================================
// Reverse Request Types (server → client requests for Elicitation/Sampling)
// ============================================================================

/// Flexible inbound JSON-RPC message (can be a request OR a response).
///
/// Used by the main loop to distinguish client requests from client responses
/// to server-initiated requests (elicitation, sampling).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcMessage {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcErrorData>,
}

/// Error data from a client response to a server-initiated request.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcErrorData {
    pub code: i32,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

// ============================================================================
// MCP Extensions
// ============================================================================

/// Params of a `notifications/tasks` notification: a full `DetailedTask`.
///
/// "Each notification carries a complete `DetailedTask` for the current
/// status, identical to what `tasks/get` would have returned at that moment."
/// The narrative spec renders these params as a bare `Task`; `schema.ts` —
/// which declares itself the source of truth — says `DetailedTask`, and the
/// prose agrees. The payload is what makes the notification worth having: a
/// client that subscribes never has to poll for the result.
///
/// This is NOT [`DetailedTask`], and the difference is one field:
/// `resultType` discriminates a RESULT, and a notification is not a result.
/// The spec's own literal notification carries no such key, and
/// [`DetailedTask::result_type`] is deliberately non-optional so that every
/// `tasks/get` answer must carry one. Reusing it here would have forced that
/// field to become skippable — weakening a MUST on the response path to serve
/// the notification path.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskNotificationParams {
    /// The seven `Task` fields, flattened to the root of `params`.
    #[serde(flatten)]
    pub task: TaskInfo,
    /// Present iff `status == Completed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present iff `status == Failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl TaskNotificationParams {
    /// Route `payload` to the field the task's status calls for.
    ///
    /// The routing lives here, once, because it is a MUST that both emission
    /// sites and `tasks/get` have to agree on: a completed task carries
    /// `result`, a failed one carries `error`, and a non-terminal one carries
    /// neither. Duplicating the match at each call site is how the two drift.
    #[must_use]
    pub fn new(task: TaskInfo, payload: Option<Value>) -> Self {
        let (result, error) = match task.status {
            TaskStatus::Completed => (payload, None),
            TaskStatus::Failed => (None, payload),
            // `working` and `input_required` have no payload yet; `cancelled`
            // never gets one — `CancelledTask` extends `Task` with no result.
            TaskStatus::Working | TaskStatus::InputRequired | TaskStatus::Cancelled => (None, None),
        };
        Self {
            task,
            result,
            error,
        }
    }
}

/// Well-known extension URIs advertised by this server.
pub mod extensions {
    /// Tasks extension (standard MCP).
    pub const TASKS: &str = "io.modelcontextprotocol/tasks";
    /// Output pagination extension (custom).
    pub const OUTPUT_PAGINATION: &str = "com.bridge-mcp/output-pagination";
    /// Multi-host execution extension (custom).
    pub const MULTI_HOST: &str = "com.bridge-mcp/multi-host";
}

// ============================================================================
// JSON-RPC Notifications
// ============================================================================

/// JSON-RPC 2.0 Notification (server → client, no id, no response expected)
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    /// Optional params payload (used by `notifications/tasks`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// `_meta` key correlating a notification to the `subscriptions/listen`
/// request that authorised it (MCP 2026-07-28,
/// `basic/patterns/subscriptions`).
///
/// Re-exported from `request_meta::keys::SUBSCRIPTION_ID` rather than
/// declared here a second time — the per-request `_meta`-envelope module
/// already owns every `io.modelcontextprotocol/` wire key. Every producer
/// and consumer of subscription notifications MUST use this constant.
pub use super::request_meta::keys::SUBSCRIPTION_ID as META_SUBSCRIPTION_ID;

impl JsonRpcNotification {
    /// Create a `notifications/tools/list_changed` notification.
    #[must_use]
    pub fn tools_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/tools/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/prompts/list_changed` notification.
    #[must_use]
    pub fn prompts_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/prompts/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/resources/list_changed` notification.
    #[must_use]
    pub fn resources_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/resources/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/tasks` notification (MCP 2026-07-28).
    ///
    /// The method name lost its `/status` suffix: 2025-11-25 spelled it
    /// `notifications/tasks/status`. Both live under the `notifications/tasks/`
    /// prefix the extension reserves, so a client subscribed to the new name
    /// would silently receive nothing from a server still sending the old one.
    #[must_use]
    pub fn task_notification(params: &TaskNotificationParams) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/tasks".to_string(),
            params: serde_json::to_value(params).ok(),
        }
    }

    /// Create a `notifications/progress` notification (MCP Progress).
    #[must_use]
    pub fn progress(
        token: &Value,
        progress: u64,
        total: Option<u64>,
        message: Option<&str>,
    ) -> Self {
        let mut params = serde_json::json!({
            "progressToken": token,
            "progress": progress,
        });
        if let Some(t) = total {
            params["total"] = serde_json::json!(t);
        }
        if let Some(m) = message {
            params["message"] = serde_json::json!(m);
        }
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/progress".to_string(),
            params: Some(params),
        }
    }

    /// Create a `notifications/message` log notification (MCP Logging).
    #[must_use]
    pub fn log_message(level: LogLevel, logger: &str, data: &Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/message".to_string(),
            params: Some(serde_json::json!({
                "level": level,
                "logger": logger,
                "data": data,
            })),
        }
    }

    /// Build the `_meta` object carrying the subscription correlation id.
    ///
    /// The id is the JSON-RPC `id` of the `subscriptions/listen` request
    /// that opened the stream — `RequestId = string | number` — so it is
    /// carried as a `Value` and copied through byte-for-byte. It is NOT an
    /// independent identifier space and must never be minted server-side.
    fn meta_subscription(subscription_id: &Value) -> Value {
        let mut meta = serde_json::Map::new();
        meta.insert(META_SUBSCRIPTION_ID.to_string(), subscription_id.clone());
        Value::Object(meta)
    }

    /// Create a subscription-scoped notification carrying only the
    /// subscription correlation `_meta`.
    ///
    /// MCP 2026-07-28 requires every notification delivered because of a
    /// `subscriptions/listen` request to name that subscription: several
    /// subscriptions share one stdio pipe, and the client routes on this
    /// id alone.
    #[must_use]
    pub fn for_subscription(method: &str, subscription_id: &Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: Some(serde_json::json!({
                "_meta": Self::meta_subscription(subscription_id),
            })),
        }
    }

    /// Create a `notifications/resources/updated` notification for one URI.
    #[must_use]
    pub fn resources_updated(uri: &str, subscription_id: &Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/resources/updated".to_string(),
            params: Some(serde_json::json!({
                "_meta": Self::meta_subscription(subscription_id),
                "uri": uri,
            })),
        }
    }

    /// Create the `notifications/subscriptions/acknowledged` notification
    /// answering a `subscriptions/listen` request.
    ///
    /// `notifications` is the subset the server actually honours — never a
    /// blind echo of the request. The client treats this value, not its
    /// own request, as the source of truth for what will arrive.
    ///
    /// This is a NOTIFICATION, not the JSON-RPC `result` for the listen
    /// request: a client's pending-request table must not resolve on it.
    #[must_use]
    pub fn subscriptions_acknowledged(subscription_id: &Value, notifications: &Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/subscriptions/acknowledged".to_string(),
            params: Some(serde_json::json!({
                "_meta": Self::meta_subscription(subscription_id),
                "notifications": notifications,
            })),
        }
    }
}

/// Messages sent through the stdout writer channel.
///
/// The writer task serializes both responses and unsolicited notifications
/// to the same stdout stream.
///
/// `Clone` is required for the per-session fanout introduced by
/// FIND-034 (audit 2026-05-09): the config watcher broadcasts a single
/// `WriterMessage` to every live session, and each `try_send` consumes
/// one copy.
#[derive(Clone)]
pub enum WriterMessage {
    /// A JSON-RPC response to a client request.
    Response(Box<JsonRpcResponse>),
    /// An unsolicited server notification (e.g., `list_changed`).
    ///
    /// A NOTIFICATION, never a request. 2026-07-28 removed the third variant
    /// this enum used to carry: *"Servers MUST send server-to-client requests
    /// ... using the MRTR pattern. The previous pattern of server-initiated
    /// requests is no longer supported."* Server-to-client requests now travel
    /// as `inputRequests` inside an `InputRequiredResult` — a RESULT, on the
    /// `Response` variant — so nothing this server writes is ever a request.
    Notification(JsonRpcNotification),
}

// ============================================================================
// MCP Roots Types
// ============================================================================

/// A root entry returned by `roots/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootEntry {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Response for `roots/list`.
#[derive(Debug, Clone, Deserialize)]
pub struct RootsListResult {
    pub roots: Vec<RootEntry>,
}

// ============================================================================
// MCP Protocol Version
// ============================================================================

/// The single MCP revision this server speaks ("Modern", 2026-07-28).
pub const PROTOCOL_VERSION: &str = "2026-07-28";
/// Every revision this server accepts, most-preferred first.
///
/// Modern-only by design (3.0.0). This slice is also the `data.supported`
/// payload of the `-32022 UnsupportedProtocolVersionError` returned to Legacy
/// clients that still send `initialize`.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28"];

/// How long a client may cache a `server/discover` result, in milliseconds.
///
/// One hour, matching the spec's own example.
///
/// Normative wording is on `/specification/2026-07-28/server/utilities/caching`:
/// `ttlMs` is *"a hint from the server indicating how long, in milliseconds, the
/// client MAY consider the result fresh"*, with semantics analogous to HTTP
/// `Cache-Control: max-age`. It is **not** a MUST-not-exceed bound on the
/// server's data — the server MAY change the underlying data before it expires;
/// the value only tells a client how long it can reasonably skip re-fetching.
///
/// Servers MUST provide a value `>= 0`, and MUST include caching hints on any
/// `resultType: "complete"` result. `0` means immediately stale; an absent value
/// makes clients assume `0`. Both are why this is a plain `u64` constant rather
/// than an `Option` — a Modern server always sends one.
pub const DISCOVER_TTL_MS: u64 = 3_600_000;

/// Discriminator on a `server/discover` result.
///
/// The spec enum has exactly two named variants at 2026-07-28 —
/// `"complete"` and `"input_required"` — over a `| string` extension point that
/// is deliberate, not an omission. Servers implementing this revision MUST
/// include the field; a client receiving a result without one MUST treat it as
/// `"complete"`.
///
/// Only `Complete` is modelled: `input_required` announces that the server needs
/// something from the client first (auth, elicitation) or is load-shedding, and
/// carries `inputRequests`/`requestState`. This server computes the whole
/// discovery payload synchronously from local config, so it has nothing to ask
/// for. Note such results are also explicitly *not* cacheable and carry no
/// `ttlMs`/`cacheScope`, which is why `DiscoverResult` can keep both non-`Option`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoverResultType {
    Complete,
}

/// Cache scope of a `server/discover` result.
///
/// Borrowed from HTTP `Cache-Control` semantics: `public` means the result may
/// be cached and replayed to *any* caller.
///
/// The spec enum is closed and has exactly two values
/// (`/specification/2026-07-28/server/utilities/caching`, where all `ttlMs` and
/// `cacheScope` normativity lives — not the discover page):
///
/// - `"public"` — the response contains no user-specific data; any client,
///   shared gateway or caching proxy MAY store it and serve it to any user.
///   Appropriate for tool/prompt/resource-template lists that are identical
///   for all users.
/// - `"private"` — the response contains data not meant to be shared between
///   callers. Caches MUST NOT be shared across authorization contexts.
///
/// `Public` is honest for a capability surface for exactly one reason:
/// bridge-mcp has no per-caller authorization. Tool-group enablement is
/// process-wide (`config.tool_groups`), and `rbac.enabled: true` is rejected at
/// config load (`src/config/loader.rs:226`) because nothing in the request path
/// enforces it. 2026-07-28 also requires list endpoints not to vary per
/// connection, so a uniform answer is the conformant shape, not a shortcut.
/// `tools/list`, `prompts/list`, `resources/list` and
/// `resources/templates/list` are `Public` on this basis.
///
/// `server/discover` is `Private` DESPITE that precondition holding for it too
/// — its `capabilities` and tool inventory are just as uniform as the list
/// endpoints above. What is NOT uniform is `instructions`: its LIMITS line
/// states `effective_max_output_chars(client_name)`, a per-client override
/// (the built-in Tier 1 override alone doubles the base limit for Claude
/// clients). A `Public` result stating one caller's limit could be replayed
/// by an intermediary to a caller entitled to a different one — RBAC being
/// dead does not make this uniform, because this varies from a plain
/// per-client config lookup that exists independently of RBAC ever shipping.
/// See `handle_discover` in `src/mcp/server.rs`.
///
/// `Private` also covers a second, unrelated case: `resources/read` does not
/// return capability metadata, it returns payload — `log://` file contents,
/// `history://recent` command history, `file://` reads off the remote host.
/// Whether or not two callers are authorized identically, announcing to every
/// intermediary that a shell history "may be cached and served to any user" is
/// a claim this server has no business making. Capability lists that are
/// genuinely uniform are `Public`; read payloads and per-caller-varying
/// results are `Private`.
///
/// The caching page is explicit that this flag is not itself a control:
/// *"Servers MUST be aware that responses with a `"public"` `cacheScope` may be
/// shared between callers even if the Result is coming from an authenticated
/// endpoint. […] MUST apply appropriate per-primitive access controls, and MUST
/// NOT rely on `cacheScope` alone to prevent unauthorized access."*
///
/// So if RBAC ever gains a request-path enforcement point, `Public` becomes an
/// information leak on the REMAINING `Public` methods above — one caller's
/// cached capability list replayed to another — and each would need to move to
/// `Private` too. The tripwire test
/// `test_cache_scope_is_private_for_two_independent_reasons` in
/// `src/mcp/server.rs` pins both `server/discover`'s existing reason (the
/// per-client LIMITS line, checked by actually diffing two payloads) and the
/// still-live RBAC precondition (checked by behavior) together.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CacheScope {
    Public,
    Private,
}

/// The caching hints 2026-07-28 REQUIRES on every cacheable result.
///
/// Six methods declare them, and the published result schemas make both fields
/// mandatory — not `optional` — on each: `server/discover`, `tools/list`,
/// `prompts/list`, `resources/list`, `resources/templates/list` and
/// `resources/read`. `tools/call`, `prompts/get` and `completion/complete` do
/// NOT declare them, so they must not carry them.
///
/// Until this type existed only `server/discover` sent the pair, and the other
/// five were rejected outright by a conforming client. That is not a soft
/// failure: the reference client answers `tools/list` with a schema error and
/// the session ends up connected with zero tools.
///
/// Flattened into each result struct so the two fields sit at the root of
/// `result`, where the schema puts them.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheHints {
    pub ttl_ms: u64,
    pub cache_scope: CacheScope,
}

impl CacheHints {
    /// Hints for a list derived from process-wide config.
    ///
    /// The tool, prompt, resource and template lists change only when the
    /// config is reloaded, which is the same lifetime as the `server/discover`
    /// payload built from that config — hence the shared TTL.
    ///
    /// One hour is defensible even though notifications are opt-in in this
    /// revision: a client that never sent `subscriptions/listen` gets no
    /// `listChanged` invalidation, so the TTL is its ONLY bound on staleness.
    /// An hour is the spec's own example value and the ceiling this server is
    /// willing to assert for a config that a human edits.
    pub const CONFIG_DERIVED: Self = Self {
        ttl_ms: DISCOVER_TTL_MS,
        cache_scope: CacheScope::Public,
    };

    /// Hints for a payload read live off a remote host.
    ///
    /// `ttl_ms: 0` — *"`0` means immediately stale"*. This is the honest value
    /// and not a placeholder: bridge-mcp has no change feed for the remote host
    /// (which is why `notifications/resources/updated` polls remote-backed
    /// schemes on a 30 s timer and emits a "poll again" hint rather than a real
    /// change event). Any positive TTL would assert a freshness window this
    /// server cannot observe.
    ///
    /// [`CacheScope::Private`] because the payload is host data — logs, command
    /// history, file contents — not capability metadata. See the enum docs.
    pub const LIVE_REMOTE: Self = Self {
        ttl_ms: 0,
        cache_scope: CacheScope::Private,
    };
}

/// `result._meta` of a `server/discover` response.
///
/// In 2026-07-28 `serverInfo` is no longer a top-level sibling of
/// `capabilities`; it lives here, under the reserved reverse-DNS key. The key
/// string is spelled exactly once, in the `serde(rename)` below.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverMeta {
    #[serde(rename = "io.modelcontextprotocol/serverInfo")]
    pub server_info: ServerInfo,
}

/// Result of `server/discover` (MCP 2026-07-28) — the Modern replacement for
/// `InitializeResult`.
///
/// Field order below matches the spec's own example.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverResult {
    pub result_type: DiscoverResultType,
    pub supported_versions: Vec<String>,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<DiscoverMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    pub ttl_ms: u64,
    pub cache_scope: CacheScope,
}

pub const SERVER_NAME: &str = "bridge-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git revision this binary was compiled from: 12 hex chars, optionally
/// suffixed `-dirty`, or `unknown` when built outside a git checkout.
/// Emitted by `build.rs`. This is the only thing that distinguishes two
/// builds of the same `CARGO_PKG_VERSION`.
pub const BUILD_REV: &str = env!("BRIDGE_MCP_BUILD_REV");
/// Vendor-namespaced `_meta` key carrying build provenance in `serverInfo`.
/// Matches the reverse-DNS package name in `server.json`.
pub const BUILD_META_KEY: &str = "io.github.muchiny/build";
/// URL of the server icon advertised in `ServerInfo` (SEP-973). Points at the
/// committed `dxt/icon.svg`, served raw from GitHub `main`.
///
/// The org is `muchiny`, matching `Cargo.toml`, `server.json` and
/// `serverInfo.websiteUrl`. `muchini` is the maintainer's unix username and
/// resolves to nothing on GitHub; `scripts/check-github-org.sh` fails CI if
/// the two spellings ever diverge again (G-27, audit 2026-08-19).
pub const SERVER_ICON_URL: &str =
    "https://raw.githubusercontent.com/muchiny/bridge-mcp/main/dxt/icon.svg";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ============== resultType discriminator (2026-07-28) ==============

    /// The literal `success` stamps and the enum the rest of the server emits
    /// must be the same string. They are declared separately — a `const` on
    /// [`JsonRpcResponse`] and a serde rename on [`ResultType`] — so nothing but
    /// this test stops them drifting apart.
    #[test]
    fn test_stamped_result_type_matches_the_enum() {
        assert_eq!(
            serde_json::to_value(ResultType::Complete).unwrap(),
            json!(JsonRpcResponse::RESULT_TYPE_COMPLETE),
        );
    }

    /// *"All results must now include a `resultType` field"* — 2026-07-28.
    #[test]
    fn test_success_stamps_result_type_complete() {
        let r = JsonRpcResponse::success(Some(json!(1)), json!({"tools": []}));
        let result = r.result.expect("a success carries a result");
        assert_eq!(result["resultType"], "complete");
        assert!(result["tools"].is_array(), "the payload survives: {result}");
    }

    /// A result that discriminates itself keeps its own value. Overwriting a
    /// task handle with `"complete"` would erase the one field that tells a
    /// client it received a handle and not an answer.
    #[test]
    fn test_success_never_overwrites_an_explicit_result_type() {
        let r = JsonRpcResponse::success(
            Some(json!(1)),
            json!({"resultType": "task", "taskId": "t-1", "status": "working"}),
        );
        assert_eq!(r.result.unwrap()["resultType"], "task");
    }

    /// The stamp is idempotent: re-wrapping an already-stamped result is a
    /// no-op rather than a duplicate key or an overwrite.
    #[test]
    fn test_success_stamp_is_idempotent() {
        let once = JsonRpcResponse::success(Some(json!(1)), json!({}))
            .result
            .unwrap();
        let twice = JsonRpcResponse::success(Some(json!(1)), once.clone())
            .result
            .unwrap();
        assert_eq!(once, twice);
        assert_eq!(twice["resultType"], "complete");
    }

    /// A non-object result cannot carry a member. It passes through untouched
    /// rather than being silently reshaped.
    #[test]
    fn test_success_leaves_a_non_object_result_alone() {
        let r = JsonRpcResponse::success(Some(json!(1)), json!([1, 2, 3]));
        assert_eq!(r.result.unwrap(), json!([1, 2, 3]));
    }

    /// An error response has no `result` member at all, so there is nothing to
    /// discriminate — `resultType` must not appear on it.
    #[test]
    fn test_error_response_carries_no_result_type() {
        let r = JsonRpcResponse::error(Some(json!(1)), JsonRpcError::internal_error("boom"));
        assert!(r.result.is_none());
        let wire = serde_json::to_value(&r).unwrap();
        assert!(wire.get("result").is_none(), "{wire}");
        assert!(wire.get("resultType").is_none(), "{wire}");
    }

    /// `success_or_serialize_error` routes through `success`, so a serialised
    /// struct is stamped exactly like a hand-built `json!` object.
    #[test]
    fn test_success_or_serialize_error_is_stamped_too() {
        #[derive(Serialize)]
        struct Payload {
            ok: bool,
        }
        let r = JsonRpcResponse::success_or_serialize_error(Some(json!(1)), &Payload { ok: true });
        let result = r.result.expect("a serialisable payload succeeds");
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["ok"], true);
    }

    // ============== JsonRpcRequest Tests ==============

    #[test]
    fn test_request_deserialization_with_id() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"test","params":{"foo":"bar"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, Some(json!(1)));
        assert_eq!(req.method, "test");
        assert!(req.params.is_some());
    }

    #[test]
    fn test_request_deserialization_without_id() {
        // Notification (no id)
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
        assert!(req.params.is_none());
    }

    #[test]
    fn test_request_deserialization_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Some(json!("abc-123")));
    }

    #[test]
    fn test_request_deserialization_null_id() {
        // In serde_json, "id": null is deserialized as None for Option<Value>
        // This is correct for JSON-RPC: null id means the request is a notification
        let json = r#"{"jsonrpc":"2.0","id":null,"method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, None);
    }

    // ============== JsonRpcResponse Tests ==============

    #[test]
    fn test_response_success_serialization() {
        let response = JsonRpcResponse::success(Some(json!(1)), json!({"result": "ok"}));
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_response_error_serialization() {
        let error = JsonRpcError::internal_error("Something went wrong");
        let response = JsonRpcResponse::error(Some(json!(1)), error);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32603"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_response_success_or_serialize_error_ok() {
        #[derive(Serialize)]
        struct TestResult {
            value: i32,
        }
        let result = TestResult { value: 42 };
        let response = JsonRpcResponse::success_or_serialize_error(Some(json!(1)), &result);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    // ============== JsonRpcError Tests ==============

    #[test]
    fn test_error_parse_error_code() {
        let error = JsonRpcError::parse_error("Invalid JSON");
        assert_eq!(error.code, -32700);
        assert_eq!(error.message, "Invalid JSON");
    }

    #[test]
    fn test_error_invalid_request_code() {
        let error = JsonRpcError::invalid_request("Missing jsonrpc");
        assert_eq!(error.code, -32600);
    }

    #[test]
    fn test_error_method_not_found_code() {
        let error = JsonRpcError::method_not_found("unknown/method");
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("unknown/method"));
    }

    #[test]
    fn test_error_invalid_params_code() {
        let error = JsonRpcError::invalid_params("host is required");
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_response_always_serializes_an_id_member() {
        // JSON-RPC 2.0 §5: the `id` member MUST be present on every
        // Response object, and MUST be Null when the id could not be
        // determined (e.g. a parse error). Omitting the key produced a
        // Response no conforming client can match.
        let response = JsonRpcResponse::error(None, JsonRpcError::parse_error("bad json"));
        let serialized = serde_json::to_value(&response).unwrap();
        assert!(
            serialized.as_object().unwrap().contains_key("id"),
            "`id` must be present on every JSON-RPC Response, got: {serialized}"
        );
        assert!(
            serialized["id"].is_null(),
            "absent id must serialize as null"
        );

        let ok = JsonRpcResponse::success(Some(json!(42)), json!({}));
        let ok_serialized = serde_json::to_value(&ok).unwrap();
        assert_eq!(ok_serialized["id"], 42);
    }

    #[test]
    fn test_error_internal_error_code() {
        let error = JsonRpcError::internal_error("Database connection failed");
        assert_eq!(error.code, -32603);
    }

    #[test]
    fn test_error_cancelled_code_default_message() {
        let error = JsonRpcError::cancelled(None);
        assert_eq!(error.code, -32800);
        assert_eq!(error.message, "Request cancelled by client");
        assert!(error.data.is_none());
    }

    #[test]
    fn test_error_cancelled_code_custom_reason() {
        let error = JsonRpcError::cancelled(Some("User pressed ESC".to_string()));
        assert_eq!(error.code, -32800);
        assert_eq!(error.message, "User pressed ESC");
    }

    /// `-32022 UnsupportedProtocolVersionError`, MCP 2026-07-28
    /// `/specification/2026-07-28/basic/versioning`. The literal example in
    /// the spec is:
    ///
    /// ```json
    /// {"code": -32022, "message": "Unsupported protocol version",
    ///  "data": {"supported": ["2026-07-28", "2025-11-25"],
    ///           "requested": "1900-01-01"}}
    /// ```
    ///
    /// Clients match on `code`, not `message`, but emitting the spec's exact
    /// string is free so we do.
    #[test]
    fn test_error_unsupported_protocol_version() {
        let error = JsonRpcError::unsupported_protocol_version("2025-11-25");

        assert_eq!(error.code, -32022);
        assert_eq!(error.message, "Unsupported protocol version");

        let data = error
            .data
            .expect("data payload is load-bearing for clients");
        assert_eq!(data["supported"], json!(["2026-07-28"]));
        assert_eq!(data["requested"], json!("2025-11-25"));
    }

    /// An empty `requested` must still serialize as a string, not be omitted —
    /// a client that reads `data.requested` unconditionally would otherwise
    /// panic on a request that carried no `protocolVersion` at all.
    #[test]
    fn test_error_unsupported_protocol_version_empty_requested() {
        let error = JsonRpcError::unsupported_protocol_version("");
        let data = error.data.expect("data payload");
        assert_eq!(data["requested"], json!(""));
    }

    // ============== MCP Types Serialization Tests ==============

    #[test]
    fn test_initialize_params_deserialization() {
        let json = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": true}
            },
            "clientInfo": {
                "name": "TestClient",
                "version": "1.0.0"
            }
        });
        let params: InitializeParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.protocol_version, "2024-11-05");
        assert_eq!(params.client_info.name, "TestClient");
    }

    #[test]
    fn test_initialize_result_serialization() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability {
                    list_changed: false,
                }),
                resources: None,
                completions: None,
                logging: None,
                extensions: None,
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
                description: None,
                website_url: None,
                icons: None,
                meta: None,
            },
            instructions: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("protocolVersion"));
        assert!(json.contains("serverInfo"));
        // Optional fields should be omitted when None
        assert!(!json.contains("description"));
        assert!(!json.contains("websiteUrl"));
        assert!(!json.contains("tasks"));
    }

    #[test]
    fn test_tool_call_result_text() {
        let result = ToolCallResult::text("Command output here");
        assert_eq!(result.content.len(), 1);
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_tool_call_result_error() {
        let result = ToolCallResult::error("Command failed");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_prompt_message_user() {
        let msg = PromptMessage::user("Check the system health");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.content_type, "text");
    }

    #[test]
    fn test_prompt_message_assistant() {
        let msg = PromptMessage::assistant("Here is the result");
        assert_eq!(msg.role, "assistant");
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = Tool {
            name: "ssh-exec".to_string(),
            description: "Execute command".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            output_schema: None,
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("inputSchema"));
        // annotations: None should be omitted
        assert!(!json.contains("annotations"));
        // `execution` is not omitted, it is GONE: MCP 2026-07-28 removed
        // per-tool task gating entirely. Kept as a tripwire against its
        // return, since a re-added `Option` field would serialize the moment
        // anything populated it.
        assert!(!json.contains("execution"));
        // icons: None should be omitted
        assert!(!json.contains("\"icons\""));
        // meta: None should be omitted
        assert!(!json.contains("_meta"));
    }

    #[test]
    fn test_resource_definition_serialization() {
        let resource = ResourceDefinition {
            uri: "ssh://host/path".to_string(),
            name: "Remote File".to_string(),
            description: Some("A file on remote host".to_string()),
            mime_type: Some("text/plain".to_string()),
        };
        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("mimeType"));
    }

    #[test]
    fn test_prompts_get_params_deserialization() {
        let json = json!({
            "name": "system-health",
            "arguments": {"host": "server1"}
        });
        let params: PromptsGetParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "system-health");
        assert_eq!(params.arguments.get("host"), Some(&"server1".to_string()));
    }

    // ============== Constants Tests ==============

    #[test]
    fn test_protocol_version_format() {
        // Protocol version should be a date in YYYY-MM-DD format
        assert_eq!(PROTOCOL_VERSION.len(), 10);
        assert!(PROTOCOL_VERSION.contains('-'));
    }

    #[test]
    fn test_server_name_not_empty() {
        assert!(!SERVER_NAME.is_empty());
    }

    #[test]
    fn test_server_version_is_semver() {
        // Version should contain at least one dot (e.g., "0.1.0")
        assert!(SERVER_VERSION.contains('.'));
    }

    /// bridge-mcp 3.0.0 speaks MCP 2026-07-28 ("Modern") and nothing else.
    ///
    /// The 2025-11-25 / 2025-06-18 / 2024-11-05 ("Legacy") revisions were
    /// dropped deliberately: there is no dual-era maintenance period. The one
    /// remnant of Legacy is the `initialize` arm that answers `-32022` with
    /// this very list (see `JsonRpcError::unsupported_protocol_version`),
    /// because a Legacy client cannot fall forward on its own.
    #[test]
    fn test_supported_protocol_versions_is_modern_only() {
        assert_eq!(PROTOCOL_VERSION, "2026-07-28");
        assert_eq!(
            SUPPORTED_PROTOCOL_VERSIONS.len(),
            1,
            "3.0.0 is Modern-only; adding a Legacy revision here re-opens \
             dual-era maintenance"
        );
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], "2026-07-28");
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], PROTOCOL_VERSION);
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(v.len(), 10, "Version {v} is not YYYY-MM-DD format");
        }
    }

    #[test]
    fn test_server_info_with_optional_fields() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test server".to_string()),
            website_url: Some("https://example.com".to_string()),
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"websiteUrl\"")); // camelCase
        assert!(!json.contains("website_url")); // NOT snake_case
    }

    #[test]
    fn test_server_info_omits_none_fields() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            website_url: None,
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("description"));
        assert!(!json.contains("websiteUrl"));
    }

    // ============== Icon Tests (SEP-973) ==============

    #[test]
    fn test_icon_full_serialization_camel_case() {
        let icon = Icon {
            src: "https://example.com/icon.png".to_string(),
            mime_type: Some("image/png".to_string()),
            sizes: Some(vec!["48x48".to_string(), "96x96".to_string()]),
            theme: Some("dark".to_string()),
        };
        let json = serde_json::to_value(&icon).unwrap();
        assert_eq!(json["src"], "https://example.com/icon.png");
        assert_eq!(json["mimeType"], "image/png");
        assert!(json["sizes"].is_array());
        assert_eq!(json["sizes"][0], "48x48");
        assert_eq!(json["theme"], "dark");
        assert!(json.get("mime_type").is_none());
    }

    #[test]
    fn test_icon_minimal_omits_optional_fields() {
        let icon = Icon {
            src: "data:image/svg+xml;base64,PHN2Zy8+".to_string(),
            mime_type: None,
            sizes: None,
            theme: None,
        };
        let json = serde_json::to_string(&icon).unwrap();
        assert!(json.contains("\"src\""));
        assert!(!json.contains("mimeType"));
        assert!(!json.contains("sizes"));
        assert!(!json.contains("theme"));
    }

    #[test]
    fn test_tool_with_icons_serialization() {
        let tool = Tool {
            name: "ssh_docker_ps".to_string(),
            description: "List containers".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            output_schema: None,
            icons: Some(vec![Icon {
                src: "https://example.com/docker.svg".to_string(),
                mime_type: Some("image/svg+xml".to_string()),
                sizes: Some(vec!["any".to_string()]),
                theme: None,
            }]),
            meta: None,
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json["icons"].is_array());
        assert_eq!(json["icons"][0]["src"], "https://example.com/docker.svg");
        assert_eq!(json["icons"][0]["sizes"][0], "any");
    }

    #[test]
    fn test_server_info_with_icons() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            website_url: None,
            icons: Some(vec![Icon {
                src: "https://example.com/server-icon.png".to_string(),
                mime_type: None,
                sizes: None,
                theme: None,
            }]),
            meta: None,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["icons"].is_array());
        assert_eq!(
            json["icons"][0]["src"],
            "https://example.com/server-icon.png"
        );
    }

    #[test]
    fn test_server_icon_url_is_https_svg() {
        assert!(
            SERVER_ICON_URL.starts_with("https://"),
            "server icon must be an https URL: {SERVER_ICON_URL}"
        );
        assert!(
            std::path::Path::new(SERVER_ICON_URL)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("svg")),
            "server icon should be an SVG: {SERVER_ICON_URL}"
        );
    }

    /// G-27 (audit 2026-08-19): `serverInfo.icons[0].src` pointed at the
    /// `muchini` org — a hard 404 — while `serverInfo.websiteUrl`
    /// (src/mcp/server.rs) used `muchiny`, which resolves. The 1.19.0
    /// CHANGELOG entry records an earlier sweep of this exact typo that missed
    /// the constant. (Referenced by release, not line number — it has moved.)
    #[test]
    fn test_server_icon_url_uses_the_canonical_github_org() {
        assert!(
            SERVER_ICON_URL.starts_with("https://raw.githubusercontent.com/muchiny/bridge-mcp/"),
            "icon URL must live under the muchiny org, got: {SERVER_ICON_URL}"
        );
        assert!(
            !SERVER_ICON_URL.contains("muchini"),
            "muchini is a unix username, not the GitHub org: {SERVER_ICON_URL}"
        );
    }

    // ============== Tool Annotations Tests ==============

    #[test]
    fn test_tool_with_annotations_serialization() {
        let tool = Tool {
            name: "ssh_docker_ps".to_string(),
            description: "List containers".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: Some(ToolAnnotations::read_only("List Docker Containers")),
            output_schema: None,
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"annotations\""));
        assert!(json.contains("\"readOnlyHint\":true"));
        assert!(json.contains("\"destructiveHint\":false"));
        assert!(json.contains("\"title\":\"List Docker Containers\""));
    }

    #[test]
    fn test_tool_without_annotations_omits_field() {
        let tool = Tool {
            name: "test".to_string(),
            description: "test".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            output_schema: None,
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(!json.contains("annotations"));
    }

    #[test]
    fn test_annotations_camel_case_serialization() {
        let ann = ToolAnnotations::mutating("Test Tool");
        let json = serde_json::to_string(&ann).unwrap();
        assert!(json.contains("readOnlyHint"));
        assert!(json.contains("destructiveHint"));
        assert!(json.contains("idempotentHint"));
        assert!(json.contains("openWorldHint"));
        // Should NOT contain snake_case
        assert!(!json.contains("read_only_hint"));
    }

    #[test]
    fn test_tool_call_result_structured_content_omitted_when_none() {
        let result = ToolCallResult::text("output");
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("structuredContent"));
    }

    #[test]
    fn test_tool_call_result_with_structured_content() {
        let result = ToolCallResult {
            content: vec![ToolContent::Text {
                text: "ok".to_string(),
            }],
            is_error: None,
            structured_content: Some(json!({"status": "running", "uptime": 3600})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("structuredContent"));
        assert!(json.contains("\"status\":\"running\""));
    }

    #[test]
    fn test_tool_content_image_serialization() {
        let content = ToolContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"image\""));
        assert!(json.contains("\"mimeType\":\"image/png\""));
        assert!(json.contains("\"data\":\"base64data\""));
    }

    #[test]
    fn test_tool_content_audio_serialization() {
        let content = ToolContent::Audio {
            data: "audiodata".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"audio\""));
        assert!(json.contains("\"mimeType\":\"audio/wav\""));
    }

    #[test]
    fn test_tool_content_resource_serialization() {
        let content = ToolContent::Resource {
            resource: EmbeddedResource {
                uri: "data://result.json".to_string(),
                mime_type: Some("application/json".to_string()),
                text: Some("{\"key\": \"value\"}".to_string()),
                blob: None,
            },
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"resource\""));
        assert!(json.contains("\"uri\":\"data://result.json\""));
        assert!(json.contains("\"mimeType\":\"application/json\""));
        // blob: None should be omitted
        assert!(!json.contains("blob"));
    }

    #[test]
    fn test_annotations_read_only_constructor() {
        let ann = ToolAnnotations::read_only("Test");
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
        assert!(!ann.is_empty());
    }

    #[test]
    fn test_annotations_destructive_constructor() {
        let ann = ToolAnnotations::destructive("Test");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, Some(false));
    }

    #[test]
    fn test_annotations_mutating_constructor() {
        let ann = ToolAnnotations::mutating("Test");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(false));
    }

    #[test]
    fn test_annotations_default_is_empty() {
        let ann = ToolAnnotations::default();
        assert!(ann.is_empty());
    }

    // ============== Notification Tests ==============

    #[test]
    fn test_notification_tools_list_changed() {
        let n = JsonRpcNotification::tools_list_changed();
        assert_eq!(n.jsonrpc, "2.0");
        assert_eq!(n.method, "notifications/tools/list_changed");
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"method\":\"notifications/tools/list_changed\""));
        // Notifications MUST NOT have an id field
        assert!(!json.contains("\"id\""));
    }

    #[test]
    fn test_notification_prompts_list_changed() {
        let n = JsonRpcNotification::prompts_list_changed();
        assert_eq!(n.method, "notifications/prompts/list_changed");
    }

    #[test]
    fn test_notification_resources_list_changed() {
        let n = JsonRpcNotification::resources_list_changed();
        assert_eq!(n.method, "notifications/resources/list_changed");
    }

    #[test]
    fn test_notification_params_omitted_when_none() {
        let n = JsonRpcNotification::tools_list_changed();
        let json = serde_json::to_string(&n).unwrap();
        assert!(!json.contains("\"params\""));
    }

    // ============== Subscription Notification Tests (2026-07-28) ==============

    #[test]
    fn test_notification_for_subscription_stamps_subscription_id() {
        let n = JsonRpcNotification::for_subscription(
            "notifications/tools/list_changed",
            &serde_json::json!(7),
        );
        assert_eq!(n.jsonrpc, "2.0");
        assert_eq!(n.method, "notifications/tools/list_changed");
        let params = n.params.expect("subscription notifications carry params");
        assert_eq!(params["_meta"][META_SUBSCRIPTION_ID], serde_json::json!(7));
    }

    #[test]
    fn test_notification_resources_updated_shape() {
        let n = JsonRpcNotification::resources_updated("history://recent", &serde_json::json!(1));
        assert_eq!(n.method, "notifications/resources/updated");
        let params = n.params.clone().expect("params present");
        assert_eq!(params["uri"], "history://recent");
        assert_eq!(params["_meta"][META_SUBSCRIPTION_ID], serde_json::json!(1));

        let v = serde_json::to_value(&n).expect("serializes");
        assert!(v.get("id").is_none(), "a notification MUST NOT carry an id");
    }

    #[test]
    fn test_notification_subscriptions_acknowledged_echoes_supported_subset() {
        let notifications = serde_json::json!({
            "toolsListChanged": true,
            "resourceSubscriptions": ["history://recent"],
        });
        let n =
            JsonRpcNotification::subscriptions_acknowledged(&serde_json::json!(3), &notifications);
        assert_eq!(n.method, "notifications/subscriptions/acknowledged");
        let params = n.params.expect("params present");
        assert_eq!(params["_meta"][META_SUBSCRIPTION_ID], serde_json::json!(3));
        assert_eq!(
            params["notifications"]["toolsListChanged"],
            serde_json::json!(true)
        );
        assert_eq!(
            params["notifications"]["resourceSubscriptions"][0],
            "history://recent"
        );
    }

    // ============== Task Types Tests (MCP 2025-11-25+) ==============

    #[test]
    fn test_task_status_serialization() {
        assert_eq!(
            serde_json::to_string(&TaskStatus::Working).unwrap(),
            "\"working\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::InputRequired).unwrap(),
            "\"input_required\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn test_task_info_serialization_camel_case() {
        let info = TaskInfo {
            task_id: "abc-123".to_string(),
            status: TaskStatus::Working,
            status_message: Some("Processing...".to_string()),
            created_at: "2025-11-25T10:30:00Z".to_string(),
            last_updated_at: "2025-11-25T10:30:00Z".to_string(),
            ttl_ms: Some(60000),
            poll_interval_ms: Some(5000),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["taskId"], "abc-123");
        assert_eq!(json["status"], "working");
        assert_eq!(json["statusMessage"], "Processing...");
        assert_eq!(json["createdAt"], "2025-11-25T10:30:00Z");
        assert_eq!(json["lastUpdatedAt"], "2025-11-25T10:30:00Z");
        assert_eq!(json["ttlMs"], 60000);
        assert_eq!(json["pollIntervalMs"], 5000);
        // The 2025-11-25 keys must be gone, not merely joined by the new
        // ones — a client reading `ttl` would silently see nothing.
        assert!(json.get("ttl").is_none());
        assert!(json.get("pollInterval").is_none());
        // Verify camelCase, not snake_case
        assert!(json.get("task_id").is_none());
    }

    /// `ttlMs` is `number | null`, so "unlimited retention" is spelled
    /// `null` — an absent key is not a legal encoding of it. Without this,
    /// adding `skip_serializing_if` to the field would break the wire
    /// contract and nothing would notice.
    #[test]
    fn ttl_ms_serializes_as_null_never_as_an_absent_key() {
        let info = TaskInfo {
            task_id: "unlimited".to_string(),
            status: TaskStatus::Working,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: None,
            poll_interval_ms: None,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert!(json.get("ttlMs").is_some(), "ttlMs must be present");
        assert!(json["ttlMs"].is_null(), "ttlMs must be null, not absent");
        // pollIntervalMs is genuinely optional and IS skipped when absent.
        assert!(json.get("pollIntervalMs").is_none());
    }

    #[test]
    fn test_task_info_omits_none_status_message() {
        let info = TaskInfo {
            task_id: "id".to_string(),
            status: TaskStatus::Completed,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: Some(1000),
            poll_interval_ms: Some(500),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("statusMessage"));
    }

    #[test]
    fn test_create_task_result_serialization() {
        let result = DetailedTask::handle(TaskInfo {
            task_id: "task-1".to_string(),
            status: TaskStatus::Working,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: Some(30000),
            poll_interval_ms: Some(2000),
        });
        let json = serde_json::to_value(&result).unwrap();
        // FLAT, not nested. 2025-11-25 wrapped these in a `task` object;
        // `Result & Task` in 2026-07-28 puts them at the root.
        assert_eq!(json["taskId"], "task-1");
        assert_eq!(json["status"], "working");
        assert!(
            json.get("task").is_none(),
            "the enclosing `task` object is the 2025-11-25 shape"
        );
        assert!(json.get("_meta").is_none());
    }

    #[test]
    fn test_create_task_result_with_meta() {
        let mut result = DetailedTask::handle(TaskInfo {
            task_id: "task-2".to_string(),
            status: TaskStatus::Working,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: Some(30000),
            poll_interval_ms: Some(2000),
        });
        result.meta = Some(json!({
            "io.modelcontextprotocol/model-immediate-response": "Task started"
        }));
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json["_meta"]["io.modelcontextprotocol/model-immediate-response"],
            "Task started"
        );
    }

    #[test]
    fn result_type_serializes_to_the_modern_wire_strings() {
        assert_eq!(
            serde_json::to_value(ResultType::Complete).unwrap(),
            "complete"
        );
        assert_eq!(serde_json::to_value(ResultType::Task).unwrap(), "task");
    }

    /// Replaces `create_task_result_emits_result_type_only_when_present`,
    /// which pinned the one property the spec forbids — that the
    /// discriminator MAY be absent.
    #[test]
    fn create_task_result_always_carries_result_type_task() {
        let task = TaskInfo {
            task_id: "task-3".to_string(),
            status: TaskStatus::Working,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: Some(30000),
            poll_interval_ms: Some(2000),
        };

        let result = DetailedTask::handle(task);
        let json = serde_json::to_value(&result).unwrap();

        // Presence AND value. Presence alone would survive a handle that
        // says `"complete"` — indistinguishable from a standard result.
        assert!(json.get("resultType").is_some());
        assert_eq!(json["resultType"], "task");
        assert_eq!(json["taskId"], "task-3");
    }

    #[test]
    fn test_task_get_params_deserialization() {
        let json = json!({"taskId": "abc-123"});
        let params: TaskGetParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.task_id, "abc-123");
    }

    #[test]
    fn test_task_cancel_params_deserialization() {
        let json = json!({"taskId": "ghi-789"});
        let params: TaskCancelParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.task_id, "ghi-789");
    }

    /// MCP 2026-07-28 deleted `params.task`. `ToolCallParams` carries no
    /// `deny_unknown_fields`, so a 2025-11-25 client that still sends the
    /// object is not rejected — the key is ignored and the call runs
    /// synchronously.
    ///
    /// That silent-ignore IS the migration behaviour operators will meet, so
    /// it is pinned rather than left to chance: the alternative (a parse
    /// error) would take a working legacy client off the air, and the
    /// difference between the two is invisible without a test.
    #[test]
    fn tool_call_params_ignores_a_legacy_task_field() {
        let json = json!({
            "name": "ssh_exec",
            "arguments": {"host": "web1", "command": "ls"},
            "task": {"ttl": 60000}
        });
        let params: ToolCallParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "ssh_exec");
        assert_eq!(params.arguments.unwrap()["host"], "web1");
    }

    #[test]
    fn tool_call_meta_parses_per_request_logging_level() {
        let json = r#"{
            "name": "ssh_exec",
            "arguments": {"host": "web1", "command": "uptime"},
            "_meta": {
                "progressToken": "tok-1",
                "io.modelcontextprotocol/loggingLevel": "debug"
            }
        }"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        let meta = params.meta.expect("_meta must parse");
        assert_eq!(meta.progress_token, Some(serde_json::json!("tok-1")));
        assert_eq!(meta.logging_level, Some(LogLevel::Debug));
    }

    #[test]
    fn tool_call_meta_logging_level_is_optional() {
        let json = r#"{"name":"ssh_exec","_meta":{"progressToken":1}}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.meta.unwrap().logging_level, None);
    }

    #[test]
    fn test_tool_meta_serializes_correctly() {
        let tool = Tool {
            name: "ssh_exec".to_string(),
            description: "Execute".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            output_schema: None,
            icons: None,
            meta: Some(json!({"anthropic/maxResultSizeChars": 200_000})),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["_meta"]["anthropic/maxResultSizeChars"], 200_000);
    }

    #[test]
    fn test_tool_meta_none_omitted() {
        let tool = Tool {
            name: "ssh_status".to_string(),
            description: "Status".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            output_schema: None,
            icons: None,
            meta: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(!json.contains("_meta"));
    }

    /// Supersedes `test_tasks_capability_serialization` and
    /// `test_server_capabilities_with_tasks`, which pinned the 2025-11-25
    /// shape: a top-level `capabilities.tasks` object carrying `list`,
    /// `cancel` and `requests.tools.call`.
    ///
    /// Tasks left core in 2026-07-28 and became an extension, so the server
    /// declares them under `capabilities.extensions` keyed by the extension
    /// identifier. Two of the three sub-keys could not be declared any more
    /// even if the object survived: `tasks/list` no longer exists, and
    /// per-request task support is not a thing a server advertises.
    ///
    /// Asserting BOTH halves — gone from one place, present in the other — is
    /// what makes this a migration test rather than a deletion test. A bare
    /// absence check would also pass for a server that stopped declaring
    /// tasks altogether, which is a different bug with the same symptom.
    #[test]
    fn tasks_are_declared_as_an_extension_not_a_core_capability() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            prompts: None,
            resources: None,
            completions: None,
            logging: None,
            extensions: Some(HashMap::from([(extensions::TASKS.to_string(), json!({}))])),
        };
        let json = serde_json::to_value(&caps).unwrap();

        assert!(
            json.get("tasks").is_none(),
            "`capabilities.tasks` is the 2025-11-25 shape: {json}"
        );
        assert!(json["extensions"][extensions::TASKS].is_object(), "{json}");
    }

    #[test]
    fn task_notification_carries_the_detailed_task_flat() {
        let info = TaskInfo {
            task_id: "task-99".to_string(),
            status: TaskStatus::Completed,
            status_message: Some("Done".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:01:00Z".to_string(),
            ttl_ms: Some(60000),
            poll_interval_ms: Some(5000),
        };
        let payload = json!({"content": [{"type": "text", "text": "hi"}], "isError": false});
        let n = JsonRpcNotification::task_notification(&TaskNotificationParams::new(
            info,
            Some(payload),
        ));

        // The 2025-11-25 name was `notifications/tasks/status`. Asserting the
        // exact string, not a prefix: both names live under the reserved
        // `notifications/tasks` prefix, so a substring check would pass for
        // either and a client subscribed to one would hear nothing from a
        // server sending the other.
        assert_eq!(n.method, "notifications/tasks");

        let params = n.params.expect("params");
        // FLAT, like every other `Task` carrier in this revision.
        assert_eq!(params["taskId"], "task-99");
        assert_eq!(params["status"], "completed");
        assert_eq!(params["ttlMs"], 60000);
        // The payload is the whole point of subscribing: no poll needed.
        assert_eq!(params["result"]["content"][0]["text"], "hi");
        assert!(params.get("error").is_none());
        // A notification is not a result: no discriminator.
        assert!(
            params.get("resultType").is_none(),
            "resultType discriminates a result shape, not a notification: {params}"
        );
    }

    /// The routing is a MUST both emission sites and `tasks/get` must agree
    /// on, so it is pinned on its own rather than only through the happy path.
    #[test]
    fn task_notification_params_route_the_payload_by_status() {
        let task = |status| TaskInfo {
            task_id: "t".to_string(),
            status,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl_ms: Some(1000),
            poll_interval_ms: None,
        };
        let payload = json!({"anything": true});

        let failed = serde_json::to_value(TaskNotificationParams::new(
            task(TaskStatus::Failed),
            Some(payload.clone()),
        ))
        .unwrap();
        assert_eq!(failed["error"], payload);
        assert!(failed.get("result").is_none());

        // A cancelled task never carries a payload: `CancelledTask` extends
        // `Task` with no result field, so a payload offered here is dropped
        // rather than invented onto the wire.
        let cancelled = serde_json::to_value(TaskNotificationParams::new(
            task(TaskStatus::Cancelled),
            Some(payload),
        ))
        .unwrap();
        assert!(cancelled.get("result").is_none(), "{cancelled}");
        assert!(cancelled.get("error").is_none(), "{cancelled}");
    }

    #[test]
    fn test_build_rev_is_a_git_sha_or_unknown() {
        // Either a 12-char hex sha (optionally "-dirty"), or "unknown" when
        // the crate was built outside a git checkout (crates.io tarball,
        // vendored source). Anything else means build.rs misread git.
        let core = BUILD_REV.strip_suffix("-dirty").unwrap_or(BUILD_REV);
        assert!(
            core == "unknown" || (core.len() == 12 && core.chars().all(|c| c.is_ascii_hexdigit())),
            "BUILD_REV must be 12 hex chars, 12 hex chars + \"-dirty\", or \"unknown\"; got {BUILD_REV:?}"
        );
        assert!(
            !BUILD_REV.is_empty(),
            "BUILD_REV is empty: build.rs did not emit cargo::rustc-env"
        );
    }

    /// Regression test for the "build.rs did not rerun after a same-branch
    /// commit" bug (see `build.rs`'s `rerun-if-changed` comment). `BUILD_REV`
    /// is a compile-time `env!()` constant, baked in whenever build.rs last
    /// ran; the git commands below run fresh every time this test *executes*,
    /// with no Cargo caching in between. If a future change to build.rs's
    /// `rerun-if-changed` set ever again fails to invalidate on a commit —
    /// exactly what happened when it only watched `.git/HEAD` — a stale
    /// compiled-in `BUILD_REV` and this live-computed value will diverge and
    /// this test will fail, even though nothing needed recompiling.
    ///
    /// This is a no-op within a single fresh `cargo test` run from a clean
    /// checkout (adding/editing this test is itself a `src` change, which
    /// unconditionally forces build.rs to rerun) — its value is catching
    /// regressions in long-lived local clones and in CI under
    /// `Swatinem/rust-cache`, which persists `target/` across commits on the
    /// same branch, i.e. precisely the reuse pattern the bug depended on.
    #[test]
    fn test_build_rev_matches_live_head_or_is_unknown() {
        if BUILD_REV == "unknown" {
            // Built outside a git checkout; nothing live to compare against.
            return;
        }
        let Some(head) = git_output(&["rev-parse", "--short=12", "HEAD"]) else {
            // git unavailable to the *test* process is an environment fact,
            // not something this test can assert on.
            return;
        };
        let dirty = git_output(&["status", "--porcelain", "--untracked-files=no"])
            .is_some_and(|s| !s.is_empty());
        let live = if dirty { format!("{head}-dirty") } else { head };

        assert_eq!(
            BUILD_REV, live,
            "BUILD_REV ({BUILD_REV}) does not match the live working tree \
             ({live}) — build.rs did not rerun after the tree changed. This is \
             the exact staleness bug build.rs exists to prevent."
        );
    }

    fn git_output(args: &[&str]) -> Option<String> {
        let out = std::process::Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[test]
    fn test_build_meta_key_is_vendor_namespaced() {
        // MCP reserves the `io.modelcontextprotocol/` prefix; ours must be a
        // reverse-DNS namespace we own, matching server.json's package name.
        assert_eq!(BUILD_META_KEY, "io.github.muchiny/build");
        assert!(!BUILD_META_KEY.starts_with("io.modelcontextprotocol/"));
    }
}
