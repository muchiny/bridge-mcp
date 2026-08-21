//! Per-request `_meta` envelope (MCP 2026-07-28).
//!
//! Modern MCP deleted the connection-scoped `initialize` handshake and moved
//! protocol version, client identity and client capabilities into a
//! reverse-DNS-namespaced `_meta` object carried on EVERY client→server
//! request. This module parses that envelope.
//!
//! Parsing is deliberately total: a missing `_meta`, a `_meta` that is not an
//! object, a key with the wrong JSON type, or a `clientInfo` missing its
//! `version` all yield `None` for the affected field and never an error. A
//! Legacy client sends none of these keys and therefore gets an all-`None`
//! `RequestMeta`, which is exactly the signal the capability lookup needs in
//! order to fall back to the session handshake flags.

use serde_json::{Map, Value};

use super::protocol::ClientInfo;

/// Exact wire keys of the `_meta` envelope.
///
/// Never spell these inline. A typo in a namespaced URI key is silent —
/// `serde_json` simply does not find it and the field reads as absent.
pub mod keys {
    /// Protocol revision the client is speaking for THIS request.
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
    /// Client identity (`{"name": ..., "version": ...}`).
    pub const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
    /// Client capabilities object (`{}` is valid and means "none").
    pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
    /// Server identity — RESPONSE side only (`server/discover` result `_meta`).
    pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
    /// Correlates a notification to its `subscriptions/listen` request.
    pub const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
    /// W3C Trace Context. Deliberately UNPREFIXED — a bare `traceparent`.
    pub const TRACEPARENT: &str = "traceparent";
}

/// Methods exempt from the mandatory `_meta.clientCapabilities` envelope.
///
/// Both entries are exempt because gating them would DESTROY A DIAGNOSTIC the
/// spec requires, not because the envelope is inconvenient there. Neither
/// method reads `params` for capabilities, but that is incidental — the
/// reason is what the client does with the answer.
///
/// `initialize` is the Legacy handshake, and a Legacy client has no `_meta`
/// by construction: it predates the envelope. Versioning says a
/// modern-only server *"**SHOULD** name the protocol versions it supports in
/// any error it returns to an `initialize` request, on any transport: legacy
/// clients have no fall-forward mechanism, and this message may be the only
/// diagnostic they can surface to users."* A `-32602` names no version. C3
/// would shadow the `-32022` arm for EVERY Legacy client — which is every
/// client that arm exists for — and replace the one actionable message they
/// can see with "your params are invalid".
///
/// `server/discover` is exempt under the client-side probe
/// (`/specification/2026-07-28/basic/transports/stdio`, "Backward
/// Compatibility") classifies a server by what `server/discover` answers: a
/// discovery result means modern; "a specific modern protocol error" means
/// modern but requiring a different version; and **"other errors or fails to
/// respond" means LEGACY**, at which point the client falls back to the
/// `initialize` handshake — which this server answers `-32022`, killing the
/// connection. A generic `-32602` is an "other error". Gating discover would
/// therefore make every dual-era client misclassify this Modern server as
/// Legacy and give up, which is the exact outcome the `-32022` arm exists to
/// prevent.
///
/// Note the two exemptions fail in OPPOSITE directions if removed: gating
/// `server/discover` makes a Modern client think the server is Legacy, and
/// gating `initialize` makes a Legacy client unable to learn the server is
/// Modern. Together they are the whole of the era-crossing surface.
pub const CAPABILITY_EXEMPT_METHODS: &[&str] = &["server/discover", "initialize"];

/// The one wording both transports use when the envelope is missing.
///
/// Shared so the stdio `-32602` body and the HTTP `400` body cannot drift
/// into describing the same refusal two different ways.
pub const MISSING_CLIENT_CAPABILITIES_MSG: &str = concat!(
    "missing `_meta[\"io.modelcontextprotocol/clientCapabilities\"]`: MCP 2026-07-28 ",
    "requires it on every client-to-server request. Send `{}` to declare no ",
    "capabilities; omitting the key entirely is a malformed request."
);

/// Whether this client-to-server message is a REQUEST that must carry
/// `_meta.clientCapabilities` and does not.
///
/// ONE definition, called from both the dispatch chokepoint (which turns it
/// into a `-32602` body) and the HTTP transport (which turns it into a `400`
/// status). Two copies of this rule would drift, and the drift would be
/// invisible: each transport's tests only exercise its own copy.
///
/// `has_id` is what separates a Request from a Notification. A Notification
/// is exempt for a reason stronger than the spec's wording ("every
/// client-to-server *request*"): JSON-RPC 2.0 §4.1 forbids answering one at
/// all, so there is no id a `-32602` could be addressed to. Gating
/// notifications would mean either inventing a response for a message that
/// must not receive one, or refusing silently — and a silent refusal is
/// indistinguishable from delivery.
///
/// An EMPTY `{}` passes. It is an authoritative declaration of no
/// capabilities, not an omission; `empty_capabilities_object_is_declared_
/// false_not_absent` pins that distinction on the parser side.
#[must_use]
pub fn lacks_required_client_capabilities(
    method: &str,
    has_id: bool,
    params: Option<&Value>,
) -> bool {
    has_id
        && !CAPABILITY_EXEMPT_METHODS.contains(&method)
        && RequestMeta::from_params(params)
            .client_capabilities
            .is_none()
}

/// The parsed per-request `_meta` envelope.
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    /// `io.modelcontextprotocol/protocolVersion`.
    pub protocol_version: Option<String>,
    /// `io.modelcontextprotocol/clientInfo`.
    pub client_info: Option<ClientInfo>,
    /// `io.modelcontextprotocol/clientCapabilities`, kept as a raw map so
    /// unknown/extension capability keys survive.
    pub client_capabilities: Option<Map<String, Value>>,
    /// Bare `traceparent` (W3C Trace Context).
    pub traceparent: Option<String>,
}

impl RequestMeta {
    /// Parse the envelope out of a request's `params`. Never fails.
    ///
    /// Every failure mode — no `params`, no `_meta`, `_meta` not an object,
    /// a key of the wrong JSON type, a `clientInfo` that does not
    /// deserialize — degrades to `None` for the affected field.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Self {
        let Some(meta) = params
            .and_then(|p| p.get("_meta"))
            .and_then(Value::as_object)
        else {
            return Self::default();
        };

        Self {
            protocol_version: meta
                .get(keys::PROTOCOL_VERSION)
                .and_then(Value::as_str)
                .map(str::to_owned),
            client_info: meta
                .get(keys::CLIENT_INFO)
                .and_then(|v| serde_json::from_value::<ClientInfo>(v.clone()).ok()),
            client_capabilities: meta
                .get(keys::CLIENT_CAPABILITIES)
                .and_then(Value::as_object)
                .cloned(),
            traceparent: meta
                .get(keys::TRACEPARENT)
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    /// A capability key counts as supported when it is present and not `null`.
    fn capability_present(caps: &Map<String, Value>, key: &str) -> bool {
        caps.get(key).is_some_and(|v| !v.is_null())
    }

    /// `None` = this request declared no client capabilities (Legacy client);
    /// `Some(b)` = it declared them and `b` is authoritative for this request.
    #[must_use]
    pub fn declares_elicitation(&self) -> Option<bool> {
        self.client_capabilities
            .as_ref()
            .map(|c| Self::capability_present(c, "elicitation"))
    }

    /// See [`Self::declares_elicitation`] for the tri-state contract.
    #[must_use]
    pub fn declares_sampling(&self) -> Option<bool> {
        self.client_capabilities
            .as_ref()
            .map(|c| Self::capability_present(c, "sampling"))
    }

    /// See [`Self::declares_elicitation`] for the tri-state contract.
    #[must_use]
    pub fn declares_roots(&self) -> Option<bool> {
        self.client_capabilities
            .as_ref()
            .map(|c| Self::capability_present(c, "roots"))
    }

    /// Whether THIS request declared support for the named MCP extension.
    ///
    /// NOT tri-state, unlike [`Self::declares_elicitation`] and its two
    /// siblings. Those return `Option<bool>` so a Legacy client that declared
    /// nothing falls back to the session handshake flags. The tasks extension
    /// FORBIDS that fallback: "A server MUST NOT return `CreateTaskResult` to
    /// a client that did not include the extension capability on its request,
    /// regardless of prior declarations." A request that did not declare it
    /// has not declared it — `false` is the only correct answer for an absent
    /// envelope.
    ///
    /// Reads `clientCapabilities.extensions[id]` — nested one level deeper
    /// than the three core capabilities, which sit at the root of the map.
    #[must_use]
    pub fn declares_extension(&self, id: &str) -> bool {
        self.client_capabilities
            .as_ref()
            .and_then(|c| c.get("extensions"))
            .and_then(Value::as_object)
            .is_some_and(|exts| Self::capability_present(exts, id))
    }

    /// The client name from `io.modelcontextprotocol/clientInfo`, if any.
    #[must_use]
    pub fn client_name(&self) -> Option<&str> {
        self.client_info.as_ref().map(|c| c.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_envelope() -> Value {
        json!({
            "name": "ssh_exec",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {
                    "name": "ExampleClient",
                    "version": "1.0.0"
                },
                "io.modelcontextprotocol/clientCapabilities": {
                    "elicitation": {},
                    "sampling": {},
                    "roots": { "listChanged": true }
                },
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
            }
        })
    }

    #[test]
    fn parses_every_key_when_present() {
        let params = full_envelope();
        let meta = RequestMeta::from_params(Some(&params));

        assert_eq!(meta.protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(meta.client_name(), Some("ExampleClient"));
        assert_eq!(
            meta.client_info.as_ref().map(|c| c.version.as_str()),
            Some("1.0.0")
        );
        assert_eq!(
            meta.traceparent.as_deref(),
            Some("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01")
        );
        assert_eq!(meta.declares_elicitation(), Some(true));
        assert_eq!(meta.declares_sampling(), Some(true));
        assert_eq!(meta.declares_roots(), Some(true));
    }

    #[test]
    fn all_none_when_meta_absent() {
        let params = json!({ "name": "ssh_exec" });
        let meta = RequestMeta::from_params(Some(&params));

        assert!(meta.protocol_version.is_none());
        assert!(meta.client_info.is_none());
        assert!(meta.client_capabilities.is_none());
        assert!(meta.traceparent.is_none());
        // Tri-state: "not declared", so the caller falls back to the session.
        assert_eq!(meta.declares_elicitation(), None);
        assert_eq!(meta.declares_sampling(), None);
        assert_eq!(meta.declares_roots(), None);
    }

    #[test]
    fn all_none_when_params_absent() {
        let meta = RequestMeta::from_params(None);
        assert!(meta.protocol_version.is_none());
        assert_eq!(meta.declares_elicitation(), None);
    }

    #[test]
    fn empty_capabilities_object_is_declared_false_not_absent() {
        // A Modern client that supports nothing sends `{}`. That is an
        // AUTHORITATIVE denial for this request, NOT "unspecified".
        let params = json!({
            "_meta": { "io.modelcontextprotocol/clientCapabilities": {} }
        });
        let meta = RequestMeta::from_params(Some(&params));
        assert_eq!(meta.declares_elicitation(), Some(false));
        assert_eq!(meta.declares_sampling(), Some(false));
        assert_eq!(meta.declares_roots(), Some(false));
    }

    #[test]
    fn null_capability_value_counts_as_unsupported() {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/clientCapabilities": { "elicitation": null }
            }
        });
        let meta = RequestMeta::from_params(Some(&params));
        assert_eq!(meta.declares_elicitation(), Some(false));
    }

    #[test]
    fn malformed_meta_is_tolerated() {
        // `_meta` is a string, not an object.
        let params = json!({ "_meta": "not-an-object" });
        let meta = RequestMeta::from_params(Some(&params));
        assert!(meta.protocol_version.is_none());
        assert_eq!(meta.declares_elicitation(), None);
    }

    #[test]
    fn malformed_individual_keys_are_tolerated() {
        let params = json!({
            "_meta": {
                // wrong type: number instead of string
                "io.modelcontextprotocol/protocolVersion": 20_260_728,
                // wrong shape: missing the required `name` field. Unlike
                // `version` (`#[serde(default)]` on `ClientInfo`, added by
                // the 2.2.0 G-18 fix so a missing version no longer drops
                // the whole handshake), `name` has no default and a
                // clientInfo missing it must still fail to deserialize.
                "io.modelcontextprotocol/clientInfo": { "version": "1.0.0" },
                // wrong type: array instead of object
                "io.modelcontextprotocol/clientCapabilities": ["elicitation"],
                // wrong type: object instead of string
                "traceparent": { "not": "a string" }
            }
        });
        let meta = RequestMeta::from_params(Some(&params));

        assert!(meta.protocol_version.is_none());
        assert!(meta.client_info.is_none());
        assert!(meta.client_capabilities.is_none());
        assert!(meta.traceparent.is_none());
        assert_eq!(meta.declares_elicitation(), None);
    }

    #[test]
    fn unknown_namespaced_keys_are_ignored() {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "com.example/whatever": { "anything": true },
                "progressToken": 42
            }
        });
        let meta = RequestMeta::from_params(Some(&params));
        assert_eq!(meta.protocol_version.as_deref(), Some("2026-07-28"));
    }

    // ========================================================================
    // declares_extension — the tasks extension gate (MCP 2026-07-28 §5.2)
    // ========================================================================

    /// The tasks extension identifier, spelled here rather than imported so
    /// this module's tests do not depend on `mcp::protocol`.
    const TASKS: &str = "io.modelcontextprotocol/tasks";

    fn meta_with_caps(caps: &Value) -> RequestMeta {
        let params = json!({
            "_meta": { "io.modelcontextprotocol/clientCapabilities": caps }
        });
        RequestMeta::from_params(Some(&params))
    }

    #[test]
    fn declares_extension_is_true_when_the_request_lists_it() {
        let meta = meta_with_caps(&json!({ "extensions": { TASKS: {} } }));
        assert!(meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_is_false_for_an_empty_extensions_map() {
        let meta = meta_with_caps(&json!({ "extensions": {} }));
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_is_false_when_no_extensions_key_is_present() {
        // Capabilities declared, but nothing under `extensions`.
        let meta = meta_with_caps(&json!({}));
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_is_false_not_none_when_meta_is_absent() {
        // THE line that separates extension semantics from elicitation
        // semantics. `declares_elicitation()` answers `None` here so the
        // caller may fall back to the session handshake. The tasks extension
        // forbids that fallback outright: an undeclared request is a
        // non-declaring request, full stop.
        let params = json!({ "name": "ssh_exec" });
        let meta = RequestMeta::from_params(Some(&params));
        assert_eq!(meta.declares_elicitation(), None);
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_is_false_for_a_null_value() {
        // `TasksExtensionCapability = Record<string, never>` — `{}` attests
        // support. `null` is not an object and attests nothing.
        let meta = meta_with_caps(&json!({ "extensions": { TASKS: null } }));
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_is_false_when_extensions_is_not_an_object() {
        let meta = meta_with_caps(&json!({ "extensions": "not-an-object" }));
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn declares_extension_requires_an_exact_identifier_match() {
        // A neighbouring identifier must not satisfy the gate: the lookup is
        // a map key, never a prefix or substring test.
        let meta = meta_with_caps(&json!({
            "extensions": { "io.modelcontextprotocol/tasks-v2": {} }
        }));
        assert!(!meta.declares_extension(TASKS));
    }

    #[test]
    fn key_constants_are_the_exact_wire_strings() {
        assert_eq!(
            keys::PROTOCOL_VERSION,
            "io.modelcontextprotocol/protocolVersion"
        );
        assert_eq!(keys::CLIENT_INFO, "io.modelcontextprotocol/clientInfo");
        assert_eq!(
            keys::CLIENT_CAPABILITIES,
            "io.modelcontextprotocol/clientCapabilities"
        );
        assert_eq!(keys::SERVER_INFO, "io.modelcontextprotocol/serverInfo");
        assert_eq!(
            keys::SUBSCRIPTION_ID,
            "io.modelcontextprotocol/subscriptionId"
        );
        assert_eq!(keys::TRACEPARENT, "traceparent");
    }
}
