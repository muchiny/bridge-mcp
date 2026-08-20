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
