//! Integrity-protected `requestState` for Multi Round-Trip Requests.
//!
//! MRTR replaced server-initiated requests: instead of the server sending its
//! own `elicitation/create` and blocking on the reply, it RETURNS an
//! `InputRequiredResult` and the client retries the original request under a
//! new id with the answers attached. The server keeps no state between the two
//! — *"it allows servers to request additional information without maintaining
//! any server-side state. The server encodes any needed context into the
//! `requestState` field, which the client echoes back on retry."*
//!
//! That context therefore travels through the client, which is why the spec is
//! blunt about what it is:
//!
//! > If a client request contains a `requestState` field, servers **MUST**
//! > treat `requestState` as an attacker-controlled input. If `requestState`
//! > influences authorization, resource access, or business logic, servers
//! > **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST** reject
//! > state that fails verification.
//!
//! On this server it influences authorization directly: the state is the token
//! that says a destructive operation was confirmed by a human. Forging one
//! would run `ssh_ansible_playbook` without the confirmation the operator
//! turned on. So integrity protection is not the optional arm here — the
//! escape clause, *"Integrity protection MAY be omitted only when tampering
//! can cause nothing worse than request failure"*, does not apply.
//!
//! # What is bound
//!
//! The three replay defences the spec asks for, all inside the MAC:
//!
//! > * the authenticated principal, rejecting state presented by a different
//! >   principal.
//! > * a short expiry (TTL), rejecting state presented after it lapses;
//! > * an identifier for the originating request, e.g. the method name and a
//! >   digest of its salient parameters, rejecting state presented on a
//! >   request that does not match.
//!
//! And the spec's own caveat, which this module does NOT solve: *"these
//! measures bound the replay window and prevent cross-user and cross-request
//! reuse, but do not by themselves guarantee single-use."* A state is
//! replayable within its TTL, by the same principal, on the same request. That
//! is acceptable for a confirmation token — replaying it re-confirms the same
//! operation the user already approved — and would NOT be acceptable for a
//! one-time redemption, which this server has none of.
//!
//! # Real HMAC
//!
//! `hmac::Hmac<Sha256>`, not the `Sha256(key || data)` construction in
//! `security::recording`. That one is a prefix-MAC and is length-extendable:
//! an attacker who has one valid `(data, tag)` pair can produce a valid tag for
//! `data || padding || suffix` without the key. It is not exploitable there
//! (the chain hashes fixed-shape records), and it is not being changed here
//! because doing so invalidates every existing recording — but it must not be
//! copied into a path where the attacker chooses the payload.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Environment variable holding the signing key, hex- or raw-encoded.
///
/// Named alongside the existing `MCP_RECORDING_KEY`.
///
/// **Set this on any deployment running more than one bridge-mcp process
/// behind one address.** Without it each process generates its own key at
/// startup, so a retry that lands on a different instance is rejected — which
/// defeats the one property MRTR exists to provide, *"without requiring a
/// shared storage layer across server instances or requiring stateful load
/// balancing"*. A single stdio process, which is the common case, needs
/// nothing.
pub const KEY_ENV: &str = "MCP_REQUEST_STATE_KEY";

/// How long an issued state stays valid.
///
/// Five minutes. The spec asks for "a short expiry"; the floor is however long
/// a human takes to read a confirmation prompt and answer it, and the ceiling
/// is how long a stolen state stays useful. A state that lapses is not a dead
/// end: the client re-sends the original request with no state at all and gets
/// a fresh `InputRequiredResult`.
pub const TTL_SECS: u64 = 300;

/// Version tag, so the format can change without a stale state being
/// misparsed as a valid one of the new shape.
const FORMAT_VERSION: &str = "v1";

/// Why a presented `requestState` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Not the `v1.<payload>.<mac>` shape, or a segment is not base64url.
    Malformed,
    /// The MAC does not verify. Either the payload was edited or it was signed
    /// with a different key — deliberately not distinguished, because telling
    /// an attacker which of the two happened is free information.
    BadSignature,
    /// Past its TTL.
    Expired,
    /// Presented by a different principal than the one it was issued to.
    WrongPrincipal,
    /// Presented on a different request than the one it was issued for.
    WrongRequest,
}

impl StateError {
    /// The client-facing wording.
    ///
    /// One sentence for every arm, and deliberately vague about WHICH check
    /// failed for the two that carry security signal: a client that behaves
    /// correctly never sees these, and one that does not should not be handed a
    /// tampering oracle. The recovery is identical in every case, so the
    /// message says that instead.
    #[must_use]
    pub const fn client_message(self) -> &'static str {
        match self {
            Self::Expired => {
                "`requestState` has expired. Re-send the original request with no \
                 `requestState` and no `inputResponses` to start a fresh round trip."
            }
            _ => {
                "`requestState` is not valid for this request. Re-send the original \
                 request with no `requestState` and no `inputResponses` to start a \
                 fresh round trip."
            }
        }
    }
}

/// The signed payload. Field names are short because this is base64'd onto
/// every round trip, and opaque because clients *"**MUST NOT** inspect, parse,
/// modify, or make any assumptions about its contents"*.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Payload {
    /// Authenticated principal, or empty when the transport has none.
    p: String,
    /// Expiry, seconds since the Unix epoch.
    exp: u64,
    /// Method the state was issued on.
    m: String,
    /// Hex SHA-256 over the salient parameters of the originating request.
    d: String,
    /// The server's own context for the round trip.
    s: serde_json::Value,
}

/// Signs and verifies `requestState` blobs.
///
/// One per server. Holds the key; nothing else. There is deliberately no map
/// of issued states — the whole point of MRTR is that the server keeps none.
pub struct RequestStateSigner {
    key: Vec<u8>,
    /// True when the key was generated at startup rather than configured.
    /// Surfaced so the server can warn once, rather than silently behaving
    /// differently across a fleet.
    ephemeral: bool,
}

impl std::fmt::Debug for RequestStateSigner {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestStateSigner")
            .field("ephemeral", &self.ephemeral)
            .finish_non_exhaustive()
    }
}

impl RequestStateSigner {
    /// Build from [`KEY_ENV`], falling back to a fresh random key.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(KEY_ENV) {
            Ok(raw) if !raw.trim().is_empty() => Self {
                key: raw.trim().as_bytes().to_vec(),
                ephemeral: false,
            },
            _ => Self::ephemeral(),
        }
    }

    /// A signer with a per-process random key.
    ///
    /// 32 bytes from two v4 UUIDs — 244 bits of CSPRNG output, since v4 fixes
    /// six version and variant bits. `uuid` is already the source of the
    /// unguessable server-request ids in `pending_requests`, so this reuses the
    /// entropy path the crate already trusts rather than adding a second one.
    ///
    /// Correct for a single process and wrong for a fleet — see [`KEY_ENV`].
    #[must_use]
    pub fn ephemeral() -> Self {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        key.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self {
            key,
            ephemeral: true,
        }
    }

    /// Whether the key is per-process rather than configured.
    #[must_use]
    pub const fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Issue a state bound to this principal, method and parameters.
    ///
    /// `context` is the server's own payload for the round trip — whatever it
    /// needs to recognise the retry. It is signed but NOT encrypted, so it must
    /// not carry anything the client may not see.
    #[must_use]
    pub fn issue(
        &self,
        principal: &str,
        method: &str,
        params_digest: &str,
        context: serde_json::Value,
    ) -> String {
        let payload = Payload {
            p: principal.to_string(),
            exp: now_secs().saturating_add(TTL_SECS),
            m: method.to_string(),
            d: params_digest.to_string(),
            s: context,
        };
        // Infallible in practice — `Payload` is a plain struct over owned
        // values — and an empty body would simply fail its own verification
        // rather than forge one, so there is no unsafe fallback here.
        let body = serde_json::to_vec(&payload).unwrap_or_default();
        let encoded = b64().encode(body);
        let signed = format!("{FORMAT_VERSION}.{encoded}");
        let mac = b64().encode(self.mac(signed.as_bytes()));
        format!("{signed}.{mac}")
    }

    /// Verify a presented state and return the server context it carries.
    ///
    /// Every check is a MUST or a SHOULD from the MRTR server requirements, and
    /// they run in this order on purpose: signature first, because an unsigned
    /// payload's `exp` and `p` are attacker-chosen and reading them before the
    /// MAC verifies would be deciding policy on forged input.
    pub fn verify(
        &self,
        state: &str,
        principal: &str,
        method: &str,
        params_digest: &str,
    ) -> Result<serde_json::Value, StateError> {
        let (signed, mac) = state.rsplit_once('.').ok_or(StateError::Malformed)?;
        let encoded = signed
            .strip_prefix(FORMAT_VERSION)
            .and_then(|rest| rest.strip_prefix('.'))
            .ok_or(StateError::Malformed)?;

        let presented = b64().decode(mac).map_err(|_| StateError::Malformed)?;
        let expected = self.mac(signed.as_bytes());
        // `ConstantTimeEq` on two EMPTY slices is true — it folds over the
        // elements and an empty fold yields the identity. `mac()` only returns
        // empty on an unreachable key-init failure, but if that ever became
        // reachable this comparison would accept a state with an empty MAC from
        // anyone. Refuse before comparing rather than relying on the
        // unreachability of the other arm.
        if expected.is_empty() {
            return Err(StateError::BadSignature);
        }
        // Constant-time: a byte-wise `==` leaks how many leading bytes matched,
        // which is enough to forge a tag one byte at a time.
        if !bool::from(presented.ct_eq(&expected)) {
            return Err(StateError::BadSignature);
        }

        let body = b64().decode(encoded).map_err(|_| StateError::Malformed)?;
        let payload: Payload = serde_json::from_slice(&body).map_err(|_| StateError::Malformed)?;

        if payload.exp <= now_secs() {
            return Err(StateError::Expired);
        }
        if payload.p != principal {
            return Err(StateError::WrongPrincipal);
        }
        if payload.m != method || payload.d != params_digest {
            return Err(StateError::WrongRequest);
        }
        Ok(payload.s)
    }

    /// HMAC-SHA256 over the signed portion.
    ///
    /// `new_from_slice` accepts a key of ANY length for HMAC — the construction
    /// hashes an over-long key and zero-pads a short one — so the error arm is
    /// unreachable for this algorithm. Handled rather than unwrapped anyway:
    /// an empty key from a failed `ephemeral()` would still produce a
    /// consistent MAC, so verification stays self-consistent instead of
    /// panicking on the request path.
    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.key) else {
            return Vec::new();
        };
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Hex SHA-256 over the parameters that identify a request.
///
/// The spec's suggestion is *"the method name and a digest of its salient
/// parameters"*. Salient means the parameters that define WHICH operation was
/// confirmed — the tool name and its arguments — and deliberately not
/// `inputResponses`, `_meta` or `requestState`, all of which differ between the
/// initial request and the retry by construction. Including any of them would
/// make every state fail its own check.
#[must_use]
pub fn params_digest(salient: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    // Serialised through `serde_json`, whose map type preserves insertion
    // order — or sorts, under the `preserve_order` feature. Either way the
    // initial request and the retry carry the SAME `params` object from the
    // same client, so the two serialise identically; this digest binds a retry
    // to its original, it is not a canonical-form hash for cross-peer
    // comparison.
    hasher.update(serde_json::to_vec(salient).unwrap_or_default());
    hex(&hasher.finalize())
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signer() -> RequestStateSigner {
        RequestStateSigner {
            key: b"test-key-not-random".to_vec(),
            ephemeral: false,
        }
    }

    const M: &str = "tools/call";

    fn digest() -> String {
        params_digest(&json!({"name": "ssh_reboot", "arguments": {"host": "pi"}}))
    }

    #[test]
    fn a_freshly_issued_state_verifies_and_returns_its_context() {
        let s = signer();
        let state = s.issue("alice", M, &digest(), json!({"key": "confirm"}));
        assert_eq!(
            s.verify(&state, "alice", M, &digest()),
            Ok(json!({"key": "confirm"}))
        );
    }

    /// The MUST: "servers MUST protect its integrity ... and MUST reject state
    /// that fails verification".
    #[test]
    fn an_edited_payload_is_rejected() {
        let s = signer();
        let state = s.issue("alice", M, &digest(), json!({"key": "confirm"}));
        let (signed, mac) = state.rsplit_once('.').unwrap();
        // Re-encode a payload claiming a different principal, keeping the
        // original MAC — the exact forgery the MAC exists to stop.
        let forged_body = serde_json::to_vec(&Payload {
            p: "mallory".to_string(),
            exp: now_secs() + 300,
            m: M.to_string(),
            d: digest(),
            s: json!({"key": "confirm"}),
        })
        .unwrap();
        let forged = format!("{FORMAT_VERSION}.{}.{mac}", b64().encode(forged_body));
        assert_ne!(forged, state, "the fixture must actually differ");
        assert_eq!(
            s.verify(&forged, "mallory", M, &digest()),
            Err(StateError::BadSignature)
        );
        let _ = signed;
    }

    /// A state signed by a different key is refused, which is what makes the
    /// per-process fallback key safe: a retry landing on another instance
    /// fails closed rather than being honoured.
    #[test]
    fn a_state_from_another_key_is_rejected() {
        let issued = signer().issue("alice", M, &digest(), json!({}));
        let other = RequestStateSigner {
            key: b"a-different-key".to_vec(),
            ephemeral: false,
        };
        assert_eq!(
            other.verify(&issued, "alice", M, &digest()),
            Err(StateError::BadSignature)
        );
    }

    /// "a short expiry (TTL), rejecting state presented after it lapses".
    #[test]
    fn an_expired_state_is_rejected() {
        let s = signer();
        // Hand-built rather than waiting five minutes.
        let body = serde_json::to_vec(&Payload {
            p: "alice".to_string(),
            exp: now_secs() - 1,
            m: M.to_string(),
            d: digest(),
            s: json!({}),
        })
        .unwrap();
        let signed = format!("{FORMAT_VERSION}.{}", b64().encode(body));
        let state = format!("{signed}.{}", b64().encode(s.mac(signed.as_bytes())));
        assert_eq!(
            s.verify(&state, "alice", M, &digest()),
            Err(StateError::Expired)
        );
    }

    /// "the authenticated principal, rejecting state presented by a different
    /// principal" — cross-user replay.
    #[test]
    fn a_state_replayed_by_another_principal_is_rejected() {
        let s = signer();
        let state = s.issue("alice", M, &digest(), json!({}));
        assert_eq!(
            s.verify(&state, "mallory", M, &digest()),
            Err(StateError::WrongPrincipal)
        );
    }

    /// "an identifier for the originating request ... rejecting state presented
    /// on a request that does not match" — cross-request replay. THIS is the
    /// one that matters most here: without it a confirmation obtained for a
    /// harmless destructive tool could be presented on `ssh_ansible_playbook`.
    #[test]
    fn a_state_replayed_on_another_request_is_rejected() {
        let s = signer();
        let state = s.issue("alice", M, &digest(), json!({}));

        let other_tool = params_digest(&json!({"name": "ssh_ansible_playbook", "arguments": {}}));
        assert_eq!(
            s.verify(&state, "alice", M, &other_tool),
            Err(StateError::WrongRequest)
        );
        assert_eq!(
            s.verify(&state, "alice", "prompts/get", &digest()),
            Err(StateError::WrongRequest)
        );
    }

    /// Same tool, different ARGUMENTS is a different request. A confirmation
    /// for `rm /tmp/x` must not authorise `rm /`.
    #[test]
    fn the_digest_separates_two_calls_to_the_same_tool() {
        let a = params_digest(&json!({"name": "ssh_exec", "arguments": {"command": "rm /tmp/x"}}));
        let b = params_digest(&json!({"name": "ssh_exec", "arguments": {"command": "rm /"}}));
        assert_ne!(a, b);
    }

    /// An empty MAC must not verify. `ConstantTimeEq` on two empty slices is
    /// TRUE, so a signer that somehow produced no tag would accept a state
    /// carrying no tag — from anyone.
    #[test]
    fn an_empty_mac_never_verifies() {
        let s = RequestStateSigner {
            key: Vec::new(),
            ephemeral: false,
        };
        // `v1.<payload>.` — a well-formed prefix with an empty MAC segment.
        let body = b64().encode(b"{}");
        let state = format!("{FORMAT_VERSION}.{body}.");
        assert!(matches!(
            s.verify(&state, "", M, &digest()),
            Err(StateError::BadSignature | StateError::Malformed)
        ));
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let s = signer();
        for bad in [
            "",
            ".",
            "v1",
            "v1.",
            "v2.aaa.bbb",
            "not-a-state",
            "v1.!!!.###",
        ] {
            let got = s.verify(bad, "alice", M, &digest());
            assert!(got.is_err(), "{bad:?} must not verify");
        }
    }

    /// The `Debug` impl must never print the key: it is the one value that
    /// forges every confirmation, and `Debug` output reaches logs.
    #[test]
    fn debug_does_not_leak_the_key() {
        let rendered = format!("{:?}", signer());
        assert!(!rendered.contains("test-key"), "{rendered}");
    }

    #[test]
    fn an_ephemeral_signer_says_so_and_still_round_trips() {
        let s = RequestStateSigner::ephemeral();
        assert!(s.is_ephemeral());
        let state = s.issue("", M, &digest(), json!({"k": 1}));
        assert_eq!(s.verify(&state, "", M, &digest()), Ok(json!({"k": 1})));
    }
}
