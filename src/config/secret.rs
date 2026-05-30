//! `RedactedSecret`: a string credential that zeroizes on drop and is
//! structurally incapable of leaking through `Debug`, `Display`, or
//! `Serialize`. Use it for every in-memory secret (passwords, passphrases,
//! API tokens) instead of `String` or bare `Zeroizing<String>`.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A string secret that is wiped from memory on drop and never reveals its
/// contents through `Debug`, `Display`, or `Serialize`.
///
/// Access the underlying value explicitly with [`RedactedSecret::as_str`] or
/// via `Deref<Target = str>` (so `&secret` coerces to `&str` at call sites).
///
/// # Escape hatch (the audited boundary)
///
/// [`RedactedSecret::as_str`] and `Deref` deliberately expose the plaintext: they
/// are THE single audited boundary where redaction stops applying. Treat every
/// `secret.as_str()` / `&*secret` as that boundary — pass it directly into an
/// auth/transport call only, and never into a logging or formatting macro (e.g.
/// `println!`, `tracing::info!`, `format!`), which would defeat the redaction.
///
/// # Intentionally not comparable
///
/// This type intentionally does NOT implement `PartialEq`, `Eq`, `Hash`, or `Ord`:
/// a derived comparison would be non-constant-time and leak secret bytes through a
/// timing side-channel. Do not add `#[derive(PartialEq)]` (etc.). If equality is
/// ever needed, compare via a constant-time primitive at the auth boundary.
#[derive(Clone)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    /// Wrap an owned `String` as a redacted, zeroizing secret.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the secret as `&str` for use at an authentication boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for RedactedSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for RedactedSecret {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl Deref for RedactedSecret {
    type Target = str;

    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for RedactedSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for RedactedSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2-super-secret";

    #[test]
    fn debug_does_not_leak() {
        let s = RedactedSecret::from(SECRET);
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains(SECRET),
            "Debug leaked the secret: {rendered}"
        );
        assert_eq!(rendered, "[REDACTED]");
    }

    #[test]
    fn serialize_does_not_leak() {
        let s = RedactedSecret::from(SECRET);
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains(SECRET),
            "Serialize leaked the secret: {json}"
        );
        assert_eq!(json, "\"[REDACTED]\"");
    }

    #[test]
    fn deserialize_reads_plain_string() {
        let s: RedactedSecret = serde_json::from_str("\"hunter2-super-secret\"").unwrap();
        assert_eq!(s.as_str(), SECRET);
    }

    #[test]
    fn deref_and_as_str_expose_value_for_use() {
        let s = RedactedSecret::from(SECRET);
        let via_deref: &str = &s;
        assert_eq!(via_deref, SECRET);
        assert_eq!(s.as_str(), SECRET);
        assert_eq!(s.len(), SECRET.len());
    }

    #[test]
    fn clone_is_independent() {
        let a = RedactedSecret::from(SECRET);
        let b = a.clone();
        assert_eq!(a.as_str(), b.as_str());
    }
}
