//! Per-session client capability flags.
//!
//! Replaces the previous server-wide `AtomicBool` fields that leaked
//! capability advertisements across clients sharing the same daemon —
//! see Vuln 9 in the 2026-05-09 audit.

use std::sync::atomic::{AtomicBool, Ordering};

/// Capabilities advertised by ONE client during its `initialize` request.
#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
pub struct SessionCapabilities {
    supports_elicitation: AtomicBool,
    supports_sampling: AtomicBool,
    supports_roots: AtomicBool,
}

impl SessionCapabilities {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_supports_elicitation(&self, v: bool) {
        self.supports_elicitation.store(v, Ordering::Relaxed);
    }
    pub fn set_supports_sampling(&self, v: bool) {
        self.supports_sampling.store(v, Ordering::Relaxed);
    }
    pub fn set_supports_roots(&self, v: bool) {
        self.supports_roots.store(v, Ordering::Relaxed);
    }

    #[must_use]
    pub fn supports_elicitation(&self) -> bool {
        self.supports_elicitation.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn supports_sampling(&self) -> bool {
        self.supports_sampling.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn supports_roots(&self) -> bool {
        self.supports_roots.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults_all_false() {
        let caps = SessionCapabilities::new();
        assert!(!caps.supports_elicitation());
        assert!(!caps.supports_sampling());
        assert!(!caps.supports_roots());
    }

    #[test]
    fn test_default_matches_new() {
        let caps = SessionCapabilities::default();
        assert!(!caps.supports_elicitation());
        assert!(!caps.supports_sampling());
        assert!(!caps.supports_roots());
    }

    #[test]
    fn test_set_get_elicitation_roundtrip() {
        let caps = SessionCapabilities::new();
        caps.set_supports_elicitation(true);
        assert!(caps.supports_elicitation());
        caps.set_supports_elicitation(false);
        assert!(!caps.supports_elicitation());
    }

    #[test]
    fn test_set_get_sampling_roundtrip() {
        let caps = SessionCapabilities::new();
        caps.set_supports_sampling(true);
        assert!(caps.supports_sampling());
        caps.set_supports_sampling(false);
        assert!(!caps.supports_sampling());
    }

    #[test]
    fn test_set_get_roots_roundtrip() {
        let caps = SessionCapabilities::new();
        caps.set_supports_roots(true);
        assert!(caps.supports_roots());
        caps.set_supports_roots(false);
        assert!(!caps.supports_roots());
    }

    #[test]
    fn test_flags_are_independent() {
        // Setting one capability must not leak into the others — this is the
        // whole point of per-session flags (Vuln 9 in the 2026-05-09 audit).
        let caps = SessionCapabilities::new();
        caps.set_supports_elicitation(true);
        assert!(caps.supports_elicitation());
        assert!(!caps.supports_sampling());
        assert!(!caps.supports_roots());

        caps.set_supports_roots(true);
        assert!(caps.supports_elicitation());
        assert!(!caps.supports_sampling());
        assert!(caps.supports_roots());
    }

    #[test]
    fn test_idempotent_repeated_set() {
        let caps = SessionCapabilities::new();
        caps.set_supports_sampling(true);
        caps.set_supports_sampling(true);
        assert!(caps.supports_sampling());
    }

    #[test]
    fn test_debug_impl_renders() {
        let caps = SessionCapabilities::new();
        let dbg = format!("{caps:?}");
        assert!(dbg.contains("SessionCapabilities"));
    }
}
