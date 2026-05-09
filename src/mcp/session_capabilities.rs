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
