//! Centralized YAML parser with `DoS` hardening (Budget / depth / size limits).
//!
//! All production-path `serde_saphyr::from_str` calls in the codebase MUST go
//! through here so the anti-DoS caps cannot be forgotten at an individual call
//! site (FIND-001 / FIND-002 / FIND-004 / FIND-032).
//!
//! `serde-saphyr` already enables a default [`serde_saphyr::Budget`] for
//! `from_str`, but the defaults are tuned for a generic, fairly liberal
//! workload (256 MiB, 50 000 anchors, depth 2 000, 250 000 nodes). Our
//! threat model — config / runbook YAML, plus YAML stdout from a single SSH
//! command — never legitimately needs anywhere near that. We therefore
//! tighten the budget aggressively to cut down billion-laughs and depth-bomb
//! amplification factors.
//!
//! Limits enforced (per call):
//! - max input size: [`MAX_YAML_BYTES`] (1 MiB)
//! - max anchors: 100
//! - max alias events: 1 000
//! - max structural depth: 50
//! - max nodes (sequences + maps + scalars): 10 000
//!
//! Test fixtures inside `#[cfg(test)] mod tests` blocks intentionally keep
//! using the bare `serde_saphyr::from_str` so they can exercise edge cases
//! that would otherwise be rejected by these caps.

use serde::de::DeserializeOwned;

use crate::error::BridgeError;

/// Hard upper bound on a YAML input we will accept from any source.
///
/// Both the in-process length check and saphyr's own
/// `max_reader_input_bytes` use this constant, so the rejection happens at
/// the earliest possible point.
pub(crate) const MAX_YAML_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum distinct `&anchor` definitions before we reject the document.
pub(crate) const MAX_ANCHORS: usize = 100;

/// Maximum alias (`*ref`) events. Caps amplification on any anchor.
pub(crate) const MAX_ALIASES: usize = 1_000;

/// Maximum structural nesting depth (sequences + mappings).
pub(crate) const MAX_DEPTH: usize = 50;

/// Maximum total parser nodes (sequence-start / map-start / scalar events).
pub(crate) const MAX_NODES: usize = 10_000;

/// Build the hardened parser options for our threat model.
fn hardened_options() -> serde_saphyr::Options {
    let budget = serde_saphyr::Budget {
        max_reader_input_bytes: Some(MAX_YAML_BYTES),
        max_anchors: MAX_ANCHORS,
        max_aliases: MAX_ALIASES,
        max_depth: MAX_DEPTH,
        max_nodes: MAX_NODES,
        ..serde_saphyr::Budget::default()
    };

    serde_saphyr::Options {
        budget: Some(budget),
        ..serde_saphyr::Options::default()
    }
}

/// Parse YAML into `T` with anti-DoS budget caps.
///
/// # Errors
///
/// Returns [`BridgeError::Config`] when:
/// - the input exceeds [`MAX_YAML_BYTES`],
/// - the input trips any saphyr [`Budget`](serde_saphyr::Budget) limit
///   (anchor count, alias count, depth, node count, total scalar bytes),
/// - the input is not valid YAML or does not match the target type `T`.
pub fn parse_yaml<T: DeserializeOwned>(input: &str) -> Result<T, BridgeError> {
    if input.len() > MAX_YAML_BYTES {
        return Err(BridgeError::Config(format!(
            "YAML input too large: {} bytes (max {})",
            input.len(),
            MAX_YAML_BYTES
        )));
    }

    serde_saphyr::from_str_with_options(input, hardened_options())
        .map_err(|e| BridgeError::Config(format!("YAML parse error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversize_input() {
        // 1 MiB + 1 byte: just over the cap.
        let input = "x".repeat(MAX_YAML_BYTES + 1);
        let out: Result<serde_json::Value, _> = parse_yaml(&input);
        match out {
            Err(BridgeError::Config(msg)) => assert!(msg.contains("too large")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn small_input_round_trips() {
        let v: serde_json::Value = parse_yaml("k: v\n").expect("parse");
        assert_eq!(v["k"], "v");
    }
}
