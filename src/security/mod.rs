mod audit;
pub mod entropy;
mod rate_limiter;
pub mod rbac;
pub mod recording;
mod sanitizer;
mod validator;

/// Crate-internal: the bounded join every shutdown path uses on the audit
/// writer. Not re-exported publicly — a library embedder spawns the task
/// itself and owns its handle, so it joins it the way it likes.
pub(crate) use audit::drain_audit_writer;
pub use audit::{AuditEvent, AuditLogger, AuditWriterTask, CommandResult, NO_HOST};
/// The two caps, re-exported for tests only. `audited_host` and
/// `elide_oversized` are deliberately absent: both are reached through
/// `audited_host_from_args` / `audited_operation` and have no caller outside
/// `audit.rs`, so re-exporting them would be an unused import. The caps have
/// no production caller outside `audit.rs` either — `src/cli/runner.rs`
/// asserts its gate lines against them, and that is a unit test.
///
/// `all(test, feature = "cli")` and not `test` alone: the asserting tests are
/// `src/cli/runner.rs`'s, and that module is `#[cfg(feature = "cli")]`, so
/// under `--all-targets --no-default-features` this was an `unused_imports`
/// error — same silent third gate as `audited_operation`'s own `cfg`.
#[cfg(all(test, feature = "cli"))]
pub(crate) use audit::{GATE_AUDIT_MAX_OPERATION_CHARS, GATE_AUDIT_MAX_VALUE_CHARS};
/// Crate-internal: the shutdown's and the reaper's own vocabulary — the two
/// reserved `tool_name` sentinels, the one stable `Interrupted` reason, the
/// in-flight registry, and the reaped-line renderer with its closed set of
/// reasons.
///
/// Here rather than beside the first caller that needed them because the
/// callers are in layers that cannot see each other: `crate::cli`'s
/// destructive gate, `crate::mcp`'s shutdown emitter and `crate::ssh`'s
/// session reaper. Not public — these are this crate's own line-format
/// policy, not a contract an embedder gets to depend on.
///
/// **This comment described a different set until the final review**: it was
/// written for the two raw-argument renderers, which moved to the
/// `#[cfg(feature = "cli")]` list below when round 1 gated them, and it was
/// left sitting above the list it no longer describes.
pub(crate) use audit::{
    INTERRUPTED_BY_SHUTDOWN, InFlightCall, InFlightCalls, InFlightClaim, RESOURCE_REAPER_TOOL,
    ReapReason, SHUTDOWN_TOOL, reaped_event,
};
/// The two renderers whose only consumer outside `audit.rs` is the CLI's
/// destructive gate, hence the gate on the feature that compiles it.
///
/// **Measured, because these two read as if they were unconditional.**
/// `audited_host_from_args`' own doc names two callers, the gate and the MCP
/// shutdown emitter — but the emitter reaches it through `InFlightCall`,
/// *inside* `audit.rs`, so it never uses this re-export. `audited_operation`
/// lost its second caller in the previous entry's round 2, when the shutdown
/// sink moved to `audited_argument_names`. With `--no-default-features`
/// (i.e. without `cli`) `src/cli` is not compiled at all — `#[cfg(feature =
/// "cli")] pub mod cli;` in `src/lib.rs` — so both of these became
/// `unused_imports` errors under `-D warnings`, in the one clippy
/// configuration **no CI job runs**. See `audited_operation`'s own `cfg`.
#[cfg(feature = "cli")]
pub(crate) use audit::{audited_host_from_args, audited_operation};
pub use entropy::EntropyDetector;
pub use rate_limiter::{RateLimitExceeded, RateLimiter};
pub use rbac::{RbacConfig, RbacEnforcer};
pub use recording::SessionRecorder;
pub use sanitizer::{ANSI_PATTERN, MAX_CUSTOM_PATTERN_LEN, MAX_OPERATOR_PATTERNS, Sanitizer};
pub use validator::CommandValidator;
