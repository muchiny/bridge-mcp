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
#[cfg(test)]
pub(crate) use audit::{GATE_AUDIT_MAX_OPERATION_CHARS, GATE_AUDIT_MAX_VALUE_CHARS};
/// Crate-internal: rendering a tool's RAW arguments into the `host` and
/// `command` fields of an audit line, bounded. Two sinks need it — the CLI's
/// destructive gate (`crate::cli`) and the MCP shutdown emitter
/// (`crate::mcp`) — and neither layer can see the other, which is why these
/// live here rather than beside the first caller that needed them. Not
/// public: the bounds are this crate's own line-format policy, not a
/// contract an embedder gets to depend on.
pub(crate) use audit::{
    INTERRUPTED_BY_SHUTDOWN, SHUTDOWN_TOOL, audited_host_from_args, audited_operation,
};
pub use entropy::EntropyDetector;
pub use rate_limiter::{RateLimitExceeded, RateLimiter};
pub use rbac::{RbacConfig, RbacEnforcer};
pub use recording::SessionRecorder;
pub use sanitizer::{ANSI_PATTERN, Sanitizer};
pub use validator::CommandValidator;
