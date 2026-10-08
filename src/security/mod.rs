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
pub use entropy::EntropyDetector;
pub use rate_limiter::{RateLimitExceeded, RateLimiter};
pub use rbac::{RbacConfig, RbacEnforcer};
pub use recording::SessionRecorder;
pub use sanitizer::{ANSI_PATTERN, Sanitizer};
pub use validator::CommandValidator;
