//! FIND-035: per-session log level isolation.
//!
//! Before this fix, `log_level` lived on `McpServer` as a global
//! `Arc<AtomicU8>`. Any session's `notifications/setLevel` rewrote it,
//! so client B could mute client A's `notifications/message` stream
//! (cross-session denial-of-observability).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bridge_mcp::mcp::protocol::{LogLevel, WriterMessage};
use bridge_mcp::mcp::session_context::SessionContext;
use tokio::sync::mpsc;

fn fresh_session() -> SessionContext {
    let (tx, _rx) = mpsc::channel::<WriterMessage>(8);
    SessionContext::new(tx)
}

#[tokio::test]
async fn log_level_starts_at_warning_per_session() {
    let s = fresh_session();
    assert_eq!(
        s.log_level.load(Ordering::Relaxed),
        LogLevel::Warning.severity(),
        "FIND-035: every fresh session must start at Warning"
    );
}

#[tokio::test]
async fn log_level_isolated_across_sessions() {
    let a = fresh_session();
    let b = fresh_session();

    // Session A drops its threshold to Debug — most chatty.
    a.log_level
        .store(LogLevel::Debug.severity(), Ordering::Relaxed);

    // Session B raises its threshold to Error — quietest.
    b.log_level
        .store(LogLevel::Error.severity(), Ordering::Relaxed);

    // Each session sees only its own value; the other session is untouched.
    assert_eq!(
        a.log_level.load(Ordering::Relaxed),
        LogLevel::Debug.severity()
    );
    assert_eq!(
        b.log_level.load(Ordering::Relaxed),
        LogLevel::Error.severity()
    );

    // The Arc handles must be distinct allocations — same pointer would
    // collapse the per-session storage into a shared cell.
    assert!(
        !Arc::ptr_eq(&a.log_level, &b.log_level),
        "FIND-035: per-session log_level must be a distinct allocation"
    );
}
