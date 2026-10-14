//! The join between the reaper's verdict and the audit line it writes,
//! driven through a **real** `SessionManager` holding a **real** SSH session.
//!
//! Why this file exists rather than a unit test in `src/ssh/session.rs`:
//! `ShellSession` is private and holds a live `russh::Channel` plus an
//! `SshClient`, with no `#[cfg(test)]` constructor, so no unit test can put a
//! session into the map — the five pre-existing `cleanup`/`close_all` tests
//! all run on an empty one. The in-process mock in `tests/ssh_mock_server.rs`
//! can now serve a shell (it grew a `shell_request` handler for this), so the
//! wiring is reachable from here and from nowhere else.
//!
//! **Every test here is wrapped in an explicit `tokio::time::timeout`**, and
//! it is a belt, not the braces. Nothing in `.config/nextest.toml` bounds a
//! test that hangs (`retries` only, no `slow-timeout`), and the risk was
//! named up front: `SshClient::open_shell` asks with `request_shell(true)`
//! and russh 0.63.3's default `shell_request` is `async { Ok(()) }`, which
//! replies with neither `channel_success` nor `channel_failure`.
//!
//! **Measured, and it does not hang.** With the mock's shell support removed
//! entirely, every test in this file fails in ~10 s with
//! `SshTimeout { seconds: 10 }` — `read_until_marker` is bounded by
//! `limits.command_timeout_seconds`, which `mock_limits()` sets to 10. So
//! the failure mode of a mock regression is a failing test, by the client's
//! own bound; the wrapper here is what guarantees that if some future path
//! is NOT bounded.
//!
//! Nothing here waits on the wall clock for an expiry: the fixture sets
//! `idle_timeout_seconds: 0`, so the session is past its bound the moment it
//! exists. `tokio::time::advance` would not help — `ShellSession` keeps
//! `std::time::Instant`s, which virtual time does not age.

mod ssh_mock_server;

use std::sync::Arc;
use std::time::Duration;

use bridge_mcp::config::{AuditConfig, SessionConfig};
use bridge_mcp::security::AuditLogger;
use bridge_mcp::ssh::SessionManager;
use ssh_mock_server::{mock_host_config, mock_limits, start_default_server};
use tempfile::TempDir;

/// Generous enough that a loaded machine does not fail it, short enough that
/// a hang is reported as a failure rather than waited out. The repository's
/// own shutdown tests use 20 s for the same purpose.
const TEST_BOUND: Duration = Duration::from_secs(20);

struct Audited {
    _dir: TempDir,
    path: std::path::PathBuf,
    logger: Arc<AuditLogger>,
    writer: tokio::task::JoinHandle<()>,
}

/// A logger whose writer really writes, into a tempdir. Rotation and
/// retention off: these tests read the live file.
fn audited() -> Audited {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let (logger, task) = AuditLogger::new(&AuditConfig {
        enabled: true,
        path: path.clone(),
        max_size_mb: 0,
        retain_days: 0,
    })
    .expect("a tempdir path must be writable");
    let writer = tokio::spawn(
        task.expect("audit is enabled, so a writer task must be produced")
            .run(),
    );
    Audited {
        _dir: dir,
        path,
        logger: Arc::new(logger),
        writer,
    }
}

fn lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(ToString::to_string)
        .collect()
}

/// **The whole chain, end to end: a real session, the reaper, the file.**
///
/// A `SessionManager` with one live session against the mock; `cleanup()`
/// finds it past the bound this config zeroes; one line lands in `audit.log`
/// naming that bound and carrying the session's own id. This is the link
/// that the unit tests in `src/ssh/session.rs` cannot reach: they prove the
/// verdict and the rendering separately and pin the call sites as source
/// text.
///
/// **Exactly one of the two bounds is zeroed per case, and the other is left
/// at its default** — which is how the line's `reason=` is shown to name the
/// bound that actually fired rather than a constant. Zeroing both would make
/// either answer look right: the first version of this test did, got
/// `max_age` (the documented tie-break) where it asserted `idle_timeout`,
/// and would have passed on a predicate that ignored `idle` entirely.
async fn a_reaped_session_names_its_bound(config: SessionConfig, expected_reason: &str) {
    tokio::time::timeout(TEST_BOUND, async move {
        let (addr, _server, _root) = start_default_server().await;
        let audit = audited();

        // A zero bound is passed by the first nanosecond, so the reaper
        // fires on its first pass and nothing here waits on a clock.
        let manager = SessionManager::new(config).with_audit_logger(Arc::clone(&audit.logger));

        let info = manager
            .create(
                "mock-host",
                &mock_host_config(addr, "tester", "testpass"),
                &mock_limits(),
                None,
            )
            .await
            .expect("the mock must serve a shell session");
        assert_eq!(
            manager.list().await.len(),
            1,
            "the session must really be in the map, or this test proves nothing"
        );
        assert!(
            lines(&audit.path).is_empty(),
            "creating a session writes no reaper line: {:?}",
            lines(&audit.path)
        );

        manager.cleanup().await;
        assert!(
            manager.list().await.is_empty(),
            "the reaper must have taken it"
        );

        audit.logger.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), audit.writer).await;

        let written = lines(&audit.path);
        assert_eq!(
            written.len(),
            1,
            "one reaped session, one line; got {written:?}"
        );
        let event: serde_json::Value =
            serde_json::from_str(&written[0]).expect("audit line must be JSONL");
        assert_eq!(event["event_type"], "state_change");
        assert_eq!(event["tool_name"], "<resource-reaper>");
        assert_eq!(event["host"], "mock-host");
        assert_eq!(
            event["command"],
            format!(
                "<resource-reaper> reason={expected_reason} session_id={}",
                info.id
            ),
            "the line must name the bound that fired and the session the auditor saw created"
        );
        assert!(
            !written[0].contains("exit_code"),
            "nothing ran: {}",
            written[0]
        );
    })
    .await
    .expect("the reaper path must TERMINATE: a hang here is a mock regression");
}

#[tokio::test]
async fn a_real_session_reaped_for_idleness_lands_one_line_naming_idle_timeout() {
    a_reaped_session_names_its_bound(
        SessionConfig {
            max_sessions: 10,
            idle_timeout_seconds: 0,
            max_age_seconds: 3600,
        },
        "idle_timeout",
    )
    .await;
}

#[tokio::test]
async fn a_real_session_reaped_for_age_lands_one_line_naming_max_age() {
    a_reaped_session_names_its_bound(
        SessionConfig {
            max_sessions: 10,
            idle_timeout_seconds: 3600,
            max_age_seconds: 0,
        },
        "max_age",
    )
    .await;
}

/// The shutdown's half of the same chain, and the reason it is a separate
/// test: `close_all` and `cleanup` are different methods with their own
/// `remove`/`drain`, so one calling the audit helper says nothing about the
/// other.
#[tokio::test]
async fn a_real_session_closed_by_the_shutdown_lands_one_line_naming_shutdown() {
    tokio::time::timeout(TEST_BOUND, async {
        let (addr, _server, _root) = start_default_server().await;
        let audit = audited();

        // The DEFAULT bounds here, so nothing is expired and the only reason
        // the session can be destroyed is the shutdown.
        let manager = SessionManager::new(SessionConfig::default())
            .with_audit_logger(Arc::clone(&audit.logger));

        let info = manager
            .create(
                "mock-host",
                &mock_host_config(addr, "tester", "testpass"),
                &mock_limits(),
                None,
            )
            .await
            .expect("the mock must serve a shell session");

        manager.cleanup().await;
        assert_eq!(
            manager.list().await.len(),
            1,
            "a fresh session is past neither the 300 s nor the 3600 s bound"
        );
        assert!(
            lines(&audit.path).is_empty(),
            "a reaper pass that reaps nothing must write nothing: {:?}",
            lines(&audit.path)
        );

        manager.close_all().await;

        audit.logger.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), audit.writer).await;

        let written = lines(&audit.path);
        assert_eq!(
            written.len(),
            1,
            "one line for the one session; got {written:?}"
        );
        let event: serde_json::Value =
            serde_json::from_str(&written[0]).expect("audit line must be JSONL");
        assert_eq!(event["tool_name"], "<resource-reaper>");
        assert_eq!(
            event["host"], "mock-host",
            "the host lives in this field and no longer in `command`"
        );
        assert_eq!(
            event["command"],
            format!("<resource-reaper> reason=shutdown session_id={}", info.id)
        );
    })
    .await
    .expect("the shutdown path must TERMINATE: a hang here is a mock regression");
}

/// **Two real sessions reaped together leave two lines, not one.**
///
/// Every other test in this file and in `src/ssh/session.rs` drives a single
/// session, so none of them could see the defect the final review found:
/// `cleanup` and `close_all` used to interleave each session's audit line
/// with that session's `client.close().await`, so a bound firing after the
/// first close left sessions 2..N with no line at all. Both sites now write
/// every line in one synchronous pass first.
///
/// **This case does not reproduce the abandonment**, and the reason is
/// worth stating rather than implying: making a real `client.close()` slow
/// enough to eat the bound needs a peer that accepts the TCP connection and
/// then never answers the SSH DISCONNECT, which the in-process mock is not —
/// it answers immediately, so the interleaved form would have passed this
/// too. What this case does add is the N-sessions-N-lines property against
/// real sessions, with each line carrying its own id; the placement is
/// pinned as source text by
/// `each_removal_site_audits_from_the_right_place`, which slices each method
/// and asserts the per-session helper appears zero times in either batch
/// body. (Its sibling
/// `every_silent_removal_site_now_audits_except_the_explicit_close` counts
/// the call sites over the whole file instead; this line named that one,
/// which has no per-body assertion.)
#[tokio::test]
async fn two_real_sessions_reaped_together_leave_one_line_each() {
    tokio::time::timeout(TEST_BOUND, async {
        let (addr, _server, _root) = start_default_server().await;
        let audit = audited();

        let manager = SessionManager::new(SessionConfig {
            max_sessions: 10,
            idle_timeout_seconds: 0,
            max_age_seconds: 3600,
        })
        .with_audit_logger(Arc::clone(&audit.logger));

        let host = mock_host_config(addr, "tester", "testpass");
        let limits = mock_limits();
        let first = manager
            .create("mock-host", &host, &limits, None)
            .await
            .expect("the mock must serve a shell session");
        let second = manager
            .create("mock-host", &host, &limits, None)
            .await
            .expect("and a second one");
        assert_ne!(
            first.id, second.id,
            "two distinct sessions, or this proves nothing"
        );
        assert_eq!(manager.list().await.len(), 2);

        manager.cleanup().await;
        assert!(
            manager.list().await.is_empty(),
            "both must have been reaped"
        );

        audit.logger.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), audit.writer).await;

        let written = lines(&audit.path);
        assert_eq!(
            written.len(),
            2,
            "two reaped sessions must leave TWO lines, not just the first; got {written:?}"
        );
        let mut commands: Vec<String> = written
            .iter()
            .map(|l| {
                let v: serde_json::Value =
                    serde_json::from_str(l).expect("audit line must be JSONL");
                v["command"]
                    .as_str()
                    .expect("command is a string")
                    .to_string()
            })
            .collect();
        commands.sort();
        let mut expected = vec![
            format!(
                "<resource-reaper> reason=idle_timeout session_id={}",
                first.id
            ),
            format!(
                "<resource-reaper> reason=idle_timeout session_id={}",
                second.id
            ),
        ];
        expected.sort();
        assert_eq!(
            commands, expected,
            "each line must name its own session: a batch that wrote the first id twice, or \
             only once, would be a different defect with the same count"
        );
    })
    .await
    .expect("the two-session reap must TERMINATE: a hang here is a mock regression");
}

/// **No double line on the explicit close**, driven through a real session.
///
/// `SessionManager::close` is the one removal site that must not audit: its
/// caller, `ssh_session_close`'s handler, writes the `state_change` line
/// itself. A unit test cannot show this, because it cannot create a session
/// to close. Here the manager has a logger, a live session and nothing else
/// writing, so the count is unambiguous — and it is zero from the manager,
/// which is what leaves exactly one line on the real path.
#[tokio::test]
async fn the_explicit_close_writes_nothing_from_the_manager() {
    tokio::time::timeout(TEST_BOUND, async {
        let (addr, _server, _root) = start_default_server().await;
        let audit = audited();

        let manager = SessionManager::new(SessionConfig::default())
            .with_audit_logger(Arc::clone(&audit.logger));

        let info = manager
            .create(
                "mock-host",
                &mock_host_config(addr, "tester", "testpass"),
                &mock_limits(),
                None,
            )
            .await
            .expect("the mock must serve a shell session");

        manager.close(&info.id).await.expect("the id exists");
        assert!(manager.list().await.is_empty());

        audit.logger.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), audit.writer).await;

        assert!(
            lines(&audit.path).is_empty(),
            "the handler owns this path's audit line; a line from the manager would be the \
             SECOND one for a single close: {:?}",
            lines(&audit.path)
        );
    })
    .await
    .expect("the explicit close must TERMINATE: a hang here is a mock regression");
}
