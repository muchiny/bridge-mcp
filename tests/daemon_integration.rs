//! Integration test for the full daemon lifecycle.
//!
//! These tests are the closest thing we have to a production smoke test
//! without spinning up an SSH server: they spawn a real daemon in the
//! same process (not a child binary), drive it through `start` →
//! `status` → `tools/list` over the Unix socket → `stop`, and verify
//! that each stage works as documented.
//!
//! We intentionally do NOT test actual SSH execution here — that's
//! covered by `e2e_raspberry.rs` which requires a real Pi.

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Wait until the daemon actually ACCEPTS connections.
///
/// `socket.exists()` is not a readiness probe. The socket file appears at
/// `bind()`, while `connect()` only succeeds after `listen()`. Under CPU
/// starvation that window opens, and these tests failed with
/// `Os { code: 111, ConnectionRefused }` roughly one run in three — measured 3
/// failures in 60 runs under 40x load, and reproduced on `main` as well as on
/// feature branches.
///
/// That flake was not merely noise: `cargo mutants` refuses to test a single
/// mutant against a red baseline (`cargo test failed in an unmutated tree`), so
/// one intermittent test blocked all mutation testing.
///
/// Connecting is the only thing that proves a connect will work. The accepted
/// connection is dropped immediately; the daemon treats that as an EOF and
/// cleans the session up, which is the same path a client closing early takes.
async fn wait_until_accepting(socket: &std::path::Path) -> bool {
    for _ in 0..50 {
        if UnixStream::connect(socket).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

use bridge_mcp::Config;
use bridge_mcp::config::{
    AuditConfig, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
    SshConfigDiscovery, ToolGroupsConfig,
};
use bridge_mcp::daemon::{self, DaemonStatus, PidFile};

fn test_config() -> Config {
    Config {
        hosts: std::collections::HashMap::new(),
        security: SecurityConfig::default(),
        limits: LimitsConfig::default(),
        audit: AuditConfig {
            // AuditConfig::default() carries the REAL path
            // (~/.local/share/bridge-mcp/audit.log). Since G-26 wired
            // max_size_mb and retain_days into the writer task, a fixture
            // inheriting that default can rotate and sweep a developer's
            // actual audit directory. No test here asserts anything about
            // audit persistence, so turn it off explicitly rather than
            // pointing at a temp path that nothing reads.
            enabled: false,
            ..AuditConfig::default()
        },
        sessions: SessionConfig::default(),
        tool_groups: ToolGroupsConfig::default(),
        ssh_config: SshConfigDiscovery::default(),
        http: HttpTransportConfig::default(),
        rbac: bridge_mcp::security::rbac::RbacConfig::default(),
        awx: None,
    }
}

/// Full daemon lifecycle test:
///   1. Daemon status on absent socket returns `NotRunning`.
///   2. Spawn daemon → socket bound → status returns `Running`.
///   3. Connect a client, send `tools/list`, read response.
///   4. Ctrl+C the daemon (via task abort).
///   5. Post-shutdown status (after `PidFile` drop) returns `NotRunning`.
#[tokio::test(flavor = "multi_thread")]
async fn test_daemon_lifecycle_start_call_stop() {
    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("daemon_test.sock");

    // Stage 1: status on absent daemon.
    let initial = daemon::daemon_status(&socket).expect("status read");
    assert_eq!(initial, DaemonStatus::NotRunning);

    // Stage 2: spawn daemon.
    let config = Arc::new(test_config());
    let daemon_handle = tokio::spawn({
        let socket = socket.clone();
        async move {
            daemon::run_daemon(config, &socket)
                .await
                .expect("daemon ok");
        }
    });

    assert!(
        wait_until_accepting(&socket).await,
        "daemon did not accept a connection within 5s"
    );

    // Status must now report Running.
    let running = daemon::daemon_status(&socket).expect("status read");
    match running {
        DaemonStatus::Running { pid, .. } => {
            assert_eq!(pid, std::process::id());
        }
        other => panic!("expected Running, got: {other:?}"),
    }

    // Stage 3: JSON-RPC tools/list over the socket.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    // `\"params\": null` is a capability-less request: MCP 2026-07-28
    // requires `_meta.clientCapabilities` on every one, so the daemon now
    // answers -32602 without it and this stage would measure the refusal
    // rather than the tool list.
    let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n";
    client.write_all(request).await.expect("write");
    client.flush().await.expect("flush");

    let (r, _w) = client.split();
    let mut reader = BufReader::new(r);
    let mut response_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
        .await
        .expect("read timeout")
        .expect("read ok");

    let response: serde_json::Value =
        serde_json::from_str(response_line.trim()).expect("valid json-rpc response");
    assert_eq!(response["id"], 1);
    assert!(response.get("result").is_some());
    assert!(response["result"]["tools"].is_array());
    assert!(
        !response["result"]["tools"].as_array().unwrap().is_empty(),
        "tools/list must return at least one tool"
    );

    drop(client);

    // Stage 4: shut down the daemon. `tokio::spawn` handles are cancel-safe
    // via `abort()`, which drops the run_daemon future. The `PidFile::Drop`
    // inside `run_daemon` removes the PID file, and our cleanup at the end
    // of `run_daemon` removes the socket file.
    //
    // In practice `abort()` may leave the socket file behind (abort cancels
    // at the next await point, possibly before cleanup runs), so we also
    // clean up explicitly below. It skips the audit drain at the end of
    // `serve()` for the same reason — harmless here, since `test_config`
    // disables auditing; `serve_returns_only_after_the_audit_lines_are_on_disk`
    // is the test that reaches it.
    daemon_handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), daemon_handle).await;
    let _ = std::fs::remove_file(&socket);

    // Explicitly remove the PID file because `abort()` skipped Drop.
    let pid_file = socket.with_extension("sock.pid");
    let _ = std::fs::remove_file(&pid_file);

    // Stage 5: status must now report NotRunning.
    let final_status = daemon::daemon_status(&socket).expect("status read");
    assert_eq!(final_status, DaemonStatus::NotRunning);
}

/// Double-start detection: a second `PidFile::acquire` on the same
/// socket must fail while the first lock is held.
#[test]
fn test_daemon_double_start_is_rejected() {
    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("double.sock");

    let _first = PidFile::acquire(&socket).expect("first lock ok");
    let second = PidFile::acquire(&socket);
    assert!(second.is_err(), "second acquire must fail");
}

/// Status reports Stale when the PID file references a dead process.
#[test]
fn test_daemon_status_reports_stale_for_dead_pid() {
    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("stale.sock");
    let pid_path = socket.with_extension("sock.pid");
    std::fs::write(&pid_path, "4294967290").expect("write stale pid");

    let status = daemon::daemon_status(&socket).expect("status read");
    match status {
        DaemonStatus::Stale { .. } => {}
        other => panic!("expected Stale, got: {other:?}"),
    }
}

/// Supersedes `test_daemon_batch_requests_are_dispatched`, which sent three
/// requests as a JSON array and asserted three responses came back.
///
/// The daemon socket shares `serve_session()` with stdio, so it inherited
/// batching from it — and 3.0.0 removes it from both. JSON-RPC batching was
/// dropped in revision 2025-06-18 and 2026-07-28 does not restore it:
/// `JSONRPCMessage` has three object forms and no array form. Until now the
/// HTTP transport refused an array while these two accepted one, so the
/// server's answer depended on which door the client knocked at.
///
/// TWO halves, and the second is what makes the first mean anything. The
/// refusal alone is satisfied by a daemon that has stopped answering at all,
/// or that drops the connection on the bad frame. So the same connection then
/// sends an ordinary `tools/list` and must get an ordinary result: the array
/// is refused, the session is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_json_array_is_refused_on_the_daemon_socket() {
    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("batch.sock");

    let config = Arc::new(test_config());
    let daemon_handle = tokio::spawn({
        let socket = socket.clone();
        async move {
            daemon::run_daemon(config, &socket)
                .await
                .expect("daemon ok");
        }
    });

    assert!(
        wait_until_accepting(&socket).await,
        "daemon did not accept a connection within 5s"
    );

    // The exact frame the superseded test asserted was dispatched.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}},{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}},{"jsonrpc":"2.0","id":3,"method":"prompts/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}]
"#;
    client.write_all(batch).await.expect("write");
    client.flush().await.expect("flush");

    let (r, mut w) = client.split();
    let mut reader = BufReader::new(r);
    let mut response_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
        .await
        .expect("read timeout")
        .expect("read ok");

    let response: serde_json::Value =
        serde_json::from_str(response_line.trim()).expect("valid json response");
    assert!(
        !response.is_array(),
        "the array must be refused, not dispatched: {response}"
    );
    // `-32600 Invalid Request`, not `-32700 Parse error`: the frame was
    // well-formed JSON. Telling the client its JSON was malformed would send
    // it looking in the wrong place.
    assert_eq!(
        response["error"]["code"], -32600,
        "expected Invalid Request: {response}"
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("batching"),
        "the refusal must say what was wrong: {response}"
    );

    // THE POSITIVE TWIN. Same connection, an ordinary single request. The
    // reader loop answers a bad line and keeps reading, so one refused frame
    // must not end the session — and a daemon that had simply stopped
    // answering would fail here rather than passing the assertions above.
    let single = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
"#;
    w.write_all(single).await.expect("write single");
    w.flush().await.expect("flush single");

    let mut single_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut single_line))
        .await
        .expect("read timeout after the refusal — the session died with the bad frame")
        .expect("read ok");
    let single_response: serde_json::Value =
        serde_json::from_str(single_line.trim()).expect("valid json response");
    assert_eq!(single_response["id"], 9, "{single_response}");
    assert!(
        single_response["result"]["tools"].is_array(),
        "the session must still serve ordinary requests: {single_response}"
    );

    drop(client);
    daemon_handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), daemon_handle).await;
    let _ = std::fs::remove_file(&socket);
    let pid_file = socket.with_extension("sock.pid");
    let _ = std::fs::remove_file(&pid_file);
}

/// **Sprint 3 Phase B.2:** malformed JSON on the daemon wire must not
/// crash the session — it should receive a JSON-RPC `parse_error`
/// (code -32700) and keep processing subsequent requests.
///
/// Before A.5 the daemon silently dropped malformed lines. After the
/// transport unification it reuses stdio's `parse_error` response path.
#[tokio::test(flavor = "multi_thread")]
async fn test_daemon_parse_error_response_sent_for_bad_json() {
    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("parse.sock");

    let config = Arc::new(test_config());
    let daemon_handle = tokio::spawn({
        let socket = socket.clone();
        async move {
            daemon::run_daemon(config, &socket)
                .await
                .expect("daemon ok");
        }
    });

    assert!(wait_until_accepting(&socket).await);

    let mut client = UnixStream::connect(&socket).await.expect("connect");
    // Line 1: garbage JSON.
    client
        .write_all(b"not actually json\n")
        .await
        .expect("write");
    // Line 2: valid request to confirm the session survived.
    //
    // The probe was `ping` until 2026-07-28 deleted the method. A deleted
    // method still proves the reader loop is alive -- it answers -32601 --
    // but it cannot satisfy the `result.is_some()` assertion below, which
    // is the half that proves the session still SERVES rather than merely
    // still replies. `tools/list` is the smallest method that does both,
    // and it carries the capability envelope every request now needs.
    client
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n")
        .await
        .expect("write");
    client.flush().await.expect("flush");

    let (r, _w) = client.split();
    let mut reader = BufReader::new(r);

    // First response should be a parse_error (id = null).
    let mut err_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut err_line))
        .await
        .expect("read timeout")
        .expect("read ok");
    let err_resp: serde_json::Value =
        serde_json::from_str(err_line.trim()).expect("valid parse error json");
    assert_eq!(
        err_resp["error"]["code"].as_i64(),
        Some(-32700),
        "expected parse_error code, got: {err_line}"
    );

    // Second response should be the successful probe with id=99.
    let mut ok_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut ok_line))
        .await
        .expect("read timeout")
        .expect("read ok");
    let ok_resp: serde_json::Value =
        serde_json::from_str(ok_line.trim()).expect("valid probe response");
    assert_eq!(ok_resp["id"].as_i64(), Some(99));
    assert!(ok_resp.get("result").is_some());

    drop(client);
    daemon_handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), daemon_handle).await;
    let _ = std::fs::remove_file(&socket);
    let pid_file = socket.with_extension("sock.pid");
    let _ = std::fs::remove_file(&pid_file);
}

// ============================================================================
// T12 (audit-integrity wave) — the drain at the end of `McpServer::serve`
// ============================================================================

/// How many pipelined tool calls the drain test issues, and the number is
/// measured rather than chosen.
///
/// ONE call does not reliably catch the defect. With the
/// `self.close_audit(); drain_audit_writer(..)` pair at the end of
/// `McpServer::serve` commented out, measured on this machine:
///
/// - `DRAIN_TEST_CALLS = 1`: red in **6 runs of 8** (`got 0 of 1`), GREEN in
///   the other 2. A detector that misses a quarter of the time is not one.
/// - `DRAIN_TEST_CALLS = 200`: red in **8 runs of 8**, with 0, 0, 157, 160,
///   164, 167, 168 and 175 of the 200 lines on disk — so between 25 and 200
///   events lost, never fewer than 25.
///
/// The volume is what makes the producer outrun the writer (one
/// `spawn_blocking` round trip per event), and the pipelining is what makes
/// it arrive faster than one request/response round trip at a time. With the
/// drain in place: 200 of 200, every run.
const DRAIN_TEST_CALLS: usize = 200;

/// One `tools/call` frame for `ssh_session_close` on a session id that
/// matches nothing.
///
/// Chosen because it audits without a network: the id resolves to no host,
/// `SessionManager::close` fails, and the handler writes one
/// `CommandResult::Error` event through `log_failure` with
/// `host: "<no-host>"`. It is annotated `mutating`, not `destructive`, so the
/// confirmation gate returns `NotRequired` — a gate refusal writes no audit
/// event at all today, which would have left this test with nothing to read.
fn session_close_frame(i: usize) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/call\",\"params\":{{\
         \"name\":\"ssh_session_close\",\
         \"arguments\":{{\"session_id\":\"t12-{i}\"}},\
         \"_meta\":{{\
         \"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\
         \"io.modelcontextprotocol/clientCapabilities\":{{}}}}}}}}\n"
    )
}

/// Read every line the daemon writes back until EOF, counting the responses
/// and collecting the method names of the notifications, and fire `first_tx`
/// on the first RESPONSE.
///
/// Spawned rather than read inline for two reasons. Without a reader the
/// server blocks writing its responses once the socket buffer fills, the
/// session never ends and `serve` never returns — a hang that would look like
/// a drain bug. And the caller needs the first-response signal while the
/// remaining answers are still arriving.
fn drain_responses(
    read_half: tokio::net::unix::OwnedReadHalf,
    first_tx: tokio::sync::oneshot::Sender<()>,
) -> tokio::task::JoinHandle<(usize, Vec<String>)> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(read_half);
        let mut first_tx = Some(first_tx);
        let mut answers = 0usize;
        let mut notifications: Vec<String> = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                // A response carries `id`; a notification does not.
                if v.get("id").is_some() {
                    answers += 1;
                    if let Some(tx) = first_tx.take() {
                        let _ = tx.send(());
                    }
                } else if let Some(m) = v.get("method").and_then(serde_json::Value::as_str) {
                    notifications.push(m.to_string());
                }
            }
            line.clear();
        }
        (answers, notifications)
    })
}

/// T12's acceptance: when `McpServer::serve` returns, the audit lines of the
/// calls it served are ON DISK.
///
/// Not "a handle was kept" and not "the sender is `None`" — the file is read,
/// synchronously, with no polling and no sleep, on the statement after
/// `serve` resolves. Any line that is not there yet is a line the process
/// would have lost.
///
/// This is the first test in the repository to drive `McpServer::serve` to a
/// RETURN. The three `run_daemon` tests above end their future with
/// `abort()`, which skips the whole shutdown block, and the two `serve` tests
/// in `src/mcp/transport/http.rs` pass `audit_task: None`. That is why the
/// discarded `JoinHandle` survived: nothing exercised the path it was
/// discarded on. `run_daemon` is deliberately not reused here — it installs
/// the process-wide signal handler and owns its own token, so the test
/// composes the same three pieces by hand in order to cancel the transport's
/// shutdown token instead of raising a signal.
///
/// **What it does NOT pin**, measured and said out loud: it does not
/// distinguish `AuditLogger::close()` from the "drop every owner" form. With
/// `close_audit()` removed and the bounded join kept, this test stays GREEN
/// and the run goes from ~0.5 s to ~2.5 s (3 runs: 2.51, 2.44, 2.81) — the
/// join waits out the whole 2 s timeout, warns, and the writer finishes
/// inside that window anyway. So the cost of the drop form here is two
/// seconds on every shutdown plus a warning that is not true, not lost
/// events. `close()`'s own semantics are pinned deterministically in
/// `src/security/audit.rs` by
/// `close_ends_the_writer_while_a_clone_of_the_logger_survives`.
#[tokio::test(flavor = "multi_thread")]
async fn serve_returns_only_after_the_audit_lines_are_on_disk() {
    use bridge_mcp::mcp::McpServer;
    use bridge_mcp::mcp::transport::unix_socket::UnixSocketTransport;

    let tmp = TempDir::new().expect("create tempdir");
    let socket = tmp.path().join("audit_drain.sock");
    let audit_path = tmp.path().join("audit.log");

    let config = Config {
        audit: AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            // No rotation and no retention sweep: this test is about the
            // drain, and a rotation mid-run would move the lines it reads.
            max_size_mb: 0,
            retain_days: 0,
        },
        ..test_config()
    };

    let (server, audit_task) = McpServer::new(config);
    let audit_task = audit_task.expect("audit is enabled, so a writer task must be produced");
    let server = Arc::new(server);

    let transport = UnixSocketTransport::bind(&socket).expect("bind the daemon socket");
    let shutdown = transport.shutdown_token();

    let serving =
        tokio::spawn(async move { server.serve(transport, Some(audit_task), None).await });

    assert!(
        wait_until_accepting(&socket).await,
        "the server did not accept a connection within 5s"
    );

    let client = UnixStream::connect(&socket).await.expect("connect");
    let (read_half, mut write_half) = client.into_split();

    // `first_tx` fires on the first RESPONSE, and the cancellation below waits
    // for it. `UnixSocketTransport::accept` selects `biased` on the shutdown
    // token, so a token cancelled before the connection is accepted ends the
    // accept loop with the session never created — measured, as a flake:
    // `0 of 200`, twice in five runs, before this handshake was added.
    let (first_tx, first_rx) = tokio::sync::oneshot::channel::<()>();
    let responses = drain_responses(read_half, first_tx);

    let mut frames = String::new();
    for i in 0..DRAIN_TEST_CALLS {
        frames.push_str(&session_close_frame(i));
    }
    write_half
        .write_all(frames.as_bytes())
        .await
        .expect("write the pipelined calls");
    write_half.flush().await.expect("flush");
    // Half-close so the session's reader hits EOF once it has consumed them
    // all; that is what lets `serve` finish draining its `JoinSet`.
    drop(write_half);

    // One response, then cancel. Waiting for ONE is what makes the test
    // deterministic (the session exists, so the accept-loop race is gone);
    // not waiting for the other 199 is what keeps it decisive. Cancelling
    // the token only ends the ACCEPT loop — the session already in the
    // `JoinSet` is drained by `serve`, so all 200 calls are still served,
    // with the writer running behind them the whole time.
    tokio::time::timeout(Duration::from_secs(10), first_rx)
        .await
        .expect("the server must answer the first call within 10s")
        .expect("the response drain must not drop the handshake");
    shutdown.cancel();

    tokio::time::timeout(Duration::from_secs(20), serving)
        .await
        .expect("serve must return within 20s (the drain is bounded at 2s)")
        .expect("the serve task must not panic")
        .expect("serve must not error");

    // Read on the very next statement. No `sleep`, no retry loop: the point
    // is that `serve` having returned is itself the guarantee.
    let contents = std::fs::read_to_string(&audit_path).expect("the audit file must exist");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(
        lines.len(),
        DRAIN_TEST_CALLS,
        "every served call must have left its line on disk by the time serve() returned; \
         got {} of {}",
        lines.len(),
        DRAIN_TEST_CALLS
    );

    // One line in full, so the test also pins WHAT was written and not only
    // how much. Looked up by its id rather than taken at index 0: a session
    // dispatches its requests concurrently, so the order the events reach the
    // channel is not the order they were sent (measured: the first line on
    // disk was `t12-1`).
    let events: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("audit line must be JSONL: {e} — line was {line:?}"))
        })
        .collect();
    let first = events
        .iter()
        .find(|e| e["command"] == "ssh_session_close session_id=t12-0")
        .expect("the line for call 0 must be on disk");
    assert_eq!(first["tool_name"], "ssh_session_close");
    assert_eq!(first["host"], "<no-host>");
    assert!(
        first["result"]["Error"]["message"].is_string(),
        "a close on an unknown session id is an Error event: {first}"
    );

    // Every id, so a drain that stopped halfway cannot pass by writing the
    // first N lines.
    for i in 0..DRAIN_TEST_CALLS {
        assert!(
            contents.contains(&format!("session_id=t12-{i}")),
            "call {i} is missing from the audit file"
        );
    }

    let (answers, notifications) = tokio::time::timeout(Duration::from_secs(5), responses)
        .await
        .expect("the response drain must finish")
        .expect("the response drain must not panic");
    assert_eq!(
        answers,
        DRAIN_TEST_CALLS,
        "the server must have answered every call it audited (notifications seen: {})",
        notifications.len()
    );
}
