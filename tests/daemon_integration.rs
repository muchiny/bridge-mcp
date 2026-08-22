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

    // Wait for the daemon to bind the socket. Poll up to 2 seconds.
    let mut ready = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if socket.exists() {
            ready = true;
            break;
        }
    }
    assert!(ready, "daemon failed to bind socket within 2s");

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
    // clean up explicitly below.
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

    // Wait for bind.
    let mut ready = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if socket.exists() {
            ready = true;
            break;
        }
    }
    assert!(ready, "daemon failed to bind socket within 2s");

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

    // Wait for bind.
    let mut ready = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if socket.exists() {
            ready = true;
            break;
        }
    }
    assert!(ready);

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
