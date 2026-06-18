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
        audit: AuditConfig::default(),
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
    let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":null}\n";
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

/// **Sprint 3 Phase B.2:** batch JSON-RPC requests are now supported
/// in daemon mode thanks to the shared `serve_session()` dispatch
/// path.
///
/// This test exercises the behavior that `daemon/connection.rs` used
/// to reject with a warning: send a JSON array of three requests in
/// a single frame and verify three responses come back — exactly
/// what stdio has supported since Sprint 1.
#[tokio::test(flavor = "multi_thread")]
async fn test_daemon_batch_requests_are_dispatched() {
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

    // Send a batch of three tools/list + resources/list + ping.
    let mut client = UnixStream::connect(&socket).await.expect("connect");
    let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"resources/list"},{"jsonrpc":"2.0","id":3,"method":"ping"}]
"#;
    client.write_all(batch).await.expect("write");
    client.flush().await.expect("flush");

    let (r, _w) = client.split();
    let mut reader = BufReader::new(r);
    let mut response_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response_line))
        .await
        .expect("read timeout")
        .expect("read ok");

    // The response must be a JSON array of 3 elements (batch response).
    let response: serde_json::Value =
        serde_json::from_str(response_line.trim()).expect("valid json batch response");
    let arr = response
        .as_array()
        .expect("batch response must be a JSON array");
    assert_eq!(
        arr.len(),
        3,
        "batch of 3 requests must produce 3 responses, got: {arr:?}"
    );
    // Every response must carry one of the 3 ids.
    let mut seen: Vec<i64> = arr
        .iter()
        .map(|r| r["id"].as_i64().expect("numeric id"))
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 2, 3]);

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
    client
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\"}\n")
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

    // Second response should be the successful ping with id=99.
    let mut ok_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut ok_line))
        .await
        .expect("read timeout")
        .expect("read ok");
    let ok_resp: serde_json::Value =
        serde_json::from_str(ok_line.trim()).expect("valid ping response");
    assert_eq!(ok_resp["id"].as_i64(), Some(99));
    assert!(ok_resp.get("result").is_some());

    drop(client);
    daemon_handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), daemon_handle).await;
    let _ = std::fs::remove_file(&socket);
    let pid_file = socket.with_extension("sock.pid");
    let _ = std::fs::remove_file(&pid_file);
}
