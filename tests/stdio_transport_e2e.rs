//! Regression test for the stdio transport accept-loop / shutdown race.
//!
//! Between v1.11.0 and v1.13.0 the server was refactored so that
//! `serve_session` ran inside a detached `tokio::spawn`, but the
//! `JoinHandle` was discarded and `serve()` returned immediately after
//! the (single-session) `accept()` returned `None`. The runtime then
//! killed the still-warming-up session task before it had read a single
//! byte from stdin, and `bridge-mcp serve` would exit silently
//! without ever responding to an `initialize` request.
//!
//! This test spawns the real binary, pipes a JSON-RPC `initialize`
//! request to its stdin, and asserts that a well-formed response comes
//! back on stdout. If the regression returns, this test will time out.

use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_bridge-mcp");

/// Minimal config that exposes no hosts and uses default security so the
/// server can boot without any SSH credentials. The config loader
/// rejects files with group/other-readable bits, so we chmod 0600.
fn write_test_config(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        "hosts:\n  stub:\n    hostname: 127.0.0.1\n    port: 22\n    user: nobody\n    \
         description: \"e2e test stub host (never dialed)\"\n    auth:\n      type: agent\n\
         security:\n  mode: permissive\nlimits: {}\nsessions: {}\n",
    )
    .expect("write test config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod test config");
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn stdio_serve_responds_to_initialize() {
    let tmp = TempDir::new().expect("tempdir");
    let config = write_test_config(tmp.path());

    let mut child = Command::new(BINARY)
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bridge-mcp serve");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);

    // Send initialize.
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\
        \"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\
        \"clientInfo\":{\"name\":\"e2e-test\",\"version\":\"1\"}}}\n";
    stdin.write_all(req).await.expect("write initialize");
    stdin.flush().await.expect("flush");

    // Read one line of response with a generous timeout. Pre-fix this
    // would hang then time out because the server exited without writing.
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .expect("server must respond within 5s (regression: stdio race)")
        .expect("read stdout");
    assert!(read > 0, "server closed stdout without responding");

    let response: serde_json::Value =
        serde_json::from_str(line.trim()).expect("response must be valid JSON");
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(
        response["result"]["serverInfo"]["name"]
            .as_str()
            .is_some_and(|n| n == "bridge-mcp"),
        "expected serverInfo.name = bridge-mcp, got: {response}"
    );

    // Closing stdin signals EOF, which lets the session's reader loop
    // exit and `serve()` shut down cleanly.
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let _ = child.start_kill();
}
