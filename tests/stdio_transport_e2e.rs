//! Regression test for the stdio transport accept-loop / shutdown race.
//!
//! Between v1.11.0 and v1.13.0 the server was refactored so that
//! `serve_session` ran inside a detached `tokio::spawn`, but the
//! `JoinHandle` was discarded and `serve()` returned immediately after
//! the (single-session) `accept()` returned `None`. The runtime then
//! killed the still-warming-up session task before it had read a single
//! byte from stdin, and `bridge-mcp serve` would exit silently
//! without ever responding to a `server/discover` request.
//!
//! This test spawns the real binary, pipes a JSON-RPC `server/discover`
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
/// rejects files with group/other-readable bits, so we chmod 0600. Audit is
/// off: without an `audit:` section the spawned `serve` would open the REAL
/// ~/.local/share/bridge-mcp/audit.log.
fn write_test_config(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        "hosts:\n  stub:\n    hostname: 127.0.0.1\n    port: 22\n    user: nobody\n    \
         description: \"e2e test stub host (never dialed)\"\n    auth:\n      type: agent\n\
         security:\n  mode: permissive\nlimits: {}\nsessions: {}\naudit:\n  enabled: false\n",
    )
    .expect("write test config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod test config");
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn stdio_serve_responds_to_discover() {
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

    // Send server/discover — the 2026-07-28 entry point. `initialize` now
    // answers -32022 and would fail the serverInfo assertion below.
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\
        \"params\":{\"_meta\":{\
        \"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\
        \"io.modelcontextprotocol/clientInfo\":{\"name\":\"e2e-test\",\"version\":\"1\"},\
        \"io.modelcontextprotocol/clientCapabilities\":{}}}}\n";
    stdin.write_all(req).await.expect("write server/discover");
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
    // serverInfo moved into result._meta in 2026-07-28.
    assert!(
        response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"]
            .as_str()
            .is_some_and(|n| n == "bridge-mcp"),
        "expected _meta serverInfo.name = bridge-mcp, got: {response}"
    );
    assert_eq!(response["result"]["resultType"], "complete");

    // Closing stdin signals EOF, which lets the session's reader loop
    // exit and `serve()` shut down cleanly.
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let _ = child.start_kill();
}

/// Guards the OTHER half of T12's bounded session drain, and it is a half
/// nothing else in the suite covers.
///
/// `McpServer::serve` bounds its session drain only when the transport says
/// it was asked to stop (`Transport::shutdown_requested`). Stdio says `false`
/// — its accept loop ends after the one session is handed out, long before
/// that session does — so the wait there stays unbounded.
///
/// Measured, with that branch removed and the bound made unconditional: this
/// binary answers the first request, then **stops answering** while stdin is
/// still open (empty read on the second request, ~2 s after the first), while
/// `stdio_serve_responds_to_discover` above stays GREEN because it answers
/// inside 1.5 s. So the existing suite would not have caught a change that
/// ends `bridge-mcp serve` a couple of seconds after start-up.
///
/// The idle is 3 s against a 2 s `SESSION_DRAIN_GRACE`: long enough to be
/// past it, short enough to keep this test cheap.
#[tokio::test(flavor = "multi_thread")]
async fn stdio_serve_still_answers_after_an_idle_longer_than_the_drain_grace() {
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
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));

    let discover = |id: u8| {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"server/discover\",\
             \"params\":{{\"_meta\":{{\
             \"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\
             \"io.modelcontextprotocol/clientInfo\":{{\"name\":\"idle-test\",\"version\":\"1\"}},\
             \"io.modelcontextprotocol/clientCapabilities\":{{}}}}}}}}\n"
        )
    };

    stdin
        .write_all(discover(1).as_bytes())
        .await
        .expect("write first discover");
    stdin.flush().await.expect("flush");
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .expect("first response within 5s")
        .expect("read stdout");
    assert!(line.contains("\"id\":1"), "unexpected first answer: {line}");

    // stdin stays OPEN across the idle: no EOF, nothing to end the session.
    tokio::time::sleep(Duration::from_secs(3)).await;

    stdin
        .write_all(discover(2).as_bytes())
        .await
        .expect("the server must still be reading stdin after the idle");
    stdin.flush().await.expect("flush");
    let mut second = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut second))
        .await
        .expect("second response within 5s")
        .expect("read stdout");
    assert!(
        read > 0,
        "the server closed stdout during the idle: a stdio session must not be \
         bounded by the shutdown drain"
    );
    assert!(
        second.contains("\"id\":2"),
        "unexpected second answer: {second}"
    );

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let _ = child.start_kill();
}
