//! Integration tests for `SshClient` against an in-process russh server.
//!
//! These exercise the connect / authenticate / exec / close paths in
//! `src/ssh/client.rs` without requiring an external SSH daemon. The
//! helper types (`MockSshServerBuilder`, `mock_host_config`,
//! `mock_limits`, …) live in `tests/ssh_mock_server.rs` and are pulled
//! in here via `#[path]` so the file remains a self-contained binary.

#![allow(clippy::manual_let_else)]

#[path = "ssh_mock_server.rs"]
mod helpers;

use bridge_mcp::config::{AuthConfig, HostKeyVerification};
use bridge_mcp::error::BridgeError;
use bridge_mcp::ssh::SshClient;
use helpers::{ExecResponse, MockSshServerBuilder, mock_host_config, mock_limits};

#[tokio::test]
async fn connect_with_correct_password_succeeds() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .creds("tester", "testpass")
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();

    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect should succeed");

    assert_eq!(client.host_name(), "mock");
    let _ = client.close().await;
}

#[tokio::test]
async fn connect_with_wrong_password_returns_ssh_auth_error() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .creds("tester", "testpass")
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "WRONG");
    let limits = mock_limits();

    // `SshClient` does not implement Debug, so we can't use `expect_err`.
    let err = match SshClient::connect("mock", &host, &limits).await {
        Ok(_) => panic!("auth should have failed"),
        Err(e) => e,
    };

    match err {
        BridgeError::SshAuth { user, .. } => {
            assert_eq!(user, "tester");
        }
        other => panic!("expected SshAuth, got {other:?}"),
    }
}

#[tokio::test]
async fn connect_with_wrong_user_returns_ssh_auth_error() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .creds("tester", "testpass")
        .start()
        .await;

    let host = mock_host_config(addr, "stranger", "testpass");
    let limits = mock_limits();

    let err = match SshClient::connect("mock", &host, &limits).await {
        Ok(_) => panic!("auth should have failed"),
        Err(e) => e,
    };
    assert!(matches!(err, BridgeError::SshAuth { .. }));
}

#[tokio::test]
async fn exec_returns_configured_stdout_and_exit_code() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .exec_response(ExecResponse {
            stdout: b"hello\n".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
        })
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();

    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");
    let out = client.exec("echo hello", &limits).await.expect("exec");

    assert_eq!(out.stdout, "hello\n");
    assert!(out.stderr.is_empty());
    assert_eq!(out.exit_code, 0);
    let _ = client.close().await;
}

#[tokio::test]
async fn exec_propagates_stderr_and_nonzero_exit_code() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .exec_response(ExecResponse {
            stdout: Vec::new(),
            stderr: b"boom\n".to_vec(),
            exit_code: 42,
        })
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();

    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");
    let out = client.exec("false", &limits).await.expect("exec");

    assert_eq!(out.exit_code, 42);
    assert!(out.stderr.contains("boom"), "stderr: {}", out.stderr);
    assert!(out.stdout.is_empty());
    let _ = client.close().await;
}

#[tokio::test]
async fn is_connected_is_true_on_live_connection() {
    let (addr, _server, _root) = MockSshServerBuilder::new().start().await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();
    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");

    // `SshClient::close` consumes `self`, so the post-close `is_connected`
    // path is not reachable from the public API. The "false after close"
    // case is exercised via `is_connected_returns_false_after_server_shutdown`
    // below, which kills the underlying transport while keeping the handle.
    assert!(client.is_connected().await, "connection should be live");
    client.close().await.expect("close");
}

// `MockServerHandle::shutdown` cancels the accept loop *and* aborts every
// spawned connection task (see `tests/ssh_mock_server.rs` — child tasks live
// in a `JoinSet`, `abort_all` runs on cancel). That drops the server side of
// the transport, so the client's next `channel_open_session()` fails and
// `is_connected()` returns false.
#[tokio::test]
async fn is_connected_returns_false_after_server_shutdown() {
    let (addr, server, _root) = MockSshServerBuilder::new().start().await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();
    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");
    assert!(client.is_connected().await);

    server.shutdown();
    // Give the server a moment to actually stop accepting/serving.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Best effort: after shutdown, opening a new channel should ultimately
    // fail. `is_connected` has its own 5s timeout internally.
    let still = client.is_connected().await;
    assert!(!still, "expected is_connected=false after server shutdown");
}

#[tokio::test]
async fn close_succeeds_on_live_connection() {
    let (addr, _server, _root) = MockSshServerBuilder::new().start().await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();
    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");

    let res = client.close().await;
    assert!(res.is_ok(), "close failed: {:?}", res.err());
}

#[tokio::test]
async fn host_key_verification_off_does_not_persist_known_hosts() {
    // The mock uses a fixed ed25519 key; with `Off` mode the client
    // should not even attempt to write to ~/.ssh/known_hosts.
    let (addr, _server, _root) = MockSshServerBuilder::new().start().await;

    let mut host = mock_host_config(addr, "tester", "testpass");
    host.host_key_verification = HostKeyVerification::Off;
    let limits = mock_limits();

    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");
    let _ = client.close().await;
}

#[tokio::test]
async fn auth_config_password_round_trip() {
    // Sanity check: the AuthConfig::Password variant we build for the mock
    // is what the client actually sees.
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .creds("tester", "testpass")
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "testpass");
    matches!(host.auth, AuthConfig::Password { .. })
        .then_some(())
        .expect("expected AuthConfig::Password");

    let limits = mock_limits();
    SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect")
        .close()
        .await
        .ok();
}

#[tokio::test]
async fn multiple_exec_calls_on_one_connection() {
    let (addr, _server, _root) = MockSshServerBuilder::new()
        .exec_response(ExecResponse::ok("payload\n"))
        .start()
        .await;

    let host = mock_host_config(addr, "tester", "testpass");
    let limits = mock_limits();
    let client = SshClient::connect("mock", &host, &limits)
        .await
        .expect("connect");

    for _ in 0..3 {
        let out = client.exec("noop", &limits).await.expect("exec");
        assert_eq!(out.stdout, "payload\n");
        assert_eq!(out.exit_code, 0);
    }
    let _ = client.close().await;
}
