//! The HTTP transport must actually write its audit trail (AUDIT-2026-08 B6).
//!
//! `McpServer::new` returns `(server, Option<AuditWriterTask>)`. The task owns
//! the receiving half of the audit channel; if it is dropped, the channel
//! closes and `AuditLogger` throws every event away on a `let _ = send(...)`.
//! `McpServer::serve` spawns it — but `main.rs` bound it to `_audit_task` on
//! the `serve-http` arm and dropped it on the spot, so the mode the docs call
//! "Enterprise (auth, audit, multi-user)" created `audit.log` with 0600
//! permissions and then left it empty forever.
//!
//! These tests pin the contract from both sides: with the writer running an
//! HTTP-borne denial reaches the file, and without it nothing does — which is
//! what the shipped binary did.

#![cfg(feature = "http")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use bridge_mcp::config::{
    AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, OsType, Protocol,
    SecurityConfig, SecurityMode,
};
use bridge_mcp::mcp::McpServer;
use bridge_mcp::mcp::transport::http::{HttpTransportConfig, build_router};

/// A config that audits to `path` and denies every command, so a single
/// `tools/call` produces exactly one audit event without touching the network.
fn denying_config(path: std::path::PathBuf) -> Config {
    let mut hosts = HashMap::new();
    hosts.insert(
        "server1".to_string(),
        HostConfig {
            hostname: "192.0.2.1".to_string(), // TEST-NET-1, never routable
            port: 22,
            user: "nobody".to_string(),
            auth: AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Linux,
            shell: None,
            retry: None,
            protocol: Protocol::default(),
            #[cfg(feature = "winrm")]
            winrm_use_tls: None,
            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,
            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,
            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        },
    );

    Config {
        hosts,
        security: SecurityConfig {
            // Standard mode with an empty whitelist: every command is denied
            // before any connection is attempted.
            mode: SecurityMode::Standard,
            whitelist: Vec::new(),
            // `ssh_exec` is annotated `destructive`, and the gate refuses
            // outright when there is no session context — which is every
            // request on this transport (`handle_request` passes `None`).
            // That is a separate, still-open defect; switching the flag off
            // here keeps these tests about the audit trail alone.
            require_elicitation_on_destructive: false,
            ..SecurityConfig::default()
        },
        audit: AuditConfig {
            enabled: true,
            path,
            ..AuditConfig::default()
        },
        ..Config::default()
    }
}

fn exec_request() -> Request<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "ssh_exec",
            "arguments": {"host": "server1", "command": "id"},
            // MCP 2026-07-28 requires the capability envelope on every
            // request; without it the POST is refused 400 at the transport
            // and the tool never runs, so no audit event is written and this
            // file's subject is never reached.
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });

    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("origin", "http://localhost:5173")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        // MCP 2026-07-28 Server Validation: three REQUIRED request headers,
        // and `Mcp-Name` mirrors `params.name` for `tools/call`. Without them
        // the POST is refused 400 + -32020 before the tool runs, so no audit
        // event is written and this file's subject is never reached.
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "ssh_exec")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Poll for the audit file to become non-empty. The writer hands the actual
/// write to `spawn_blocking`, so the event is not on disk the instant the
/// response comes back.
async fn wait_for_audit_lines(path: &std::path::Path) -> String {
    for _ in 0..100 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.trim().is_empty()
        {
            return contents;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

#[tokio::test]
async fn http_tool_call_is_written_to_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");

    let (server, audit_task) = McpServer::new(denying_config(audit_path.clone()));
    let audit_task = audit_task.expect("audit is enabled, so a writer task must be produced");
    tokio::spawn(audit_task.run());

    let router = build_router(Arc::new(server), HttpTransportConfig::default());
    let response = router.oneshot(exec_request()).await.unwrap();
    assert!(
        response.status().is_success(),
        "JSON-RPC errors travel in the body, not the status: {:?}",
        response.status()
    );

    let contents = wait_for_audit_lines(&audit_path).await;
    assert!(
        !contents.trim().is_empty(),
        "the denied command must be recorded in {}",
        audit_path.display()
    );

    let first = contents.lines().next().unwrap();
    let event: serde_json::Value = serde_json::from_str(first)
        .unwrap_or_else(|e| panic!("audit line must be JSONL: {e} — line was {first:?}"));
    assert_eq!(event["host"], "server1");
    assert_eq!(event["command"], "id");
}

#[tokio::test]
async fn dropping_the_writer_task_silently_loses_the_audit_trail() {
    // This is exactly what `main.rs` used to do on the serve-http arm. Pinned
    // as a test so the failure mode stays visible: no error, no warning, an
    // empty file. If a future change makes the logger fall back to a
    // synchronous write, this test fails and should simply be deleted.
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");

    let (server, audit_task) = McpServer::new(denying_config(audit_path.clone()));
    drop(audit_task);

    let router = build_router(Arc::new(server), HttpTransportConfig::default());
    let response = router.oneshot(exec_request()).await.unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(200)).await;

    let contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        contents.trim().is_empty(),
        "without the writer task the events are dropped — got: {contents}"
    );
}
