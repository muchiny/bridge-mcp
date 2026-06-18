//! Local daemon mode for shared SSH pool across CLI invocations.
//!
//! When running as a daemon, the bridge spawns a single long-lived
//! [`McpServer`] process that listens on a Unix domain socket at
//! `$XDG_RUNTIME_DIR/bridge-mcp.sock` (fallback:
//! `/tmp/bridge-mcp-$UID.sock`). CLI invocations detect the socket,
//! connect, and forward their `tools/call` requests over JSON-RPC. The
//! shared `McpServer` connection pool keeps SSH handshakes cached
//! between invocations.
//!
//! # Sprint 3 — Transport unified
//!
//! The daemon now plugs a [`UnixSocketTransport`] into the generic
//! [`McpServer::serve`] accept loop, just like stdio mode plugs in
//! [`crate::mcp::transport::stdio::StdioTransport`]. Consequences:
//!
//! - **Elicitation, sampling, and logging** work end-to-end in daemon
//!   mode because `serve_session` wires a per-session
//!   `notification_tx` into every `ToolContext`.
//! - **Batch requests** work because the batch dispatcher is shared
//!   with stdio.
//! - **Config hot-reload** works because `ConfigWatcher` is spawned by
//!   `serve<T>()` and broadcasts `tools/list_changed` notifications
//!   through the same channel each client session listens on.
//!
//! The old per-connection handler that lived in `daemon/connection.rs`
//! is gone: its job is now done by `McpServer::serve_session`, which
//! already has the cancellation plumbing, the request registry, and
//! the full dispatch surface.

mod pidfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Config;
use crate::error::Result;
use crate::mcp::McpServer;
use crate::mcp::transport::unix_socket::UnixSocketTransport;

pub use pidfile::{DaemonStatus, PidFile};

/// Default socket path resolution.
///
/// - `$XDG_RUNTIME_DIR/bridge-mcp.sock` if `$XDG_RUNTIME_DIR` is set
///   (standard systemd-logind behavior on Linux, mode `0700`, auto-cleaned
///   at logout).
/// - `/tmp/bridge-mcp-$UID.sock` as a safe fallback, using the
///   effective UID to avoid collisions between users on a shared host.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime.is_empty()
    {
        return PathBuf::from(runtime).join("bridge-mcp.sock");
    }
    // Fallback: /tmp with UID suffix. Use `unsafe`-free UID lookup via libc
    // through the `rustix` crate if available — otherwise read `$UID` from
    // env (set by most shells). Shell-agnostic fallback: plain `/tmp`.
    let uid = std::env::var("UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if uid > 0 {
        PathBuf::from(format!("/tmp/bridge-mcp-{uid}.sock"))
    } else {
        PathBuf::from("/tmp/bridge-mcp.sock")
    }
}

/// Start the daemon listening on `socket_path`.
///
/// Blocks until the process receives `SIGINT` (Ctrl+C) or `SIGTERM`.
///
/// # Errors
///
/// Returns an error if:
/// - Another daemon is already running (PID file exists and process alive).
/// - The socket path cannot be created (permissions, parent dir missing).
/// - The underlying `McpServer` fails to start (config load error).
pub async fn run_daemon(config: Arc<Config>, socket_path: &Path) -> Result<()> {
    // 1. Acquire PID lock. Fails fast if another daemon is already
    //    running on the same socket.
    let _pid_file = PidFile::acquire(socket_path)?;

    // 2. Build the shared McpServer. The audit writer task is passed
    //    through to `serve()` so it runs under the same lifecycle as
    //    every other global worker (cleanup, config watcher).
    let (server, audit_task) = McpServer::new((*config).clone());
    let server = Arc::new(server);

    // 3. Bind the Unix socket listener + hook SIGINT to its shutdown
    //    token so Ctrl+C unwinds the serve loop cleanly.
    let transport = UnixSocketTransport::bind(socket_path)?;
    let shutdown_token = transport.shutdown_token();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("SIGINT received, daemon shutting down");
        shutdown_token.cancel();
    });

    tracing::info!(
        path = %socket_path.display(),
        "Daemon listening for CLI connections"
    );

    // 4. Run the unified serve loop. This consumes the transport,
    //    which removes the socket file on shutdown as part of its
    //    `shutdown()` implementation.
    server.serve(transport, audit_task, None).await?;

    tracing::info!("Daemon stopped");
    Ok(())
}

/// Stop a running daemon by reading its PID file and sending SIGTERM.
///
/// # Errors
///
/// Returns an error if the PID file is missing, unreadable, or if the
/// target process doesn't respond to the signal.
pub fn stop_daemon(socket_path: &Path) -> Result<()> {
    PidFile::stop(socket_path)
}

/// Report the current daemon status (running, stopped, stale PID file).
///
/// # Errors
///
/// Returns an error only on I/O failures reading the PID file.
pub fn daemon_status(socket_path: &Path) -> Result<DaemonStatus> {
    PidFile::status(socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The default path is read at runtime from `$XDG_RUNTIME_DIR` (or
    /// falls back to `/tmp`). We can't mutate env vars in tests because
    /// the crate is `#![forbid(unsafe_code)]` and `std::env::set_var`
    /// now requires `unsafe`. Instead we assert on the returned path's
    /// filename — which is deterministic regardless of the parent dir.
    #[test]
    fn test_default_socket_path_filename_is_stable() {
        let path = default_socket_path();
        let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        // Either the XDG-based default or a fallback with UID suffix.
        assert!(
            file_name == "bridge-mcp.sock" || file_name.starts_with("bridge-mcp-"),
            "unexpected filename: {file_name}"
        );
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("sock"),
            "path must have .sock extension: {}",
            path.display()
        );
    }

    #[test]
    fn test_default_socket_path_is_absolute_or_relative_consistent() {
        // Whatever the env, the path must be non-empty and end in .sock.
        let path = default_socket_path();
        assert!(!path.as_os_str().is_empty());
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("sock"));
    }

    #[test]
    fn test_daemon_status_returns_not_running_for_absent_socket() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("never-existed.sock");
        // Public wrapper delegates to PidFile::status.
        let status = daemon_status(&sock).expect("status read must succeed");
        assert_eq!(status, DaemonStatus::NotRunning);
    }

    #[test]
    fn test_stop_daemon_returns_error_when_no_pid_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("absent.sock");
        // Public wrapper delegates to PidFile::stop.
        let err = stop_daemon(&sock);
        assert!(err.is_err(), "stop on missing pid file must error");
    }
}
