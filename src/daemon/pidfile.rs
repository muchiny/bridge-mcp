//! PID file management for the daemon lifecycle.
//!
//! Each daemon instance writes its PID to a file next to its Unix socket
//! (e.g. `$XDG_RUNTIME_DIR/bridge-mcp.sock.pid`). The file serves two
//! purposes:
//!
//! 1. **Double-start prevention** — [`PidFile::acquire`] fails if the
//!    file exists and the referenced PID is still alive.
//! 2. **Remote shutdown** — [`PidFile::stop`] reads the PID and sends
//!    SIGTERM to the daemon.
//!
//! The file is removed by the [`PidFile::Drop`] impl when the daemon
//! exits cleanly. Crashes leave a stale file behind — `acquire` detects
//! this case by checking the PID against the process table and takes
//! over the lock.

use std::path::{Path, PathBuf};

use crate::error::{BridgeError, Result};

/// Derive the PID file path from a socket path.
///
/// Appends `.pid` to the socket path so the two files live side by side.
#[must_use]
fn pid_path_for(socket_path: &Path) -> PathBuf {
    let mut p = socket_path.to_path_buf();
    let mut os = p.as_os_str().to_os_string();
    os.push(".pid");
    p = PathBuf::from(os);
    p
}

/// Status reported by [`super::daemon_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// No PID file — the daemon is not running (or was never started).
    NotRunning,
    /// PID file exists and the process is alive at `pid`.
    Running { pid: u32, socket: PathBuf },
    /// PID file exists but the process is gone (stale lock).
    Stale { pid: u32 },
}

/// RAII guard holding a daemon PID lock.
///
/// Writing the PID file is done in [`Self::acquire`]; the file is
/// removed in [`Drop::drop`]. The PID is stored so the [`Drop`] impl
/// only unlinks the file if it still contains our PID — protecting
/// against the edge case where a second daemon took over via stale
/// detection and we'd otherwise delete its active lock on our exit.
pub struct PidFile {
    path: PathBuf,
    pid: u32,
}

impl PidFile {
    /// Acquire an exclusive PID lock next to `socket_path`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Another daemon is already running (PID file exists and PID alive).
    /// - The PID file cannot be created (permission denied, parent dir
    ///   missing).
    pub fn acquire(socket_path: &Path) -> Result<Self> {
        let path = pid_path_for(socket_path);

        // Check for existing PID file.
        if path.exists() {
            let existing = match std::fs::read_to_string(&path) {
                Ok(s) => s.trim().parse::<u32>().ok(),
                Err(_) => None,
            };

            if let Some(pid) = existing
                && is_process_alive(pid)
            {
                return Err(BridgeError::Config(format!(
                    "Another daemon is already running (PID {pid}). \
                     Use `bridge-mcp daemon stop` to stop it, or pass \
                     a different --socket-path."
                )));
            }

            // Stale file — take over.
            tracing::warn!(
                path = %path.display(),
                "Removing stale PID file from crashed daemon"
            );
            let _ = std::fs::remove_file(&path);
        }

        // Write our PID.
        let pid = std::process::id();
        std::fs::write(&path, pid.to_string()).map_err(BridgeError::Io)?;

        tracing::debug!(
            path = %path.display(),
            pid,
            "PID lock acquired"
        );

        Ok(Self { path, pid })
    }

    /// Stop a running daemon by sending SIGTERM to its PID.
    ///
    /// # Errors
    ///
    /// Returns an error if the PID file is missing, unreadable, or the
    /// signal fails to deliver.
    pub fn stop(socket_path: &Path) -> Result<()> {
        let path = pid_path_for(socket_path);
        let pid: u32 = std::fs::read_to_string(&path)
            .map_err(|_| {
                BridgeError::Config(format!("No daemon PID file found at {}", path.display()))
            })?
            .trim()
            .parse()
            .map_err(|_| {
                BridgeError::Config(format!("PID file at {} is corrupted", path.display()))
            })?;

        if !is_process_alive(pid) {
            // Stale: just remove the file.
            let _ = std::fs::remove_file(&path);
            return Err(BridgeError::Config(format!(
                "Daemon (PID {pid}) is not running; removed stale PID file"
            )));
        }

        // Send SIGTERM. We use `kill` with `libc::SIGTERM = 15`.
        send_sigterm(pid)?;
        tracing::info!(pid, "Sent SIGTERM to daemon");
        Ok(())
    }

    /// Report the current status.
    ///
    /// # Errors
    ///
    /// Returns an error only on I/O failures reading the PID file.
    pub fn status(socket_path: &Path) -> Result<DaemonStatus> {
        let path = pid_path_for(socket_path);
        if !path.exists() {
            return Ok(DaemonStatus::NotRunning);
        }
        let content = std::fs::read_to_string(&path).map_err(BridgeError::Io)?;
        let Ok(pid) = content.trim().parse::<u32>() else {
            return Ok(DaemonStatus::Stale { pid: 0 });
        };
        if is_process_alive(pid) {
            Ok(DaemonStatus::Running {
                pid,
                socket: socket_path.to_path_buf(),
            })
        } else {
            Ok(DaemonStatus::Stale { pid })
        }
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Only remove the file if it still contains our PID. Prevents
        // clobbering a replacement daemon that took over via stale
        // detection between our acquire and drop.
        if let Ok(content) = std::fs::read_to_string(&self.path)
            && content.trim().parse::<u32>() == Ok(self.pid)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Check whether a PID is still alive by sending `signal 0` (no-op probe).
///
/// Linux-only. On non-Linux hosts, returns `false` (the daemon mode is
/// intended for Linux hosts where the MCP bridge typically runs).
#[cfg(unix)]
fn is_process_alive(pid: u32) -> bool {
    // `/proc/$PID` check is simpler than a libc::kill call and doesn't
    // require `unsafe`. It covers the vast majority of Linux cases where
    // the daemon will run.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(unix))]
fn is_process_alive(_pid: u32) -> bool {
    false
}

/// Send SIGTERM to `pid` via a command-line `kill` fallback.
///
/// Using the `kill(1)` binary avoids pulling in `libc` / `nix` just for
/// one signal call, and keeps the crate `#![forbid(unsafe_code)]`.
fn send_sigterm(pid: u32) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(BridgeError::Io)?;

    if !status.success() {
        return Err(BridgeError::Config(format!(
            "kill -TERM {pid} failed with status {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_pid_path_for_appends_dot_pid() {
        let p = pid_path_for(Path::new("/tmp/test.sock"));
        assert_eq!(p, PathBuf::from("/tmp/test.sock.pid"));
    }

    #[test]
    fn test_is_process_alive_current_process() {
        let pid = std::process::id();
        assert!(is_process_alive(pid), "current process must be alive");
    }

    #[test]
    fn test_is_process_alive_impossible_pid() {
        assert!(!is_process_alive(u32::MAX - 1));
    }

    #[test]
    fn test_acquire_creates_pid_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let _guard = PidFile::acquire(&sock).unwrap();

        let pid_path = pid_path_for(&sock);
        assert!(pid_path.exists());
        let content = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(content.trim(), std::process::id().to_string());
    }

    #[test]
    fn test_acquire_fails_if_already_locked() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let _guard = PidFile::acquire(&sock).unwrap();

        // Second acquire must fail because our PID is alive.
        let second = PidFile::acquire(&sock);
        assert!(second.is_err());
        if let Err(BridgeError::Config(msg)) = second {
            assert!(msg.contains("already running"));
        } else {
            panic!("expected Config error, got different variant");
        }
    }

    #[test]
    fn test_acquire_takes_over_stale_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let pid_path = pid_path_for(&sock);

        // Write a stale PID that's definitely not alive.
        std::fs::write(&pid_path, "999999999").unwrap();

        // acquire should remove the stale file and take over.
        let guard = PidFile::acquire(&sock).unwrap();

        let content = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(content.trim(), std::process::id().to_string());

        drop(guard);
    }

    #[test]
    fn test_drop_removes_pid_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let pid_path = pid_path_for(&sock);

        {
            let _guard = PidFile::acquire(&sock).unwrap();
            assert!(pid_path.exists());
        }
        // Guard dropped — file should be gone.
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_status_not_running_when_no_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("absent.sock");
        let status = PidFile::status(&sock).unwrap();
        assert_eq!(status, DaemonStatus::NotRunning);
    }

    #[test]
    fn test_status_running_when_pid_alive() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("running.sock");
        let _guard = PidFile::acquire(&sock).unwrap();
        let status = PidFile::status(&sock).unwrap();
        match status {
            DaemonStatus::Running { pid, socket } => {
                assert_eq!(pid, std::process::id());
                assert_eq!(socket, sock);
            }
            other => panic!("expected Running, got: {other:?}"),
        }
    }

    #[test]
    fn test_status_stale_when_pid_dead() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("stale.sock");
        let pid_path = pid_path_for(&sock);
        std::fs::write(&pid_path, "999999999").unwrap();

        let status = PidFile::status(&sock).unwrap();
        match status {
            DaemonStatus::Stale { pid } => assert_eq!(pid, 999_999_999),
            other => panic!("expected Stale, got: {other:?}"),
        }
    }

    #[test]
    fn test_stop_fails_when_no_pid_file() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("nofile.sock");
        assert!(PidFile::stop(&sock).is_err());
    }
}
