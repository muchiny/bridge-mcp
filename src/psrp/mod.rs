//! PSRP (`PowerShell` Remoting Protocol) adapter.
//!
//! Wraps `psrp_rs::RunspacePool` to provide native `PowerShell` execution
//! over `WinRM` transport. Returns typed `PsValue` objects converted to
//! [`CommandOutput`] for compatibility with the standard tool pipeline.
//!
//! # Lifetime constraint
//!
//! `WinrmPsrpTransport<'c>` borrows `&'c WinrmClient`, making
//! `RunspacePool<WinrmPsrpTransport<'c>>` non-`'static` and uncacheable
//! in a `HashMap`. This V1 implementation works around the constraint by
//! caching the `WinrmClient` (avoids TLS/auth per call) and creating a
//! fresh `RunspacePool` per `exec()` call (~150-300 ms overhead).
//!
//! A future optimization can use a task-based architecture where a
//! long-lived tokio task owns both the client and pool, communicating
//! via channels for true session reuse with zero per-call overhead.

pub mod pool;

use std::sync::Arc;
use std::time::Instant;

use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::config::LimitsConfig;
use crate::error::Result;
use crate::ssh::CommandOutput;

/// An active PSRP connection backed by a cached `WinrmClient`.
///
/// Each `exec()` call opens a scoped `RunspacePool`, runs the script,
/// and closes the pool. The `WinrmClient` is reused across calls
/// (cached by `PsrpPool`), avoiding TLS handshake overhead.
pub struct PsrpConnection {
    client: Arc<winrm_rs::WinrmClient>,
    host_name: String,
    failed: bool,
}

impl PsrpConnection {
    /// Wrap a cached `WinrmClient` for PSRP execution.
    #[must_use]
    pub fn from_parts(host_name: &str, client: Arc<winrm_rs::WinrmClient>) -> Self {
        Self {
            client,
            host_name: host_name.to_string(),
            failed: false,
        }
    }

    /// Execute a `PowerShell` script via PSRP.
    ///
    /// Opens a scoped `RunspacePool`, runs the script with all 7 PS
    /// streams captured, closes the pool, and converts the result to
    /// [`CommandOutput`].
    ///
    /// # Errors
    ///
    /// Returns an error if the PSRP handshake, script execution, or
    /// pool close fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            command = %command,
            "Executing PSRP command"
        );

        // Build PSRP creation fragments (static, no network)
        let (rpid, creation) =
            psrp_rs::RunspacePool::<psrp_rs::WinrmPsrpTransport<'_>>::build_creation_fragments(
                1, 1,
            )?;

        // Open transport (borrows &self.client — scoped to this function)
        let transport =
            psrp_rs::WinrmPsrpTransport::open(&self.client, &self.host_name, &creation).await?;

        // Open RunspacePool from transport
        let mut pool = psrp_rs::RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;

        // Wrap command with Out-String to force text output, making PSRP
        // output identical to SSH/WinRM. Without this, PSRP returns typed
        // PsValue objects whose string representation may differ from the
        // formatted text that handlers expect to parse.
        let wrapped = format!("{command} | Out-String");

        // Run the PowerShell script with all 7 streams
        let result = psrp_rs::Pipeline::new(&wrapped)
            .run_all_streams(&mut pool)
            .await?;

        // Close the pool (releases server-side runspace)
        pool.close().await?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(pipeline_result_to_command_output(&result, duration_ms))
    }

    /// Execute with cancellation token propagation.
    ///
    /// When a `CancellationToken` is provided (from MCP `notifications/cancelled`),
    /// the PSRP pipeline is run with `run_all_streams_with_cancel()` so the
    /// operation can be interrupted mid-flight.
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput> {
        let Some(cancel) = token else {
            return self.exec(command, limits).await;
        };

        let start = Instant::now();

        debug!(
            host = %self.host_name,
            command = %command,
            "Executing PSRP command (with cancel)"
        );

        let (rpid, creation) =
            psrp_rs::RunspacePool::<psrp_rs::WinrmPsrpTransport<'_>>::build_creation_fragments(
                1, 1,
            )?;

        let transport =
            psrp_rs::WinrmPsrpTransport::open(&self.client, &self.host_name, &creation).await?;

        let mut pool = psrp_rs::RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;

        let wrapped = format!("{command} | Out-String");

        let result = psrp_rs::Pipeline::new(&wrapped)
            .run_all_streams_with_cancel(&mut pool, cancel)
            .await?;

        pool.close().await?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(pipeline_result_to_command_output(&result, duration_ms))
    }

    /// Mark connection as failed (triggers pool eviction on next lookup).
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Host name for logging/eviction.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }
}

/// Convert a PSRP `PipelineResult` (7 streams) to a bridge `CommandOutput`.
///
/// - **stdout**: output stream values joined by newlines
/// - **stderr**: error + warning messages joined by newlines
/// - **`exit_code`**: 0 = Completed, 1 = Failed, 2 = Stopped
fn pipeline_result_to_command_output(
    result: &psrp_rs::PipelineResult,
    duration_ms: u64,
) -> CommandOutput {
    let stdout = result
        .output
        .iter()
        .map(psvalue_to_string)
        .collect::<Vec<_>>()
        .join("\n");

    let mut stderr_parts = Vec::new();
    for err in &result.typed_errors() {
        let msg = err
            .exception
            .as_ref()
            .and_then(|e| e.message.as_deref())
            .unwrap_or("(unknown error)");
        stderr_parts.push(format!("ERROR: {msg}"));
    }
    for warn in &result.typed_warnings() {
        stderr_parts.push(format!("WARNING: {}", warn.message));
    }

    let exit_code = match result.state {
        psrp_rs::PipelineState::Completed => 0,
        psrp_rs::PipelineState::Stopped => 2,
        _ => 1, // Failed, Running, NotStarted, etc.
    };

    CommandOutput {
        stdout,
        stderr: stderr_parts.join("\n"),
        exit_code,
        duration_ms,
    }
}

/// Convert a `PsValue` to a human-readable string.
///
/// `PsValue` does not implement `Display`. Strategy:
/// - String-like types: use `as_str()`
/// - Objects with `to_string`: use that
/// - Null: empty string
/// - Everything else: `Debug` formatting
fn psvalue_to_string(v: &psrp_rs::clixml::PsValue) -> String {
    if let Some(s) = v.as_str() {
        return s.to_string();
    }
    match v {
        psrp_rs::clixml::PsValue::Null => String::new(),
        psrp_rs::clixml::PsValue::Bool(b) => b.to_string(),
        psrp_rs::clixml::PsValue::I32(n) => n.to_string(),
        psrp_rs::clixml::PsValue::I64(n) => n.to_string(),
        psrp_rs::clixml::PsValue::Double(f) => f.to_string(),
        psrp_rs::clixml::PsValue::Object(obj) => obj.to_string.as_deref().unwrap_or("").to_string(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_parts_creates_connection() {
        let host = test_host_config();
        let (cfg, creds) = crate::winrm::build_winrm_config(&host).unwrap();
        let client = Arc::new(winrm_rs::WinrmClient::new(cfg, creds).unwrap());
        let conn = PsrpConnection::from_parts("test-host", client);
        assert_eq!(conn.host_name(), "test-host");
        assert!(!conn.failed);
    }

    #[test]
    fn test_mark_failed() {
        let host = test_host_config();
        let (cfg, creds) = crate::winrm::build_winrm_config(&host).unwrap();
        let client = Arc::new(winrm_rs::WinrmClient::new(cfg, creds).unwrap());
        let mut conn = PsrpConnection::from_parts("test-host", client);
        conn.mark_failed();
        assert!(conn.failed);
    }

    #[test]
    fn test_pipeline_result_completed() {
        let result = psrp_rs::PipelineResult {
            output: vec![psrp_rs::clixml::PsValue::String("hello".to_string())],
            state: psrp_rs::PipelineState::Completed,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, 42);
        assert_eq!(output.stdout, "hello");
        assert!(output.stderr.is_empty());
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.duration_ms, 42);
    }

    #[test]
    fn test_pipeline_result_failed() {
        let result = psrp_rs::PipelineResult {
            state: psrp_rs::PipelineState::Failed,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, 0);
        assert_eq!(output.exit_code, 1);
    }

    #[test]
    fn test_pipeline_result_stopped() {
        let result = psrp_rs::PipelineResult {
            state: psrp_rs::PipelineState::Stopped,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, 0);
        assert_eq!(output.exit_code, 2);
    }

    #[test]
    fn test_pipeline_result_multi_output() {
        let result = psrp_rs::PipelineResult {
            output: vec![
                psrp_rs::clixml::PsValue::String("line1".to_string()),
                psrp_rs::clixml::PsValue::String("line2".to_string()),
            ],
            state: psrp_rs::PipelineState::Completed,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, 0);
        assert_eq!(output.stdout, "line1\nline2");
    }

    #[test]
    fn test_psvalue_to_string_variants() {
        assert_eq!(psvalue_to_string(&psrp_rs::clixml::PsValue::Null), "");
        assert_eq!(
            psvalue_to_string(&psrp_rs::clixml::PsValue::String("hi".to_string())),
            "hi"
        );
        assert_eq!(psvalue_to_string(&psrp_rs::clixml::PsValue::I32(42)), "42");
        assert_eq!(
            psvalue_to_string(&psrp_rs::clixml::PsValue::Bool(true)),
            "true"
        );
        assert_eq!(
            psvalue_to_string(&psrp_rs::clixml::PsValue::Double(99.5)),
            "99.5"
        );
    }

    fn test_host_config() -> crate::config::HostConfig {
        crate::config::HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 5986,
            user: "admin".to_string(),
            auth: crate::config::AuthConfig::Password {
                password: crate::config::RedactedSecret::from("pass"),
            },
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
            #[cfg(feature = "winrm")]
            winrm_use_tls: None,
            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,
            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,
            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        }
    }
}
