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
use crate::winrm::{ScriptShape, script_shape};

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
    /// streams captured, reads the script's exit code, closes the pool, and
    /// converts the result to [`CommandOutput`].
    ///
    /// # Errors
    ///
    /// Returns an error if the PSRP handshake or the script execution fails
    /// (a closing failure is logged and ignored).
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        self.run(command, None).await
    }

    /// Execute with cancellation token propagation.
    ///
    /// When a `CancellationToken` is provided (from MCP `notifications/cancelled`),
    /// the PSRP pipeline is run with `run_all_streams_with_cancel()` so the
    /// operation can be interrupted mid-flight.
    ///
    /// # Errors
    ///
    /// As [`Self::exec`].
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        _limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput> {
        self.run(command, token).await
    }

    /// The body of [`Self::exec`] and [`Self::exec_with_cancel`].
    async fn run(
        &mut self,
        command: &str,
        cancel: Option<CancellationToken>,
    ) -> Result<CommandOutput> {
        let start = Instant::now();

        // Logged as the adapter received it, before the pipeline below adds
        // the exit-code capture: the audit log, the history and the security
        // checks never see that line (nor the `Set-Location` a `working_dir`
        // adds upstream).
        debug!(
            host = %self.host_name,
            command = %command,
            cancellable = cancel.is_some(),
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

        let pipeline = command_pipeline(command);
        let result = match &cancel {
            None => pipeline.run_all_streams(&mut pool).await,
            Some(cancel) => {
                pipeline
                    .run_all_streams_with_cancel(&mut pool, cancel.clone())
                    .await
            }
        };

        // Only a completed script reached the line that records its exit
        // code; a failed or stopped one is an error below anyway.
        let exit_code = match &result {
            Ok(r) if matches!(r.state, psrp_rs::PipelineState::Completed) => {
                self.recorded_exit_code(&mut pool, cancel.as_ref()).await
            }
            _ => None,
        };

        // Close the pool (releases server-side runspace) before propagating a
        // pipeline error — `?` here used to skip the close, so every failing
        // command left a live runspace on the server. They accumulate until
        // `MaxShellsPerUser` (30 by default) and then every later Create
        // fails with `InternalError`, which looks like a broken host.
        //
        // The close itself is best-effort: the server may already have torn
        // the shell down after CommandState/Done, in which case Delete
        // answers `InvalidSelectors: the shell was not found`. Propagating
        // that discarded a pipeline that had already produced its output.
        if let Err(e) = pool.close().await {
            debug!(host = %self.host_name, error = %e, "PSRP pool close failed (ignored)");
        }
        let result = result?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(pipeline_result_to_command_output(
            &result,
            exit_code,
            duration_ms,
        ))
    }

    /// The exit code [`EXIT_CODE_CAPTURE`] recorded in the runspace, read by a
    /// second pipeline on the same pool (one runspace, so its global variables
    /// carry over).
    ///
    /// `None` when nothing was recorded (the script ended on its own `exit`,
    /// `return` or `break` before the capture line), or when the read failed,
    /// was cancelled through `cancel` or took longer than
    /// [`PROBE_TIME_LIMIT`]: the output is already collected, so the read
    /// never discards it, and the pool is closed after it either way.
    async fn recorded_exit_code(
        &self,
        pool: &mut psrp_rs::RunspacePool<psrp_rs::WinrmPsrpTransport<'_>>,
        cancel: Option<&CancellationToken>,
    ) -> Option<u32> {
        let stop = cancel.map_or_else(CancellationToken::new, CancellationToken::child_token);
        let probe = psrp_rs::Pipeline::new(EXIT_CODE_PROBE).run_with_cancel(pool, stop);
        match tokio::time::timeout(PROBE_TIME_LIMIT, probe).await {
            Ok(Ok(values)) => exit_code_from_probe(&values),
            Ok(Err(e)) => {
                debug!(host = %self.host_name, error = %e, "PSRP exit code read failed (ignored)");
                None
            }
            Err(_) => {
                debug!(host = %self.host_name, "PSRP exit code read timed out (ignored)");
                None
            }
        }
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

/// Appended to the caller's script: records in the runspace the exit code
/// the `WinRM` adapter's suffix gives `powershell.exe`.
///
/// A pipeline has no process exit code, so PSRP reported 0 for every script
/// that completed, `cmd /c exit 3` included. This line runs right after the
/// caller's last statement, so `$?` is that statement's: success gives 0; a
/// failure gives `$LASTEXITCODE` when a native program set a non-zero one
/// (the last native program's, as over `WinRM`), else 1. `$LASTEXITCODE` is
/// read through `Get-Variable`, which `Set-StrictMode` does not fault when no
/// native program has run. The blank line first ends a statement the caller
/// left on a trailing backtick.
const EXIT_CODE_CAPTURE: &str = "\n\nif ($?) { $global:__bridge_mcp_exit_code = 0 } \
     else { $__bridge_mcp_native = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction Ignore; \
     if ($__bridge_mcp_native -is [int] -and $__bridge_mcp_native -ne 0) { $global:__bridge_mcp_exit_code = $__bridge_mcp_native } \
     else { $global:__bridge_mcp_exit_code = 1 } }";

/// The second pipeline: outputs what [`EXIT_CODE_CAPTURE`] recorded, and
/// nothing, rather than a strict-mode error, when it recorded nothing.
const EXIT_CODE_PROBE: &str =
    "Get-Variable -Name __bridge_mcp_exit_code -Scope Global -ValueOnly -ErrorAction Ignore";

/// How long the second pipeline may take to read the exit code back: one
/// variable read on an idle runspace, so far longer than it needs.
const PROBE_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The pipeline that runs the caller's `command`.
///
/// Two commands: the script and `Out-String`, which formats everything the
/// script outputs as the console would, so PSRP output reads like
/// `SSH`/`WinRM` output. The script is the command then
/// [`EXIT_CODE_CAPTURE`], except for one with named blocks
/// ([`ScriptShape::NamedBlocks`]), which nothing may follow: it is sent as
/// written, records no exit code and reports 0 when it completes, as before. `Out-String` used to
/// be appended to the text (`{command} | Out-String`), which piped only the
/// last statement and made any script ending on a statement that cannot be
/// piped (`if`, `foreach`, `try`, `while`) a parse error: "An empty pipe
/// element is not allowed".
///
/// No UTF-8 switch as in the `WinRM` adapter: the PSRP server process has no
/// console, and setting `[Console]::OutputEncoding` there fails with "The
/// handle is invalid". `PowerShell`'s own strings travel as UTF-16 `CLIXML`
/// and arrive intact; a native program's non-ASCII output does not
/// (`cmd /c echo héllo-€` came back as "h‚llo-?" on Server 2012 R2 and 2025).
fn command_pipeline(command: &str) -> psrp_rs::Pipeline {
    let script = match script_shape(command) {
        ScriptShape::Plain | ScriptShape::Preamble => format!("{command}{EXIT_CODE_CAPTURE}"),
        ScriptShape::NamedBlocks => command.to_owned(),
    };
    psrp_rs::Pipeline::new(script).add_command(psrp_rs::Command::new("Out-String"))
}

/// The exit code in the probe's output, if it holds one.
///
/// An exit code outside `u32` (a negative `NTSTATUS` such as `-1073741819`)
/// becomes 1, as in the `WinRM` adapter.
fn exit_code_from_probe(values: &[psrp_rs::clixml::PsValue]) -> Option<u32> {
    match values.first()? {
        psrp_rs::clixml::PsValue::I32(n) => Some(u32::try_from(*n).unwrap_or(1)),
        psrp_rs::clixml::PsValue::I64(n) => Some(u32::try_from(*n).unwrap_or(1)),
        psrp_rs::clixml::PsValue::U32(n) => Some(*n),
        _ => None,
    }
}

/// Convert a PSRP `PipelineResult` (7 streams) to a bridge `CommandOutput`.
///
/// - **stdout**: output stream values joined by newlines
/// - **stderr**: error + warning messages joined by newlines
/// - **`exit_code`**: Completed gives the code the script recorded
///   ([`EXIT_CODE_CAPTURE`]), 0 when it recorded none; Failed gives 1 and
///   Stopped 2 (psrp-rs reports both as errors, so they are not reached
///   from `exec`)
fn pipeline_result_to_command_output(
    result: &psrp_rs::PipelineResult,
    recorded_exit_code: Option<u32>,
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
        psrp_rs::PipelineState::Completed => recorded_exit_code.unwrap_or(0),
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
        let output = pipeline_result_to_command_output(&result, None, 42);
        assert_eq!(output.stdout, "hello");
        assert_eq!(output.stderr, "");
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.duration_ms, 42);
    }

    #[test]
    fn test_pipeline_result_failed() {
        let result = psrp_rs::PipelineResult {
            state: psrp_rs::PipelineState::Failed,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, None, 0);
        assert_eq!(output.exit_code, 1);
    }

    #[test]
    fn test_pipeline_result_stopped() {
        let result = psrp_rs::PipelineResult {
            state: psrp_rs::PipelineState::Stopped,
            ..Default::default()
        };
        let output = pipeline_result_to_command_output(&result, None, 0);
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
        let output = pipeline_result_to_command_output(&result, None, 0);
        assert_eq!(output.stdout, "line1\nline2");
    }

    #[test]
    fn test_pipeline_result_completed_uses_the_recorded_exit_code() {
        let result = psrp_rs::PipelineResult {
            state: psrp_rs::PipelineState::Completed,
            ..Default::default()
        };
        assert_eq!(
            pipeline_result_to_command_output(&result, Some(3), 0).exit_code,
            3
        );
        assert_eq!(
            pipeline_result_to_command_output(&result, Some(0), 0).exit_code,
            0
        );
        // Nothing recorded (the script ended on its own `exit`): as before.
        assert_eq!(
            pipeline_result_to_command_output(&result, None, 0).exit_code,
            0
        );
    }

    #[test]
    fn test_pipeline_result_failed_or_stopped_ignore_a_recorded_code() {
        for (state, code) in [
            (psrp_rs::PipelineState::Failed, 1),
            (psrp_rs::PipelineState::Stopped, 2),
        ] {
            let result = psrp_rs::PipelineResult {
                state,
                ..Default::default()
            };
            assert_eq!(
                pipeline_result_to_command_output(&result, Some(3), 0).exit_code,
                code
            );
        }
    }

    #[test]
    fn test_exit_code_from_probe() {
        use psrp_rs::clixml::PsValue;
        assert_eq!(exit_code_from_probe(&[PsValue::I32(3)]), Some(3));
        assert_eq!(exit_code_from_probe(&[PsValue::I32(0)]), Some(0));
        assert_eq!(exit_code_from_probe(&[PsValue::I64(300)]), Some(300));
        assert_eq!(exit_code_from_probe(&[PsValue::U32(7)]), Some(7));
        // A negative NTSTATUS (access violation) is 1, as over WinRM.
        assert_eq!(
            exit_code_from_probe(&[PsValue::I32(-1_073_741_819)]),
            Some(1)
        );
        assert_eq!(exit_code_from_probe(&[PsValue::I64(i64::MAX)]), Some(1));
        // Nothing recorded.
        assert_eq!(exit_code_from_probe(&[]), None);
        assert_eq!(exit_code_from_probe(&[PsValue::Null]), None);
        assert_eq!(
            exit_code_from_probe(&[PsValue::String("3".to_string())]),
            None
        );
        // Only the first value counts.
        assert_eq!(
            exit_code_from_probe(&[PsValue::I32(4), PsValue::I32(5)]),
            Some(4)
        );
    }

    #[test]
    fn test_command_pipeline_pipes_the_whole_script_into_out_string() {
        let pipeline = command_pipeline("if ($true) { 1 }");
        // Two commands, not `… | Out-String` glued onto the text: a script
        // ending on `if`/`foreach` used to fail to parse.
        assert_eq!(pipeline.len(), 2);
        let xml = pipeline.__create_pipeline_xml_for_test();
        assert!(xml.contains("if ($true) { 1 }"), "{xml}");
        assert!(xml.contains("__bridge_mcp_exit_code"), "{xml}");
        assert!(xml.contains("Out-String"), "{xml}");
        assert!(!xml.contains("} | Out-String"), "{xml}");
    }

    #[test]
    fn test_command_pipeline_appends_the_capture_after_the_script() {
        // Plain and preamble scripts alike: the capture follows the caller's
        // text (before it, it would record 0 for every script; before a
        // `param` block, it would not parse).
        for command in [
            "Get-Date",
            "param($n = 1)\n$n",
            "using namespace System\n[Math]::Abs(-1)",
        ] {
            let xml = command_pipeline(command).__create_pipeline_xml_for_test();
            let script = xml
                .find(command)
                .unwrap_or_else(|| panic!("{command:?}: {xml}"));
            let capture = xml.find("__bridge_mcp_exit_code").unwrap();
            assert!(script < capture, "{command:?}: {xml}");
        }
    }

    #[test]
    fn test_command_pipeline_sends_named_blocks_as_written() {
        let command = "begin { $n = 0 }\nprocess { $n++ }\nend { $n }";
        let pipeline = command_pipeline(command);
        assert_eq!(pipeline.len(), 2);
        let xml = pipeline.__create_pipeline_xml_for_test();
        assert!(xml.contains("end { $n }"), "{xml}");
        // Nothing may follow named blocks.
        assert!(!xml.contains("__bridge_mcp_exit_code"), "{xml}");
        assert!(xml.contains("Out-String"), "{xml}");
    }

    #[test]
    fn test_exit_code_capture_records_the_powershell_exe_rule() {
        // Same decision as the WinRM suffix: `$?` of the caller's last
        // statement, then a native non-zero `$LASTEXITCODE`, else 1.
        assert!(
            EXIT_CODE_CAPTURE.starts_with("\n\nif ($?) { $global:__bridge_mcp_exit_code = 0 }")
        );
        assert!(EXIT_CODE_CAPTURE.contains(
            "$__bridge_mcp_native = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction Ignore;"
        ));
        assert!(EXIT_CODE_CAPTURE.contains(
            "if ($__bridge_mcp_native -is [int] -and $__bridge_mcp_native -ne 0) \
             { $global:__bridge_mcp_exit_code = $__bridge_mcp_native }"
        ));
        assert!(EXIT_CODE_CAPTURE.ends_with("else { $global:__bridge_mcp_exit_code = 1 } }"));
        // Never a bare read: `Set-StrictMode` faults it when no native
        // program has run, and the capture line then records nothing.
        assert!(!EXIT_CODE_CAPTURE.contains("$LASTEXITCODE"));
        assert_eq!(
            EXIT_CODE_PROBE,
            "Get-Variable -Name __bridge_mcp_exit_code -Scope Global -ValueOnly -ErrorAction Ignore"
        );
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
            ansible: None,
        }
    }
}
