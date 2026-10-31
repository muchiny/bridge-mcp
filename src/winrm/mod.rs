//! `WinRM` protocol adapter — Windows Remote Management.
//!
//! Wraps `winrm_rs::WinrmClient` for remote command execution on Windows
//! hosts via WS-Management (SOAP over HTTP/HTTPS, ports 5985/5986).
//!
//! Feature-gated behind `winrm`.

pub mod pool;

pub use pool::{WinRmPool, WinRmPoolConfig};

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Build a `winrm_rs::WinrmConfig` + `winrm_rs::WinrmCredentials` from a bridge `HostConfig`.
///
/// This is the canonical mapping from bridge config types to `winrm-rs` types and is
/// used by both the `WinRmPool` cold path and the PSRP adapter.
///
/// # TLS auto-detection
///
/// `winrm_use_tls` overrides TLS selection. When absent, TLS is auto-detected from
/// the port: port 5986 → TLS enabled, anything else → TLS disabled.
///
/// # Errors
///
/// Returns `BridgeError::ConfigInvalid` when `auth` is `Key` or `Agent` (SSH-only).
pub fn build_winrm_config(
    host_config: &HostConfig,
) -> Result<(winrm_rs::WinrmConfig, winrm_rs::WinrmCredentials)> {
    let use_tls = host_config
        .winrm_use_tls
        .unwrap_or(host_config.port == 5986);

    let mut winrm_cfg = winrm_rs::WinrmConfig {
        port: host_config.port,
        use_tls,
        accept_invalid_certs: host_config.winrm_accept_invalid_certs.unwrap_or(false),
        operation_timeout_secs: host_config.winrm_operation_timeout_secs.unwrap_or(60),
        max_envelope_size: host_config.winrm_max_envelope_size.unwrap_or(153_600),
        ..winrm_rs::WinrmConfig::default()
    };

    let credentials = match &host_config.auth {
        crate::config::AuthConfig::Password { password } => {
            winrm_cfg.auth_method = winrm_rs::AuthMethod::Basic;
            winrm_rs::WinrmCredentials::new(host_config.user.clone(), password.as_str(), "")
        }
        crate::config::AuthConfig::Ntlm { password, domain } => {
            winrm_cfg.auth_method = winrm_rs::AuthMethod::Ntlm;
            winrm_rs::WinrmCredentials::new(
                host_config.user.clone(),
                password.as_str(),
                domain.as_deref().unwrap_or(""),
            )
        }
        crate::config::AuthConfig::Certificate {
            cert_path,
            key_path,
        } => {
            winrm_cfg.auth_method = winrm_rs::AuthMethod::Certificate;
            winrm_cfg.client_cert_pem = Some(cert_path.clone());
            winrm_cfg.client_key_pem = Some(key_path.clone());
            winrm_rs::WinrmCredentials::new(host_config.user.clone(), "", "")
        }
        crate::config::AuthConfig::Kerberos => {
            winrm_cfg.auth_method = winrm_rs::AuthMethod::Kerberos;
            winrm_rs::WinrmCredentials::new(host_config.user.clone(), "", "")
        }
        crate::config::AuthConfig::Key { .. } => {
            return Err(BridgeError::ConfigInvalid {
                field: "auth".to_string(),
                reason: "SSH key authentication is not supported for WinRM; \
                         use password, ntlm, certificate, or kerberos"
                    .to_string(),
            });
        }
        crate::config::AuthConfig::Agent => {
            return Err(BridgeError::ConfigInvalid {
                field: "auth".to_string(),
                reason: "SSH agent authentication is not supported for WinRM; \
                         use password, ntlm, certificate, or kerberos"
                    .to_string(),
            });
        }
    };

    Ok((winrm_cfg, credentials))
}

/// What a cancellable run returns once the bridge's time limit stopped it.
///
/// The run's token is cancelled both by the client (through its parent token)
/// and by the time limit, so winrm-rs answers `Cancelled` either way; only a
/// stop the client did not ask for is a timeout. A run that finished, or
/// failed on its own, before the stop landed keeps its own result.
fn after_time_limit(
    result: std::result::Result<winrm_rs::CommandOutput, winrm_rs::WinrmError>,
    client_cancelled: bool,
    seconds: u64,
) -> Result<winrm_rs::CommandOutput> {
    match result {
        Err(winrm_rs::WinrmError::Cancelled) if !client_cancelled => {
            Err(BridgeError::SshTimeout { seconds })
        }
        other => other.map_err(BridgeError::from),
    }
}

/// An active `WinRM` connection wrapping `winrm_rs::WinrmClient`.
///
/// Unlike the previous implementation (hand-rolled SOAP with `cmd.exe /c`),
/// this adapter delegates to `winrm-rs` for proper WS-Man protocol handling,
/// `NTLMv2`/Kerberos/Certificate auth, and `PowerShell` execution via
/// `run_powershell()`.
pub struct WinRmConnection {
    client: Arc<winrm_rs::WinrmClient>,
    host_name: String,
    failed: bool,
}

impl WinRmConnection {
    /// Wrap a cached `WinrmClient` for a specific host.
    ///
    /// Used by `WinRmPool::get_connection()` to hand out connections
    /// backed by a pooled client without rebuilding the HTTP/TLS stack.
    #[must_use]
    pub fn from_parts(host_name: &str, client: Arc<winrm_rs::WinrmClient>) -> Self {
        Self {
            client,
            host_name: host_name.to_string(),
            failed: false,
        }
    }

    /// Execute a `PowerShell` command via `WinRM`.
    ///
    /// Uses `WinrmClient::run_powershell_with_timeout()`, which encodes the
    /// script as UTF-16LE base64 and runs it via
    /// `powershell.exe -EncodedCommand`. This correctly handles all
    /// `PowerShell` syntax — unlike the previous `cmd.exe /c` approach that
    /// broke on PS-specific commands.
    ///
    /// The command is bounded by `limits.command_timeout_seconds`, like an
    /// SSH command: since winrm-rs 1.3.0 a plain `run_powershell` has no
    /// overall time limit and would wait for a silent command forever. On
    /// expiry winrm-rs terminates the command and deletes the remote shell.
    ///
    /// # Errors
    ///
    /// Returns an error if the `WinRM` request fails (auth, timeout, SOAP fault).
    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        self.exec_with_cancel(command, limits, None).await
    }

    /// Execute with cancellation token propagation.
    ///
    /// When a `CancellationToken` is provided (from MCP `notifications/cancelled`),
    /// uses `WinrmClient::run_powershell_with_cancel()` so the operation can be
    /// interrupted mid-flight. With or without a token, the command is
    /// stopped once `limits.command_timeout_seconds` have elapsed; on either
    /// stop winrm-rs terminates the command and deletes the remote shell.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::SshTimeout` when the time limit is reached,
    /// `BridgeError::Cancelled` when the token is cancelled, and the mapped
    /// `WinRM` error when the request fails.
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
        token: Option<tokio_util::sync::CancellationToken>,
    ) -> Result<CommandOutput> {
        let start = Instant::now();
        let time_limit = Duration::from_secs(limits.command_timeout_seconds);

        debug!(
            host = %self.host_name,
            command = %command,
            cancellable = token.is_some(),
            "Executing WinRM PowerShell command"
        );

        // The winrm-rs futures are boxed: inlined, they put ~20 KB into every
        // future that awaits a connection (`clippy::large_futures`).
        let output = match token {
            None => {
                Box::pin(self.client.run_powershell_with_timeout(
                    &self.host_name,
                    command,
                    time_limit,
                ))
                .await?
            }
            Some(token) => {
                // winrm-rs has no call that takes both a token and a time
                // limit: a child token stops the command on either.
                let stop = token.child_token();
                let mut run = Box::pin(self.client.run_powershell_with_cancel(
                    &self.host_name,
                    command,
                    stop.clone(),
                ));
                tokio::select! {
                    result = &mut run => result?,
                    () = tokio::time::sleep(time_limit) => {
                        stop.cancel();
                        after_time_limit(
                            run.await,
                            token.is_cancelled(),
                            limits.command_timeout_seconds,
                        )?
                    }
                }
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: u32::try_from(output.exit_code).unwrap_or(1),
            duration_ms,
        })
    }

    /// Mark this connection as failed (triggers pool eviction on next lookup).
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Host name for logging/eviction.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_host_config() -> HostConfig {
        HostConfig {
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
            winrm_use_tls: None,
            winrm_accept_invalid_certs: None,
            winrm_operation_timeout_secs: None,
            winrm_max_envelope_size: None,
        }
    }

    #[test]
    fn test_build_winrm_config_password_basic() {
        let host = test_host_config();
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        assert_eq!(cfg.port, 5986);
        assert!(cfg.use_tls);
        assert!(!cfg.accept_invalid_certs);
        assert_eq!(cfg.operation_timeout_secs, 60);
        assert_eq!(cfg.max_envelope_size, 153_600);
        assert!(matches!(cfg.auth_method, winrm_rs::AuthMethod::Basic));
        assert_eq!(creds.username, "admin");
    }

    #[test]
    fn test_build_winrm_config_ntlm() {
        let mut host = test_host_config();
        host.auth = crate::config::AuthConfig::Ntlm {
            password: crate::config::RedactedSecret::from("secret"),
            domain: Some("CORP".to_string()),
        };
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        assert!(matches!(cfg.auth_method, winrm_rs::AuthMethod::Ntlm));
        assert_eq!(creds.domain, "CORP");
    }

    #[test]
    fn test_build_winrm_config_kerberos() {
        let mut host = test_host_config();
        host.auth = crate::config::AuthConfig::Kerberos;
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(matches!(cfg.auth_method, winrm_rs::AuthMethod::Kerberos));
    }

    #[test]
    fn test_build_winrm_config_certificate() {
        let mut host = test_host_config();
        host.auth = crate::config::AuthConfig::Certificate {
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
        };
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(matches!(cfg.auth_method, winrm_rs::AuthMethod::Certificate));
        assert_eq!(cfg.client_cert_pem, Some("/path/to/cert.pem".to_string()));
        assert_eq!(cfg.client_key_pem, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_build_winrm_config_rejects_ssh_key() {
        let mut host = test_host_config();
        host.auth = crate::config::AuthConfig::Key {
            path: "/path/to/key".to_string(),
            passphrase: None,
        };
        let result = build_winrm_config(&host);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not supported for WinRM")
        );
    }

    #[test]
    fn test_build_winrm_config_rejects_agent() {
        let mut host = test_host_config();
        host.auth = crate::config::AuthConfig::Agent;
        let result = build_winrm_config(&host);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_winrm_config_tls_auto_detect() {
        let mut host = test_host_config();
        host.port = 5985;
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(!cfg.use_tls);

        host.port = 5986;
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(cfg.use_tls);
    }

    #[test]
    fn test_build_winrm_config_tls_override() {
        let mut host = test_host_config();
        host.port = 5985;
        host.winrm_use_tls = Some(true); // Force TLS on HTTP port
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(cfg.use_tls);
    }

    #[test]
    fn test_build_winrm_config_custom_options() {
        let mut host = test_host_config();
        host.winrm_accept_invalid_certs = Some(true);
        host.winrm_operation_timeout_secs = Some(120);
        host.winrm_max_envelope_size = Some(500_000);
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(cfg.accept_invalid_certs);
        assert_eq!(cfg.operation_timeout_secs, 120);
        assert_eq!(cfg.max_envelope_size, 500_000);
    }

    #[test]
    fn test_from_parts_creates_connection() {
        let host = test_host_config();
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        let client = Arc::new(winrm_rs::WinrmClient::new(cfg, creds).unwrap());
        let conn = WinRmConnection::from_parts("test-host", client);
        assert_eq!(conn.host_name(), "test-host");
        assert!(!conn.failed);
    }

    /// A `WinRM` endpoint that accepts the TCP connection and never answers,
    /// the shape of a host whose command never returns. Since winrm-rs 1.3.0
    /// `run_powershell` has no overall time limit, so only the bridge's own
    /// `command_timeout_seconds` can end such a call. The listener must be
    /// kept alive for as long as the connection is used.
    async fn silent_endpoint() -> (tokio::net::TcpListener, WinRmConnection) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut host = test_host_config();
        host.hostname = "127.0.0.1".to_string();
        host.port = listener.local_addr().unwrap().port();
        host.winrm_use_tls = Some(false);
        // Bounds winrm-rs' clean-up after the stop, so the test stays short.
        host.winrm_operation_timeout_secs = Some(1);
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        let client = Arc::new(winrm_rs::WinrmClient::new(cfg, creds).unwrap());
        (
            listener,
            WinRmConnection::from_parts(&host.hostname, client),
        )
    }

    fn one_second_limit() -> LimitsConfig {
        LimitsConfig {
            command_timeout_seconds: 1,
            ..LimitsConfig::default()
        }
    }

    fn finished_output() -> winrm_rs::CommandOutput {
        winrm_rs::CommandOutput {
            stdout: b"done".to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
        }
    }

    #[test]
    fn after_time_limit_reports_its_own_stop_as_a_timeout() {
        let result = after_time_limit(Err(winrm_rs::WinrmError::Cancelled), false, 7);
        assert!(
            matches!(result, Err(BridgeError::SshTimeout { seconds: 7 })),
            "{result:?}"
        );
    }

    #[test]
    fn after_time_limit_keeps_a_client_cancellation() {
        let result = after_time_limit(Err(winrm_rs::WinrmError::Cancelled), true, 7);
        assert!(matches!(result, Err(BridgeError::Cancelled)), "{result:?}");
    }

    #[test]
    fn after_time_limit_returns_output_that_beat_the_stop() {
        let output = after_time_limit(Ok(finished_output()), false, 7).unwrap();
        assert_eq!(output.stdout, b"done");
    }

    #[test]
    fn after_time_limit_maps_a_failure_of_the_command_itself() {
        let result = after_time_limit(
            Err(winrm_rs::WinrmError::AuthFailed("denied".to_string())),
            false,
            7,
        );
        assert!(
            matches!(result, Err(BridgeError::SshAuth { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn exec_stops_at_command_timeout_when_the_host_never_answers() {
        let (_listener, mut conn) = silent_endpoint().await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            conn.exec("Start-Sleep 3600", &one_second_limit()),
        )
        .await
        .expect("exec ignored limits.command_timeout_seconds");

        assert!(
            matches!(result, Err(BridgeError::SshTimeout { seconds: 1 })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn exec_with_cancel_stops_at_command_timeout_when_never_cancelled() {
        let (_listener, mut conn) = silent_endpoint().await;
        let token = tokio_util::sync::CancellationToken::new();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            conn.exec_with_cancel("Start-Sleep 3600", &one_second_limit(), Some(token)),
        )
        .await
        .expect("exec_with_cancel ignored limits.command_timeout_seconds");

        assert!(
            matches!(result, Err(BridgeError::SshTimeout { seconds: 1 })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn exec_with_cancel_reports_a_client_cancellation_as_cancelled() {
        let (_listener, mut conn) = silent_endpoint().await;
        let token = tokio_util::sync::CancellationToken::new();
        let canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            canceller.cancel();
        });
        let limits = LimitsConfig {
            command_timeout_seconds: 60,
            ..LimitsConfig::default()
        };

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            conn.exec_with_cancel("Start-Sleep 3600", &limits, Some(token)),
        )
        .await
        .expect("exec_with_cancel ignored the cancellation");

        assert!(matches!(result, Err(BridgeError::Cancelled)), "{result:?}");
    }

    #[test]
    fn test_mark_failed() {
        let host = test_host_config();
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        let client = Arc::new(winrm_rs::WinrmClient::new(cfg, creds).unwrap());
        let mut conn = WinRmConnection::from_parts("test-host", client);
        assert!(!conn.failed);
        conn.mark_failed();
        assert!(conn.failed);
    }
}
