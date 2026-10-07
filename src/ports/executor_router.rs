//! Executor Router — Protocol-aware dispatcher
//!
//! `ExecutorRouter` wraps the SSH `ConnectionPool` and dispatches connections
//! based on the `protocol` field in each host's configuration. Non-SSH
//! protocol adapters (`WinRM`, Telnet, K8s, Serial, SSM, Azure, GCP) are feature-gated.
//!
//! The router exposes the same public API as `ConnectionPool`, enabling a
//! clean cut-over in `ToolContext` without changing any of the tool handlers.

use crate::config::{HostConfig, LimitsConfig, Protocol};
use crate::error::Result;
use crate::ssh::{CommandOutput, ConnectionPool, PoolConfig, PoolStats, PooledConnectionGuard};

/// Protocol-aware connection router.
///
/// Holds one connection pool per protocol backend. For SSH hosts (the default),
/// connections are delegated to the inner `ConnectionPool`. Non-SSH adapters
/// create standalone connections behind feature flags.
#[allow(clippy::struct_field_names)]
pub struct ExecutorRouter {
    ssh_pool: ConnectionPool,
    /// Reqwest HTTPS client cache for `WinRM` hosts (Sprint 3 Phase B.4).
    #[cfg(feature = "winrm")]
    winrm_pool: crate::winrm::WinRmPool,
    /// `kube::Client` cache for K8s Exec hosts (Sprint 3 Phase B.5).
    #[cfg(feature = "k8s-exec")]
    k8s_exec_pool: crate::k8s_exec::K8sExecPool,
    /// PSRP `RunspacePool` cache for PSRP hosts.
    #[cfg(feature = "psrp")]
    psrp_pool: crate::psrp::pool::PsrpPool,
    /// Mock output for testing — when set, `get_connection_with_jump` returns
    /// a `ConnectionGuard::Mock` that returns this output instead of connecting.
    #[cfg(test)]
    mock_output: Option<CommandOutput>,
    /// Mock `exec()` delay for cancellation tests. Only meaningful when
    /// `mock_output` is also set.
    #[cfg(test)]
    mock_delay: Option<std::time::Duration>,
    /// Every `exec` / `exec_with_stdin` the mock connections served, in
    /// order. Lets a test observe what actually reached the channel.
    #[cfg(test)]
    mock_calls: MockCalls,
}

impl ExecutorRouter {
    /// Create a router with default pool configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            ssh_pool: ConnectionPool::with_defaults(),
            #[cfg(feature = "winrm")]
            winrm_pool: crate::winrm::WinRmPool::new(),
            #[cfg(feature = "k8s-exec")]
            k8s_exec_pool: crate::k8s_exec::K8sExecPool::new(),
            #[cfg(feature = "psrp")]
            psrp_pool: crate::psrp::pool::PsrpPool::new(),
            #[cfg(test)]
            mock_output: None,
            #[cfg(test)]
            mock_delay: None,
            #[cfg(test)]
            mock_calls: MockCalls::default(),
        }
    }

    /// Create a router with a custom SSH pool configuration.
    #[must_use]
    pub fn new(ssh_pool_config: PoolConfig) -> Self {
        Self {
            ssh_pool: ConnectionPool::new(ssh_pool_config),
            #[cfg(feature = "winrm")]
            winrm_pool: crate::winrm::WinRmPool::new(),
            #[cfg(feature = "k8s-exec")]
            k8s_exec_pool: crate::k8s_exec::K8sExecPool::new(),
            #[cfg(feature = "psrp")]
            psrp_pool: crate::psrp::pool::PsrpPool::new(),
            #[cfg(test)]
            mock_output: None,
            #[cfg(test)]
            mock_delay: None,
            #[cfg(test)]
            mock_calls: MockCalls::default(),
        }
    }

    /// Get or create a connection to the specified host.
    ///
    /// Dispatches to the appropriate protocol backend based on
    /// `host_config.protocol`.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<ConnectionGuard<'_>> {
        self.get_connection_with_jump(host_name, host_config, limits, None)
            .await
    }

    /// Get or create a connection, optionally via a jump host.
    ///
    /// This is the primary entry point used by tool handlers. It dispatches
    /// to the correct protocol adapter based on `host_config.protocol`.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    #[allow(clippy::too_many_lines)]
    pub async fn get_connection_with_jump(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        jump_host: Option<(&str, &HostConfig)>,
    ) -> Result<ConnectionGuard<'_>> {
        // Test-only: return mock connection if configured
        #[cfg(test)]
        if let Some(ref output) = self.mock_output {
            let conn = match self.mock_delay {
                Some(delay) => MockConnection::new_with_delay(output.clone(), delay),
                None => MockConnection::new(output.clone()),
            }
            .with_calls(self.mock_calls.clone());
            return Ok(ConnectionGuard::Mock(conn));
        }

        match host_config.protocol {
            Protocol::Ssh => {
                let guard = self
                    .ssh_pool
                    .get_connection_with_jump(host_name, host_config, limits, jump_host)
                    .await?;
                Ok(ConnectionGuard::Ssh(guard))
            }
            #[cfg(feature = "winrm")]
            Protocol::WinRm => {
                let conn = self
                    .winrm_pool
                    .get_connection(host_name, host_config, limits)
                    .await?;
                Ok(ConnectionGuard::WinRm(conn))
            }
            #[cfg(feature = "telnet")]
            Protocol::Telnet => {
                let conn = crate::telnet::TelnetConnection::connect(host_name, host_config, limits)
                    .await?;
                Ok(ConnectionGuard::Telnet(conn))
            }
            #[cfg(feature = "k8s-exec")]
            Protocol::K8sExec => {
                let conn = self
                    .k8s_exec_pool
                    .get_connection(host_name, host_config, limits)
                    .await?;
                Ok(ConnectionGuard::K8sExec(conn))
            }
            #[cfg(feature = "serial")]
            Protocol::Serial => {
                let conn =
                    crate::serial_port::SerialConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::Serial(conn))
            }
            #[cfg(feature = "ssm")]
            Protocol::Ssm => {
                let conn =
                    crate::ssm::SsmConnection::connect(host_name, host_config, limits).await?;
                Ok(ConnectionGuard::Ssm(conn))
            }
            #[cfg(feature = "azure")]
            Protocol::Azure => {
                let conn = crate::cloud_exec::azure::AzureRunConnection::connect(
                    host_name,
                    host_config,
                    limits,
                )
                .await?;
                Ok(ConnectionGuard::Azure(conn))
            }
            #[cfg(feature = "gcp")]
            Protocol::Gcp => {
                let conn = crate::cloud_exec::gcp::GcpRunConnection::connect(
                    host_name,
                    host_config,
                    limits,
                )
                .await?;
                Ok(ConnectionGuard::Gcp(conn))
            }
            #[cfg(feature = "psrp")]
            Protocol::Psrp => {
                let conn = self
                    .psrp_pool
                    .get_connection(host_name, host_config, limits)
                    .await?;
                Ok(ConnectionGuard::Psrp(conn))
            }
        }
    }

    /// Clean up idle and expired connections across all protocol pools.
    pub async fn cleanup(&self) {
        self.ssh_pool.cleanup().await;
        #[cfg(feature = "winrm")]
        self.winrm_pool.cleanup().await;
        #[cfg(feature = "k8s-exec")]
        self.k8s_exec_pool.cleanup().await;
        #[cfg(feature = "psrp")]
        self.psrp_pool.cleanup().await;
    }

    /// Get statistics for the SSH connection pool.
    #[must_use = "pool stats should be used for monitoring or logging"]
    pub async fn stats(&self) -> PoolStats {
        self.ssh_pool.stats().await
    }

    /// Actively check all pooled connections and remove dead ones.
    pub async fn health_check(&self) {
        self.ssh_pool.health_check().await;
    }

    /// Close all connections across all protocol pools.
    pub async fn close_all(&self) {
        self.ssh_pool.close_all().await;
        #[cfg(feature = "winrm")]
        self.winrm_pool.close_all().await;
        #[cfg(feature = "k8s-exec")]
        self.k8s_exec_pool.close_all().await;
        #[cfg(feature = "psrp")]
        self.psrp_pool.close_all().await;
    }
}

/// Unified connection guard for all supported protocols.
///
/// Each tool handler calls `conn.exec(command, limits)` and
/// `conn.mark_failed()` — this enum dispatches to the correct
/// protocol adapter transparently.
#[allow(clippy::large_enum_variant)]
pub enum ConnectionGuard<'a> {
    /// SSH connection (pooled, returned to pool on drop).
    Ssh(PooledConnectionGuard<'a>),
    /// Mock connection for testing (returns pre-configured output).
    #[cfg(test)]
    Mock(MockConnection),
    /// `WinRM` connection (HTTP/SOAP, stateless).
    #[cfg(feature = "winrm")]
    WinRm(crate::winrm::WinRmConnection),
    /// Telnet connection (persistent TCP session).
    #[cfg(feature = "telnet")]
    Telnet(crate::telnet::TelnetConnection),
    /// Kubernetes Exec (direct K8s API pod exec).
    #[cfg(feature = "k8s-exec")]
    K8sExec(crate::k8s_exec::K8sExecConnection),
    /// Serial port (RS-232/USB).
    #[cfg(feature = "serial")]
    Serial(crate::serial_port::SerialConnection),
    /// AWS SSM (Systems Manager `SendCommand`).
    #[cfg(feature = "ssm")]
    Ssm(crate::ssm::SsmConnection),
    /// Azure Run Command (REST API).
    #[cfg(feature = "azure")]
    Azure(crate::cloud_exec::azure::AzureRunConnection),
    /// GCP OS Command (`gcloud` CLI).
    #[cfg(feature = "gcp")]
    Gcp(crate::cloud_exec::gcp::GcpRunConnection),
    /// PSRP (`PowerShell` Remoting Protocol over `WinRM` transport).
    #[cfg(feature = "psrp")]
    Psrp(crate::psrp::PsrpConnection),
}

/// Callers gate on `HostConfig::sudo_password_for_exec`, so this is a backstop.
/// The message must not contain "connection": `is_retryable_error` treats that
/// substring in an `SshExec` reason as transient, and this refusal is not.
///
/// Non-SSH protocols have no channel to write a stdin to; refuse rather than
/// drop the bytes (the only use is a POSIX `sudo -S` password).
#[cfg(any(
    feature = "winrm",
    feature = "telnet",
    feature = "k8s-exec",
    feature = "serial",
    feature = "ssm",
    feature = "azure",
    feature = "gcp",
    feature = "psrp"
))]
fn reject_stdin(stdin: Option<&[u8]>) -> Result<()> {
    if stdin.is_some() {
        return Err(crate::error::BridgeError::SshExec {
            reason: crate::error::STDIN_NOT_SSH_REASON.to_string(),
        });
    }
    Ok(())
}

impl ConnectionGuard<'_> {
    /// Execute a command using this connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails.
    ///
    /// # Panics
    ///
    /// Panics if the SSH connection has already been taken.
    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        match self {
            Self::Ssh(guard) => guard.exec(command, limits).await,
            #[cfg(test)]
            Self::Mock(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "winrm")]
            Self::WinRm(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "telnet")]
            Self::Telnet(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "k8s-exec")]
            Self::K8sExec(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "serial")]
            Self::Serial(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "ssm")]
            Self::Ssm(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "azure")]
            Self::Azure(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "gcp")]
            Self::Gcp(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "psrp")]
            Self::Psrp(conn) => conn.exec(command, limits).await,
        }
    }

    /// Execute a command, feeding `stdin` to the remote process over the
    /// channel rather than through the command text.
    ///
    /// **`stdin` carries the sudo password and nothing else.** It must never
    /// be reached by caller-supplied bytes: command validation (whitelist and
    /// blacklist) inspects only the command text, so anything delivered here
    /// bypasses it by construction. A tool that exposed stdin to callers would
    /// let `bash` read a script from it and defeat the blacklist. Do not
    /// generalize this parameter without validating what it carries.
    ///
    /// Only SSH has a channel to write to. With `stdin: None` every protocol
    /// behaves exactly like [`Self::exec`]; with `Some`, every non-SSH
    /// protocol returns an error rather than silently dropping the bytes
    /// (the one use is a POSIX `sudo -S` password, which means nothing
    /// there). The test-only mock records `stdin` (see `ExecutorRouter::mock_calls`).
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails, or if `stdin` is
    /// `Some` on a non-SSH connection.
    pub async fn exec_with_stdin(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        limits: &LimitsConfig,
    ) -> Result<CommandOutput> {
        match self {
            Self::Ssh(guard) => guard.exec_with_stdin(command, stdin, limits).await,
            #[cfg(test)]
            Self::Mock(conn) => conn.exec_with_stdin(command, stdin, limits).await,
            #[cfg(feature = "winrm")]
            Self::WinRm(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "telnet")]
            Self::Telnet(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "k8s-exec")]
            Self::K8sExec(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "serial")]
            Self::Serial(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "ssm")]
            Self::Ssm(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "azure")]
            Self::Azure(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "gcp")]
            Self::Gcp(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
            #[cfg(feature = "psrp")]
            Self::Psrp(conn) => {
                reject_stdin(stdin)?;
                conn.exec(command, limits).await
            }
        }
    }

    /// Mark this connection as failed (won't be returned to pool).
    pub fn mark_failed(&mut self) {
        match self {
            Self::Ssh(guard) => guard.mark_failed(),
            #[cfg(test)]
            Self::Mock(conn) => conn.mark_failed(),
            #[cfg(feature = "winrm")]
            Self::WinRm(conn) => conn.mark_failed(),
            #[cfg(feature = "telnet")]
            Self::Telnet(conn) => conn.mark_failed(),
            #[cfg(feature = "k8s-exec")]
            Self::K8sExec(conn) => conn.mark_failed(),
            #[cfg(feature = "serial")]
            Self::Serial(conn) => conn.mark_failed(),
            #[cfg(feature = "ssm")]
            Self::Ssm(conn) => conn.mark_failed(),
            #[cfg(feature = "azure")]
            Self::Azure(conn) => conn.mark_failed(),
            #[cfg(feature = "gcp")]
            Self::Gcp(conn) => conn.mark_failed(),
            #[cfg(feature = "psrp")]
            Self::Psrp(conn) => conn.mark_failed(),
        }
    }
}

// ============================================================================
// Test-only mock infrastructure
// ============================================================================

/// Mock connection that returns pre-configured output for testing.
///
/// Used by `ExecutorRouter::mock()` to enable full pipeline testing
/// of `StandardToolHandler` without real SSH connections.
#[cfg(test)]
pub struct MockConnection {
    output: CommandOutput,
    failed: bool,
    /// Optional delay before `exec()` returns. Used by cancellation tests
    /// to simulate a long-running command that can be interrupted by a
    /// `CancellationToken` racing against it in a `tokio::select!`.
    delay: Option<std::time::Duration>,
    /// Shared with the router that made this connection.
    calls: MockCalls,
}

/// `(command, stdin)` for every call a mock connection served.
#[cfg(test)]
type MockCalls = std::sync::Arc<std::sync::Mutex<Vec<(String, Option<Vec<u8>>)>>>;

#[cfg(test)]
impl MockConnection {
    /// Record into `calls` instead of a private log.
    #[must_use]
    fn with_calls(mut self, calls: MockCalls) -> Self {
        self.calls = calls;
        self
    }

    /// Create a mock connection that returns the given output immediately.
    #[must_use]
    pub fn new(output: CommandOutput) -> Self {
        Self {
            output,
            failed: false,
            delay: None,
            calls: MockCalls::default(),
        }
    }

    /// Create a mock connection that sleeps `delay` before returning.
    ///
    /// Useful for cancellation tests: the mock blocks inside `exec().await`
    /// long enough that a concurrent `cancel_request()` can fire and the
    /// outer `tokio::select!` can observe it.
    #[must_use]
    pub fn new_with_delay(output: CommandOutput, delay: std::time::Duration) -> Self {
        Self {
            output,
            failed: false,
            delay: Some(delay),
            calls: MockCalls::default(),
        }
    }

    /// Execute returns the pre-configured output, optionally after a delay.
    pub async fn exec(&self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        self.exec_with_stdin(command, None, limits).await
    }

    /// Like [`Self::exec`], recording the command and the stdin it was given.
    pub async fn exec_with_stdin(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
        _limits: &LimitsConfig,
    ) -> Result<CommandOutput> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((command.to_string(), stdin.map(<[u8]>::to_vec)));
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        Ok(self.output.clone())
    }

    /// Mark this mock as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }
}

#[cfg(test)]
impl ExecutorRouter {
    /// Create a mock router that returns pre-configured output for any host.
    ///
    /// The mock router bypasses real SSH connections, enabling full pipeline
    /// testing of `StandardToolHandler` steps 7-18.
    #[must_use]
    pub fn mock(output: CommandOutput) -> Self {
        Self {
            ssh_pool: ConnectionPool::with_defaults(),
            #[cfg(feature = "winrm")]
            winrm_pool: crate::winrm::WinRmPool::new(),
            #[cfg(feature = "k8s-exec")]
            k8s_exec_pool: crate::k8s_exec::K8sExecPool::new(),
            #[cfg(feature = "psrp")]
            psrp_pool: crate::psrp::pool::PsrpPool::new(),
            mock_output: Some(output),
            mock_delay: None,
            mock_calls: MockCalls::default(),
        }
    }

    /// Create a mock router whose `exec()` blocks for the given duration
    /// before returning.
    ///
    /// Used by cancellation tests to prove that a `CancellationToken` racing
    /// the `exec().await` inside `StandardToolHandler` actually interrupts
    /// the in-flight command.
    #[must_use]
    pub fn mock_with_delay(output: CommandOutput, delay: std::time::Duration) -> Self {
        Self {
            ssh_pool: ConnectionPool::with_defaults(),
            #[cfg(feature = "winrm")]
            winrm_pool: crate::winrm::WinRmPool::new(),
            #[cfg(feature = "k8s-exec")]
            k8s_exec_pool: crate::k8s_exec::K8sExecPool::new(),
            #[cfg(feature = "psrp")]
            psrp_pool: crate::psrp::pool::PsrpPool::new(),
            mock_output: Some(output),
            mock_delay: Some(delay),
            mock_calls: MockCalls::default(),
        }
    }

    /// What the mock connections received so far: `(command, stdin)` pairs.
    #[must_use]
    pub fn mock_calls(&self) -> Vec<(String, Option<Vec<u8>>)> {
        self.mock_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_router_with_defaults() {
        let _router = ExecutorRouter::with_defaults();
    }

    #[test]
    fn test_executor_router_new() {
        let _router = ExecutorRouter::new(PoolConfig::default());
    }

    #[tokio::test]
    async fn test_executor_router_stats_empty() {
        let router = ExecutorRouter::with_defaults();
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_cleanup_empty() {
        let router = ExecutorRouter::with_defaults();
        router.cleanup().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_health_check_empty() {
        let router = ExecutorRouter::with_defaults();
        router.health_check().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_close_all_empty() {
        let router = ExecutorRouter::with_defaults();
        router.close_all().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_operations_sequence() {
        let router = ExecutorRouter::with_defaults();
        let s1 = router.stats().await;
        assert_eq!(s1.total_connections, 0);

        router.cleanup().await;
        router.health_check().await;
        router.close_all().await;

        let s2 = router.stats().await;
        assert_eq!(s2.total_connections, 0);
    }

    #[test]
    fn test_executor_router_custom_pool_config() {
        let config = PoolConfig {
            max_connections_per_host: 5,
            max_idle_seconds: 120,
            max_age_seconds: 1800,
        };
        let _router = ExecutorRouter::new(config);
    }

    #[test]
    fn test_pool_config_default_values() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_idle_seconds, 300);
        assert_eq!(config.max_age_seconds, 3600);
    }

    #[tokio::test]
    async fn test_executor_router_stats_empty_connections_by_host() {
        let router = ExecutorRouter::with_defaults();
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
        assert!(stats.connections_by_host.is_empty());
    }

    #[tokio::test]
    async fn test_executor_router_cleanup_then_stats() {
        let router = ExecutorRouter::with_defaults();
        router.cleanup().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
        assert!(stats.connections_by_host.is_empty());
    }

    #[tokio::test]
    async fn test_executor_router_close_all_idempotent() {
        let router = ExecutorRouter::with_defaults();
        router.close_all().await;
        router.close_all().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_health_check_idempotent() {
        let router = ExecutorRouter::with_defaults();
        router.health_check().await;
        router.health_check().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_interleaved_operations() {
        let router = ExecutorRouter::with_defaults();

        router.health_check().await;
        let s1 = router.stats().await;
        assert_eq!(s1.total_connections, 0);

        router.cleanup().await;
        let s2 = router.stats().await;
        assert_eq!(s2.total_connections, 0);

        router.close_all().await;
        let s3 = router.stats().await;
        assert_eq!(s3.total_connections, 0);

        // Run all again
        router.health_check().await;
        router.cleanup().await;
        let s4 = router.stats().await;
        assert_eq!(s4.total_connections, 0);
    }

    #[test]
    fn test_pool_config_custom_values_preserved() {
        let config = PoolConfig {
            max_connections_per_host: 1,
            max_idle_seconds: 10,
            max_age_seconds: 60,
        };
        let router = ExecutorRouter::new(config);
        // Router created successfully with minimal pool config
        let _ = router;
    }
}
