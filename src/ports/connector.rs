//! SSH Connector Port
//!
//! This module defines traits for SSH connection creation and operations,
//! abstracting away the underlying SSH implementation for testability.

use std::future::Future;

use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;
use crate::ssh::CommandOutput;

/// Trait for creating SSH connections
///
/// This trait abstracts the SSH connection creation, allowing for
/// mock implementations in tests without requiring real SSH servers.
pub trait SshConnector: Send + Sync {
    /// The type of client returned by this connector
    type Client: SshClientTrait;

    /// Connect to a host using the provided configuration
    ///
    /// # Arguments
    /// * `host_name` - The host alias as defined in configuration
    /// * `host` - The host configuration
    /// * `limits` - Connection and command limits
    fn connect(
        &self,
        host_name: &str,
        host: &HostConfig,
        limits: &LimitsConfig,
    ) -> impl Future<Output = Result<Self::Client>> + Send;

    /// Connect to a host through a jump host (bastion)
    ///
    /// # Arguments
    /// * `host_name` - The target host alias
    /// * `host` - The target host configuration
    /// * `jump_host_name` - The jump host alias
    /// * `jump_host` - The jump host configuration
    /// * `limits` - Connection and command limits
    fn connect_via_jump(
        &self,
        host_name: &str,
        host: &HostConfig,
        jump_host_name: &str,
        jump_host: &HostConfig,
        limits: &LimitsConfig,
    ) -> impl Future<Output = Result<Self::Client>> + Send;
}

/// Trait for SSH client operations
///
/// This trait abstracts operations on an established SSH connection,
/// allowing for mock implementations in tests.
pub trait SshClientTrait: Send + Sync {
    /// Execute a command on the remote host
    fn exec(
        &self,
        command: &str,
        limits: &LimitsConfig,
    ) -> impl Future<Output = Result<CommandOutput>> + Send;

    /// Check if the connection is still alive
    fn is_connected(&self) -> impl Future<Output = bool> + Send;

    /// Get the host name
    fn host_name(&self) -> &str;

    /// Close the connection
    fn close(self) -> impl Future<Output = Result<()>> + Send;
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::config::OsType;
    use crate::error::BridgeError;

    /// Mock SSH connector for testing
    #[derive(Default)]
    pub struct MockSshConnector {
        /// Predefined clients for hosts
        clients: Mutex<HashMap<String, MockClientConfig>>,
        /// Errors to return for specific hosts
        errors: Mutex<HashMap<String, BridgeError>>,
        /// Record of connection attempts
        connect_calls: Mutex<Vec<ConnectCall>>,
    }

    #[derive(Clone)]
    struct MockClientConfig {
        exec_responses: HashMap<String, CommandOutput>,
        default_response: CommandOutput,
        is_connected: bool,
    }

    impl Default for MockClientConfig {
        fn default() -> Self {
            Self {
                exec_responses: HashMap::new(),
                default_response: CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 10,
                },
                is_connected: true,
            }
        }
    }

    /// Record of a connection attempt
    #[derive(Debug, Clone)]
    pub struct ConnectCall {
        pub host_name: String,
        pub jump_host: Option<String>,
    }

    impl MockSshConnector {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a host that will successfully connect
        pub fn add_host(&self, host_name: &str) {
            self.clients
                .lock()
                .unwrap()
                .insert(host_name.to_string(), MockClientConfig::default());
        }

        /// Add a host with custom exec responses
        pub fn add_host_with_responses(
            &self,
            host_name: &str,
            responses: HashMap<String, CommandOutput>,
        ) {
            self.clients.lock().unwrap().insert(
                host_name.to_string(),
                MockClientConfig {
                    exec_responses: responses,
                    ..Default::default()
                },
            );
        }

        /// Add a host that returns a specific error on connect
        pub fn add_host_error(&self, host_name: &str, error: BridgeError) {
            self.errors
                .lock()
                .unwrap()
                .insert(host_name.to_string(), error);
        }

        /// Add a disconnected host (`is_connected` returns false)
        pub fn add_disconnected_host(&self, host_name: &str) {
            self.clients.lock().unwrap().insert(
                host_name.to_string(),
                MockClientConfig {
                    is_connected: false,
                    ..Default::default()
                },
            );
        }

        /// Get all connection attempts
        #[must_use]
        pub fn get_connect_calls(&self) -> Vec<ConnectCall> {
            self.connect_calls.lock().unwrap().clone()
        }

        /// Get number of connection attempts
        #[must_use]
        pub fn connect_count(&self) -> usize {
            self.connect_calls.lock().unwrap().len()
        }
    }

    impl SshConnector for MockSshConnector {
        type Client = MockSshClient;

        fn connect(
            &self,
            host_name: &str,
            _host: &HostConfig,
            _limits: &LimitsConfig,
        ) -> impl std::future::Future<Output = Result<Self::Client>> + Send {
            // Record the connection attempt
            self.connect_calls.lock().unwrap().push(ConnectCall {
                host_name: host_name.to_string(),
                jump_host: None,
            });

            // Check for errors
            if let Some(error) = self.errors.lock().unwrap().get(host_name) {
                return std::future::ready(Err(match error {
                    BridgeError::SshConnection { host, reason } => BridgeError::SshConnection {
                        host: host.clone(),
                        reason: reason.clone(),
                    },
                    BridgeError::SshAuth { user, host } => BridgeError::SshAuth {
                        user: user.clone(),
                        host: host.clone(),
                    },
                    BridgeError::SshTimeout { seconds } => {
                        BridgeError::SshTimeout { seconds: *seconds }
                    }
                    _ => BridgeError::SshConnection {
                        host: host_name.to_string(),
                        reason: "Mock error".to_string(),
                    },
                }));
            }

            // Get the client config or return error
            let clients = self.clients.lock().unwrap();
            std::future::ready(if let Some(config) = clients.get(host_name) {
                Ok(MockSshClient::new(host_name, config.clone()))
            } else {
                Err(BridgeError::SshConnection {
                    host: host_name.to_string(),
                    reason: "Host not configured in mock".to_string(),
                })
            })
        }

        fn connect_via_jump(
            &self,
            host_name: &str,
            _host: &HostConfig,
            jump_host_name: &str,
            _jump_host: &HostConfig,
            _limits: &LimitsConfig,
        ) -> impl std::future::Future<Output = Result<Self::Client>> + Send {
            // Record the connection attempt with jump host
            self.connect_calls.lock().unwrap().push(ConnectCall {
                host_name: host_name.to_string(),
                jump_host: Some(jump_host_name.to_string()),
            });

            // Check for errors
            if let Some(error) = self.errors.lock().unwrap().get(host_name) {
                return std::future::ready(Err(match error {
                    BridgeError::SshConnection { host, reason } => BridgeError::SshConnection {
                        host: host.clone(),
                        reason: reason.clone(),
                    },
                    BridgeError::SshAuth { user, host } => BridgeError::SshAuth {
                        user: user.clone(),
                        host: host.clone(),
                    },
                    BridgeError::SshTimeout { seconds } => {
                        BridgeError::SshTimeout { seconds: *seconds }
                    }
                    _ => BridgeError::SshConnection {
                        host: host_name.to_string(),
                        reason: "Mock error".to_string(),
                    },
                }));
            }

            // Get the client config or return error
            let clients = self.clients.lock().unwrap();
            std::future::ready(if let Some(config) = clients.get(host_name) {
                Ok(MockSshClient::new(host_name, config.clone()))
            } else {
                Err(BridgeError::SshConnection {
                    host: host_name.to_string(),
                    reason: "Host not configured in mock".to_string(),
                })
            })
        }
    }

    /// Mock SSH client for testing
    pub struct MockSshClient {
        host_name: String,
        exec_responses: HashMap<String, CommandOutput>,
        default_response: CommandOutput,
        is_connected: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
        exec_calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockSshClient {
        fn new(host_name: &str, config: MockClientConfig) -> Self {
            Self {
                host_name: host_name.to_string(),
                exec_responses: config.exec_responses,
                default_response: config.default_response,
                is_connected: Arc::new(AtomicBool::new(config.is_connected)),
                closed: Arc::new(AtomicBool::new(false)),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Create a new mock client with default settings
        #[must_use]
        pub fn new_default(host_name: &str) -> Self {
            Self::new(host_name, MockClientConfig::default())
        }

        /// Create a mock client with specific responses
        #[must_use]
        pub fn with_responses(host_name: &str, responses: HashMap<String, CommandOutput>) -> Self {
            Self::new(
                host_name,
                MockClientConfig {
                    exec_responses: responses,
                    ..Default::default()
                },
            )
        }

        /// Set the connection state
        pub fn set_connected(&self, connected: bool) {
            self.is_connected.store(connected, Ordering::SeqCst);
        }

        /// Get all executed commands
        #[must_use]
        pub fn get_exec_calls(&self) -> Vec<String> {
            self.exec_calls.lock().unwrap().clone()
        }

        /// Check if client was closed
        #[must_use]
        pub fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    impl SshClientTrait for MockSshClient {
        fn exec(
            &self,
            command: &str,
            _limits: &LimitsConfig,
        ) -> impl std::future::Future<Output = Result<CommandOutput>> + Send {
            // Record the exec call
            self.exec_calls.lock().unwrap().push(command.to_string());

            // Return the configured response or default
            std::future::ready(if let Some(response) = self.exec_responses.get(command) {
                Ok(response.clone())
            } else {
                Ok(self.default_response.clone())
            })
        }

        fn is_connected(&self) -> impl std::future::Future<Output = bool> + Send {
            std::future::ready(self.is_connected.load(Ordering::SeqCst))
        }

        fn host_name(&self) -> &str {
            &self.host_name
        }

        fn close(self) -> impl std::future::Future<Output = Result<()>> + Send {
            self.closed.store(true, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn create_test_host_config() -> HostConfig {
            HostConfig {
                hostname: "test.example.com".to_string(),
                port: 22,
                user: "testuser".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: crate::config::HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::Linux,
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

        fn create_test_limits() -> LimitsConfig {
            LimitsConfig::default()
        }

        // ============== MockSshConnector Tests ==============

        #[tokio::test]
        async fn test_mock_connector_new() {
            let connector = MockSshConnector::new();
            assert_eq!(connector.connect_count(), 0);
        }

        #[tokio::test]
        async fn test_mock_connector_add_host() {
            let connector = MockSshConnector::new();
            connector.add_host("test-host");

            let host = create_test_host_config();
            let limits = create_test_limits();
            let client = connector.connect("test-host", &host, &limits).await;

            assert!(client.is_ok());
        }

        #[tokio::test]
        async fn test_mock_connector_unknown_host() {
            let connector = MockSshConnector::new();

            let host = create_test_host_config();
            let limits = create_test_limits();
            let result = connector.connect("unknown-host", &host, &limits).await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_mock_connector_error() {
            let connector = MockSshConnector::new();
            connector.add_host_error(
                "error-host",
                BridgeError::SshConnection {
                    host: "error-host".to_string(),
                    reason: "Connection refused".to_string(),
                },
            );

            let host = create_test_host_config();
            let limits = create_test_limits();
            let result = connector.connect("error-host", &host, &limits).await;

            assert!(result.is_err());
            if let Err(BridgeError::SshConnection { reason, .. }) = result {
                assert!(reason.contains("refused"));
            } else {
                panic!("Expected SshConnection error");
            }
        }

        #[tokio::test]
        async fn test_mock_connector_connect_calls() {
            let connector = MockSshConnector::new();
            connector.add_host("host1");
            connector.add_host("host2");

            let host = create_test_host_config();
            let limits = create_test_limits();

            let _ = connector.connect("host1", &host, &limits).await;
            let _ = connector.connect("host2", &host, &limits).await;
            let _ = connector.connect("host1", &host, &limits).await;

            let calls = connector.get_connect_calls();
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[0].host_name, "host1");
            assert_eq!(calls[1].host_name, "host2");
            assert_eq!(calls[2].host_name, "host1");
        }

        #[tokio::test]
        async fn test_mock_connector_via_jump() {
            let connector = MockSshConnector::new();
            connector.add_host("target");
            connector.add_host("bastion");

            let target_host = create_test_host_config();
            let jump_host = create_test_host_config();
            let limits = create_test_limits();

            let result = connector
                .connect_via_jump("target", &target_host, "bastion", &jump_host, &limits)
                .await;

            assert!(result.is_ok());

            let calls = connector.get_connect_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].host_name, "target");
            assert_eq!(calls[0].jump_host, Some("bastion".to_string()));
        }

        // ============== MockSshClient Tests ==============

        #[tokio::test]
        async fn test_mock_client_exec_default() {
            let client = MockSshClient::new_default("test-host");
            let limits = create_test_limits();

            let result = client.exec("echo hello", &limits).await;

            assert!(result.is_ok());
            let output = result.unwrap();
            assert_eq!(output.exit_code, 0);
        }

        #[tokio::test]
        async fn test_mock_client_exec_custom_response() {
            let mut responses = HashMap::new();
            responses.insert(
                "whoami".to_string(),
                CommandOutput {
                    stdout: "testuser\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 5,
                },
            );

            let client = MockSshClient::with_responses("test-host", responses);
            let limits = create_test_limits();

            let result = client.exec("whoami", &limits).await;

            assert!(result.is_ok());
            let output = result.unwrap();
            assert_eq!(output.stdout, "testuser\n");
        }

        #[tokio::test]
        async fn test_mock_client_exec_calls_recorded() {
            let client = MockSshClient::new_default("test-host");
            let limits = create_test_limits();

            let _ = client.exec("cmd1", &limits).await;
            let _ = client.exec("cmd2", &limits).await;

            let calls = client.get_exec_calls();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], "cmd1");
            assert_eq!(calls[1], "cmd2");
        }

        #[tokio::test]
        async fn test_mock_client_is_connected() {
            let client = MockSshClient::new_default("test-host");

            assert!(client.is_connected().await);

            client.set_connected(false);
            assert!(!client.is_connected().await);
        }

        #[tokio::test]
        async fn test_mock_client_host_name() {
            let client = MockSshClient::new_default("my-server");
            assert_eq!(client.host_name(), "my-server");
        }

        #[tokio::test]
        async fn test_mock_client_close() {
            let client = MockSshClient::new_default("test-host");
            let closed = client.closed.clone();

            assert!(!closed.load(Ordering::SeqCst));

            let result = client.close().await;
            assert!(result.is_ok());
            assert!(closed.load(Ordering::SeqCst));
        }

        // ============== MockSshConnector with Responses ==============

        #[tokio::test]
        async fn test_mock_connector_with_responses() {
            let connector = MockSshConnector::new();

            let mut responses = HashMap::new();
            responses.insert(
                "ls".to_string(),
                CommandOutput {
                    stdout: "file1\nfile2\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 10,
                },
            );

            connector.add_host_with_responses("host1", responses);

            let host = create_test_host_config();
            let limits = create_test_limits();
            let client = connector.connect("host1", &host, &limits).await.unwrap();

            let output = client.exec("ls", &limits).await.unwrap();
            assert_eq!(output.stdout, "file1\nfile2\n");
        }

        #[tokio::test]
        async fn test_mock_connector_disconnected_host() {
            let connector = MockSshConnector::new();
            connector.add_disconnected_host("dead-host");

            let host = create_test_host_config();
            let limits = create_test_limits();
            let client = connector
                .connect("dead-host", &host, &limits)
                .await
                .unwrap();

            assert!(!client.is_connected().await);
        }

        // ============== Edge Cases ==============

        #[tokio::test]
        async fn test_mock_client_exec_empty_command() {
            let client = MockSshClient::new_default("test-host");
            let limits = create_test_limits();

            let result = client.exec("", &limits).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_mock_client_exec_unicode_command() {
            let client = MockSshClient::new_default("test-host");
            let limits = create_test_limits();

            let result = client.exec("echo 日本語", &limits).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_mock_connector_auth_error() {
            let connector = MockSshConnector::new();
            connector.add_host_error(
                "auth-fail",
                BridgeError::SshAuth {
                    user: "baduser".to_string(),
                    host: "auth-fail".to_string(),
                },
            );

            let host = create_test_host_config();
            let limits = create_test_limits();
            let result = connector.connect("auth-fail", &host, &limits).await;

            assert!(matches!(result, Err(BridgeError::SshAuth { .. })));
        }

        #[tokio::test]
        async fn test_mock_connector_timeout_error() {
            let connector = MockSshConnector::new();
            connector.add_host_error("slow-host", BridgeError::SshTimeout { seconds: 30 });

            let host = create_test_host_config();
            let limits = create_test_limits();
            let result = connector.connect("slow-host", &host, &limits).await;

            assert!(matches!(
                result,
                Err(BridgeError::SshTimeout { seconds: 30 })
            ));
        }
    }
}
