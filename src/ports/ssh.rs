//! SSH Executor Port
//!
//! This module defines the trait for SSH command execution,
//! abstracting away the underlying SSH implementation.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;

/// Output from a command execution
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u32,
    pub duration_ms: u64,
}

impl From<crate::ssh::CommandOutput> for CommandOutput {
    fn from(output: crate::ssh::CommandOutput) -> Self {
        Self {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration_ms: output.duration_ms,
        }
    }
}

/// Trait for SSH command execution
///
/// This trait abstracts the SSH client implementation, allowing
/// for easy testing with mock implementations and potential
/// alternative SSH backends.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `SshExecutor`",
    label = "this type cannot be used as an SSH executor",
    note = "implement execute(), upload(), download(), and is_reachable()"
)]
#[async_trait]
pub trait SshExecutor: Send + Sync {
    /// Execute a command on the specified host
    ///
    /// # Arguments
    /// * `host` - The host alias as defined in configuration
    /// * `command` - The command to execute
    /// * `timeout` - Maximum execution time
    ///
    /// # Returns
    /// The command output including stdout, stderr, and exit code
    async fn execute(&self, host: &str, command: &str, timeout: Duration) -> Result<CommandOutput>;

    /// Upload a file to a remote host
    ///
    /// # Arguments
    /// * `host` - The host alias as defined in configuration
    /// * `local` - Path to the local file
    /// * `remote` - Destination path on the remote host
    async fn upload(&self, host: &str, local: &Path, remote: &Path) -> Result<()>;

    /// Download a file from a remote host
    ///
    /// # Arguments
    /// * `host` - The host alias as defined in configuration
    /// * `remote` - Path to the file on the remote host
    /// * `local` - Destination path on the local machine
    async fn download(&self, host: &str, remote: &Path, local: &Path) -> Result<()>;

    /// Check if a host is reachable
    ///
    /// # Arguments
    /// * `host` - The host alias as defined in configuration
    async fn is_reachable(&self, host: &str) -> bool;
}

#[cfg(test)]
#[allow(dead_code)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Mock SSH executor for testing
    pub struct MockSshExecutor {
        /// Predefined responses for commands
        responses: Mutex<HashMap<String, CommandOutput>>,
        /// Record of executed commands
        executed: Mutex<Vec<(String, String)>>,
        /// Whether hosts are reachable (default: true)
        reachable: AtomicBool,
        /// Record of upload operations
        uploads: Mutex<Vec<(String, String, String)>>,
        /// Record of download operations
        downloads: Mutex<Vec<(String, String, String)>>,
    }

    impl MockSshExecutor {
        pub fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
                executed: Mutex::new(Vec::new()),
                reachable: AtomicBool::new(true),
                uploads: Mutex::new(Vec::new()),
                downloads: Mutex::new(Vec::new()),
            }
        }

        /// Add a predefined response for a command
        pub fn add_response(&self, command: &str, output: CommandOutput) {
            self.responses
                .lock()
                .unwrap()
                .insert(command.to_string(), output);
        }

        /// Get the list of executed commands
        pub fn get_executed(&self) -> Vec<(String, String)> {
            self.executed.lock().unwrap().clone()
        }

        /// Set whether hosts are reachable
        pub fn set_reachable(&self, reachable: bool) {
            self.reachable.store(reachable, Ordering::SeqCst);
        }

        /// Get list of upload operations
        pub fn get_uploads(&self) -> Vec<(String, String, String)> {
            self.uploads.lock().unwrap().clone()
        }

        /// Get list of download operations
        pub fn get_downloads(&self) -> Vec<(String, String, String)> {
            self.downloads.lock().unwrap().clone()
        }
    }

    impl Default for MockSshExecutor {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    #[allow(clippy::option_if_let_else)]
    impl SshExecutor for MockSshExecutor {
        async fn execute(
            &self,
            host: &str,
            command: &str,
            _timeout: Duration,
        ) -> Result<CommandOutput> {
            self.executed
                .lock()
                .unwrap()
                .push((host.to_string(), command.to_string()));

            let responses = self.responses.lock().unwrap();
            if let Some(response) = responses.get(command) {
                Ok(response.clone())
            } else {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 10,
                })
            }
        }

        async fn upload(&self, host: &str, local: &Path, remote: &Path) -> Result<()> {
            self.uploads.lock().unwrap().push((
                host.to_string(),
                local.to_string_lossy().to_string(),
                remote.to_string_lossy().to_string(),
            ));
            Ok(())
        }

        async fn download(&self, host: &str, remote: &Path, local: &Path) -> Result<()> {
            self.downloads.lock().unwrap().push((
                host.to_string(),
                remote.to_string_lossy().to_string(),
                local.to_string_lossy().to_string(),
            ));
            Ok(())
        }

        async fn is_reachable(&self, _host: &str) -> bool {
            self.reachable.load(Ordering::SeqCst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    // ============== CommandOutput Tests ==============

    #[test]
    fn test_command_output_new() {
        let output = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 100,
        };

        assert_eq!(output.stdout, "hello");
        assert_eq!(output.stderr, "");
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.duration_ms, 100);
    }

    #[test]
    fn test_command_output_clone() {
        let output = CommandOutput {
            stdout: "test".to_string(),
            stderr: "err".to_string(),
            exit_code: 127,
            duration_ms: 1000,
        };

        let cloned = output.clone();
        assert_eq!(cloned.stdout, output.stdout);
        assert_eq!(cloned.stderr, output.stderr);
        assert_eq!(cloned.exit_code, output.exit_code);
        assert_eq!(cloned.duration_ms, output.duration_ms);
    }

    #[test]
    fn test_command_output_debug() {
        let output = CommandOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 50,
        };

        let debug_str = format!("{output:?}");
        assert!(debug_str.contains("CommandOutput"));
        assert!(debug_str.contains("stdout"));
        assert!(debug_str.contains("hello"));
    }

    #[test]
    fn test_command_output_from_ssh_output() {
        let ssh_output = crate::ssh::CommandOutput {
            stdout: "ssh stdout".to_string(),
            stderr: "ssh stderr".to_string(),
            exit_code: 42,
            duration_ms: 123,
        };

        let port_output: CommandOutput = ssh_output.into();
        assert_eq!(port_output.stdout, "ssh stdout");
        assert_eq!(port_output.stderr, "ssh stderr");
        assert_eq!(port_output.exit_code, 42);
        assert_eq!(port_output.duration_ms, 123);
    }

    #[test]
    fn test_command_output_unicode() {
        let output = CommandOutput {
            stdout: "日本語 🎉 émoji".to_string(),
            stderr: "错误信息".to_string(),
            exit_code: 0,
            duration_ms: 100,
        };

        assert!(output.stdout.contains("日本語"));
        assert!(output.stdout.contains("🎉"));
        assert!(output.stderr.contains("错误信息"));
    }

    #[test]
    fn test_command_output_multiline() {
        let output = CommandOutput {
            stdout: "line1\nline2\nline3".to_string(),
            stderr: "err1\nerr2".to_string(),
            exit_code: 0,
            duration_ms: 200,
        };

        assert_eq!(output.stdout.lines().count(), 3);
        assert_eq!(output.stderr.lines().count(), 2);
    }

    #[test]
    fn test_command_output_empty() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 0,
        };

        assert_eq!(output.stdout, "");
        assert_eq!(output.stderr, "");
    }

    #[test]
    fn test_command_output_large_exit_code() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: u32::MAX,
            duration_ms: 0,
        };

        assert_eq!(output.exit_code, u32::MAX);
    }

    // ============== MockSshExecutor Tests ==============

    #[tokio::test]
    async fn test_mock_executor_new() {
        let mock = mock::MockSshExecutor::new();
        assert_eq!(
            mock.get_executed(),
            [] as [(std::string::String, std::string::String); 0]
        );
    }

    #[tokio::test]
    async fn test_mock_executor_default() {
        let mock = mock::MockSshExecutor::default();
        assert_eq!(
            mock.get_executed(),
            [] as [(std::string::String, std::string::String); 0]
        );
    }

    #[tokio::test]
    async fn test_mock_executor_execute_default_response() {
        let mock = mock::MockSshExecutor::new();

        let result = mock
            .execute("host1", "echo hello", Duration::from_secs(10))
            .await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "");
    }

    #[tokio::test]
    async fn test_mock_executor_execute_custom_response() {
        let mock = mock::MockSshExecutor::new();
        mock.add_response(
            "whoami",
            CommandOutput {
                stdout: "testuser\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 5,
            },
        );

        let result = mock
            .execute("host1", "whoami", Duration::from_secs(10))
            .await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.stdout, "testuser\n");
    }

    #[tokio::test]
    async fn test_mock_executor_records_commands() {
        let mock = mock::MockSshExecutor::new();

        let _ = mock.execute("host1", "cmd1", Duration::from_secs(10)).await;
        let _ = mock.execute("host2", "cmd2", Duration::from_secs(10)).await;
        let _ = mock.execute("host1", "cmd3", Duration::from_secs(10)).await;

        let executed = mock.get_executed();
        assert_eq!(executed.len(), 3);
        assert_eq!(executed[0], ("host1".to_string(), "cmd1".to_string()));
        assert_eq!(executed[1], ("host2".to_string(), "cmd2".to_string()));
        assert_eq!(executed[2], ("host1".to_string(), "cmd3".to_string()));
    }

    #[tokio::test]
    async fn test_mock_executor_upload() {
        let mock = mock::MockSshExecutor::new();

        let local = PathBuf::from("/local/file.txt");
        let remote = PathBuf::from("/remote/file.txt");

        let result = mock.upload("host1", &local, &remote).await;
        assert!(result.is_ok());

        let uploads = mock.get_uploads();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].0, "host1");
        assert!(uploads[0].1.contains("local"));
        assert!(uploads[0].2.contains("remote"));
    }

    #[tokio::test]
    async fn test_mock_executor_download() {
        let mock = mock::MockSshExecutor::new();

        let remote = PathBuf::from("/remote/file.txt");
        let local = PathBuf::from("/local/file.txt");

        let result = mock.download("host1", &remote, &local).await;
        assert!(result.is_ok());

        let downloads = mock.get_downloads();
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].0, "host1");
        assert!(downloads[0].1.contains("remote"));
        assert!(downloads[0].2.contains("local"));
    }

    #[tokio::test]
    async fn test_mock_executor_is_reachable_default() {
        let mock = mock::MockSshExecutor::new();
        assert!(mock.is_reachable("any-host").await);
    }

    #[tokio::test]
    async fn test_mock_executor_is_reachable_configurable() {
        let mock = mock::MockSshExecutor::new();

        mock.set_reachable(false);
        assert!(!mock.is_reachable("host1").await);

        mock.set_reachable(true);
        assert!(mock.is_reachable("host1").await);
    }

    #[tokio::test]
    async fn test_mock_executor_multiple_responses() {
        let mock = mock::MockSshExecutor::new();

        mock.add_response(
            "cmd1",
            CommandOutput {
                stdout: "output1".to_string(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 10,
            },
        );

        mock.add_response(
            "cmd2",
            CommandOutput {
                stdout: "output2".to_string(),
                stderr: "error2".to_string(),
                exit_code: 1,
                duration_ms: 20,
            },
        );

        let result1 = mock
            .execute("host", "cmd1", Duration::from_secs(10))
            .await
            .unwrap();
        let result2 = mock
            .execute("host", "cmd2", Duration::from_secs(10))
            .await
            .unwrap();

        assert_eq!(result1.stdout, "output1");
        assert_eq!(result1.exit_code, 0);
        assert_eq!(result2.stdout, "output2");
        assert_eq!(result2.stderr, "error2");
        assert_eq!(result2.exit_code, 1);
    }

    #[tokio::test]
    async fn test_mock_executor_overwrite_response() {
        let mock = mock::MockSshExecutor::new();

        mock.add_response(
            "cmd",
            CommandOutput {
                stdout: "first".to_string(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 10,
            },
        );

        mock.add_response(
            "cmd",
            CommandOutput {
                stdout: "second".to_string(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 10,
            },
        );

        let result = mock
            .execute("host", "cmd", Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(result.stdout, "second");
    }

    #[tokio::test]
    async fn test_mock_executor_multiple_uploads() {
        let mock = mock::MockSshExecutor::new();

        let _ = mock
            .upload(
                "host1",
                &PathBuf::from("/local1"),
                &PathBuf::from("/remote1"),
            )
            .await;
        let _ = mock
            .upload(
                "host2",
                &PathBuf::from("/local2"),
                &PathBuf::from("/remote2"),
            )
            .await;

        let uploads = mock.get_uploads();
        assert_eq!(uploads.len(), 2);
    }

    #[tokio::test]
    async fn test_mock_executor_multiple_downloads() {
        let mock = mock::MockSshExecutor::new();

        let _ = mock
            .download(
                "host1",
                &PathBuf::from("/remote1"),
                &PathBuf::from("/local1"),
            )
            .await;
        let _ = mock
            .download(
                "host2",
                &PathBuf::from("/remote2"),
                &PathBuf::from("/local2"),
            )
            .await;

        let downloads = mock.get_downloads();
        assert_eq!(downloads.len(), 2);
    }

    // ============== SshExecutor Trait Tests ==============

    #[tokio::test]
    async fn test_ssh_executor_trait_object() {
        let mock = mock::MockSshExecutor::new();
        let executor: &dyn SshExecutor = &mock;

        let result = executor
            .execute("host", "command", Duration::from_secs(10))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ssh_executor_box() {
        let mock = Box::new(mock::MockSshExecutor::new());
        let executor: Box<dyn SshExecutor> = mock;

        let result = executor
            .execute("host", "command", Duration::from_secs(10))
            .await;
        assert!(result.is_ok());
    }
}
