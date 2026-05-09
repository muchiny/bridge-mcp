mod client;
mod connector;
pub mod known_hosts;
mod pool;
mod retry;
pub mod session;
mod sftp;

pub use client::{CommandOutput, SshClient, build_russh_client_config};
pub use connector::RealSshConnector;
pub use known_hosts::{VerifyResult, verify_host_key};
pub use pool::{ConnectionPool, PoolConfig, PoolStats, PooledConnectionGuard};
pub use retry::{RetryConfig, is_retryable_error, with_retry, with_retry_if};
pub use session::{SessionExecResult, SessionInfo, SessionManager};
pub use sftp::{
    DEFAULT_CHUNK_SIZE, DirectoryTransferResult, RemoteDirEntry, SftpClient, TransferMode,
    TransferOptions, TransferProgress, TransferResult,
};
