use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: String },

    #[error("Invalid configuration: {field} - {reason}")]
    ConfigInvalid { field: String, reason: String },

    // SSH errors
    #[error("SSH connection failed to {host}: {reason}")]
    SshConnection { host: String, reason: String },

    #[error("SSH host key mismatch for {host}: expected {expected}, got {actual}")]
    SshHostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    #[error("SSH host key unknown for {host} (fingerprint: {fingerprint})")]
    SshHostKeyUnknown { host: String, fingerprint: String },

    #[error("SSH authentication failed for {user}@{host}")]
    SshAuth { user: String, host: String },

    #[error("SSH key not found: {path}")]
    SshKeyNotFound { path: String },

    #[error("SSH key invalid format: {path}")]
    SshKeyInvalid { path: String },

    #[error("SSH command execution failed: {reason}")]
    SshExec { reason: String },

    #[error("SSH command timeout after {seconds}s")]
    SshTimeout { seconds: u64 },

    #[error("SSH output too large (limit: {limit_bytes} bytes)")]
    SshOutputTooLarge { limit_bytes: usize },

    // Security errors
    #[error("Command denied: {reason}")]
    CommandDenied { reason: String },

    // MCP protocol errors
    #[error("MCP protocol error: {0}")]
    McpProtocol(String),

    #[error("MCP invalid request: {0}")]
    McpInvalidRequest(String),

    #[error("MCP unknown method: {method}")]
    McpUnknownMethod { method: String },

    #[error("MCP missing parameter: {param}")]
    McpMissingParam { param: String },

    #[error("MCP unknown tool: {tool}")]
    McpUnknownTool { tool: String },

    // Session errors
    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: String },

    #[error("Too many sessions (max: {max})")]
    TooManySessions { max: usize },

    #[error("Session expired: {session_id}")]
    SessionExpired { session_id: String },

    // Tunnel errors
    #[error("Tunnel error: {reason}")]
    Tunnel { reason: String },

    // SOCKS proxy errors
    #[error("SOCKS proxy error for {host}: {reason}")]
    SocksProxy { host: String, reason: String },

    // Host errors
    #[error("Unknown host: {host}")]
    UnknownHost { host: String },

    // File transfer errors
    #[error("File transfer error: {reason}")]
    FileTransfer { reason: String },

    // Database command errors
    #[error("Database command error: {reason}")]
    DatabaseCommand { reason: String },

    // SFTP errors
    #[error("SFTP error: {reason}")]
    Sftp { reason: String },

    // Client request errors (elicitation/sampling)
    #[error("Client request error: {reason}")]
    ClientRequest { reason: String },

    // Elicitation errors
    #[error("Elicitation error: {reason}")]
    Elicitation { reason: String },

    // Sampling errors
    #[error("Sampling error: {reason}")]
    Sampling { reason: String },

    /// Request was cancelled by the client via `notifications/cancelled`.
    ///
    /// Handlers that see this error should NOT be retried — see
    /// `is_retryable_error` in `src/ssh/retry.rs`. The JSON-RPC response is
    /// built with error code `-32800` (MCP 2025-11-25 custom range for
    /// cancellation).
    #[error("Request cancelled by client")]
    Cancelled,

    /// AWX/AAP REST API returned a non-2xx HTTP status.
    ///
    /// Surfaced by `AwxCommandBuilder::parse_checked_response` so a 4xx/5xx from
    /// AWX (expired token → 401, RBAC → 403, bad id → 404, validation → 400) is
    /// reported as an error instead of being handed to the model as an opaque
    /// success. `detail` carries the AWX `detail`/`__all__` message when present.
    #[error("AWX API error: HTTP {status} - {detail}")]
    AwxApi { status: u16, detail: String },

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // JSON errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // YAML errors
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_saphyr::Error),
}

pub type Result<T> = std::result::Result<T, BridgeError>;

/// Map `winrm_rs::WinrmError` to `BridgeError`.
///
/// - Auth failures → `BridgeError::SshAuth` (`WinRM` has no separate concept;
///   the SSH variant is reused as a protocol-agnostic auth error).
/// - Timeout → `BridgeError::SshTimeout`.
/// - Cancellation → `BridgeError::Cancelled`.
/// - Everything else → `BridgeError::SshExec`.
#[cfg(feature = "winrm")]
impl From<winrm_rs::WinrmError> for BridgeError {
    fn from(e: winrm_rs::WinrmError) -> Self {
        match e {
            winrm_rs::WinrmError::AuthFailed(_) => BridgeError::SshAuth {
                user: "unknown".to_string(),
                host: "WinRM".to_string(),
            },
            winrm_rs::WinrmError::Timeout(seconds) => BridgeError::SshTimeout { seconds },
            winrm_rs::WinrmError::Cancelled => BridgeError::Cancelled,
            other => BridgeError::SshExec {
                reason: other.to_string(),
            },
        }
    }
}

/// Map `psrp_rs::PsrpError` to `BridgeError`.
///
/// - `PsrpError::Winrm(we)` → delegate to the `WinrmError` mapping.
/// - `PsrpError::Cancelled` → `BridgeError::Cancelled`.
/// - Everything else → `BridgeError::SshExec`.
#[cfg(feature = "psrp")]
impl From<psrp_rs::PsrpError> for BridgeError {
    fn from(e: psrp_rs::PsrpError) -> Self {
        match e {
            psrp_rs::PsrpError::Winrm(we) => BridgeError::from(we),
            psrp_rs::PsrpError::Cancelled => BridgeError::Cancelled,
            other => BridgeError::SshExec {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Configuration Errors ==============

    #[test]
    fn test_config_error_display() {
        let err = BridgeError::Config("test error".to_string());
        assert_eq!(format!("{err}"), "Configuration error: test error");
    }

    #[test]
    fn test_config_not_found_display() {
        let err = BridgeError::ConfigNotFound {
            path: "/path/to/config.yaml".to_string(),
        };
        assert!(format!("{err}").contains("/path/to/config.yaml"));
    }

    #[test]
    fn test_config_invalid_display() {
        let err = BridgeError::ConfigInvalid {
            field: "hosts".to_string(),
            reason: "cannot be empty".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("hosts"));
        assert!(msg.contains("cannot be empty"));
    }

    // ============== SSH Errors ==============

    #[test]
    fn test_ssh_connection_display() {
        let err = BridgeError::SshConnection {
            host: "server1".to_string(),
            reason: "connection refused".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("server1"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_ssh_host_key_mismatch_display() {
        let err = BridgeError::SshHostKeyMismatch {
            host: "server1".to_string(),
            expected: "SHA256:abc123".to_string(),
            actual: "SHA256:xyz789".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("server1"));
        assert!(msg.contains("abc123"));
        assert!(msg.contains("xyz789"));
    }

    #[test]
    fn test_ssh_host_key_unknown_display() {
        let err = BridgeError::SshHostKeyUnknown {
            host: "newserver".to_string(),
            fingerprint: "SHA256:newkey".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("newserver"));
        assert!(msg.contains("SHA256:newkey"));
    }

    #[test]
    fn test_ssh_auth_display() {
        let err = BridgeError::SshAuth {
            user: "admin".to_string(),
            host: "server1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("admin"));
        assert!(msg.contains("server1"));
    }

    #[test]
    fn test_ssh_key_not_found_display() {
        let err = BridgeError::SshKeyNotFound {
            path: "/home/user/.ssh/id_rsa".to_string(),
        };
        assert!(format!("{err}").contains("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_ssh_key_invalid_display() {
        let err = BridgeError::SshKeyInvalid {
            path: "/path/to/key".to_string(),
        };
        assert!(format!("{err}").contains("/path/to/key"));
    }

    #[test]
    fn test_ssh_exec_display() {
        let err = BridgeError::SshExec {
            reason: "channel closed".to_string(),
        };
        assert!(format!("{err}").contains("channel closed"));
    }

    #[test]
    fn test_ssh_timeout_display() {
        let err = BridgeError::SshTimeout { seconds: 30 };
        let msg = format!("{err}");
        assert!(msg.contains("30"));
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_ssh_output_too_large_display() {
        let err = BridgeError::SshOutputTooLarge {
            limit_bytes: 10_485_760,
        };
        assert!(format!("{err}").contains("10485760"));
    }

    // ============== Security Errors ==============

    #[test]
    fn test_command_denied_display() {
        let err = BridgeError::CommandDenied {
            reason: "matches blacklist".to_string(),
        };
        assert!(format!("{err}").contains("matches blacklist"));
    }

    // ============== SOCKS Proxy Errors ==============

    #[test]
    fn test_socks_proxy_display() {
        let err = BridgeError::SocksProxy {
            host: "server1".to_string(),
            reason: "connection refused".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("server1"));
        assert!(msg.contains("connection refused"));
        assert!(msg.contains("SOCKS"));
    }

    // ============== MCP Errors ==============

    #[test]
    fn test_mcp_protocol_display() {
        let err = BridgeError::McpProtocol("invalid message".to_string());
        assert!(format!("{err}").contains("invalid message"));
    }

    #[test]
    fn test_mcp_invalid_request_display() {
        let err = BridgeError::McpInvalidRequest("missing id".to_string());
        assert!(format!("{err}").contains("missing id"));
    }

    #[test]
    fn test_mcp_unknown_method_display() {
        let err = BridgeError::McpUnknownMethod {
            method: "unknown/method".to_string(),
        };
        assert!(format!("{err}").contains("unknown/method"));
    }

    #[test]
    fn test_mcp_missing_param_display() {
        let err = BridgeError::McpMissingParam {
            param: "host".to_string(),
        };
        assert!(format!("{err}").contains("host"));
    }

    #[test]
    fn test_mcp_unknown_tool_display() {
        let err = BridgeError::McpUnknownTool {
            tool: "nonexistent_tool".to_string(),
        };
        assert!(format!("{err}").contains("nonexistent_tool"));
    }

    // ============== Session Errors ==============

    #[test]
    fn test_session_not_found_display() {
        let err = BridgeError::SessionNotFound {
            session_id: "abc-123".to_string(),
        };
        assert!(format!("{err}").contains("abc-123"));
    }

    #[test]
    fn test_too_many_sessions_display() {
        let err = BridgeError::TooManySessions { max: 10 };
        assert!(format!("{err}").contains("10"));
    }

    #[test]
    fn test_session_expired_display() {
        let err = BridgeError::SessionExpired {
            session_id: "expired-session".to_string(),
        };
        assert!(format!("{err}").contains("expired-session"));
    }

    // ============== Host Errors ==============

    #[test]
    fn test_unknown_host_display() {
        let err = BridgeError::UnknownHost {
            host: "mystery-server".to_string(),
        };
        assert!(format!("{err}").contains("mystery-server"));
    }

    // ============== File Transfer Errors ==============

    #[test]
    fn test_file_transfer_display() {
        let err = BridgeError::FileTransfer {
            reason: "permission denied".to_string(),
        };
        assert!(format!("{err}").contains("permission denied"));
    }

    #[test]
    fn test_sftp_display() {
        let err = BridgeError::Sftp {
            reason: "no such file".to_string(),
        };
        assert!(format!("{err}").contains("no such file"));
    }

    // ============== Cancellation ==============

    #[test]
    fn test_cancelled_display() {
        let err = BridgeError::Cancelled;
        assert_eq!(format!("{err}"), "Request cancelled by client");
    }

    #[test]
    fn test_cancelled_debug() {
        let err = BridgeError::Cancelled;
        assert_eq!(format!("{err:?}"), "Cancelled");
    }

    // ============== From Implementations ==============

    #[test]
    fn test_io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let bridge_err: BridgeError = io_err.into();
        assert!(format!("{bridge_err}").contains("file not found"));
    }

    #[test]
    fn test_json_error_from() {
        let json_str = "{ invalid json }";
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let bridge_err: BridgeError = json_err.into();
        assert!(format!("{bridge_err}").contains("JSON"));
    }

    // ============== Debug Trait ==============

    #[test]
    fn test_error_debug() {
        let err = BridgeError::Config("test".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("Config"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_all_variants_debug() {
        // Ensure all variants implement Debug correctly
        let variants: Vec<BridgeError> = vec![
            BridgeError::Config("a".to_string()),
            BridgeError::ConfigNotFound {
                path: "b".to_string(),
            },
            BridgeError::ConfigInvalid {
                field: "c".to_string(),
                reason: "d".to_string(),
            },
            BridgeError::SshConnection {
                host: "e".to_string(),
                reason: "f".to_string(),
            },
            BridgeError::SshHostKeyMismatch {
                host: "g".to_string(),
                expected: "h".to_string(),
                actual: "i".to_string(),
            },
            BridgeError::SshHostKeyUnknown {
                host: "j".to_string(),
                fingerprint: "k".to_string(),
            },
            BridgeError::SshAuth {
                user: "l".to_string(),
                host: "m".to_string(),
            },
            BridgeError::SshKeyNotFound {
                path: "n".to_string(),
            },
            BridgeError::SshKeyInvalid {
                path: "o".to_string(),
            },
            BridgeError::SshExec {
                reason: "p".to_string(),
            },
            BridgeError::SshTimeout { seconds: 30 },
            BridgeError::SshOutputTooLarge { limit_bytes: 100 },
            BridgeError::CommandDenied {
                reason: "q".to_string(),
            },
            BridgeError::McpProtocol("s".to_string()),
            BridgeError::McpInvalidRequest("t".to_string()),
            BridgeError::McpUnknownMethod {
                method: "u".to_string(),
            },
            BridgeError::McpMissingParam {
                param: "v".to_string(),
            },
            BridgeError::McpUnknownTool {
                tool: "w".to_string(),
            },
            BridgeError::SessionNotFound {
                session_id: "x".to_string(),
            },
            BridgeError::TooManySessions { max: 5 },
            BridgeError::SessionExpired {
                session_id: "y".to_string(),
            },
            BridgeError::Tunnel {
                reason: "tunnel failed".to_string(),
            },
            BridgeError::SocksProxy {
                host: "proxy-host".to_string(),
                reason: "connection refused".to_string(),
            },
            BridgeError::UnknownHost {
                host: "z".to_string(),
            },
            BridgeError::FileTransfer {
                reason: "aa".to_string(),
            },
            BridgeError::DatabaseCommand {
                reason: "db error".to_string(),
            },
            BridgeError::Sftp {
                reason: "bb".to_string(),
            },
            BridgeError::ClientRequest {
                reason: "timeout".to_string(),
            },
            BridgeError::Elicitation {
                reason: "declined".to_string(),
            },
            BridgeError::Sampling {
                reason: "not supported".to_string(),
            },
            BridgeError::Cancelled,
        ];

        for err in variants {
            // Ensure debug doesn't panic
            let _ = format!("{err:?}");
            // Ensure display doesn't panic
            let _ = format!("{err}");
        }
    }

    // ============== Result Type ==============

    #[test]
    fn test_result_type_alias() {
        // Verify Result type alias works correctly
        let ok_result: Result<i32> = Ok(42);
        let err_result: Result<i32> = Err(BridgeError::Config("test".to_string()));

        assert!(ok_result.is_ok());
        assert!(err_result.is_err());
    }

    #[test]
    fn test_result_err() {
        let result: Result<i32> = Err(BridgeError::Config("error".to_string()));
        assert!(result.is_err());
    }
}
