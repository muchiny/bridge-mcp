//! Telnet protocol adapter — legacy network equipment
//!
//! Implements remote command execution over Telnet, primarily for
//! legacy network devices (Cisco IOS, Juniper, `MikroTik`, etc.)
//! that do not support SSH.
//!
//! In-house minimal RFC 854 client (no third-party Telnet crate) so the
//! adapter has zero unmaintained transitive dependencies. The negotiation
//! policy is intentionally minimal: refuse every option (reply `DONT` to
//! `WILL`, `WONT` to `DO`), drop subnegotiation blocks. This is sufficient
//! for command-line network gear that only needs raw character mode.
//!
//! Feature-gated behind `telnet`.

use std::time::{Duration, Instant};

use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default Telnet port.
const DEFAULT_TELNET_PORT: u16 = 23;

/// Login-prompt matcher ("login:", "Login:", "Username:"-style endings).
/// Compiled once — the login flow runs on every reconnect.
#[allow(clippy::expect_used)] // static regex literal
static LOGIN_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("ogin:").expect("static regex"));

/// Password-prompt matcher ("password:", "Password:").
#[allow(clippy::expect_used)] // static regex literal
static PASS_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new("assword:").expect("static regex"));

/// Default prompt regex for network devices.
const DEFAULT_PROMPT: &str = r"[>#$]";

/// Connect / login / exec timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Read buffer size for a single socket read.
const READ_BUF_SIZE: usize = 4096;

// Telnet protocol bytes (RFC 854).
const IAC: u8 = 0xFF;
const DONT: u8 = 0xFE;
const DO: u8 = 0xFD;
const WONT: u8 = 0xFC;
const WILL: u8 = 0xFB;
const SB: u8 = 0xFA;
const SE: u8 = 0xF0;

/// An active Telnet connection to a network device.
pub struct TelnetConnection {
    stream: TcpStream,
    prompt_re: Regex,
    host_name: String,
    failed: bool,
}

impl TelnetConnection {
    /// Establish a Telnet connection and authenticate.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or authentication fails.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let port = if host_config.port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            host_config.port
        };

        let password = match &host_config.auth {
            crate::config::AuthConfig::Password { password } => password.to_string(),
            _ => {
                return Err(BridgeError::Config(format!(
                    "Telnet host '{host_name}' requires password authentication"
                )));
            }
        };

        let addr = format!("{}:{port}", host_config.hostname);
        info!(host = %host_name, addr = %addr, "Connecting via Telnet");

        let stream = timeout(IO_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| BridgeError::SshExec {
                reason: format!("Telnet connect timeout to {addr}"),
            })?
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet connection failed: {e}"),
            })?;

        let prompt_re = Regex::new(DEFAULT_PROMPT)
            .map_err(|e| BridgeError::Config(format!("Invalid Telnet prompt regex: {e}")))?;

        let mut conn = Self {
            stream,
            prompt_re,
            host_name: host_name.to_string(),
            failed: false,
        };

        // Login flow: wait for "ogin:" → send user, "assword:" → send pass, prompt → ready.
        conn.read_until(&LOGIN_RE)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet login prompt not received: {e}"),
            })?;
        conn.write_line(&host_config.user)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet login send failed: {e}"),
            })?;

        conn.read_until(&PASS_RE)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet password prompt not received: {e}"),
            })?;
        conn.write_line(&password)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet password send failed: {e}"),
            })?;

        let prompt_re_clone = conn.prompt_re.clone();
        conn.read_until(&prompt_re_clone)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet shell prompt not received after auth: {e}"),
            })?;

        info!(host = %host_name, "Telnet authenticated");
        Ok(conn)
    }

    /// Execute a command over the Telnet session.
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(host = %self.host_name, command = %command, "Executing Telnet command");

        self.write_line(command)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet exec write failed: {e}"),
            })?;

        let prompt_re = self.prompt_re.clone();
        let raw = self
            .read_until(&prompt_re)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet exec read failed: {e}"),
            })?;

        // Strip the command echo (first line) and the trailing prompt line.
        let stdout = strip_echo_and_prompt(&raw, command);

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        // Telnet doesn't have separate stdout/stderr or exit codes.
        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: 0,
            duration_ms,
        })
    }

    /// Mark this connection as failed (won't be reused).
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "Telnet connection marked as failed");
    }

    /// Send a line terminated by `\r\n`.
    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        timeout(IO_TIMEOUT, async {
            self.stream.write_all(line.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "telnet write timeout"))?
    }

    /// Read from the socket, processing IAC sequences, until `re` matches the
    /// accumulated data buffer.
    async fn read_until(&mut self, re: &Regex) -> std::io::Result<String> {
        let mut data: Vec<u8> = Vec::with_capacity(READ_BUF_SIZE);
        let mut buf = [0u8; READ_BUF_SIZE];
        let mut iac_replies: Vec<u8> = Vec::new();

        loop {
            let n = timeout(IO_TIMEOUT, self.stream.read(&mut buf))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "telnet read timeout")
                })??;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "telnet peer closed",
                ));
            }

            process_iac(&buf[..n], &mut data, &mut iac_replies);

            if !iac_replies.is_empty() {
                self.stream.write_all(&iac_replies).await?;
                self.stream.flush().await?;
                iac_replies.clear();
            }

            // Use lossy decode for the match check; non-UTF8 device output stays
            // intact in `data` (we re-decode at the end) but regex needs &str.
            let view = String::from_utf8_lossy(&data);
            if re.is_match(&view) {
                return Ok(view.into_owned());
            }
        }
    }
}

/// Walk a chunk of bytes received from the wire, splitting Telnet IAC control
/// sequences from regular data. Negotiation policy: refuse every option.
fn process_iac(chunk: &[u8], data: &mut Vec<u8>, replies: &mut Vec<u8>) {
    let mut i = 0;
    while i < chunk.len() {
        let b = chunk[i];
        if b != IAC {
            data.push(b);
            i += 1;
            continue;
        }
        // IAC found — need at least one more byte for the command.
        if i + 1 >= chunk.len() {
            // Incomplete sequence at end of chunk. For simplicity we drop it;
            // in practice the next read will start fresh and a partial IAC at
            // the chunk boundary is rare on real devices.
            return;
        }
        let cmd = chunk[i + 1];
        match cmd {
            // Escaped 0xFF in the data stream.
            IAC => {
                data.push(IAC);
                i += 2;
            }
            // Three-byte option negotiation: refuse everything.
            WILL => {
                if i + 2 < chunk.len() {
                    replies.extend_from_slice(&[IAC, DONT, chunk[i + 2]]);
                    i += 3;
                } else {
                    return;
                }
            }
            DO => {
                if i + 2 < chunk.len() {
                    replies.extend_from_slice(&[IAC, WONT, chunk[i + 2]]);
                    i += 3;
                } else {
                    return;
                }
            }
            WONT | DONT => {
                // Acknowledge silently (peer is telling us they won't / we shouldn't).
                if i + 2 < chunk.len() {
                    i += 3;
                } else {
                    return;
                }
            }
            // Subnegotiation: skip until IAC SE.
            SB => {
                let mut j = i + 2;
                while j + 1 < chunk.len() {
                    if chunk[j] == IAC && chunk[j + 1] == SE {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                i = j;
            }
            // Two-byte commands we don't care about (NOP, GA, etc.).
            _ => {
                i += 2;
            }
        }
    }
}

/// Remove the command echo (typically the first line of `raw`) and the
/// trailing prompt line that triggered `read_until` to return.
fn strip_echo_and_prompt(raw: &str, command: &str) -> String {
    let mut lines: Vec<&str> = raw.split('\n').collect();

    // Drop a leading line that contains the echoed command (devices often
    // echo the command back before the response).
    if let Some(first) = lines.first() {
        let first_trim = first.trim_end_matches('\r').trim();
        if first_trim == command.trim() || first_trim.ends_with(command.trim()) {
            lines.remove(0);
        }
    }

    // Drop trailing empty lines first, then the prompt line itself, then any
    // remaining trailing empty lines (devices may pad with blank lines around
    // the prompt).
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    if let Some(last) = lines.last() {
        let trimmed = last.trim_end_matches('\r').trim();
        if trimmed
            .chars()
            .last()
            .is_some_and(|c| matches!(c, '>' | '#' | '$'))
        {
            lines.pop();
        }
    }
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }

    lines
        .iter()
        .map(|l| l.trim_end_matches('\r'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_telnet_port() {
        assert_eq!(DEFAULT_TELNET_PORT, 23);
    }

    #[test]
    fn test_default_prompt() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(re.is_match("#"));
        assert!(re.is_match(">"));
        assert!(re.is_match("$"));
    }

    #[test]
    fn test_default_prompt_regex_no_match() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(!re.is_match("hello"));
        assert!(!re.is_match(""));
    }

    #[test]
    fn test_default_prompt_regex_in_context() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(re.is_match("Router#"));
        assert!(re.is_match("Switch>"));
        assert!(re.is_match("user@host$"));
    }

    #[test]
    fn test_default_port_value() {
        assert_eq!(DEFAULT_TELNET_PORT, 23);
        const { assert!(DEFAULT_TELNET_PORT < 1024) };
    }

    #[test]
    fn test_port_fallback_from_ssh() {
        let ssh_port: u16 = 22;
        let telnet_port = if ssh_port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            ssh_port
        };
        assert_eq!(telnet_port, 23);
    }

    #[test]
    fn test_port_custom_value() {
        let custom_port: u16 = 2323;
        let telnet_port = if custom_port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            custom_port
        };
        assert_eq!(telnet_port, 2323);
    }

    #[test]
    fn test_addr_format() {
        let hostname = "192.168.1.1";
        let port = DEFAULT_TELNET_PORT;
        let addr = format!("{hostname}:{port}");
        assert_eq!(addr, "192.168.1.1:23");
    }

    #[test]
    fn test_default_prompt_is_valid_regex() {
        let result = regex::Regex::new(DEFAULT_PROMPT);
        assert!(result.is_ok());
    }

    // ── IAC parser tests (new in-house client) ────────────────────────────

    #[test]
    fn test_process_iac_plain_data_passthrough() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        process_iac(b"hello world", &mut data, &mut replies);
        assert_eq!(data, b"hello world");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_process_iac_escaped_ff() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        process_iac(&[b'a', IAC, IAC, b'b'], &mut data, &mut replies);
        assert_eq!(data, vec![b'a', 0xFF, b'b']);
        assert!(replies.is_empty());
    }

    #[test]
    fn test_process_iac_will_refused_with_dont() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        // IAC WILL ECHO (0x01)
        process_iac(&[IAC, WILL, 0x01, b'x'], &mut data, &mut replies);
        assert_eq!(data, b"x");
        assert_eq!(replies, vec![IAC, DONT, 0x01]);
    }

    #[test]
    fn test_process_iac_do_refused_with_wont() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        // IAC DO SGA (0x03)
        process_iac(&[IAC, DO, 0x03], &mut data, &mut replies);
        assert!(data.is_empty());
        assert_eq!(replies, vec![IAC, WONT, 0x03]);
    }

    #[test]
    fn test_process_iac_dont_and_wont_silent() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        process_iac(&[IAC, DONT, 0x01, IAC, WONT, 0x02], &mut data, &mut replies);
        assert!(data.is_empty());
        assert!(replies.is_empty());
    }

    #[test]
    fn test_process_iac_subnegotiation_skipped() {
        let mut data = Vec::new();
        let mut replies = Vec::new();
        // IAC SB <opt> <data> IAC SE then "ok"
        process_iac(
            &[
                IAC, SB, 0x18, 0x00, b'X', b'T', b'E', b'R', b'M', IAC, SE, b'o', b'k',
            ],
            &mut data,
            &mut replies,
        );
        assert_eq!(data, b"ok");
        assert!(replies.is_empty());
    }

    #[test]
    fn test_strip_echo_and_prompt_basic() {
        let raw = "show version\r\nIOS v15.2\r\n\r\nRouter#";
        let out = strip_echo_and_prompt(raw, "show version");
        assert_eq!(out, "IOS v15.2");
    }

    #[test]
    fn test_strip_echo_and_prompt_no_echo() {
        let raw = "line1\r\nline2\r\nRouter>";
        let out = strip_echo_and_prompt(raw, "show version");
        assert_eq!(out, "line1\nline2");
    }
}
