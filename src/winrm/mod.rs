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

/// Refusal of `auth: password` (Basic) over plain HTTP.
const BASIC_OVER_HTTP: &str = "`password` (Basic) over plain HTTP would send the password and \
     every message in clear; use `ntlm`, which works on the same listener and seals the \
     messages, or HTTPS (port 5986 or `winrm_use_tls: true`) with a server certificate that \
     chains to a public root";

/// Refusal of `auth: password` (Basic) with `winrm_accept_invalid_certs`.
const BASIC_UNVERIFIED: &str = "`password` (Basic) with `winrm_accept_invalid_certs` would send \
     the password to a server whose certificate is not verified; use `ntlm`, or a server \
     certificate that chains to a public root (winrm-rs checks the roots it bundles, not the \
     bridge host's certificate store)";

/// Whether `host_config` reaches `WinRM` over HTTPS: `winrm_use_tls` when set,
/// else port 5986.
#[must_use]
pub fn winrm_uses_tls(host_config: &HostConfig) -> bool {
    host_config
        .winrm_use_tls
        .unwrap_or(host_config.port == 5986)
}

/// Why `auth: password` (Basic) is refused for `host_config`, if it is.
///
/// Over plain HTTP the password and every SOAP body would cross in clear;
/// with `winrm_accept_invalid_certs` the password would go to a server nobody
/// verified. winrm-rs 2 refuses both too, but in terms of its own settings,
/// which the bridge does not expose. [`build_winrm_config`] refuses the host
/// with this reason, and the config loader warns with it, so the two cannot
/// disagree.
#[must_use]
pub fn basic_auth_refusal(host_config: &HostConfig) -> Option<&'static str> {
    if !matches!(host_config.auth, crate::config::AuthConfig::Password { .. }) {
        None
    } else if !winrm_uses_tls(host_config) {
        Some(BASIC_OVER_HTTP)
    } else if host_config.winrm_accept_invalid_certs.unwrap_or(false) {
        Some(BASIC_UNVERIFIED)
    } else {
        None
    }
}

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
/// Returns `BridgeError::ConfigInvalid` when `auth` is `Key` or `Agent` (SSH-only),
/// or `password` refused by [`basic_auth_refusal`].
pub fn build_winrm_config(
    host_config: &HostConfig,
) -> Result<(winrm_rs::WinrmConfig, winrm_rs::WinrmCredentials)> {
    if let Some(reason) = basic_auth_refusal(host_config) {
        return Err(BridgeError::ConfigInvalid {
            field: "auth".to_string(),
            reason: reason.to_string(),
        });
    }
    let use_tls = winrm_uses_tls(host_config);

    let mut winrm_cfg = winrm_rs::WinrmConfig {
        port: Some(host_config.port),
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

/// Build the `winrm_rs::WinrmClient` for `host_config`, shared by the `WinRM`
/// and PSRP pools.
///
/// winrm-rs checks the settings when the client is built, before anything is
/// sent. It refuses `auth: password` (Basic) over plain HTTP, where the
/// password and every SOAP body would cross in clear, and over HTTPS with
/// `winrm_accept_invalid_certs`; it refuses `auth: certificate` without TLS
/// or without a usable certificate and key. Those are configuration errors:
/// they are reported with winrm-rs's reason, not as an authentication failure
/// that names no one.
///
/// # Errors
///
/// `BridgeError::ConfigInvalid` when [`build_winrm_config`] refuses the host
/// or winrm-rs refuses the client.
pub fn build_winrm_client(host_config: &HostConfig) -> Result<Arc<winrm_rs::WinrmClient>> {
    let (config, credentials) = build_winrm_config(host_config)?;
    winrm_rs::WinrmClient::new(config, credentials)
        .map(Arc::new)
        .map_err(|e| BridgeError::ConfigInvalid {
            field: "auth".to_string(),
            reason: e.to_string(),
        })
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

/// Switches the console output encoding to UTF-8, without a byte-order mark,
/// before the caller's text runs.
///
/// `powershell.exe` starts on the console's OEM code page (437 on an en-US
/// Windows), whatever `WINRS_CODEPAGE` says, and the adapter decodes stdout as
/// UTF-8: "héllo-€" came back as "h\u{FFFD}llo-?". Measured over `WinRM` with
/// this switch: on Windows `PowerShell` 5.1 (Server 2025), its own strings and
/// native programs' output (`cmd /c echo`) come back in UTF-8, its error
/// records do not; on 4.0 (Server 2012 R2), native programs' output and error
/// records do, its own strings do not. Nothing came back worse.
///
/// Only in `FullLanguage`: in Constrained Language Mode (a host under
/// WDAC/AppLocker script enforcement) `New-Object` of this type is refused, so
/// the switch would add "Cannot create type" to every command's stderr. A
/// skipped `if` leaves `$?` true, where a caught exception would leave it
/// false for a command that is only comments.
const UTF8_OUTPUT_PREFIX: &str = "if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false }";

/// Makes the process exit code the native one when the caller's last
/// statement failed.
///
/// `powershell.exe -EncodedCommand` exits 0 or 1 from `$?` and keeps a native
/// program's code in `$LASTEXITCODE`: `cmd /c exit 3` reported 1. When the
/// last statement succeeded, nothing changes (0); when it failed, the code is
/// `$LASTEXITCODE` if a native program set a non-zero one, else 1. That is the
/// last native program's code, not necessarily the last statement's:
/// `cmd /c exit 3; Get-Item C:\nope` gives 3. A caller's own `exit N` ends the
/// script first and keeps N.
///
/// `$LASTEXITCODE` is read through `Get-Variable`: until a native program has
/// run it does not exist, and reading it bare under `Set-StrictMode` added
/// "The variable '$LASTEXITCODE' cannot be retrieved" to the caller's errors.
/// The blank line first ends a statement the caller left on a trailing
/// backtick, which would otherwise continue onto this line.
const EXIT_CODE_SUFFIX: &str = "\n\nif (-not $?) { $__bridge_mcp_native = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction Ignore; if ($__bridge_mcp_native -is [int] -and $__bridge_mcp_native -ne 0) { exit $__bridge_mcp_native } else { exit 1 } }";

/// The script sent to `powershell.exe` for the caller's `command`.
///
/// What may be added depends on the command's [`ScriptShape`]:
///
/// - [`ScriptShape::Plain`]: [`UTF8_OUTPUT_PREFIX`] and `"; "` on the
///   command's first line, so the line numbers in `PowerShell`'s errors do not
///   move (on a line of its own it gave "At line:2" for a one-line command),
///   then the command, then [`EXIT_CODE_SUFFIX`]. The prefix takes a line of
///   its own above a first line that opens with `#requires`, which is only
///   read as such as the first item on its line.
/// - [`ScriptShape::Preamble`]: the command, then [`EXIT_CODE_SUFFIX`]. It
///   keeps the console code page.
/// - [`ScriptShape::NamedBlocks`]: the command as written, with the exit code
///   and code page it had before the adapter added anything.
fn powershell_script(command: &str) -> String {
    match script_shape(command) {
        ScriptShape::Plain => {
            let separator = if opens_with_requires(command) {
                "\n"
            } else {
                "; "
            };
            format!("{UTF8_OUTPUT_PREFIX}{separator}{command}{EXIT_CODE_SUFFIX}")
        }
        ScriptShape::Preamble => format!("{command}{EXIT_CODE_SUFFIX}"),
        ScriptShape::NamedBlocks => command.to_owned(),
    }
}

/// Whether `command`'s first line opens with `#requires` (any case).
fn opens_with_requires(command: &str) -> bool {
    command
        .lines()
        .next()
        .unwrap_or("")
        .trim_start()
        .get(..9)
        .is_some_and(|word| word.eq_ignore_ascii_case("#requires"))
}

/// What a `PowerShell` script's structure lets an adapter add around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptShape {
    /// Statements only: text may go before and after them.
    Plain,
    /// Opens with a `using` statement or a `param` block (with the attributes
    /// that may precede it), which only the start of a script accepts: text
    /// may follow, nothing may come first.
    Preamble,
    /// Has `begin` / `process` / `end` / `dynamicparam` named blocks, which
    /// nothing may follow and only a preamble may precede.
    NamedBlocks,
}

/// The [`ScriptShape`] of `command`.
///
/// Leading blank space and comments (`#` lines, `#requires` included, and
/// `<# … #>` blocks) are skipped, as the parser skips them. A script that
/// opens with ordinary statements is [`ScriptShape::Plain`] whatever follows:
/// a named block after a statement is already a parse error. After a
/// preamble, finding where the `param` block ends would take a `PowerShell`
/// lexer (its default values can hold strings, brackets and comments), so any
/// `begin {`, `process {`, `end {` or `dynamicparam {` in the text, even in a
/// function or a string, makes it [`ScriptShape::NamedBlocks`]: such a script
/// is sent as written rather than broken.
pub(crate) fn script_shape(command: &str) -> ScriptShape {
    let Some(start) = skip_trivia(command) else {
        // An unterminated block comment: a parse error whatever is added.
        return ScriptShape::Plain;
    };
    if opens_named_block(start) {
        ScriptShape::NamedBlocks
    } else if !opens_preamble(start) {
        ScriptShape::Plain
    } else if mentions_named_block(command) {
        ScriptShape::NamedBlocks
    } else {
        ScriptShape::Preamble
    }
}

/// `text` without its leading blank space and comments; `None` when a block
/// comment never ends.
fn skip_trivia(text: &str) -> Option<&str> {
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("<#") {
            let end = after.find("#>")?;
            rest = after.get(end.saturating_add(2)..)?;
        } else if rest.starts_with('#') {
            rest = rest
                .find('\n')
                .and_then(|end| rest.get(end..))
                .unwrap_or("");
        } else {
            return Some(rest);
        }
    }
}

/// What follows `keyword` when `text` opens with it (any case) as a whole
/// word.
fn after_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let head = text.get(..keyword.len())?;
    let rest = text.get(keyword.len()..)?;
    let word_goes_on = rest
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
    (head.eq_ignore_ascii_case(keyword) && !word_goes_on).then_some(rest)
}

/// Whether `text` opens with a named block: its keyword, then `{`, with
/// only blank space or comments between them.
fn opens_named_block(text: &str) -> bool {
    ["begin", "process", "end", "dynamicparam"]
        .into_iter()
        .any(|keyword| {
            after_keyword(text, keyword)
                .and_then(skip_trivia)
                .is_some_and(|rest| rest.starts_with('{'))
        })
}

/// Whether `text` opens with a `using` statement, a `param` block, or the
/// attributes of one (`[CmdletBinding()]`, `[OutputType([string])]`, …).
/// `[int]'5'` and `[Console]::Out` are expressions: no `param` follows them.
fn opens_preamble(text: &str) -> bool {
    if after_keyword(text, "using").is_some() || after_keyword(text, "param").is_some() {
        return true;
    }
    let mut rest = text;
    while rest.starts_with('[') {
        match after_brackets(rest).and_then(skip_trivia) {
            Some(after) => rest = after,
            None => return false,
        }
    }
    rest.len() < text.len() && after_keyword(rest, "param").is_some()
}

/// `text` after the bracketed group it opens with, nested brackets and
/// brackets inside quoted strings included (`[ValidateSet('a]')]`); `None`
/// when the group never closes.
fn after_brackets(text: &str) -> Option<&str> {
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match quote {
            // Inside a string: a doubled quote stays inside (`'it''s'`), and
            // so does a backtick-escaped character in a double-quoted one.
            Some(open) => {
                if c == '`' && open == '"' {
                    chars.next();
                } else if quote_kind(c) == Some(open) {
                    if chars
                        .clone()
                        .next()
                        .is_some_and(|(_, n)| quote_kind(n) == Some(open))
                    {
                        chars.next();
                    } else {
                        quote = None;
                    }
                }
            }
            None => match c {
                '[' => depth = depth.saturating_add(1),
                ']' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return text.get(at.saturating_add(1)..);
                    }
                }
                _ => quote = quote_kind(c),
            },
        }
    }
    None
}

/// The quote family `c` belongs to: `PowerShell` reads the typographic single
/// quotes (U+2018 to U+201B) as `'` and the double ones (U+201C to U+201E) as
/// `"`.
fn quote_kind(c: char) -> Option<char> {
    match c {
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => Some('\''),
        '"' | '\u{201C}' | '\u{201D}' | '\u{201E}' => Some('"'),
        _ => None,
    }
}

/// Whether a named block opens anywhere in `text`: its keyword as a whole
/// word, not a variable (`$end`), a parameter (`-End`), a member (`.End`) or
/// a scoped name (`$script:end`), then `{`.
fn mentions_named_block(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["begin", "process", "end", "dynamicparam"]
        .into_iter()
        .any(|keyword| {
            lower.match_indices(keyword).any(|(at, _)| {
                let free = lower
                    .get(..at)
                    .and_then(|head| head.chars().next_back())
                    .is_none_or(|c| {
                        !(c.is_alphanumeric() || matches!(c, '_' | '-' | '$' | '.' | ':'))
                    });
                free && lower.get(at..).is_some_and(opens_named_block)
            })
        })
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

        // Logged as the adapter received it, before the wrapping below: the
        // audit log, the history and the security checks never see the
        // prefix and suffix (nor the `Set-Location` a `working_dir` adds
        // upstream).
        debug!(
            host = %self.host_name,
            command = %command,
            cancellable = token.is_some(),
            "Executing WinRM PowerShell command"
        );
        let script = powershell_script(command);

        // The winrm-rs futures are boxed: inlined, they put ~20 KB into every
        // future that awaits a connection (`clippy::large_futures`).
        let output = match token {
            None => {
                Box::pin(self.client.run_powershell_with_timeout(
                    &self.host_name,
                    &script,
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
                    &script,
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

    /// `test_host_config` with NTLM, which winrm-rs accepts over plain HTTP
    /// and with `winrm_accept_invalid_certs` (Basic is refused in both).
    fn ntlm_host_config() -> HostConfig {
        HostConfig {
            auth: crate::config::AuthConfig::Ntlm {
                password: crate::config::RedactedSecret::from("pass"),
                domain: None,
            },
            ..test_host_config()
        }
    }

    #[test]
    fn test_build_winrm_config_password_basic() {
        let host = test_host_config();
        let (cfg, creds) = build_winrm_config(&host).unwrap();
        assert_eq!(cfg.port, Some(5986));
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
        let mut host = ntlm_host_config();
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
        let mut host = ntlm_host_config();
        host.winrm_accept_invalid_certs = Some(true);
        host.winrm_operation_timeout_secs = Some(120);
        host.winrm_max_envelope_size = Some(500_000);
        let (cfg, _) = build_winrm_config(&host).unwrap();
        assert!(cfg.accept_invalid_certs);
        assert_eq!(cfg.operation_timeout_secs, 120);
        assert_eq!(cfg.max_envelope_size, 500_000);
    }

    #[test]
    fn basic_auth_refusal_names_only_password_without_verified_https() {
        let mut host = test_host_config();
        assert_eq!(basic_auth_refusal(&host), None);
        host.winrm_accept_invalid_certs = Some(true);
        assert_eq!(basic_auth_refusal(&host), Some(BASIC_UNVERIFIED));
        host.port = 5985;
        assert_eq!(basic_auth_refusal(&host), Some(BASIC_OVER_HTTP));
        host.winrm_use_tls = Some(true);
        host.winrm_accept_invalid_certs = None;
        assert_eq!(basic_auth_refusal(&host), None);
        let mut ntlm = ntlm_host_config();
        ntlm.port = 5985;
        ntlm.winrm_accept_invalid_certs = Some(true);
        assert_eq!(basic_auth_refusal(&ntlm), None);
    }

    #[test]
    fn password_over_plain_http_is_refused() {
        for (port, use_tls) in [(5985, None), (5986, Some(false))] {
            let mut host = test_host_config();
            host.port = port;
            host.winrm_use_tls = use_tls;
            let err = build_winrm_config(&host).unwrap_err();
            assert!(
                matches!(&err, BridgeError::ConfigInvalid { field, reason }
                    if field == "auth" && reason.contains("plain HTTP")),
                "{err:?}"
            );
        }
    }

    #[test]
    fn password_with_invalid_certs_is_refused() {
        let mut host = test_host_config();
        host.winrm_accept_invalid_certs = Some(true);
        let err = build_winrm_config(&host).unwrap_err();
        assert!(
            matches!(&err, BridgeError::ConfigInvalid { field, reason }
                if field == "auth" && reason.contains("winrm_accept_invalid_certs")),
            "{err:?}"
        );
        // Explicitly verified certificates keep Basic over HTTPS working.
        host.winrm_accept_invalid_certs = Some(false);
        assert!(build_winrm_client(&host).is_ok());
    }

    #[test]
    fn build_winrm_client_reports_a_refusal_of_winrm_rs_as_a_config_error() {
        // winrm-rs refuses certificate authentication without TLS when the
        // client is built; it used to read as "SSH authentication failed
        // for unknown@WinRM".
        let mut host = test_host_config();
        host.port = 5985;
        host.auth = crate::config::AuthConfig::Certificate {
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
        };
        let Err(err) = build_winrm_client(&host) else {
            panic!("winrm-rs accepted certificate authentication over plain HTTP");
        };
        assert!(
            matches!(&err, BridgeError::ConfigInvalid { field, reason }
                if field == "auth" && !reason.is_empty()),
            "{err:?}"
        );
    }

    #[test]
    fn build_winrm_client_accepts_ntlm_over_plain_http() {
        let mut host = ntlm_host_config();
        host.port = 5985;
        assert!(build_winrm_client(&host).is_ok());
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
        // NTLM: winrm-rs refuses Basic over plain HTTP.
        let mut host = ntlm_host_config();
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
    fn powershell_script_wraps_a_plain_command_between_prefix_and_suffix() {
        let script = powershell_script("cmd /c exit 3");
        assert_eq!(
            script,
            format!("{UTF8_OUTPUT_PREFIX}; cmd /c exit 3{EXIT_CODE_SUFFIX}")
        );
    }

    #[test]
    fn powershell_script_keeps_the_callers_line_numbers() {
        // PowerShell reports errors as "At line:N": the caller's line N must
        // still be line N of the script sent.
        let command = "Get-Date\n  Get-Item C:\\nope\r\n'third'";
        let script = powershell_script(command);
        let lines: Vec<&str> = script.lines().collect();
        assert!(lines[0].starts_with(UTF8_OUTPUT_PREFIX));
        assert!(lines[0].ends_with("; Get-Date"));
        assert_eq!(lines[1], "  Get-Item C:\\nope");
        assert_eq!(lines[2], "'third'");
    }

    #[test]
    fn powershell_script_puts_the_prefix_above_a_leading_requires() {
        for command in ["#requires -Version 3\nGet-Date", "  #REQUIRES -Version 3"] {
            assert!(opens_with_requires(command), "{command:?}");
            assert_eq!(
                powershell_script(command),
                format!("{UTF8_OUTPUT_PREFIX}\n{command}{EXIT_CODE_SUFFIX}"),
            );
        }
        // Not on the first line, or not first on it: the prefix stays inline.
        assert!(!opens_with_requires("\n#requires -Version 3"));
        assert!(!opens_with_requires("Get-Date #requires"));
        assert!(!opens_with_requires("#require"));
        assert!(!opens_with_requires(""));
    }

    #[test]
    fn powershell_script_prefix_sets_utf8_without_bom_in_full_language_only() {
        // `UTF8Encoding $false`: `[Text.Encoding]::UTF8` would emit a BOM in
        // front of stdout, which breaks a JSON or base64 reader. Measured in
        // Constrained Language Mode on Server 2025 and 2012 R2: without the
        // guard, every command got "Cannot create type" in stderr.
        assert_eq!(
            UTF8_OUTPUT_PREFIX,
            "if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') \
             { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false }"
        );
    }

    #[test]
    fn powershell_script_suffix_maps_failure_to_the_native_code() {
        // Checked on Windows Server 2025 (PowerShell 5.1) and 2012 R2 (4.0):
        // `cmd /c exit 3` -> 3, `exit 7` -> 7, a failing cmdlet -> 1, a
        // successful last statement -> 0, and under `Set-StrictMode` a
        // failing cmdlet -> 1 with no error about `$LASTEXITCODE`.
        assert_eq!(
            EXIT_CODE_SUFFIX,
            "\n\nif (-not $?) { $__bridge_mcp_native = Get-Variable -Name LASTEXITCODE \
             -ValueOnly -ErrorAction Ignore; if ($__bridge_mcp_native -is [int] -and \
             $__bridge_mcp_native -ne 0) { exit $__bridge_mcp_native } else { exit 1 } }"
        );
        // Never a bare read, which `Set-StrictMode` faults.
        assert!(!EXIT_CODE_SUFFIX.contains("$LASTEXITCODE"));
        // A trailing backtick in the caller's text continues onto the next
        // line only: the blank line ends that statement before the suffix.
        let script = powershell_script("Get-Date `");
        assert!(script.contains("Get-Date `\n\nif (-not $?)"));
    }

    #[test]
    fn powershell_script_adds_only_the_suffix_after_a_preamble() {
        for command in [
            "using namespace System.Text\n[StringBuilder]::new()",
            "param($Name = 'x')\n$Name",
            "Param (\n  [string]$Name\n)\n$Name",
            "[CmdletBinding()]\nparam()\n'ok'",
            "[OutputType([string])] param() 'ok'",
            "[Diagnostics.CodeAnalysis.SuppressMessage('a', '')]\n[CmdletBinding()]\nparam()",
            "#requires -Version 5\nusing namespace System",
            "  <# header #>\n  # note\n  param()",
            "using namespace Ünïcode",
            // A function's own blocks are not named blocks of the script, but
            // `ForEach-Object -Begin {}` and `$end` do not look like them.
            "param($n)\n1..$n | ForEach-Object -Begin { $s = 0 } -Process { $s += $_ } -End { $s }",
            "param()\n$end = 1; $x.End; $script:end",
            // Brackets inside an attribute's quoted arguments.
            "[ValidateSet('a]')]\nparam($x)",
            "[Diagnostics.CodeAnalysis.SuppressMessage(\"x\", 'it''s ]')]\n[CmdletBinding()]\nparam()",
            "[Alias(\"a`\"]\")]\nparam()",
            "[ValidateSet(\u{2018}a]\u{2019})]\nparam($x)",
        ] {
            assert_eq!(script_shape(command), ScriptShape::Preamble, "{command:?}");
            assert_eq!(
                powershell_script(command),
                format!("{command}{EXIT_CODE_SUFFIX}")
            );
        }
    }

    #[test]
    fn powershell_script_sends_named_blocks_as_written() {
        for command in [
            "begin { $n = 0 }\nprocess { $n++ }\nend { $n }",
            "END{ 'done' }",
            "dynamicparam {}",
            "# a filter\nprocess\n{ $_ }",
            "param()\nbegin {}\nend {}",
            "[CmdletBinding()]\nparam([int]$x)\n\nEnd { $x }",
            "using namespace System\nprocess { $_ }",
            // Comments between the keyword and its brace.
            "param()\nprocess # per item\n{ $_ }",
            "param()\nbegin <# setup #> { }\nend { }",
            "end <# c #>\n{ 'x' }",
            // Over-detection, on purpose: a preamble then a function with
            // blocks is sent as written too.
            "param()\nfunction f { begin {} process {} }\nf",
        ] {
            assert_eq!(
                script_shape(command),
                ScriptShape::NamedBlocks,
                "{command:?}"
            );
            assert_eq!(powershell_script(command), command);
        }
    }

    #[test]
    fn powershell_script_wraps_ordinary_commands() {
        for command in [
            "Get-Date",
            "usingfoo",
            "parameters",
            "param-thing",
            "$param = 1",
            "[Console]::OutputEncoding.WebName",
            "[int]'5'",
            "[string[]]$a = 'x', 'y'",
            "[unclosed",
            "# just a comment",
            "# using namespace X\nGet-Date",
            "<# param() #> Get-Date",
            "<# unterminated",
            "",
            "Write-Output 'using namespace X'",
            "beginning",
            "end",
            "process-thing { }",
            "Get-Process",
            "éparam()",
            // A named block after a statement is a parse error either way.
            "Get-Date\nend { }",
            // A function's blocks in a plain script.
            "function f { begin {} process { $_ } }\n1 | f",
        ] {
            assert_eq!(script_shape(command), ScriptShape::Plain, "{command:?}");
            assert!(
                powershell_script(command).starts_with(UTF8_OUTPUT_PREFIX),
                "{command:?}"
            );
        }
    }

    #[test]
    fn after_brackets_skips_one_nested_group() {
        assert_eq!(after_brackets("[a[b]c] d"), Some(" d"));
        assert_eq!(after_brackets("[]"), Some(""));
        assert_eq!(after_brackets("[a"), None);
        assert_eq!(after_brackets("]a["), None);
    }

    #[test]
    fn after_brackets_skips_quoted_strings() {
        assert_eq!(after_brackets("['a]'] x"), Some(" x"));
        assert_eq!(after_brackets("['it''s ]'] x"), Some(" x"));
        assert_eq!(after_brackets("[\"a`\"]\"] x"), Some(" x"));
        assert_eq!(after_brackets("[\"a\"\"]\"] x"), Some(" x"));
        // A backtick is literal in single quotes: the quote after it closes.
        assert_eq!(after_brackets("['a`'] x"), Some(" x"));
        // Typographic quotes close the string they family-match.
        assert_eq!(after_brackets("[\u{2018}a]\u{2019}] x"), Some(" x"));
        assert_eq!(after_brackets("[\u{201C}a]\"] x"), Some(" x"));
        // An unterminated string never closes the group.
        assert_eq!(after_brackets("['a]"), None);
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
