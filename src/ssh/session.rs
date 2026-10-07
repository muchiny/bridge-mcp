//! SSH Session Manager
//!
//! Manages persistent interactive SSH shell sessions that maintain state
//! (working directory, environment variables) across multiple command executions.
//!
//! Each session owns a dedicated SSH connection and an interactive shell channel.
//! Commands are sent through the shell's stdin and output is read until a unique
//! marker appears, enabling reliable output delimiting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::{HostConfig, LimitsConfig, SessionConfig, ShellType};
use crate::error::{BridgeError, Result};

use super::client::SshClient;

/// Marker prefix used to delimit command output in interactive shells
const MARKER_PREFIX: &str = "---SSHB_";

/// How long the next command waits for a timed-out command's leftover output
/// to finish arriving before the session is given up as unusable.
///
/// A command that overran its deadline is still running, and its output plus
/// its markers are still on their way down the same channel. They have to be
/// read and discarded before the next command reads anything, or they would be
/// returned as *its* output. This is the grace the drain gets; past it there is
/// real evidence the session cannot be reused, and it is closed.
const STALE_OUTPUT_DRAIN_TIMEOUT_SECS: u64 = 10;

/// Shell keywords and command prefixes that can lead a command segment without
/// moving the command into a child shell, so an `exit` behind one of them still
/// ends the session's own shell. `(` is deliberately absent: a subshell *does*
/// isolate. `command` and `builtin` are here because they run their argument in
/// the current shell, not a child one.
const SAME_SHELL_LEADING_KEYWORDS: &[&str] = &[
    "{", "!", "if", "then", "elif", "else", "while", "until", "do", "time", "command", "builtin",
];

/// Active shell session with a persistent channel
struct ShellSession {
    id: String,
    host: String,
    shell: ShellType,
    channel: russh::Channel<russh::client::Msg>,
    client: SshClient,
    cwd: String,
    created_at: Instant,
    last_used: Instant,
    /// End marker of a command that overran its deadline and whose output has
    /// therefore not been read yet.
    ///
    /// `Some` means the channel still holds bytes that belong to a *previous*
    /// command. They are drained before the next command is sent; without that,
    /// the next `parse_exec_output` would split on the first occurrence of the
    /// new begin marker and hand the stale text back as the new command's
    /// output — a wrong result reported as a correct one.
    pending_end_marker: Option<String>,
}

/// Session information returned by list operations
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub host: String,
    pub cwd: String,
    pub created_at_secs_ago: u64,
    pub last_used_secs_ago: u64,
}

/// Result of executing a command in a session
#[derive(Debug, Clone, Serialize)]
pub struct SessionExecResult {
    pub session_id: String,
    pub output: String,
    /// The command's exit code, when one representable as a `u32` was read.
    /// `None` means no such code was read: the begin marker was missing, or
    /// the code line is not a decimal `u32`. The shell may well have answered
    /// — a PowerShell `$LASTEXITCODE` is signed and routinely negative — so
    /// `None` is "no usable code", not "unreadable reply", and never "exited 1".
    pub exit_code: Option<u32>,
    pub cwd: String,
}

/// Manages persistent SSH shell sessions
pub struct SessionManager {
    sessions: Mutex<HashMap<String, ShellSession>>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Create a new interactive shell session on the specified host
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The maximum number of sessions has been reached
    /// - SSH connection to the host fails
    /// - Opening a shell channel fails
    pub async fn create(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        jump_host: Option<(&str, &HostConfig)>,
    ) -> Result<SessionInfo> {
        // Check session limit before connecting
        {
            let sessions = self.sessions.lock().await;
            if sessions.len() >= self.config.max_sessions {
                tracing::error!(
                    host = %host_name,
                    current = sessions.len(),
                    max = self.config.max_sessions,
                    "Session limit reached"
                );
                return Err(BridgeError::TooManySessions {
                    max: self.config.max_sessions,
                });
            }
        }

        let session_id = Uuid::new_v4().to_string();

        // Create a dedicated SSH connection (not from pool)
        let client = if let Some((jump_name, jump_config)) = jump_host {
            SshClient::connect_via_jump(host_name, host_config, jump_name, jump_config, limits)
                .await?
        } else {
            SshClient::connect(host_name, host_config, limits).await?
        };

        // Initialize the shell session. If anything fails after connect,
        // close the SSH connection properly (sends SSH DISCONNECT).
        let (channel, shell, cwd) =
            match Self::init_shell(&client, host_config, limits, &session_id).await {
                Ok(result) => result,
                Err(e) => {
                    if let Err(close_err) = client.close().await {
                        warn!(
                            host = %host_name,
                            error = %close_err,
                            "Failed to close client after session init failure"
                        );
                    }
                    return Err(e);
                }
            };

        let now = Instant::now();
        let info = SessionInfo {
            id: session_id.clone(),
            host: host_name.to_string(),
            cwd: cwd.clone(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        let session = ShellSession {
            id: session_id,
            host: host_name.to_string(),
            shell,
            channel,
            client,
            cwd,
            created_at: now,
            last_used: now,
            pending_end_marker: None,
        };

        self.sessions.lock().await.insert(info.id.clone(), session);
        info!(session_id = %info.id, host = %host_name, "Session created");

        Ok(info)
    }

    /// Execute a command in an existing session
    ///
    /// A command that overruns its deadline does **not** destroy the session:
    /// the shell is still there, the command is merely slow. What the timeout
    /// does leave behind is unread output, so the end marker of that command is
    /// remembered and drained before the next command runs — otherwise the next
    /// `parse_exec_output` would hand the previous command's bytes back as this
    /// one's result.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session ID is not found
    /// - The session has expired (max age or idle timeout exceeded)
    /// - The command would run `exit` in the session's own shell, which would
    ///   end the session instead of the command
    /// - An earlier command in the session timed out and still has not
    ///   finished, so its leftover output could not be drained first
    /// - Sending the command to the shell fails
    /// - The command times out
    #[allow(clippy::significant_drop_tightening)]
    pub async fn exec(
        &self,
        session_id: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<SessionExecResult> {
        let mut sessions = self.sessions.lock().await;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| BridgeError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        // Check expiry
        let max_age = Duration::from_secs(self.config.max_age_seconds);
        let max_idle = Duration::from_secs(self.config.idle_timeout_seconds);

        if session.created_at.elapsed() > max_age || session.last_used.elapsed() > max_idle {
            let id = session.id.clone();
            sessions.remove(session_id);
            return Err(BridgeError::SessionExpired { session_id: id });
        }

        // A top-level `exit` is fed to the session's own shell and ends it, so
        // the session — not the command — is what would exit.
        Self::refuse_command_that_ends_the_session(session_id, session.shell, command)?;

        // A previous command in this session overran its deadline. It is still
        // running, so its output and its markers are still on their way down
        // this same channel: read them out and throw them away before sending
        // anything, or they would come back as *this* command's output.
        if let Err(e) = Self::drain_stale_output(session).await {
            // The channel gave EOF or closed while draining. *That* is evidence
            // the shell is gone — the same rule as below, at its other site.
            if Self::read_error_proves_shell_is_gone(&e) {
                if let Some(dead_session) = sessions.remove(session_id) {
                    let _ = dead_session.client.close().await;
                }
                return Err(BridgeError::SshExec {
                    reason: format!(
                        "the session's shell closed while discarding the output of an earlier \
                         command that had timed out ({e}); the session is gone. Create a new one."
                    ),
                });
            }
            // Only a deadline again: the earlier command still has not
            // finished. Nothing may be sent, because its bytes are still ahead
            // of this command's — but that is no more evidence that the shell is
            // dead than the first timeout was, so the session and its pending
            // marker are kept and the caller may retry. An abandoned session is
            // collected by the idle reaper.
            warn!(
                session_id = %session_id,
                "An earlier command in this session has still not finished; refusing to send \
                 a new one whose output could not be told apart from it"
            );
            return Err(BridgeError::SshExec {
                reason: format!(
                    "an earlier command in this session timed out and has still not finished \
                     {STALE_OUTPUT_DRAIN_TIMEOUT_SECS}s later. Its output is still arriving on \
                     this session's channel, so a new command's output could not be told apart \
                     from it. Retry once it has finished, or close the session with \
                     ssh_session_close."
                ),
            });
        }

        // Only now, once this call is actually going to run a command. Marking
        // the session used before the two guards above would keep a session
        // that every call refuses out of reach of the idle reaper: a caller
        // retrying a blocked drain would renew it forever, so it would hold a
        // `max_sessions` slot until `max_age_seconds` — twelve times longer
        // than `idle_timeout_seconds` under the defaults.
        session.last_used = Instant::now();

        let exec_id = Uuid::new_v4().to_string();
        let begin_marker = format!("{MARKER_PREFIX}B_{exec_id}---");
        let end_marker = format!("{MARKER_PREFIX}E_{exec_id}---");

        // Send command with markers (shell-aware)
        let wrapped = Self::build_exec_wrapper(session.shell, command, &begin_marker, &end_marker);

        if let Err(e) = session.channel.data(wrapped.as_bytes()).await {
            // Channel is dead - remove and close the zombie session
            if let Some(dead_session) = sessions.remove(session_id) {
                let _ = dead_session.client.close().await;
            }
            return Err(BridgeError::SshExec {
                reason: format!("Failed to send command to session: {e}"),
            });
        }

        // Read until end marker
        let raw = match Self::read_until_marker_inclusive(
            &mut session.channel,
            &end_marker,
            timeout_secs,
        )
        .await
        {
            Ok(output) => output,
            Err(e) => {
                if Self::read_error_proves_shell_is_gone(&e) {
                    // The channel gave EOF or closed: the shell really is gone.
                    // Remove and close the zombie session.
                    if let Some(dead_session) = sessions.remove(session_id) {
                        let _ = dead_session.client.close().await;
                    }
                } else {
                    // Only the deadline expired. That says nothing about the
                    // shell — the command is merely slow — so the session
                    // stays. What it does say is that this command's output has
                    // not been read: remember its end marker so the next
                    // command drains it instead of receiving it as its own.
                    session.pending_end_marker = Some(end_marker.clone());
                    warn!(
                        session_id = %session_id,
                        "Command timed out; the session is kept and its leftover output will \
                         be discarded before the next command"
                    );
                }
                return Err(e);
            }
        };

        // Parse output
        let (output, exit_code, new_cwd) = Self::parse_exec_output(&raw, &begin_marker);

        session.cwd.clone_from(&new_cwd);

        debug!(
            session_id = %session_id,
            exit_code = ?exit_code,
            cwd = %new_cwd,
            "Session command executed"
        );

        Ok(SessionExecResult {
            session_id: session_id.to_string(),
            output,
            exit_code,
            cwd: new_cwd,
        })
    }

    /// List all active sessions
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .map(|s| SessionInfo {
                id: s.id.clone(),
                host: s.host.clone(),
                cwd: s.cwd.clone(),
                created_at_secs_ago: s.created_at.elapsed().as_secs(),
                last_used_secs_ago: s.last_used.elapsed().as_secs(),
            })
            .collect()
    }

    /// Get the host alias associated with a session
    pub async fn get_session_host(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).map(|s| s.host.clone())
    }

    /// Close a specific session
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is not found.
    pub async fn close(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.remove(session_id) {
            let _ = session.client.close().await;
            info!(session_id = %session_id, "Session closed");
            Ok(())
        } else {
            Err(BridgeError::SessionNotFound {
                session_id: session_id.to_string(),
            })
        }
    }

    /// Close all sessions
    #[allow(clippy::significant_drop_tightening)]
    pub async fn close_all(&self) {
        let mut sessions = self.sessions.lock().await;
        let count = sessions.len();
        let drained: Vec<_> = sessions.drain().collect();
        drop(sessions); // Release lock before closing connections
        for (_, session) in drained {
            let _ = session.client.close().await;
        }
        if count > 0 {
            info!(count = count, "All sessions closed");
        }
    }

    /// Clean up expired sessions
    #[allow(clippy::significant_drop_tightening)]
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.lock().await;
        let max_idle = Duration::from_secs(self.config.idle_timeout_seconds);
        let max_age = Duration::from_secs(self.config.max_age_seconds);

        // Collect expired session IDs
        let expired_ids: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.last_used.elapsed() > max_idle || s.created_at.elapsed() > max_age)
            .map(|(id, _)| id.clone())
            .collect();

        if expired_ids.is_empty() {
            return;
        }

        // Remove expired sessions from the map
        let expired: Vec<_> = expired_ids
            .iter()
            .filter_map(|id| {
                debug!(session_id = %id, "Cleaning up expired session");
                sessions.remove(id)
            })
            .collect();

        let remaining = sessions.len();
        drop(sessions); // Release lock before closing connections

        // Close SSH connections properly (sends SSH DISCONNECT)
        for session in expired {
            if let Err(e) = session.client.close().await {
                warn!(session_id = %session.id, error = %e, "Failed to close expired session");
            }
        }

        info!(
            expired = expired_ids.len(),
            remaining = remaining,
            "Cleaned up expired sessions"
        );
    }

    /// Build the shell initialization command that disables echo and prompts.
    /// Initialize a shell session: open channel, disable echo/prompts, get CWD.
    ///
    /// Extracted to allow the caller to close the SSH client on error.
    async fn init_shell(
        client: &SshClient,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        session_id: &str,
    ) -> Result<(russh::Channel<russh::client::Msg>, ShellType, String)> {
        let mut channel = client.open_shell().await?;
        let shell = host_config.effective_shell();

        // Initialize: disable echo and prompts (shell-aware)
        let init_marker = format!("{MARKER_PREFIX}INIT_{session_id}---");
        let init_cmd = Self::build_init_command(shell, &init_marker);

        channel
            .data(init_cmd.as_bytes())
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to initialize shell: {e}"),
            })?;

        // Wait for init marker (consumes MOTD, bashrc output, etc.)
        Self::read_until_marker(&mut channel, &init_marker, limits.command_timeout_seconds).await?;

        // Get initial working directory (shell-aware)
        let cwd_marker = format!("{MARKER_PREFIX}CWD_{session_id}---");
        let cwd_cmd = Self::build_cwd_command(shell, &cwd_marker);

        channel
            .data(cwd_cmd.as_bytes())
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to get initial cwd: {e}"),
            })?;

        let cwd_output =
            Self::read_until_marker(&mut channel, &cwd_marker, limits.command_timeout_seconds)
                .await?;

        let cwd = cwd_output.lines().last().unwrap_or("/").trim().to_string();

        Ok((channel, shell, cwd))
    }

    /// Build the shell initialization command that disables echo and prompts.
    fn build_init_command(shell: ShellType, marker: &str) -> String {
        match shell {
            ShellType::Posix => format!(
                "stty -echo 2>/dev/null; unset PROMPT_COMMAND; \
                 export PS1='' PS2='' PS3='' PS4=''; \
                 echo \"{marker}\"\n"
            ),
            ShellType::Cmd => format!("@echo off\r\nprompt $S\r\necho {marker}\r\n"),
            ShellType::PowerShell => format!(
                "function prompt {{''}}; \
                 $ProgressPreference='SilentlyContinue'; \
                 Write-Host '{marker}'\n"
            ),
        }
    }

    /// Build the command to retrieve the current working directory.
    fn build_cwd_command(shell: ShellType, marker: &str) -> String {
        match shell {
            ShellType::Posix => format!("pwd\necho \"{marker}\"\n"),
            ShellType::Cmd => format!("cd\r\necho {marker}\r\n"),
            ShellType::PowerShell => format!("(Get-Location).Path\nWrite-Host '{marker}'\n"),
        }
    }

    /// Refuse a command that would end the session's own shell instead of
    /// itself, and tell the caller how to run it without doing that.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::McpInvalidRequest`] when the command runs a
    /// top-level `exit`. Deliberately *not* `CommandDenied`: this is not a
    /// security denial, and `CommandDenied` maps to a different CLI exit code.
    fn refuse_command_that_ends_the_session(
        session_id: &str,
        shell: ShellType,
        command: &str,
    ) -> Result<()> {
        if !Self::command_runs_exit_in_session_shell(command) {
            return Ok(());
        }
        let hint = Self::exit_isolation_hint(shell);
        warn!(
            session_id = %session_id,
            "Refused a command that would have ended the session's shell"
        );
        // The command itself is deliberately NOT quoted back: after elevation
        // it can carry a sudo password.
        Err(BridgeError::McpInvalidRequest(format!(
            "this command runs `exit` in the session's own shell, which would end the session \
             instead of the command — every later call on it would then fail. If the exit \
             status is what you want, {hint}. For a one-shot command outside any session, use \
             ssh_exec."
        )))
    }

    /// Read and discard the output of a command that overran its deadline.
    ///
    /// A command that timed out is still running, so its output and its
    /// begin/end markers are still on their way down the session's channel.
    /// The next command reads from that same channel, and `parse_exec_output`
    /// splits on the first occurrence of the *new* begin marker — so every
    /// stale byte still in flight would be returned as the next command's
    /// output. Reading up to the stale end marker and throwing it away is what
    /// keeps the next result the next command's own.
    ///
    /// Does nothing when no command timed out. `pending_end_marker` is cleared
    /// only on success: a drain that only got part way must be resumed, because
    /// the marker is still ahead in the channel.
    ///
    /// Known narrow limit: the bytes the timed-out read had already consumed are
    /// gone, so if the deadline expired between two channel messages that split
    /// the end marker itself, the drain can never match it and the session stays
    /// unusable until the idle reaper collects it. That fails loudly — every
    /// call returns the error below — and never returns another command's
    /// output. Closing it means carrying the partial read forward, which this
    /// change does not do.
    ///
    /// # Errors
    ///
    /// Returns the read error: [`BridgeError::SshTimeout`] when the earlier
    /// command still has not finished within
    /// `STALE_OUTPUT_DRAIN_TIMEOUT_SECS`, or [`BridgeError::SshExec`] when the
    /// channel gave EOF or closed. The caller decides what each one means for
    /// the session.
    async fn drain_stale_output(session: &mut ShellSession) -> Result<()> {
        let Some(stale_marker) = session.pending_end_marker.clone() else {
            return Ok(());
        };

        let stale = Self::read_until_marker_inclusive(
            &mut session.channel,
            &stale_marker,
            STALE_OUTPUT_DRAIN_TIMEOUT_SECS,
        )
        .await?;

        session.pending_end_marker = None;
        info!(
            session_id = %session.id,
            discarded_bytes = stale.len(),
            "Discarded the leftover output of a command that had timed out"
        );
        Ok(())
    }

    /// Does `command` run `exit` in the session's **own** shell?
    ///
    /// The session is an interactive shell held open across calls, and the
    /// command is fed to that shell as-is. A top-level `exit` therefore ends
    /// the shell itself: the session is destroyed, and every later call on it
    /// fails. The caller is told so and given the isolated forms instead;
    /// refusing is the only way to keep the promise the session makes.
    ///
    /// The rule is **"the first word of a top-level command segment is
    /// `exit`"**, not "the text contains `exit`". Segments are split on `;`,
    /// `&`, `|`, newlines, and a `)` at depth 0 (a `case` arm's pattern
    /// terminator), all outside quotes and outside anything that runs in a child
    /// shell (`( … )`, `$( … )`, backticks); a `#` that starts a word ends the
    /// line at any depth, `$'…'` is read as ANSI-C quoting, where a backslash
    /// escapes, and `${…}` is counted, so that inside a parameter expansion a
    /// `#` is an operator rather than a comment, a separator is text, and a bare
    /// `(` is text — while quotes, nested braces, `$( … )`, backticks and `$'…'`
    /// stay live there, as bash has them.
    /// Leading words that introduce a command without leaving the current
    /// shell (`{`, `then`, `do`, `time`, `command`, `builtin`, a `NAME=value`
    /// assignment, a redirection and its target) are stepped over; `(` is not,
    /// because a subshell genuinely isolates. Matching ignores letter case,
    /// since `cmd.exe` and PowerShell do.
    ///
    /// # Stated limits
    ///
    /// This is a lexical rule, not a shell parser. It is a heuristic, and the
    /// point of this list is that every gap known to it is named here **and**
    /// pinned by a test, so none of them is a guarantee the code does not make.
    ///
    /// Each row below was checked against bash used as an oracle — the command
    /// written into a non-interactive shell's stdin, then `echo`, with a
    /// distinct `exit N` so that a returned `N` proves the branch really ran —
    /// so "bash survives" and "bash dies" are measured, not deduced from how
    /// this lexer looks. `bash -c` cannot model it: there the shell under test
    /// terminates either way. **Two rows are about shells there is no oracle
    /// for here — `cmd.exe` and PowerShell — and both are marked "Reasoned, not
    /// measured".**
    ///
    /// One thing the oracle shows that reading cannot: an *unterminated*
    /// construct is not a death. bash answers rc 2 with `unexpected EOF`, and a
    /// session shell fed one stays alive consuming the wrapper that follows, so
    /// it surfaces as a timeout rather than as a lost session. Several rows
    /// allowed below are that, not a survival.
    ///
    /// **Over-refusals** — refused here although the shell would have survived.
    /// Measured on bash except for the marked row, where bash *dies* and the
    /// refusal is therefore right on bash and wrong only on `cmd.exe`. A clear
    /// error is the safe direction: under-refusal destroys the session in
    /// silence.
    ///
    /// - A here-document body is not recognised, so `cat <<EOF` / `exit` /
    ///   `EOF` is refused although the `exit` is only text.
    /// - `ls | exit` is refused although bash runs every stage of a pipeline in
    ///   a subshell. Whether the last stage runs in the current shell is shell-
    ///   and option-dependent (`lastpipe`, zsh, ksh), so it is refused
    ///   everywhere.
    /// - Matching ignores letter case, so `EXIT 1` is refused although POSIX
    ///   has no such builtin. The cost is nil — no such command exists — and it
    ///   is what makes the rule hold for `cmd.exe` and PowerShell.
    /// - `exit &` and `exit 0 &` are refused although an async list runs in a
    ///   subshell.
    /// - A bare leading number is refused: `1 exit` and `007 exit` look like a
    ///   file descriptor before a command, and nothing here can tell them from
    ///   an ordinary first word.
    /// - A multi-line function body is refused — `func() {` / `exit 1` / `}` —
    ///   while the one-line `func() { exit 1; }` is allowed. Asymmetric, and
    ///   bash survives both, since neither *runs* the body.
    /// - A bad substitution is refused: `echo ${x(} ; exit 120` and its kin have
    ///   no operator, so bash aborts the whole line — the `exit` with it — and
    ///   lives. Refusing costs nothing, because no valid command contains one.
    /// - **Reasoned, not measured:** on `cmd.exe`, `^` escapes a separator and
    ///   this rule does not know it, so `echo a^& exit` is refused although
    ///   cmd.exe would pass `exit` to `echo`. There is no cmd.exe oracle here;
    ///   on bash the same text really does exit, so the refusal is right there.
    ///
    /// **Under-refusals** (allowed here, and the shell really does end —
    /// measured on bash except for the marked row). These can still destroy a
    /// session:
    ///
    /// - Indirection is not followed: `eval exit`, and `command -p exit` — the
    ///   flagged form; the bare `command exit` *is* caught. `$CMD` expanding to
    ///   `exit` likewise.
    /// - A `case` pattern in its optional leading-paren form,
    ///   `case $x in (a) exit;; esac`, looks like a subshell to the depth
    ///   counter. The common form without the leading paren is caught.
    /// - An unbalanced quote makes the rest of the command look quoted, hiding
    ///   a later separator. The imbalance can come from the input — a
    ///   here-document body holding an apostrophe, `cat <<EOF` / `don't` /
    ///   `EOF` / `exit 1`, which is the source known here — **or this lexer can
    ///   manufacture it** out of a perfectly balanced command by tracking a
    ///   construct it does not model wrongly. That is not hypothetical: it is what a
    ///   quote-blind brace counter did to `${x:-"}"}`, and what the ordinary
    ///   single-quote state did to `$'don\'t'`. Both are fixed; the general
    ///   hazard is why this list does not claim to be exhaustive.
    /// - An **unterminated `${`** raises the expansion count for the rest of the
    ///   input, and a separator inside an expansion is text, so every later
    ///   separator is swallowed with it. Usually harmless, because an unmatched
    ///   `${` is a syntax error and bash answers `unexpected EOF` without dying —
    ///   but not always: `cat <<EOF` / `${x` / `EOF` / `exit 98` makes bash
    ///   report a bad substitution for that line, carry on, and exit 98.
    ///   Pre-existing — allowed identically before and after the `${…}` work —
    ///   and named rather than fixed, because closing it needs the here-document
    ///   bodies this rule does not parse.
    /// - A **sourced** script: `. deploy.sh` or `source deploy.sh` runs in this
    ///   shell, so its `exit` ends the session. (A script run the ordinary way
    ///   is a child process and cannot end the session — an earlier version of
    ///   this list said "a script that ends in `exit`", which was wrong.)
    /// - **Reasoned, not measured:** PowerShell's backtick is an escape
    ///   character, but this lexer reads it as command substitution, so a
    ///   separator behind it is swallowed and ``Write-Host `; exit`` is allowed.
    ///   On PowerShell that `exit` ends the session. No PowerShell oracle was
    ///   run here, and bash cannot stand in for one: there the same text is an
    ///   unterminated backtick (rc 2, `unexpected EOF`), not a death, so bash
    ///   cannot adjudicate this row either way.
    /// - **Out of scope:** `logout`, and `exec <cmd>` (which replaces the
    ///   shell), end a session shell the same way and are not detected here.
    fn command_runs_exit_in_session_shell(command: &str) -> bool {
        Self::top_level_segments(command)
            .iter()
            .any(|segment| Self::segment_runs_exit(segment))
    }

    /// Split a command into the segments that run in the session's own shell.
    ///
    /// Everything inside quotes, a subshell, a command substitution or
    /// backticks stays inside the segment it belongs to, because an `exit`
    /// there cannot reach the session shell.
    ///
    /// Two splits are less obvious than the rest and each closes a hole found
    /// by review:
    ///
    /// - A `)` **at depth 0** cannot be closing a `(`, so it is a `case` arm's
    ///   pattern terminator and the arm's body is a new segment. That is what
    ///   catches `case $x in a) exit;; esac`, whose `exit` follows no separator.
    ///   The depth test is what keeps `( exit 7 )` and `echo $(date) exit`
    ///   allowed: there the `)` closes a paren and merely lowers the depth.
    /// - A `#` that starts a word outside quotes is a comment, and the shell
    ///   ignores the rest of the line. Skipping it is not cosmetic: a comment
    ///   holding an apostrophe (`# don't ask`) or a `(` used to open a quote or
    ///   a paren state that swallowed the newline and every command after it.
    fn top_level_segments(command: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut segment = String::new();
        let mut depth: usize = 0;
        // How many `${` parameter expansions are open. Separate from `depth`
        // because a `#` inside `( … )` IS a comment and a `#` inside `${ … }`
        // is an operator.
        //
        // What is live inside a parameter expansion was **measured against
        // bash**, by checking where the expansion ends rather than by reasoning
        // about it (`echo A${x:-…}B` shows it: `A(B` means the `}` closed the
        // expansion, `A}B` means it did not):
        //
        // | inside `${…}`      | live?  | probe result        |
        // |--------------------|--------|---------------------|
        // | `'…'` / `"…"`      | live   | `A}B`               |
        // | `${…}` (nested)    | live   | —                   |
        // | `$( … )`           | live   | `A}B`               |
        // | backtick           | live   | `A}B`               |
        // | `$'…'`             | live   | `A}B`               |
        // | **bare `(`**       | `text` | **`A(B`**           |
        //
        // So exactly one arm needs the guard: the bare `(`, which must not
        // raise `depth`. Everything else stays as it is. A comment and a
        // separator are also text inside an expansion, and are guarded where
        // they are handled.
        //
        // Getting that set wrong is what the two previous bugs were, each from
        // the opposite side. A brace-counting consumer treated *all* of these
        // as text — right about `(`, wrong about quotes. Counting braces while
        // leaving every state live saw quotes — right — but let the unmatched
        // `(` in `${PATH//(/_}` raise `depth` forever, so the separator guard
        // never fired again and the `exit` behind it was swallowed.
        let mut expansion_depth: usize = 0;
        let mut in_single = false;
        let mut in_double = false;
        let mut in_backtick = false;
        let mut escaped = false;
        // True when the next character would begin a word, which is the only
        // position where `#` introduces a comment.
        let mut at_word_start = true;
        let mut chars = command.chars().peekable();

        while let Some(c) = chars.next() {
            let starts_word = at_word_start;
            at_word_start = c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')');

            if escaped {
                segment.push(c);
                escaped = false;
                at_word_start = false;
                continue;
            }
            match c {
                '\\' if !in_single => {
                    escaped = true;
                    segment.push(c);
                }
                '\'' if !in_double && !in_backtick => {
                    in_single = !in_single;
                    segment.push(c);
                }
                '"' if !in_single && !in_backtick => {
                    in_double = !in_double;
                    segment.push(c);
                }
                _ if in_single || in_double => segment.push(c),
                '`' => {
                    in_backtick = !in_backtick;
                    segment.push(c);
                }
                _ if in_backtick => segment.push(c),
                // A comment: the shell ignores the rest of the line, and so
                // must this, or an apostrophe or paren inside it would change
                // how everything after the newline is read. Skipped at **any**
                // depth — a comment inside `( … )` or `$( … )` swallowed the
                // newline and every command after it just as well — but the
                // segment is closed only at depth 0, because closing it deeper
                // would make `echo $(ls # c\nexit )` look like a top-level
                // `exit` when that `exit` is inside the substitution.
                '#' if starts_word && expansion_depth == 0 => {
                    for skipped in chars.by_ref() {
                        if skipped == '\n' {
                            break;
                        }
                    }
                    if depth == 0 {
                        segments.push(std::mem::take(&mut segment));
                    }
                    at_word_start = true;
                }
                // `${…}` opens a parameter expansion, not a command. Counted
                // rather than consumed: the loop's own quote, escape and `$'…'`
                // handling then applies inside it for free, which is what a
                // separate brace-counting consumer got wrong — it could not see
                // that the `}` in `${x:-"}"}` is quoted, so it ended the
                // expansion early and the leftover quote swallowed the
                // separator and the `exit` behind it.
                //
                // Only `${` counts, never a bare `{`, so a quoted brace can
                // never raise the count either.
                '$' if chars.peek() == Some(&'{') => {
                    chars.next();
                    segment.push_str("${");
                    expansion_depth += 1;
                }
                // `$'…'` is ANSI-C quoting, where a backslash escapes — `\'`
                // included, so the closing quote is not the first `'` seen.
                // Reading it with the ordinary single-quote state mistracked it
                // and swallowed the next separator, `exit` and all.
                '$' if chars.peek() == Some(&'\'') => {
                    Self::consume_ansi_c_quoted(&mut chars, &mut segment);
                    at_word_start = false;
                }
                '$' if chars.peek() == Some(&'(') => {
                    chars.next();
                    depth += 1;
                    segment.push_str("$(");
                }
                '(' if expansion_depth == 0 => {
                    depth += 1;
                    segment.push(c);
                }
                // Closing a paren only lowers the depth. At depth 0 there is no
                // paren to close, so this terminates a `case` arm's pattern and
                // what follows is a command in the session's own shell.
                ')' if depth > 0 => {
                    depth -= 1;
                    segment.push(c);
                }
                // Closes a parameter expansion. Reached only when the `}` is
                // outside quotes, because the quote arms above run first — which
                // is the whole point of counting here instead of consuming.
                '}' if expansion_depth > 0 => {
                    expansion_depth -= 1;
                    segment.push(c);
                }
                // `expansion_depth == 0` because a separator inside `${…}` is
                // ordinary text, not a separator: bash prints ` ;exit ` for
                // `echo ${x:- ;exit }` and lives. Without this the counting
                // above would split there and refuse it.
                ')' | ';' | '&' | '|' | '\n' if depth == 0 && expansion_depth == 0 => {
                    segments.push(std::mem::take(&mut segment));
                }
                _ => segment.push(c),
            }
        }
        segments.push(segment);
        segments
    }

    /// Consume a `$'…'` ANSI-C quoted string whole, appending it to `segment`.
    ///
    /// The opening `$` is already consumed and the `'` is next. A backslash
    /// escapes the character after it, `\'` included, so the closing quote is
    /// not the first `'` seen — which is what the ordinary single-quote state
    /// got wrong, swallowing the separator after `$'don\'t'` and the `exit`
    /// behind it.
    fn consume_ansi_c_quoted(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
        segment: &mut String,
    ) {
        chars.next();
        segment.push_str("$'");
        while let Some(quoted) = chars.next() {
            segment.push(quoted);
            if quoted == '\\' {
                if let Some(escaped_char) = chars.next() {
                    segment.push(escaped_char);
                }
            } else if quoted == '\'' {
                break;
            }
        }
    }

    /// Is the command this segment runs `exit`?
    ///
    /// Steps over the leading words that do not move the command into a child
    /// shell, then compares the next word — whole, not as a prefix.
    fn segment_runs_exit(segment: &str) -> bool {
        // Set when a word ended on `<` or `>`: the word after it is the
        // redirection's target, not the command name (`1> /tmp/x exit`).
        let mut expect_redirect_target = false;

        for raw_word in segment.split_whitespace() {
            if expect_redirect_target {
                expect_redirect_target = false;
                continue;
            }
            expect_redirect_target = raw_word.ends_with(['<', '>']);

            // A redirection glued to the command name (`exit>x`) is not part of
            // the name; a redirection written before it (`>x`, `2>/dev/null`) is
            // not a name at all and the name follows it. What is left of the
            // word before the operator is a file descriptor number, if anything.
            let word = raw_word.split(['<', '>']).next().unwrap_or(raw_word);
            if word.eq_ignore_ascii_case("exit") {
                return true;
            }
            if word.is_empty()
                || word.bytes().all(|b| b.is_ascii_digit())
                || SAME_SHELL_LEADING_KEYWORDS.contains(&word)
                || Self::is_assignment_prefix(word)
            {
                continue;
            }
            return false;
        }
        false
    }

    /// Is `word` a `NAME=value` assignment prefix, as in `FOO=bar exit 1`?
    fn is_assignment_prefix(word: &str) -> bool {
        let Some((name, _)) = word.split_once('=') else {
            return false;
        };
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// How to run an `exit` without ending the session, per shell.
    fn exit_isolation_hint(shell: ShellType) -> &'static str {
        match shell {
            ShellType::Posix => {
                "wrap it in a subshell — `( exit 7 )` — or run it in a child shell — \
                 `sh -c 'exit 7'`. A body that runs in a child shell cannot reach this \
                 session's own shell, so it is never refused: that is also the way past \
                 the here-document over-refusal, and `sudo: true` does it incidentally, \
                 since elevation wraps the whole line in `sudo -n bash -c '…'` (or `sudo -S \
                 -p '' bash -c '…'` on a password host) before this rule sees it"
            }
            ShellType::Cmd => "run it in a child interpreter — `cmd /c \"exit 7\"`",
            ShellType::PowerShell => {
                "run it in a child interpreter — `powershell -Command 'exit 7'`"
            }
        }
    }

    /// Does this error from reading a command's output prove the session shell
    /// is gone?
    ///
    /// A deadline that expired does not prove it: the command may simply be
    /// slow and the shell is still there, waiting for it to finish. Every other
    /// error on this path comes from the channel itself — EOF or a close — and
    /// that does prove it. The rule reads the **variant**; the message text
    /// says nothing reliable about which case this is.
    fn read_error_proves_shell_is_gone(err: &BridgeError) -> bool {
        !matches!(err, BridgeError::SshTimeout { .. })
    }

    /// Build the exec wrapper that captures exit code and cwd after a command.
    fn build_exec_wrapper(
        shell: ShellType,
        command: &str,
        begin_marker: &str,
        end_marker: &str,
    ) -> String {
        match shell {
            ShellType::Posix => format!(
                "{command}\n\
                 __sshb_rc=$?\n\
                 echo \"{begin_marker}\"\n\
                 echo $__sshb_rc\n\
                 pwd\n\
                 echo \"{end_marker}\"\n"
            ),
            ShellType::Cmd => format!(
                "{command}\r\n\
                 echo {begin_marker}\r\n\
                 echo %ERRORLEVEL%\r\n\
                 cd\r\n\
                 echo {end_marker}\r\n"
            ),
            ShellType::PowerShell => format!(
                "{command}\n\
                 $__sshb_rc = $LASTEXITCODE; if ($null -eq $__sshb_rc) {{ $__sshb_rc = 0 }}\n\
                 Write-Host '{begin_marker}'\n\
                 Write-Host $__sshb_rc\n\
                 (Get-Location).Path\n\
                 Write-Host '{end_marker}'\n"
            ),
        }
    }

    /// Read channel output until a specific marker string appears.
    ///
    /// Returns everything before the line containing the marker.
    async fn read_until_marker(
        channel: &mut russh::Channel<russh::client::Msg>,
        marker: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let raw = Self::read_until_marker_inclusive(channel, marker, timeout_secs).await?;

        // Return everything before the marker line
        if let Some(pos) = raw.find(marker) {
            let line_start = raw[..pos].rfind('\n').map_or(0, |p| p + 1);
            Ok(raw[..line_start].to_string())
        } else {
            Ok(raw)
        }
    }

    /// Read channel output until a specific marker string appears.
    ///
    /// Returns the full output including the marker line.
    async fn read_until_marker_inclusive(
        channel: &mut russh::Channel<russh::client::Msg>,
        marker: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let mut output = String::new();
        let deadline = Duration::from_secs(timeout_secs);

        let result = timeout(deadline, async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        output.push_str(&String::from_utf8_lossy(&data));
                        if output.contains(marker) {
                            return Ok(());
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        // stderr - include in output
                        output.push_str(&String::from_utf8_lossy(&data));
                        if output.contains(marker) {
                            return Ok(());
                        }
                    }
                    Some(ChannelMsg::Eof) | None => {
                        return Err(BridgeError::SshExec {
                            reason: "Shell session closed unexpectedly".to_string(),
                        });
                    }
                    _ => {}
                }
            }
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(BridgeError::SshTimeout {
                seconds: timeout_secs,
            }),
        }
    }

    /// Parse exec output to extract command output, exit code, and new cwd
    ///
    /// Expected format in `raw`:
    /// ```text
    /// {command output}
    /// {begin_marker}
    /// {exit_code}
    /// {cwd}
    /// {end_marker}  (may or may not be present)
    /// ```
    ///
    /// The exit code is `None` when no code representable as a `u32` was read:
    /// begin marker absent, or the code line missing / not a decimal `u32`
    /// (which includes a negative PowerShell `$LASTEXITCODE`, a reply that was
    /// read perfectly well but does not fit the type). It is never invented —
    /// a real `1` from the shell and "the parser understood nothing" must stay
    /// distinguishable for every consumer downstream.
    #[allow(clippy::option_if_let_else)]
    fn parse_exec_output(raw: &str, begin_marker: &str) -> (String, Option<u32>, String) {
        if let Some(begin_pos) = raw.find(begin_marker) {
            // The output is everything that precedes the marker. The previous
            // split walked back to the last `\n` BEFORE the marker, which
            // returned the empty string whenever the command did not end its
            // output with a newline: the marker then shared the line, `rfind`
            // returned None, `line_start` was 0, and everything was thrown
            // away — a `printf` without `\n`, or a `cat` of a file with no
            // final newline, looked as if it had produced nothing at all.
            let command_output = raw[..begin_pos].trim_end().to_string();

            // After begin marker: exit code and cwd
            let after_begin = begin_pos + begin_marker.len();
            let metadata = raw[after_begin..].trim();
            let mut lines = metadata.lines();

            let exit_code: Option<u32> = lines.next().and_then(|s| s.trim().parse().ok());

            let cwd = lines
                .next()
                .map_or_else(|| "/".to_string(), |s| s.trim().to_string());

            (command_output, exit_code, cwd)
        } else {
            // Fallback: couldn't find begin marker, return the raw output and
            // no exit code — none was read.
            warn!("Could not find begin marker in session output");
            (raw.to_string(), None, "/".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exec_output_basic() {
        let begin = "---SSHB_B_test123---";
        let raw = format!("hello world\nline 2\n{begin}\n0\n/home/user\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "hello world\nline 2");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/home/user");
    }

    #[test]
    fn test_parse_exec_output_nonzero_exit() {
        let begin = "---SSHB_B_test456---";
        let raw = format!("error output\n{begin}\n127\n/tmp\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "error output");
        assert_eq!(exit_code, Some(127));
        assert_eq!(cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_empty_output() {
        let begin = "---SSHB_B_test789---";
        let raw = format!("{begin}\n0\n/root\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/root");
    }

    #[test]
    fn test_parse_exec_output_multiline() {
        let begin = "---SSHB_B_multi---";
        let raw = format!("line 1\nline 2\nline 3\n{begin}\n0\n/var/log\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "line 1\nline 2\nline 3");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/var/log");
    }

    #[test]
    fn test_parse_exec_output_missing_marker() {
        let (output, exit_code, cwd) =
            SessionManager::parse_exec_output("some output", "---MISSING---");
        assert_eq!(output, "some output");
        // No begin marker: no code was read, and none may be invented.
        assert_eq!(exit_code, None);
        assert_eq!(cwd, "/");
    }

    /// The property of the whole change: a command that really exited 1, a
    /// missing begin marker and an unparsable code line are three different
    /// states, and only the first carries a number.
    #[test]
    fn a_real_one_is_distinguishable_from_an_unread_code() {
        let begin = "---SSHB_B_three---";
        let real = format!("out\n{begin}\n1\n/tmp\n");
        let garbled = format!("out\n{begin}\ngarbage\n/tmp\n");
        let (_, real_code, _) = SessionManager::parse_exec_output(&real, begin);
        let (_, garbled_code, _) = SessionManager::parse_exec_output(&garbled, begin);
        let (_, no_marker_code, _) = SessionManager::parse_exec_output("out", begin);
        assert_eq!(real_code, Some(1));
        assert_eq!(garbled_code, None);
        assert_eq!(no_marker_code, None);
        // No `assert_ne!` here: after the three pins above they could not
        // fail. The three `assert_eq!` carry the property by themselves.
    }

    #[test]
    fn test_session_manager_creation() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);
        drop(manager);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        let sessions = manager.list().await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_close_nonexistent() {
        let manager = SessionManager::new(SessionConfig::default());
        let result = manager.close("nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_exec_nonexistent() {
        let manager = SessionManager::new(SessionConfig::default());
        let result = manager.exec("nonexistent", "ls", 30).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_close_all_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        manager.close_all().await;
    }

    #[tokio::test]
    async fn test_cleanup_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        manager.cleanup().await;
    }

    // ============== SessionInfo Tests ==============

    #[test]
    fn test_session_info_serialization() {
        let info = SessionInfo {
            id: "test-uuid".to_string(),
            host: "server1".to_string(),
            cwd: "/home/user".to_string(),
            created_at_secs_ago: 60,
            last_used_secs_ago: 10,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-uuid"));
        assert!(json.contains("server1"));
        assert!(json.contains("/home/user"));
    }

    #[test]
    fn test_session_info_clone() {
        let info = SessionInfo {
            id: "abc123".to_string(),
            host: "host1".to_string(),
            cwd: "/tmp".to_string(),
            created_at_secs_ago: 100,
            last_used_secs_ago: 5,
        };

        let cloned = info.clone();
        assert_eq!(cloned.id, info.id);
        assert_eq!(cloned.host, info.host);
        assert_eq!(cloned.cwd, info.cwd);
    }

    #[test]
    fn test_session_info_debug() {
        let info = SessionInfo {
            id: "debug-test".to_string(),
            host: "debug-host".to_string(),
            cwd: "/".to_string(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("SessionInfo"));
        assert!(debug_str.contains("debug-test"));
    }

    // ============== SessionExecResult Tests ==============

    #[test]
    fn test_session_exec_result_serialization() {
        let result = SessionExecResult {
            session_id: "session-123".to_string(),
            output: "command output".to_string(),
            exit_code: Some(0),
            cwd: "/var/log".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("session-123"));
        assert!(json.contains("command output"));
        assert!(json.contains("exit_code"));
    }

    #[test]
    fn test_session_exec_result_clone() {
        let result = SessionExecResult {
            session_id: "sess1".to_string(),
            output: "hello\nworld".to_string(),
            exit_code: Some(127),
            cwd: "/opt".to_string(),
        };

        let cloned = result.clone();
        assert_eq!(cloned.session_id, result.session_id);
        assert_eq!(cloned.output, result.output);
        assert_eq!(cloned.exit_code, result.exit_code);
        assert_eq!(cloned.cwd, result.cwd);
    }

    #[test]
    fn test_session_exec_result_debug() {
        let result = SessionExecResult {
            session_id: "debug-session".to_string(),
            output: "test output".to_string(),
            exit_code: Some(1),
            cwd: "/home".to_string(),
        };

        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("SessionExecResult"));
    }

    // ============== parse_exec_output Edge Cases ==============

    #[test]
    fn test_parse_exec_output_with_trailing_newlines() {
        let begin = "---SSHB_B_trail---";
        let raw = format!("output line\n\n\n{begin}\n0\n/home\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "output line");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/home");
    }

    #[test]
    fn test_parse_exec_output_with_windows_crlf() {
        let begin = "---SSHB_B_crlf---";
        let raw = format!("line1\r\nline2\r\n{begin}\r\n0\r\n/tmp\r\n");

        let (output, exit_code, _cwd) = SessionManager::parse_exec_output(&raw, begin);
        // Output should contain CRLF as-is
        assert!(output.contains("line1"));
        assert!(output.contains("line2"));
        assert_eq!(exit_code, Some(0));
    }

    #[test]
    fn test_parse_exec_output_with_unicode() {
        let begin = "---SSHB_B_uni---";
        let raw = format!("日本語出力\n中文\n{begin}\n0\n/home/用户\n");

        let (output, _exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("日本語出力"));
        assert!(output.contains("中文"));
        assert_eq!(cwd, "/home/用户");
    }

    #[test]
    fn test_parse_exec_output_exit_code_parse_failure() {
        let begin = "---SSHB_B_bad---";
        let raw = format!("output\n{begin}\nnot_a_number\n/tmp\n");

        let (_, exit_code, actual_cwd) = SessionManager::parse_exec_output(&raw, begin);
        // A code line that does not parse is "not read", not "exited 1".
        assert_eq!(exit_code, None);
        assert_eq!(actual_cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_missing_cwd() {
        let begin = "---SSHB_B_nocwd---";
        let raw = format!("output\n{begin}\n0\n");

        let (_, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, Some(0));
        // When cwd is missing, default to "/"
        assert_eq!(cwd, "/");
    }

    #[test]
    fn test_parse_exec_output_empty_raw() {
        let (output, exit_code, cwd) = SessionManager::parse_exec_output("", "---MARKER---");
        assert_eq!(output, "");
        // Empty input has no marker, hence no code.
        assert_eq!(exit_code, None);
        assert_eq!(cwd, "/");
    }

    #[test]
    fn test_parse_exec_output_only_marker() {
        let begin = "---SSHB_B_only---";
        let raw = format!("{begin}\n0\n/root\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/root");
    }

    #[test]
    fn test_parse_exec_output_special_chars_in_output() {
        let begin = "---SSHB_B_special---";
        let raw = format!("output with $VAR and `backticks` and \"quotes\"\n{begin}\n0\n/tmp\n");

        let (output, _, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("$VAR"));
        assert!(output.contains("`backticks`"));
        assert!(output.contains("\"quotes\""));
    }

    #[test]
    fn test_parse_exec_output_very_large_exit_code() {
        let begin = "---SSHB_B_large---";
        let raw = format!("output\n{begin}\n4294967295\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, Some(u32::MAX));
    }

    #[test]
    fn test_parse_exec_output_negative_exit_code() {
        let begin = "---SSHB_B_neg---";
        let raw = format!("output\n{begin}\n-1\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // A negative number is not a u32: the code was not read, not 1.
        assert_eq!(exit_code, None);
    }

    // ============== SessionManager Lifecycle Tests ==============

    #[tokio::test]
    async fn test_manager_multiple_list_calls() {
        let manager = SessionManager::new(SessionConfig::default());

        let list1 = manager.list().await;
        let list2 = manager.list().await;
        let list3 = manager.list().await;

        assert!(list1.is_empty());
        assert!(list2.is_empty());
        assert!(list3.is_empty());
    }

    #[tokio::test]
    async fn test_manager_cleanup_multiple_times() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.cleanup().await;
        manager.cleanup().await;
        manager.cleanup().await;

        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_manager_close_all_then_list() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.close_all().await;
        let list = manager.list().await;

        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_manager_cleanup_then_close_all() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.cleanup().await;
        manager.close_all().await;

        assert!(manager.list().await.is_empty());
    }

    // ============== SessionConfig Tests ==============

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        // Verify defaults are sensible
        assert!(config.max_sessions > 0);
        assert!(config.idle_timeout_seconds > 0);
        assert!(config.max_age_seconds > 0);
    }

    // ============== Concurrent Manager Access ==============

    #[tokio::test]
    async fn test_manager_concurrent_list_calls() {
        let manager = std::sync::Arc::new(SessionManager::new(SessionConfig::default()));

        let mut handles = vec![];
        for _ in 0..10 {
            let mgr = manager.clone();
            handles.push(tokio::spawn(async move { mgr.list().await }));
        }

        for handle in handles {
            let list = handle.await.unwrap();
            assert!(list.is_empty());
        }
    }

    #[tokio::test]
    async fn test_manager_concurrent_close_nonexistent() {
        let manager = std::sync::Arc::new(SessionManager::new(SessionConfig::default()));

        let mut handles = vec![];
        for i in 0..5 {
            let mgr = manager.clone();
            let id = format!("nonexistent-{i}");
            handles.push(tokio::spawn(async move { mgr.close(&id).await }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_err());
        }
    }

    // ============== parse_exec_output Additional Edge Cases ==============

    #[test]
    fn test_parse_exec_output_marker_at_start() {
        let begin = "---SSHB_B_start---";
        let raw = format!("{begin}\n0\n/home\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/home");
    }

    #[test]
    fn test_parse_exec_output_very_long_output() {
        let begin = "---SSHB_B_long---";
        let long_output = "x".repeat(100_000);
        let raw = format!("{long_output}\n{begin}\n0\n/tmp\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output.len(), 100_000);
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_binary_garbage() {
        let begin = "---SSHB_B_bin---";
        let raw = format!("\x00\x01\x02output\n{begin}\n0\n/bin\n");

        let (output, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("output"));
        assert_eq!(exit_code, Some(0));
    }

    #[test]
    fn test_parse_exec_output_path_with_spaces() {
        let begin = "---SSHB_B_space---";
        let raw = format!("output\n{begin}\n0\n/home/user/my folder/sub dir\n");

        let (_, _, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(cwd, "/home/user/my folder/sub dir");
    }

    #[test]
    fn test_parse_exec_output_path_with_unicode() {
        let begin = "---SSHB_B_uni---";
        let raw = format!("output\n{begin}\n0\n/home/ユーザー/ドキュメント\n");

        let (_, _, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert!(cwd.contains("ユーザー"));
    }

    #[test]
    fn test_parse_exec_output_exit_code_with_whitespace() {
        let begin = "---SSHB_B_ws---";
        let raw = format!("output\n{begin}\n  42  \n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, Some(42));
    }

    #[test]
    fn test_parse_exec_output_overflow_exit_code() {
        let begin = "---SSHB_B_over---";
        // u32::MAX + 1 should fail to parse
        let raw = format!("output\n{begin}\n4294967296\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Out of u32 range: not read. Never a fabricated 1.
        assert_eq!(exit_code, None);
    }

    #[test]
    fn test_parse_exec_output_float_exit_code() {
        let begin = "---SSHB_B_float---";
        let raw = format!("output\n{begin}\n1.5\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // A float is not a decimal u32: not read. Never a fabricated 1.
        assert_eq!(exit_code, None);
    }

    #[test]
    fn test_parse_exec_output_hex_exit_code() {
        let begin = "---SSHB_B_hex---";
        let raw = format!("output\n{begin}\n0xFF\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Hex is not a decimal u32: not read. Never a fabricated 1.
        assert_eq!(exit_code, None);
    }

    #[test]
    fn test_parse_exec_output_marker_in_output() {
        // What if the output contains something that looks like a marker?
        let begin = "---SSHB_B_meta---";
        let raw = format!("some output with ---SSHB--- in it\n{begin}\n0\n/tmp\n");

        let (output, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("---SSHB---"));
        assert_eq!(exit_code, Some(0));
    }

    // ============== SessionInfo Tests ==============

    #[test]
    fn test_session_info_all_fields() {
        let info = SessionInfo {
            id: "abc-123-def".to_string(),
            host: "production-server".to_string(),
            cwd: "/var/www/html".to_string(),
            created_at_secs_ago: 3600,
            last_used_secs_ago: 60,
        };

        assert_eq!(info.id, "abc-123-def");
        assert_eq!(info.host, "production-server");
        assert_eq!(info.cwd, "/var/www/html");
        assert_eq!(info.created_at_secs_ago, 3600);
        assert_eq!(info.last_used_secs_ago, 60);
    }

    #[test]
    fn test_session_info_max_values() {
        let info = SessionInfo {
            id: "max".to_string(),
            host: "host".to_string(),
            cwd: "/".to_string(),
            created_at_secs_ago: u64::MAX,
            last_used_secs_ago: u64::MAX,
        };

        assert_eq!(info.created_at_secs_ago, u64::MAX);
        assert_eq!(info.last_used_secs_ago, u64::MAX);
    }

    #[test]
    fn test_session_info_empty_strings() {
        let info = SessionInfo {
            id: String::new(),
            host: String::new(),
            cwd: String::new(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        assert_eq!(info.id, "");
        assert_eq!(info.host, "");
        assert_eq!(info.cwd, "");
    }

    // ============== SessionExecResult Tests ==============

    #[test]
    fn test_session_exec_result_all_fields() {
        let result = SessionExecResult {
            session_id: "session-xyz".to_string(),
            output: "Hello, World!\n".to_string(),
            exit_code: Some(0),
            cwd: "/home/user".to_string(),
        };

        assert_eq!(result.session_id, "session-xyz");
        assert_eq!(result.output, "Hello, World!\n");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.cwd, "/home/user");
    }

    #[test]
    fn test_session_exec_result_empty_output() {
        let result = SessionExecResult {
            session_id: "sess".to_string(),
            output: String::new(),
            exit_code: Some(0),
            cwd: "/".to_string(),
        };

        assert_eq!(result.output, "");
    }

    #[test]
    fn test_session_exec_result_large_output() {
        let large_output = "x".repeat(1_000_000);
        let result = SessionExecResult {
            session_id: "large".to_string(),
            output: large_output.clone(),
            exit_code: Some(0),
            cwd: "/".to_string(),
        };

        assert_eq!(result.output.len(), 1_000_000);
    }

    #[test]
    fn test_session_exec_result_json_serialization() {
        let result = SessionExecResult {
            session_id: "test-123".to_string(),
            output: "output\nwith\nnewlines".to_string(),
            exit_code: Some(42),
            cwd: "/test".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test-123"));
        assert!(json.contains("42"));
        assert!(json.contains("/test"));

        // Verify it can be deserialized (if we had Deserialize)
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["exit_code"], 42);

        let unread = SessionExecResult {
            exit_code: None,
            ..result
        };
        let value: serde_json::Value = serde_json::to_value(&unread).unwrap();
        assert!(
            value["exit_code"].is_null(),
            "unread code serializes as null"
        );
    }

    // ============== SessionConfig Edge Cases ==============

    #[test]
    fn test_session_config_custom_values() {
        let config = SessionConfig {
            max_sessions: 100,
            idle_timeout_seconds: 7200,
            max_age_seconds: 86400,
        };

        assert_eq!(config.max_sessions, 100);
        assert_eq!(config.idle_timeout_seconds, 7200);
        assert_eq!(config.max_age_seconds, 86400);
    }

    #[test]
    fn test_session_config_zero_values() {
        let config = SessionConfig {
            max_sessions: 0,
            idle_timeout_seconds: 0,
            max_age_seconds: 0,
        };

        assert_eq!(config.max_sessions, 0);
        assert_eq!(config.idle_timeout_seconds, 0);
        assert_eq!(config.max_age_seconds, 0);
    }

    // ============== MARKER_PREFIX Tests ==============

    #[test]
    fn test_marker_prefix_format() {
        // MARKER_PREFIX should be unique and recognizable
        assert!(MARKER_PREFIX.starts_with("---"));
        assert!(MARKER_PREFIX.contains("SSHB"));
    }

    // ============== build_init_command Tests ==============

    #[test]
    fn test_build_init_command_posix() {
        let cmd = SessionManager::build_init_command(ShellType::Posix, "MARKER_123");
        assert!(cmd.contains("stty -echo"));
        assert!(cmd.contains("PS1=''"));
        assert!(cmd.contains("MARKER_123"));
    }

    #[test]
    fn test_build_init_command_cmd() {
        let cmd = SessionManager::build_init_command(ShellType::Cmd, "MARKER_456");
        assert!(cmd.contains("@echo off"));
        assert!(cmd.contains("prompt $S"));
        assert!(cmd.contains("MARKER_456"));
    }

    #[test]
    fn test_build_init_command_powershell() {
        let cmd = SessionManager::build_init_command(ShellType::PowerShell, "MARKER_789");
        assert!(cmd.contains("function prompt"));
        assert!(cmd.contains("SilentlyContinue"));
        assert!(cmd.contains("MARKER_789"));
    }

    // ============== build_cwd_command Tests ==============

    #[test]
    fn test_build_cwd_command_posix() {
        let cmd = SessionManager::build_cwd_command(ShellType::Posix, "CWD_MARKER");
        assert!(cmd.contains("pwd"));
        assert!(cmd.contains("CWD_MARKER"));
    }

    #[test]
    fn test_build_cwd_command_cmd() {
        let cmd = SessionManager::build_cwd_command(ShellType::Cmd, "CWD_MARKER");
        assert!(cmd.contains("cd\r\n"));
        assert!(cmd.contains("CWD_MARKER"));
    }

    #[test]
    fn test_build_cwd_command_powershell() {
        let cmd = SessionManager::build_cwd_command(ShellType::PowerShell, "CWD_MARKER");
        assert!(cmd.contains("Get-Location"));
        assert!(cmd.contains("CWD_MARKER"));
    }

    // ============== build_exec_wrapper Tests ==============

    #[test]
    fn test_build_exec_wrapper_posix() {
        let cmd = SessionManager::build_exec_wrapper(ShellType::Posix, "ls -la", "BEGIN", "END");
        assert!(cmd.contains("ls -la"));
        assert!(cmd.contains("BEGIN"));
        assert!(cmd.contains("END"));
        assert!(cmd.contains("__sshb_rc=$?"));
        assert!(cmd.contains("pwd"));
    }

    #[test]
    fn test_build_exec_wrapper_cmd() {
        let cmd = SessionManager::build_exec_wrapper(ShellType::Cmd, "dir", "BEGIN", "END");
        assert!(cmd.contains("dir"));
        assert!(cmd.contains("BEGIN"));
        assert!(cmd.contains("END"));
        assert!(cmd.contains("%ERRORLEVEL%"));
        assert!(cmd.contains("cd\r\n"));
    }

    #[test]
    fn test_build_exec_wrapper_powershell() {
        let cmd = SessionManager::build_exec_wrapper(
            ShellType::PowerShell,
            "Get-Process",
            "BEGIN",
            "END",
        );
        assert!(cmd.contains("Get-Process"));
        assert!(cmd.contains("BEGIN"));
        assert!(cmd.contains("END"));
        assert!(cmd.contains("$LASTEXITCODE"));
        assert!(cmd.contains("Get-Location"));
    }

    // ============== get_session_host Tests ==============

    #[tokio::test]
    async fn test_get_session_host_nonexistent() {
        let manager = SessionManager::new(SessionConfig::default());
        assert!(manager.get_session_host("nonexistent").await.is_none());
    }

    #[test]
    fn test_marker_not_in_common_output() {
        let common_outputs = [
            "ls -la",
            "total 42",
            "drwxr-xr-x",
            "Hello World",
            "Error: command not found",
            "#!/bin/bash",
        ];

        for output in common_outputs {
            assert!(!output.contains(MARKER_PREFIX));
        }
    }

    // ============== build_init_command Content Verification ==============

    #[test]
    fn test_build_init_command_posix_disables_all_prompts() {
        let cmd = SessionManager::build_init_command(ShellType::Posix, "MARKER");
        assert!(cmd.contains("PS1=''"));
        assert!(cmd.contains("PS2=''"));
        assert!(cmd.contains("PS3=''"));
        assert!(cmd.contains("PS4=''"));
        assert!(cmd.contains("unset PROMPT_COMMAND"));
    }

    #[test]
    fn test_build_init_command_posix_ends_with_newline() {
        let cmd = SessionManager::build_init_command(ShellType::Posix, "MARKER");
        assert!(cmd.ends_with('\n'));
    }

    #[test]
    fn test_build_init_command_cmd_uses_crlf() {
        let cmd = SessionManager::build_init_command(ShellType::Cmd, "MARKER");
        assert!(cmd.contains("\r\n"));
    }

    #[test]
    fn test_build_init_command_powershell_disables_progress() {
        let cmd = SessionManager::build_init_command(ShellType::PowerShell, "MARKER");
        assert!(cmd.contains("$ProgressPreference='SilentlyContinue'"));
    }

    // ============== build_cwd_command Content Verification ==============

    #[test]
    fn test_build_cwd_command_posix_uses_echo() {
        let cmd = SessionManager::build_cwd_command(ShellType::Posix, "MARKER");
        assert!(cmd.contains("echo \"MARKER\""));
    }

    #[test]
    fn test_build_cwd_command_powershell_uses_write_host() {
        let cmd = SessionManager::build_cwd_command(ShellType::PowerShell, "MARKER");
        assert!(cmd.contains("Write-Host 'MARKER'"));
    }

    // ============== build_exec_wrapper Content Verification ==============

    #[test]
    fn test_build_exec_wrapper_posix_captures_exit_code() {
        let cmd = SessionManager::build_exec_wrapper(ShellType::Posix, "test_cmd", "B", "E");
        // The wrapper should capture exit code before any other command
        let rc_pos = cmd.find("__sshb_rc=$?").unwrap();
        let begin_pos = cmd.find('B').unwrap();
        assert!(
            rc_pos < begin_pos,
            "Exit code should be captured before begin marker"
        );
    }

    #[test]
    fn test_build_exec_wrapper_powershell_handles_null_lastexitcode() {
        let cmd =
            SessionManager::build_exec_wrapper(ShellType::PowerShell, "Write-Host hi", "B", "E");
        // PowerShell should handle null $LASTEXITCODE (non-native commands)
        assert!(cmd.contains("$null"));
        assert!(cmd.contains("$__sshb_rc = 0"));
    }

    #[test]
    fn test_build_exec_wrapper_cmd_captures_errorlevel() {
        let cmd = SessionManager::build_exec_wrapper(ShellType::Cmd, "dir", "B", "E");
        assert!(cmd.contains("echo %ERRORLEVEL%"));
    }

    #[test]
    fn test_build_exec_wrapper_with_multiline_command() {
        let cmd = SessionManager::build_exec_wrapper(
            ShellType::Posix,
            "echo line1\necho line2",
            "BEGIN",
            "END",
        );
        assert!(cmd.contains("echo line1\necho line2"));
        assert!(cmd.contains("BEGIN"));
        assert!(cmd.contains("END"));
    }

    #[test]
    fn test_build_exec_wrapper_with_special_chars_in_command() {
        let cmd = SessionManager::build_exec_wrapper(
            ShellType::Posix,
            "echo 'hello \"world\"' | grep -c hello",
            "B",
            "E",
        );
        assert!(cmd.contains("echo 'hello \"world\"' | grep -c hello"));
    }

    // ============== parse_exec_output with end_marker present ==============

    #[test]
    fn test_parse_exec_output_with_end_marker() {
        let begin = "---SSHB_B_test---";
        let end = "---SSHB_E_test---";
        let raw = format!("output here\n{begin}\n0\n/home/user\n{end}\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "output here");
        assert_eq!(exit_code, Some(0));
        assert_eq!(cwd, "/home/user");
    }

    #[test]
    fn test_parse_exec_output_cwd_with_trailing_whitespace() {
        let begin = "---SSHB_B_ws---";
        let raw = format!("output\n{begin}\n0\n  /home/user  \n");

        let (_, _, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(cwd, "/home/user");
    }

    // ============== SessionManager Config Interaction ==============

    #[test]
    fn test_session_config_idle_less_than_age() {
        let config = SessionConfig {
            max_sessions: 10,
            idle_timeout_seconds: 300,
            max_age_seconds: 3600,
        };
        // Sensible: idle timeout should be less than max age
        assert!(config.idle_timeout_seconds < config.max_age_seconds);
    }

    #[tokio::test]
    async fn test_manager_get_session_host_returns_none_for_empty_manager() {
        let manager = SessionManager::new(SessionConfig::default());
        let host = manager.get_session_host("any-id").await;
        assert!(host.is_none());
    }

    #[tokio::test]
    async fn test_manager_exec_returns_session_not_found() {
        let manager = SessionManager::new(SessionConfig::default());
        let err = manager.exec("missing-id", "ls", 30).await.unwrap_err();
        match err {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "missing-id");
            }
            other => panic!("Expected SessionNotFound, got: {other:?}"),
        }
    }

    // ============== Task 4: output without a trailing newline ==============

    #[test]
    fn output_without_a_trailing_newline_is_not_swallowed() {
        let begin = "__BEGIN__";
        // The command wrote "sans-nl" with no `\n`, so the marker shares the line.
        let raw = format!("sans-nl{begin}\n0\n/home/muchini\n");
        let (out, rc, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(
            out, "sans-nl",
            "output without a trailing newline was thrown away"
        );
        assert_eq!(rc, Some(0));
        assert_eq!(cwd, "/home/muchini");
    }

    #[test]
    fn output_with_a_trailing_newline_still_parses() {
        let begin = "__BEGIN__";
        let raw = format!("avec-nl\n{begin}\n0\n/home/muchini\n");
        let (out, rc, _) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(out, "avec-nl");
        assert_eq!(rc, Some(0));
    }

    // ============== Task 4: a top-level `exit` is refused, not run ==============

    /// The table of ruling R5, one row per case, verbatim.
    #[test]
    fn top_level_exit_detection_matches_the_required_table() {
        for refused in ["exit", "exit 7", "cd /tmp && exit 1"] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "must be refused, it would kill the session shell: {refused}"
            );
        }
        for allowed in [
            "grep exit /etc/passwd",
            "cd /tmp",
            "echo done",
            "( exit 7 )",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "must be allowed: {allowed}"
            );
        }
    }

    #[test]
    fn exit_is_detected_after_every_top_level_separator() {
        for refused in [
            "ls; exit",
            "ls || exit 2",
            "ls | exit",
            "ls\nexit 3",
            "ls;exit",
            "exit;ls",
            "exit & ",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "must be refused: {refused}"
            );
        }
    }

    #[test]
    fn exit_inside_a_child_shell_is_allowed() {
        for allowed in [
            "( exit 7 )",
            "(exit 7)",
            "ls; ( exit 7 )",
            "echo $(exit 7)",
            "echo `exit 7`",
            "sh -c 'exit 7'",
            "bash -c \"exit 7\"",
            "sudo -n bash -c 'exit 7'",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "the caller isolated it deliberately, it cannot kill the session: {allowed}"
            );
        }
    }

    #[test]
    fn exit_inside_a_quoted_string_is_not_a_command() {
        for allowed in [
            "echo \"a; exit\"",
            "echo 'a; exit'",
            "echo 'exit'",
            "grep -E '^exit$' /etc/profile",
            "awk '{print $1}' f; echo ok",
            "echo \"don't\"; echo ok",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "must be allowed, the `exit` is quoted text: {allowed}"
            );
        }
    }

    #[test]
    fn exit_must_be_the_whole_word_not_a_prefix() {
        for allowed in [
            "exitcode=1",
            "exit7",
            "exiting",
            "./exit_handler",
            "systemctl status exit.service",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "must be allowed, `exit` is only a prefix here: {allowed}"
            );
        }
    }

    /// `{ … }`, `then`, `do` and `time` run the command in the *same* shell,
    /// so an `exit` behind them still kills the session. `( … )` does not.
    #[test]
    fn exit_behind_a_same_shell_keyword_is_still_refused() {
        for refused in [
            "{ exit 7; }",
            "if true; then exit 1; fi",
            "for i in 1 2; do exit 1; done",
            "time exit 1",
            "! exit 1",
            "FOO=bar exit 1",
            "exit>/dev/null",
            ">/tmp/x exit 1",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "must be refused, this `exit` runs in the session's own shell: {refused}"
            );
        }
    }

    /// A `case` arm's body runs in the session's own shell, and its `exit`
    /// follows a `)` rather than a separator. Review finding, Important 1.
    #[test]
    fn exit_in_a_case_arm_is_refused() {
        for refused in [
            "case $x in a) exit;; esac",
            "case \"$x\" in *) exit 1;; esac",
            "case $x in a|b) exit;; esac",
            "case $x in a) cd /tmp;; b) exit 1;; esac",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a case arm runs in the session's own shell: {refused}"
            );
        }
    }

    /// A `)` that closes a `(` is not a case-arm terminator: the paren forms
    /// must stay allowed, which is why the split is made where the depth is
    /// known rather than on the word.
    #[test]
    fn a_closing_subshell_paren_is_not_a_case_arm_terminator() {
        for allowed in [
            "( exit 7 )",
            "(exit 7)",
            "echo $(exit 7)",
            "echo $(date) exit",
            "f() ( exit )",
            "(( 1 > 0 )) && echo ok",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "a `)` closing a `(` must not turn into a segment break: {allowed}"
            );
        }
    }

    /// A `#` comment used to open a quote or a paren that swallowed the rest
    /// of the command, `exit` included. Review finding, Important 2.
    #[test]
    fn a_comment_does_not_hide_the_exit_after_it() {
        for refused in [
            "cd /app  # don't ask\nexit 1",
            "echo hi # note (paren\nexit",
            "ls # comment\nexit 7",
            "ls #\nexit",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a comment must not hide the command after it: {refused:?}"
            );
        }
    }

    /// A comment inside `( … )` or `$( … )` swallowed the newline and the
    /// command after it just as well as one at top level. Re-review, A.
    /// Every input here was confirmed against bash: a shell fed it on stdin
    /// dies, so refusing is correct and not over-refusal.
    #[test]
    fn a_comment_inside_a_subshell_does_not_hide_the_exit_after_it() {
        for refused in [
            "( ls # don't\n) ; exit",
            "echo $(ls # don't\n) ; exit",
            "echo $(ls | # don't\ncat) ; exit",
            "( ls # note (paren\n) ; exit",
            "if true; then ( ls # don't\n) ; fi ; exit",
            "( echo A # don't\n) ; exit 9",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a comment inside a paren must not hide the command after it: {refused:?}"
            );
        }
    }

    /// The other half of that fix: the comment is skipped at any depth, but the
    /// segment is closed only at depth 0, or the `exit` *inside* the
    /// substitution would look like a top-level one. Every input here was
    /// confirmed alive in bash, so refusing any of them would be over-refusal.
    #[test]
    fn an_exit_inside_a_commented_substitution_is_still_allowed() {
        for allowed in [
            "echo $(ls # c\nexit )",
            "( # comment\n echo hi )",
            "( # comment\n exit )",
            "( echo ${x#prefix} )",
            "echo ${#PATH}",
            "( grep -c '#' /etc/hosts )",
            "( echo a#b )",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "skipping comments at depth must not break this: {allowed:?}"
            );
        }
        // `$'…'` is not ANSI-C quoting inside double quotes, and the separator
        // after it must still split. bash dies on this one.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("echo \"$'x'\" ; exit"),
            "a `$'` inside double quotes is literal, and the `;` still separates"
        );
    }

    /// A `#` inside `${…}` is an operator, not a comment, so skipping to
    /// end-of-line from inside one swallowed the separator and the `exit`
    /// behind it. Re-review round 3, minor 1. Each input below was confirmed
    /// against bash with a distinct `exit N`: the process really returned `N`,
    /// which proves the branch ran rather than merely that the shell is gone.
    #[test]
    fn a_hash_inside_a_parameter_expansion_does_not_hide_the_exit() {
        for refused in [
            "echo ${x:- #} ; exit",
            "echo ${UNSET:- #hi} ; exit 4",
            "echo ${PATH/ #/X} ; exit 6",
            "echo ${x:- #} ; exit 7",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a `#` inside ${{…}} is an operator, and the exit behind it is real: {refused}"
            );
        }
    }

    /// A quoted brace inside `${…}` must not end the expansion. Counting braces
    /// without looking at quotes ended it early, and the leftover quote then
    /// swallowed the separator and the `exit` behind it — a regression this task
    /// introduced and then removed, not a pre-existing gap. bash dies on every
    /// row below, each at the return code its `exit` names.
    #[test]
    fn a_quoted_brace_inside_a_parameter_expansion_does_not_hide_the_exit() {
        for refused in [
            "echo ${x:-\"}\"} ; exit",
            "echo ${x:-'}'} ; exit",
            "echo ${x:-\"{\"} ; exit 29",
            "echo ${x:-'{'} ; exit 30",
            "echo ${x#\"}\"} ; exit 32",
            "echo ${x:-$'}'} ; exit 35",
            "VAR=${OTHER:-\"}\"} ; exit 43",
            // Balanced pairs were never the problem, and must stay refused.
            "echo ${JSON:-\"{}\"} ; exit 31",
            // A brace inside a substitution inside the expansion: bash dies on
            // both of these too (rc 44 and rc 45).
            "echo ${x:-$(echo {)} ; exit 44",
            "echo ${x:-$(echo })} ; exit 45",
            // The expansion closes, and the separator AFTER it still splits.
            "echo ${x:-a;exit} ; exit 46",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a quoted brace must not end the expansion early: {refused}"
            );
        }

        // A bare `(` inside `${…}` is text in bash, so it must not raise the
        // paren depth — when it did, the separator guard never fired again and
        // the `exit` behind it was swallowed. bash dies at each rc below.
        for refused in [
            "echo ${PATH//(/_} ; exit 134",
            "echo ${x/(/y} ; exit 133",
            "echo ${x#(} ; exit 132",
            "echo ${x:-a(b} ; exit 135",
            "VAR=${OTHER:-(} ; exit 136",
            "echo ${x:-${y//(/}} ; exit 155",
            "echo ${x:-(} ; exit 130",
            "( echo ${x:-(} ) ; exit 87",
            "if true; then echo ${x:-(}; fi ; exit 89",
            "printf %s ${x:-(} ; exit 90",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a bare `(` inside ${{…}} must not raise the paren depth: {refused}"
            );
        }
        // …while a substitution inside an expansion stays LIVE, which is what
        // bash does — `echo A${x:-$(echo })}B` prints `A}B`, so its `}` does not
        // close the expansion. Guarding these too would have allowed 28 rows
        // that bash kills.
        for refused in [
            "echo ${x:-$(echo hi)} ; exit 5",
            "echo ${x:-`echo hi`} ; exit 11",
            "echo ${x:-$'hi'} ; exit 12",
            "echo ${x:-`echo }`} ; exit 67",
            "echo ${x:-$( ( ls ) )} ; exit 1",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a substitution inside ${{…}} is live, and the exit after it is real: {refused}"
            );
        }
        // The bare paren really is text, so this stays allowed: bash prints A(B.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("echo A${x:-(}B"),
            "a bare `(` inside ${{…}} is text, not a subshell"
        );
        // An `exit` inside a substitution inside an expansion is not top level.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("echo ${x:-$(ls; exit)}"),
            "that `exit` runs inside the substitution"
        );

        // A separator INSIDE `${…}` is ordinary text: bash prints these and
        // lives, so splitting there would be over-refusal.
        for allowed in ["echo ${x:- ;exit }", "echo ${x:-a;exit}"] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "a `;` inside ${{…}} is text, not a separator: {allowed}"
            );
        }
    }

    /// …and a parameter expansion that merely *uses* `#` as its operator must
    /// stay allowed. bash keeps every one of these alive.
    #[test]
    fn a_parameter_expansion_using_hash_as_an_operator_is_allowed() {
        for allowed in [
            "( echo ${x#prefix} )",
            "( echo ${x#exit} )",
            "echo ${#PATH}",
            "echo $((2#101))",
            "x=1; echo ${x#1}",
            "echo \"${x:- #}\"",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "consuming ${{…}} whole must not refuse this: {allowed}"
            );
        }
    }

    /// `$'…'` is ANSI-C quoting: `\'` is an escaped apostrophe, not the closing
    /// quote. Reading it as an ordinary single-quoted string mistracked the
    /// state and ate the separator. Re-review, B. bash: both of these die.
    #[test]
    fn ansi_c_quoting_does_not_hide_the_exit_after_it() {
        for refused in ["echo $'don\\'t' ; exit 9", "echo $'a\\'b' ; exit"] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "an escaped apostrophe inside $'…' must not hide the exit: {refused:?}"
            );
        }
        // …without refusing the ordinary case.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("echo $'x' exit"),
            "`exit` is an argument to echo here"
        );
    }

    #[test]
    fn a_hash_that_is_not_a_comment_is_left_alone() {
        for allowed in [
            "echo '#not a comment; exit'",
            "echo \"#exit\"",
            "curl http://example.test/page#frag",
            "echo a#b",
            "grep '#' /etc/hosts",
            "# just a comment",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "must be allowed, the `#` is not a comment introducing an exit: {allowed}"
            );
        }
    }

    /// A numbered file descriptor made the first word non-empty, so the walk
    /// stopped before the command name. Review finding, minor.
    #[test]
    fn a_redirection_prefix_does_not_hide_the_exit() {
        for refused in [
            ">/tmp/x exit 1",
            "2>/dev/null exit 1",
            "2>&1 exit",
            "1> /tmp/x exit",
            "2>> /tmp/x exit 3",
        ] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "a redirection before the command name must be stepped over: {refused}"
            );
        }
    }

    /// `command` and `builtin` run their argument in the current shell.
    #[test]
    fn exit_behind_a_same_shell_command_prefix_is_refused() {
        for refused in ["command exit 7", "builtin exit", "command exit"] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(refused),
                "`command`/`builtin` do not start a child shell: {refused}"
            );
        }
    }

    /// The stated limits of the rule (see the function's doc comment). These
    /// are pinned so the limit is a decision, not a surprise.
    #[test]
    fn the_stated_limits_of_exit_detection_are_pinned() {
        // Over-refusal: a here-document body is not parsed.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("cat <<EOF\nexit\nEOF"),
            "documented limit: a here-doc body is refused although it is only text"
        );
        // Under-refusal: indirection is not followed.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("eval exit"),
            "documented limit: `eval exit` is not detected"
        );
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("command -p exit 7"),
            "documented limit: a flagged `command -p exit` is not detected"
        );
        // Under-refusal: a case pattern written in its optional leading-paren
        // form looks like a subshell to the lexer.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("case $x in (a) exit;; esac"),
            "documented limit: the `(pattern)` form of a case arm is not detected"
        );
        // Over-refusal: matching ignores case, so `EXIT` is refused on POSIX
        // where it is not the builtin.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("EXIT 1"),
            "documented limit: `EXIT` is refused although POSIX has no such builtin"
        );
        // Under-refusal: an apostrophe in a here-document body opens an
        // unbalanced quote. bash dies on this one; the rule misses it.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("cat <<EOF\ndon't\nEOF\nexit 1"),
            "documented limit: an apostrophe in a here-doc body still hides a later exit"
        );
        // Under-refusal: an unterminated `${` swallows every later separator.
        // bash reports a bad substitution for that line, carries on, and really
        // does exit 98. Pre-existing: allowed at b7856fb too.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("cat <<EOF\n${x\nEOF\nexit 98"),
            "documented limit: an unterminated ${{ in a here-doc body hides the exit"
        );
        // Under-refusal: a *sourced* script's `exit` ends the session shell
        // (bash dies on `. script` and on `source script`). A script run the
        // ordinary way is a child process and cannot, which is why the limit
        // names sourcing and not "a script that ends in exit".
        for sourced in [". /tmp/deploy.sh", "source /tmp/deploy.sh"] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(sourced),
                "documented limit: a sourced script's exit is not detected: {sourced}"
            );
        }
        // Under-refusal, REASONED not measured: PowerShell's backtick is an
        // escape character, but this lexer reads it as command substitution, so
        // the separator after it is swallowed. On PowerShell that `exit` ends
        // the session; no PowerShell oracle was run, and bash cannot stand in —
        // there the same text is an unterminated backtick (rc 2, `unexpected
        // EOF`), not a death.
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("Write-Host `; exit"),
            "documented limit: a PowerShell backtick escape hides the exit after it"
        );
        // Over-refusal on input no valid command contains: `${x(}` has no
        // operator, so bash aborts the line — `exit` included — and lives.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("echo ${x(} ; exit 120"),
            "documented limit: a bad substitution is refused"
        );
        // Over-refusal: an async list runs in a subshell, so bash survives
        // `exit &` — this refuses it anyway.
        for asynchronous in ["exit &", "exit 0 &"] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(asynchronous),
                "documented limit: an async `exit` is refused although it cannot kill the \
                 shell: {asynchronous}"
            );
        }
        // Over-refusal: stepping over a file-descriptor number cannot tell one
        // from an ordinary first word, so a bare leading number is refused.
        // bash survives `1 exit` — `1` is simply not a command.
        for numeric in ["1 exit", "007 exit"] {
            assert!(
                SessionManager::command_runs_exit_in_session_shell(numeric),
                "documented limit: a bare leading number is treated as an fd: {numeric}"
            );
        }
        // Over-refusal, and asymmetric: a multi-line function body is refused
        // while the one-liner is allowed. bash survives both — neither *runs*
        // the body.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("func() {\n exit 1\n}"),
            "documented limit: a multi-line function body is refused"
        );
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("func() { exit 1; }"),
            "documented limit: the one-line form of the same definition is allowed"
        );
        // Over-refusal on `cmd.exe` only: `^` escapes a separator there and
        // this rule does not know it, so `exit` after an escaped `&` is
        // refused although cmd.exe would pass it as an argument. Reasoned from
        // cmd.exe's escaping rules, NOT measured — there is no cmd.exe oracle
        // here. On bash the same text really does exit, so the refusal is
        // correct there.
        assert!(
            SessionManager::command_runs_exit_in_session_shell("echo a^& exit"),
            "documented limit: a cmd.exe `^`-escaped separator still splits"
        );
        assert!(
            !SessionManager::command_runs_exit_in_session_shell("$CMD"),
            "documented limit: an expansion that yields `exit` is not detected"
        );
        // Under-refusal: `logout` and `exec` end a session shell too and are
        // out of this task's scope.
        assert!(!SessionManager::command_runs_exit_in_session_shell(
            "logout"
        ));
        assert!(!SessionManager::command_runs_exit_in_session_shell(
            "exec sh"
        ));
    }

    #[test]
    fn exit_detection_ignores_letter_case() {
        // cmd.exe and PowerShell are case-insensitive, and this rule guards
        // every shell type.
        assert!(SessionManager::command_runs_exit_in_session_shell("Exit"));
        assert!(SessionManager::command_runs_exit_in_session_shell("EXIT 1"));
    }

    #[test]
    fn ordinary_commands_are_never_refused() {
        for allowed in [
            "",
            "   ",
            "ls -la",
            "printf sans-nl",
            "cd /app && npm install",
            "kubectl get pods -o json | jq '.items[0]'",
            "systemctl is-active --quiet nginx && echo up || echo down",
            "command -v jq >/dev/null",
            "echo hi > /tmp/out",
            "case $x in a) cd /tmp;; *) echo other;; esac",
        ] {
            assert!(
                !SessionManager::command_runs_exit_in_session_shell(allowed),
                "must be allowed: {allowed}"
            );
        }
    }

    #[test]
    fn the_isolation_hint_names_a_child_shell_for_every_shell_type() {
        assert!(SessionManager::exit_isolation_hint(ShellType::Posix).contains("sh -c"));
        assert!(SessionManager::exit_isolation_hint(ShellType::Cmd).contains("cmd /c"));
        assert!(SessionManager::exit_isolation_hint(ShellType::PowerShell).contains("powershell"));
    }

    #[test]
    fn a_session_ending_exit_is_refused_as_an_invalid_request_not_a_denial() {
        let err =
            SessionManager::refuse_command_that_ends_the_session("s1", ShellType::Posix, "exit 7")
                .expect_err("a top-level exit must be refused");
        match err {
            // Not `CommandDenied`: that variant means a security denial and
            // maps to a different CLI exit code.
            BridgeError::McpInvalidRequest(msg) => {
                assert!(
                    msg.contains("sh -c"),
                    "the refusal must name a way to run it safely: {msg}"
                );
            }
            other => panic!("Expected McpInvalidRequest, got: {other:?}"),
        }
    }

    /// After elevation the command can carry a sudo password, and the refusal
    /// is both logged and returned to the caller.
    #[test]
    fn the_refusal_never_quotes_the_command_back() {
        let err = SessionManager::refuse_command_that_ends_the_session(
            "s1",
            ShellType::Posix,
            "SUPERSECRET=hunter2 exit 7",
        )
        .expect_err("a top-level exit must be refused");
        assert!(
            !err.to_string().contains("hunter2"),
            "the refusal echoed the command back: {err}"
        );
    }

    #[test]
    fn an_ordinary_command_is_not_refused() {
        SessionManager::refuse_command_that_ends_the_session(
            "s1",
            ShellType::Posix,
            "cd /app && npm install",
        )
        .expect("an ordinary command must be allowed through");
    }

    // ============== Task 4: a timeout no longer evicts the session ==============

    #[test]
    fn a_timeout_does_not_prove_the_shell_is_gone() {
        assert!(!SessionManager::read_error_proves_shell_is_gone(
            &BridgeError::SshTimeout { seconds: 30 }
        ));
    }

    #[test]
    fn a_closed_channel_does_prove_the_shell_is_gone() {
        assert!(SessionManager::read_error_proves_shell_is_gone(
            &BridgeError::SshExec {
                reason: "Shell session closed unexpectedly".to_string(),
            }
        ));
    }

    /// The rule reads the error *variant*, never the message text: an
    /// `SshExec` whose reason happens to say "timeout" still evicts, and an
    /// `SshTimeout` whose message says nothing of the sort still does not.
    #[test]
    fn the_eviction_rule_reads_the_variant_not_the_message() {
        assert!(SessionManager::read_error_proves_shell_is_gone(
            &BridgeError::SshExec {
                reason: "timeout while reading".to_string(),
            }
        ));
        assert!(!SessionManager::read_error_proves_shell_is_gone(
            &BridgeError::SshTimeout { seconds: 1 }
        ));
        // Any other error from this path is treated as fatal: the rule is
        // closed, only the timeout is exempt.
        assert!(SessionManager::read_error_proves_shell_is_gone(
            &BridgeError::SshOutputTooLarge { limit_bytes: 10 }
        ));
    }
}
