use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::AuditConfig;

/// Host value for an audited operation that has no target host at all.
///
/// Exactly one production caller: `ssh_config_set`, which changes a limit of
/// the bridge process itself ("not a remote host (there is no host param)",
/// its own description) — plus the failure paths of the `*_close` / `*_stop`
/// state tools, where the id handed in matched nothing, so no host was ever
/// resolved to name.
///
/// The angle brackets are the point: no host alias in a `config.yaml` can
/// contain them, so `"host":"<no-host>"` can never be confused with a real
/// target, and `grep '<no-host>'` over `audit.log` enumerates exactly the
/// hostless events. It is the single convention for the whole crate — before
/// it there was none, every non-test caller passed a real alias, and the
/// alternative was the empty string, which reads like a bug in the writer.
///
/// **It reaches the command history too, not only `audit.log`.** The failure
/// paths named above go through `ExecuteCommandUseCase::log_failure`, which
/// writes a `HistoryEntry` as well, so `ssh_history` and the
/// `history://recent` resource both show entries whose `host` is this
/// sentinel. Checked, for those two consumers: `CommandHistory::for_host`
/// filters on `e.host == host` with no validation and `ssh_history` only
/// prints the field, so the value is inert — a real-alias query simply never
/// matches it. One sharp edge, from the code: `history_resource`'s
/// `parse_query` does no percent-decoding, so `history://recent?host=<no-host>`
/// matches **literally** and the correctly-encoded `host=%3Cno-host%3E` does
/// not.
pub const NO_HOST: &str = "<no-host>";

/// Result of a command execution for audit purposes
#[derive(Debug, Clone, Serialize)]
pub enum CommandResult {
    /// A process ran on the target host and exited `exit_code`.
    Success { exit_code: u32, duration_ms: u64 },
    /// The bridge could not carry the operation out: a connection failure, a
    /// timeout, an unread exit code. Carries no code, because none was read.
    Error { message: String },
    /// Security refused the command before anything ran.
    Denied { reason: String },
    /// Server state changed, and **no process ran anywhere** to change it.
    ///
    /// For the operations whose whole effect is on the bridge or on the SSH
    /// transport: opening or closing a persistent session, opening or closing
    /// a tunnel, starting or stopping a recording, setting a runtime limit.
    /// They are audited because they change what the server is, not because a
    /// command was executed.
    ///
    /// **It carries the duration and no exit code, and the absence is the
    /// honest information** — the same doctrine
    /// `ToolCallResult::remote_exit_code` (`src/ports/protocol.rs`) states for
    /// its `None`: *"no claim about a remote exit code. Either nothing ran
    /// remotely, or …"*. Here it is the first of those: nothing ran. An
    /// `exit_code: 0` would be a **verdict** ("a command succeeded") posted on
    /// a **fact** that never happened, and announcing an outcome on a signal
    /// that cannot establish one is the very fault this variant exists to
    /// remove. It is also what `ssh_file_write` documents for its SFTP branch
    /// and what `SessionExecResult::exit_code` was changed to stop doing.
    ///
    /// Reading one of these lines: `event_type` says which kind of state
    /// change it is, `tool_name` which tool did it (always set — `AuditLogger::
    /// log` is the only writer of that field), and `command` carries the
    /// *operation* rather than a shell command, in the form
    /// `<tool> <identifying-arg>=<value>`.
    StateChanged { duration_ms: u64 },
    /// A confirmation gate let a destructive call through, and **nothing has
    /// run yet** when this line is written.
    ///
    /// Written by the CLI's destructive gate (`confirm_destructive`,
    /// `src/cli/runner.rs`) through
    /// `ExecuteCommandUseCase::log_confirmed`, at the moment the decision is
    /// taken — before the call is dispatched, and before it is even settled
    /// which path (a running daemon, or in-process) will serve it. Whatever
    /// the call then does writes its own, later event; this one records only
    /// the decision.
    ///
    /// **It carries neither an exit code nor a duration, for the reason
    /// [`Self::StateChanged`] carries no code: nothing ran.** `by` names what
    /// answered — the `--yes` flag, or the terminal prompt — which is the one
    /// thing a reader cannot reconstruct from the rest of the line.
    ///
    /// **The allow path is audited, not only the refusals, and that is the
    /// point of the variant.** A trail that recorded refusals alone could not
    /// tell a destructive call that ran *after* the gate from one that ran
    /// without ever meeting it — which is precisely what the CLI did until
    /// 2026-08-31, on the default configuration.
    ///
    /// **It does not follow that a missing line means a bypassed gate**, and
    /// the bound belongs here because this doc-comment opens by saying the
    /// writer is the CLI: the MCP server's own destructive gate
    /// (`check_destructive_elicitation`) writes no audit event at all today,
    /// and the CLI, the daemon and the MCP server append to the **same**
    /// `audit.log`. On a shared trail, a destructive line with no
    /// `command_confirmed` beside it means "this call did not come through
    /// the CLI gate". The inference is sound for CLI-served calls only.
    ///
    /// **And on a shared trail it is not just unsound but unusable**, because
    /// [`AuditEvent`] carries no field naming what served the call: a reader
    /// cannot tell which lines came from the CLI, so they cannot select the
    /// population the rule applies to. Fully usable on a trail only the CLI
    /// writes to.
    Confirmed { by: String },
}

/// Audit event for logging
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    /// The kind of outcome this line records, never the tool that produced
    /// it — that is `tool_name`, and the two are not interchangeable.
    ///
    /// It used to be a fixed literal set by whichever constructor ran:
    /// `"ssh_exec"` from [`AuditEvent::new`] for a command that ran,
    /// `"command_denied"` from [`AuditEvent::denied`] for one that was
    /// refused. [`AuditEvent::tagged`] now takes it as a parameter, so the
    /// set is open; `"state_change"` (from
    /// `ExecuteCommandUseCase::log_state_change`) and `"command_confirmed"`
    /// (from `ExecuteCommandUseCase::log_confirmed`) are the third and fourth
    /// values in the log today. A consumer must therefore treat an unknown value as data,
    /// not as a parse error — and a caller must keep passing a kind of
    /// outcome, which is the contract the field's name carries and the only
    /// thing stopping it from drifting into a second, unreliable `tool_name`.
    pub event_type: String,
    /// Target host alias, or [`NO_HOST`] when the operation had no target.
    pub host: String,
    /// The command that ran — or, when no command ran, the operation the
    /// event is about: the state change for a [`CommandResult::StateChanged`]
    /// event, and the call the gate was asked about for a
    /// [`CommandResult::Confirmed`] one.
    pub command: String,
    /// Name of the tool that generated this event (e.g., `ssh_redis_cli`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub result: CommandResult,
    /// Reduction params supplied on this call (`jq_filter`, `columns`, ...),
    /// so adoption can be measured from the log with a grep. Filled by the
    /// `StandardTool` pipeline, by the direct handlers that go through
    /// `process_success(.., &dr.used_params())`, and by `ssh_ls`, which builds
    /// its own event. It lists what was *supplied*, written before the
    /// reduction runs (the event is emitted by `process_success` itself): a
    /// call whose reduction then fails, or is skipped on a non-zero exit,
    /// still lists them.
    ///
    /// **An absent key does not mean "unfiltered output".** With
    /// `skip_serializing_if` it also appears on events that hard-code the
    /// list: `log_success` (`ssh_session_exec`), the file-transfer tools that
    /// build an `AuditEvent` by hand (none takes a reduction param), and the
    /// nine tools that reject every reduction param. And two things that
    /// change what the caller saw are recorded nowhere: `max_output`
    /// truncation and `summarize=true` sampling. Do not build the
    /// "unfiltered" population from lines lacking this key.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reduction: Vec<&'static str>,
}

impl AuditEvent {
    /// Create a new audit event
    #[must_use]
    pub fn new(host: &str, command: &str, result: CommandResult) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: "ssh_exec".to_string(),
            host: host.to_string(),
            command: command.to_string(),
            tool_name: None,
            result,
            reduction: Vec::new(),
        }
    }

    /// Create an event for a denied command
    #[must_use]
    pub fn denied(host: &str, command: &str, reason: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: "command_denied".to_string(),
            host: host.to_string(),
            command: command.to_string(),
            tool_name: None,
            result: CommandResult::Denied {
                reason: reason.to_string(),
            },
            reduction: Vec::new(),
        }
    }

    /// Create an event under the `event_type` **and** the `result` the caller
    /// names — the only constructor that fixes neither.
    ///
    /// **That is the whole reason it exists.** [`Self::new`] hard-codes
    /// `event_type: "ssh_exec"` and [`Self::denied`] hard-codes
    /// `"command_denied"`, so before this no code outside this module could
    /// write that field at all: a tunnel being opened would have been stamped
    /// `ssh_exec`, which is the same conflation the mandatory `tool` on the
    /// use-case entry points was added to remove, one layer down.
    ///
    /// `result` is a parameter for the same reason `event_type` is. A
    /// constructor that took the type but pinned the result would open a door
    /// its own body closes: the next caller that needs a new `event_type`
    /// almost certainly needs a different `CommandResult` with it, and would
    /// have to either mislabel its event or reopen this signature. The
    /// `event_type`/`result` pair belongs to the caller, as one decision.
    ///
    /// Callers do not reach this directly. Each goes through the named,
    /// typed facade for its kind of event — today
    /// `ExecuteCommandUseCase::log_state_change`, which passes
    /// `"state_change"` with [`CommandResult::StateChanged`], and
    /// `ExecuteCommandUseCase::log_confirmed`, which passes
    /// `"command_confirmed"` with [`CommandResult::Confirmed`] — because
    /// `tool` is mandatory on those facades and consultative nowhere.
    ///
    /// `command` receives whatever identifies the thing audited: a shell
    /// command for an event that ran one, or the **operation** (the tool and
    /// its identifying argument, e.g.
    /// `ssh_tunnel_close tunnel_id=tunnel-pi-8080-80`) for one that did not,
    /// so every consumer that reads `command` keeps working on a non-empty,
    /// meaningful value. `host` is a real alias whenever one is resolvable,
    /// and [`NO_HOST`] when there is none.
    ///
    /// `tool_name` is left unset here, like in the other two constructors:
    /// `AuditLogger::log` takes the tool and is the single writer of it.
    #[must_use]
    pub fn tagged(event_type: &str, host: &str, command: &str, result: CommandResult) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            host: host.to_string(),
            command: command.to_string(),
            tool_name: None,
            result,
            reduction: Vec::new(),
        }
    }

    /// Convenience constructor step, used by tests to build an already named
    /// event. Production does not rely on it: `AuditLogger::log` takes the
    /// tool as a parameter and overwrites `tool_name` with it, so the name
    /// set here never reaches a sink.
    #[must_use]
    pub fn with_tool_name(mut self, name: &str) -> Self {
        self.tool_name = Some(name.to_string());
        self
    }
}

/// Audit logger that writes events to a file and/or tracing
///
/// Uses an async channel to avoid blocking on file writes.
pub struct AuditLogger {
    /// Only `needs_rotation`, `rotate` and `cleanup_old_files` ever read
    /// this, and all three are test-only (F6) — the writer task carries its
    /// own copy of the settings it needs. Gated so a release build does not
    /// clone an `AuditConfig` nothing reads.
    #[cfg(test)]
    config: AuditConfig,
    /// Sending half of the writer channel, behind a lock so [`Self::close`]
    /// can drop it through a `&self` — which is the only reference anything
    /// holds, since every owner of a logger holds an [`Arc`] of it.
    ///
    /// **Why a lock and not a bare `Option`:** the writer loop ends when the
    /// LAST sender is dropped, and clones of the `Arc<AuditLogger>` outlive
    /// the function that has to wait for the drain — background tasks and
    /// every `ToolContext` hold one. Dropping one owner therefore closes
    /// nothing. Taking the sender out from behind this lock closes the
    /// channel whatever the clone count is.
    ///
    /// The critical section is the `send` in [`Self::log`] and the `take` in
    /// [`Self::close`], and nothing else: **no `.await` is ever taken while
    /// this lock is held**, so a `std::sync::Mutex` is the right one and a
    /// blocked runtime worker is impossible.
    sender: std::sync::Mutex<Option<mpsc::UnboundedSender<AuditEvent>>>,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
    /// Clock used for the retention cutoff; injectable so the boundary
    /// (mtime == cutoff) is deterministically testable. Read only by
    /// `cleanup_old_files`, which is test-only (F6); the writer task calls
    /// `cleanup_old_audit_files` with the real clock directly.
    #[cfg(test)]
    now_fn: fn() -> DateTime<Utc>,
    /// In-memory copy of every event passed to `log`, kept only when the
    /// logger was built via `for_test`. Lets a use-case test assert on
    /// exactly what would have been audited (`tool_name` included) without
    /// standing up a writer task or touching the filesystem. `disabled` and
    /// `new` both leave this `None`, so they behave exactly as before.
    #[cfg(test)]
    captured: Option<std::sync::Mutex<Vec<AuditEvent>>>,
}

/// Background task that writes audit events to a file.
///
/// Its loop ends only when the channel closes, which happens when the last
/// sender is dropped or when [`AuditLogger::close`] takes the sender out.
/// **Join it, never `abort()` it**: the write itself runs in a
/// `tokio::task::spawn_blocking` followed by `rotate_if_needed`, so an abort
/// loses the event in flight and the rotation it was about to trigger.
/// `drain_audit_writer` is the bounded join every entry point uses.
pub struct AuditWriterTask {
    rx: mpsc::UnboundedReceiver<AuditEvent>,
    file: File,
    sanitizer: Option<Arc<crate::security::Sanitizer>>,
    /// Live audit log path, needed to rename and reopen on rotation.
    path: PathBuf,
    /// `max_size_mb` in bytes. `0` disables rotation.
    max_bytes: u64,
    retain_days: u32,
    /// Bytes in the live file. Seeded from the file's current length so a
    /// restart on an already-large log rotates on the next event instead of
    /// growing without bound.
    written_bytes: u64,
}

impl AuditWriterTask {
    /// Run the writer task, consuming events from the channel
    pub async fn run(mut self) {
        while let Some(mut event) = self.rx.recv().await {
            // Defensive: sanitize at the writer side too in case a logger
            // sent us an event without sanitizing first. Belt-and-braces:
            // when both sides share the same `Arc<Sanitizer>` we guarantee
            // no secret ever lands in the JSONL file.
            if let Some(ref s) = self.sanitizer {
                event.command = s.sanitize(&event.command).into_owned();
            }
            if let Ok(json) = serde_json::to_string(&event) {
                let line = format!("{json}\n");
                let line_len = line.len() as u64;
                // Clone file handle for spawn_blocking
                if let Ok(mut file) = self.file.try_clone() {
                    let written = tokio::task::spawn_blocking(move || {
                        if let Err(e) = file.write_all(line.as_bytes()) {
                            warn!(error = %e, "Failed to write audit event to file");
                            return false;
                        }
                        if let Err(e) = file.flush() {
                            warn!(error = %e, "Failed to flush audit log file");
                            return false;
                        }
                        true
                    })
                    .await
                    .unwrap_or(false);

                    if written {
                        self.written_bytes = self.written_bytes.saturating_add(line_len);
                        self.rotate_if_needed();
                    }
                }
            }
        }
    }

    /// Rotate the live audit log once it has grown past `max_size_mb`.
    ///
    /// G-26 (audit 2026-08-19): this is the ONLY production caller of
    /// rotation. It has to live here because this task owns the open `File`
    /// handle — renaming the path from anywhere else would leave every later
    /// event appended to the renamed inode.
    ///
    /// A rotation failure never drops audit events -- that would be strictly
    /// worse than an oversized log. But it does permanently disable rotation
    /// for this task (see `reopen_after_rotation` for the same reasoning on
    /// the sibling arm): the causes of a failing `rename(2)` here are all
    /// persistent (EROFS remount, permission change, parent directory moved
    /// or deleted, MAC denial, an external logrotate that removed the live
    /// log), so retrying once per event would issue an unbounded stream of
    /// doomed syscalls and `warn!` lines that can never succeed.
    fn rotate_if_needed(&mut self) {
        if self.max_bytes == 0 || self.written_bytes < self.max_bytes {
            return;
        }

        let rotated = match rename_with_timestamp(&self.path, Utc::now()) {
            Ok(rotated) => rotated,
            Err(e) => {
                error!(
                    error = %e,
                    path = %self.path.display(),
                    "Failed to rotate audit log; disabling further rotation for \
                     this run (events keep landing in the current, oversized file \
                     until the process restarts)"
                );
                self.max_bytes = 0;
                return;
            }
        };
        // The second `Utc::now()` is a separate sample from the one that
        // named the archive; passing `rotated` keeps the sweep off it no
        // matter how far apart the two readings land (F8).
        cleanup_old_audit_files(
            &self.path,
            self.retain_days,
            Utc::now(),
            Some(rotated.as_path()),
        );

        self.reopen_after_rotation();
    }

    /// Reopen the live audit log after `rotate_if_needed` has already
    /// renamed it aside.
    ///
    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections): a
    /// failure here used to be a `warn!` with `self.file` and
    /// `written_bytes` left untouched. Since the rename already succeeded,
    /// `self.file` was left pointing at the RENAMED (now-archived) inode —
    /// every subsequent event would keep landing in a file nobody tails,
    /// and because `written_bytes` was never reset, `rotate_if_needed`
    /// would immediately try to rotate again on the very next event,
    /// calling `rename_with_timestamp` on a source that no longer exists at
    /// `self.path` — failing the exact same way, forever, once per event.
    /// A rename(2) syscall failing on every single event is strictly worse
    /// than the oversized-log problem rotation exists to solve.
    ///
    /// On failure this now logs once, at `error!` (a human should notice
    /// this), and permanently disables further rotation attempts for this
    /// task by zeroing `max_bytes` — `rotate_if_needed`'s guard clause then
    /// short-circuits on every future call. Events keep landing in the
    /// renamed file until the process restarts; that is a known, bounded
    /// degradation instead of an unbounded per-event retry loop.
    fn reopen_after_rotation(&mut self) {
        match open_audit_file(&self.path) {
            Ok(file) => {
                self.file = file;
                self.written_bytes = 0;
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %self.path.display(),
                    "Failed to reopen audit log after rotation; disabling further \
                     rotation for this run (events will keep landing in the \
                     rotated file until the process restarts)"
                );
                self.max_bytes = 0;
            }
        }
    }
}

/// Open (creating if needed) the audit log in append mode, 0600 on unix.
fn open_audit_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Rename `path` to `<file_name>.<YYYYmmdd_HHMMSS>` in the same directory.
///
/// MINOR (fix round 1, audit 2026-08-19): `%Y%m%d_%H%M%S` is one-second
/// resolution. Two rotations inside the same wall-clock second used to
/// collide on this name, and `fs::rename` silently clobbers an existing
/// destination on Unix — the first archive would just vanish. If the
/// timestamped name is already taken, an incrementing numeric suffix is
/// appended until a free name is found, so a collision loses nothing.
///
/// Returns the archive's path so the caller can hand it to
/// `cleanup_old_audit_files` and have the sweep skip it — see F8 there.
fn rename_with_timestamp(path: &Path, now: DateTime<Utc>) -> std::io::Result<PathBuf> {
    let timestamp = now.format("%Y%m%d_%H%M%S");
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("audit.log");

    let mut rotated_path = path.with_file_name(format!("{base_name}.{timestamp}"));
    let mut suffix: u32 = 1;
    while rotated_path.exists() {
        rotated_path = path.with_file_name(format!("{base_name}.{timestamp}.{suffix}"));
        suffix += 1;
    }

    std::fs::rename(path, &rotated_path)?;
    Ok(rotated_path)
}

/// Whether `name` is one of `live_file_name`'s rotated archives, i.e. exactly
/// the shape `rename_with_timestamp` writes: `<live file name>.<YYYYmmdd_HHMMSS>`
/// with an optional `.<n>` same-second collision counter.
///
/// F2 (re-review of the 2026-08-19 audit corrections): the first fix scoped
/// the retention sweep with `starts_with("<live file name>.")` — "anything
/// after a dot". That is not the shape rotation writes, and it captures files
/// that belong to somebody else: a second instance configured `audit.path:
/// .../audit.log.staging` has a LIVE log starting with `audit.log.`, so the
/// busy instance would delete it on its first rotation, silently. An external
/// logrotate's `audit.log.1` and `audit.log.gz` are caught the same way.
/// Matching the suffix shape exactly is what makes the sweep safe.
fn is_own_rotated_archive(name: &str, live_file_name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(live_file_name)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };

    // `<YYYYmmdd_HHMMSS>`, optionally followed by `.<n>`.
    let (timestamp, counter) = match suffix.split_once('.') {
        Some((timestamp, counter)) => (timestamp, Some(counter)),
        None => (suffix, None),
    };

    // Byte-wise so a multibyte filename can never panic on a slice boundary.
    let timestamp = timestamp.as_bytes();
    let timestamp_ok = timestamp.len() == 15
        && timestamp[8] == b'_'
        && timestamp[..8].iter().all(u8::is_ascii_digit)
        && timestamp[9..].iter().all(u8::is_ascii_digit);

    let counter_ok = match counter {
        None => true,
        Some(counter) => !counter.is_empty() && counter.as_bytes().iter().all(u8::is_ascii_digit),
    };

    timestamp_ok && counter_ok
}

/// Remove this log's own rotated archives whose mtime predates the retention
/// cutoff. `retain_days == 0` disables cleanup.
///
/// CRITICAL (fix round 1 of the 2026-08-19 audit corrections): this used to
/// delete EVERY file in `path`'s parent directory older than `retain_days`,
/// with no filename check — `audit.path: ~/audit.log` swept the operator's
/// entire home directory. Only files matching `<live file name>.<suffix>`
/// (the shape `rename_with_timestamp` produces) are eligible; nothing else
/// in that directory belongs to this writer. See `is_own_rotated_archive` for
/// why the match has to be the exact archive shape and not a bare prefix.
///
/// F7 (re-review): the sweep is no longer silent. Removal used to be
/// `let _ = std::fs::remove_file(...)` with no log line and no counter, so a
/// sweep that deleted nothing (EACCES, EBUSY, an already-vanished file) was
/// indistinguishable from one that deleted every archive in the directory —
/// on the very release that turns this destructive code path on for the
/// first time.
///
/// F8 (re-review): `just_rotated` names the archive the caller has just
/// created, and it is skipped unconditionally, whatever its mtime says.
/// Rotation samples `Utc::now()` for the archive name and the sweep compares
/// each candidate's FILESYSTEM mtime against `now - retain_days`, so a forward
/// wall-clock jump larger than `retain_days` — a VM resumed from a snapshot, a
/// dead RTC, a first NTP sync on a box that booted at the epoch — puts the
/// archive created microseconds earlier on the wrong side of the cutoff and
/// deletes the very events rotation just preserved. Callers with nothing to
/// protect pass `None`.
fn cleanup_old_audit_files(
    path: &Path,
    retain_days: u32,
    now: DateTime<Utc>,
    just_rotated: Option<&Path>,
) {
    if retain_days == 0 {
        return;
    }

    let Some(parent) = path.parent() else {
        return;
    };
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let cutoff = now - chrono::Duration::days(i64::from(retain_days));

    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(
                error = %e,
                directory = %parent.display(),
                "Failed to scan the audit directory for expired archives"
            );
            return;
        }
    };

    let mut removed: usize = 0;
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        if !is_own_rotated_archive(&entry_name.to_string_lossy(), file_name) {
            continue;
        }
        // Never sweep the archive this rotation just wrote (F8).
        if just_rotated.is_some_and(|just_rotated| just_rotated == entry.path()) {
            continue;
        }
        if let Ok(metadata) = entry.metadata()
            && let Ok(modified) = metadata.modified()
        {
            let modified: DateTime<Utc> = modified.into();
            if modified < cutoff {
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(e) => warn!(
                        error = %e,
                        archive = %entry.path().display(),
                        "Failed to remove an expired audit archive"
                    ),
                }
            }
        }
    }

    info!(removed, cutoff = %cutoff, "audit retention swept archives");
}

/// How long a shutdown waits for the audit writer to finish.
///
/// Every entry point that owns a writer pays this at most once, and only
/// when the writer is still busy — a drained writer joins immediately.
pub(crate) const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Join an [`AuditWriterTask`]'s handle, bounded by [`DRAIN_TIMEOUT`].
///
/// The caller MUST have closed the channel first — [`AuditLogger::close`],
/// or dropping every owner of the logger — or this waits the full timeout
/// and then warns, because the writer is still blocked on `recv()`.
///
/// Joined and never `abort()`ed: the write runs in a `spawn_blocking` and is
/// followed by `rotate_if_needed`, so an abort loses the event in flight and
/// the rotation it was about to trigger.
pub(crate) async fn drain_audit_writer(writer: Option<tokio::task::JoinHandle<()>>) {
    if let Some(handle) = writer
        && tokio::time::timeout(DRAIN_TIMEOUT, handle).await.is_err()
    {
        // Formatted from the constant so the sentence cannot go stale if the
        // bound changes.
        warn!(
            "audit writer did not drain within {}s; events may be lost",
            DRAIN_TIMEOUT.as_secs()
        );
    }
}

impl AuditLogger {
    /// Create a new async audit logger with the given configuration
    ///
    /// Returns the logger and an optional writer task that must be spawned.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit log file cannot be created or opened.
    pub fn new(config: &AuditConfig) -> std::io::Result<(Self, Option<AuditWriterTask>)> {
        if !config.enabled {
            return Ok((Self::disabled(), None));
        }

        // Ensure parent directory exists
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = open_audit_file(&config.path)?;
        // Seed the rotation counter from the existing file so a restart on an
        // already-oversized log rotates on the next event (G-26).
        let written_bytes = file.metadata().map_or(0, |m| m.len());

        // Create channel for async logging
        let (tx, rx) = mpsc::unbounded_channel();

        let logger = Self {
            #[cfg(test)]
            config: config.clone(),
            sender: std::sync::Mutex::new(Some(tx)),
            sanitizer: None,
            #[cfg(test)]
            now_fn: Utc::now,
            #[cfg(test)]
            captured: None,
        };

        let task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: config.path.clone(),
            max_bytes: config.max_size_mb.saturating_mul(1024 * 1024),
            retain_days: config.retain_days,
            written_bytes,
        };

        Ok((logger, Some(task)))
    }

    /// Like `new` but applies a sanitizer to `event.command` before write/log.
    ///
    /// The same `Arc<Sanitizer>` is shared between the logger (for tracing
    /// emission) and the writer task (for the JSONL file), so secrets are
    /// masked on both sinks.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit log file cannot be created or opened.
    pub fn new_with_sanitizer(
        config: &AuditConfig,
        sanitizer: crate::security::Sanitizer,
    ) -> std::io::Result<(Self, Option<AuditWriterTask>)> {
        let (mut logger, task) = Self::new(config)?;
        let san = Arc::new(sanitizer);
        logger.sanitizer = Some(Arc::clone(&san));
        let task = task.map(|mut t| {
            t.sanitizer = Some(san);
            t
        });
        Ok((logger, task))
    }

    /// Whether a sanitizer is wired to mask `event.command` before logging.
    #[must_use]
    pub fn has_sanitizer(&self) -> bool {
        self.sanitizer.is_some()
    }

    /// Close the channel to the writer task, so its loop can end and the
    /// caller can join it.
    ///
    /// Call this, then join the [`AuditWriterTask`]'s handle (the
    /// crate-internal `drain_audit_writer` is the bounded join the entry
    /// points use), before the process exits. Without it the writer is
    /// still blocked on `recv()` when the runtime goes away, and every
    /// event still queued is lost — silently, because [`Self::log`] ends in
    /// `let _ = sender.send(event)` on an unbounded channel, which cannot
    /// fail in a way anything observes.
    ///
    /// **Why this exists rather than "drop the logger":** the writer loop
    /// ends when the last sender is dropped, and the senders live in clones
    /// of an `Arc<AuditLogger>` held by background tasks and by every
    /// `ToolContext`. The function that has to wait for the drain does not
    /// own them, cannot enumerate them, and nothing in the crate pins the
    /// property that they die first. Taking the sender out from behind the
    /// lock ends the channel whatever the clone count is.
    ///
    /// **Idempotent, and events logged afterwards are dropped on purpose**
    /// — `log` keeps working, writes its `tracing` line, and sends nowhere.
    /// After a close the file sink is gone; that is the point of calling it
    /// at shutdown and nowhere else.
    pub fn close(&self) {
        let mut guard = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Dropped explicitly, not merely taken: dropping the sender is the
        // whole effect.
        drop(guard.take());
    }

    /// Create a disabled audit logger (for testing or when audit is off)
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            // Not `AuditConfig::default()`: that is `enabled: true`, and until
            // `default_audit_path` got its test-build branch it was the REAL
            // ~/.local/share/bridge-mcp/audit.log, so `rotate()` on a disabled
            // logger renamed a developer's live audit log. Off, and pointing
            // at no file at all.
            #[cfg(test)]
            config: AuditConfig {
                enabled: false,
                path: PathBuf::new(),
                ..AuditConfig::default()
            },
            sender: std::sync::Mutex::new(None),
            sanitizer: None,
            #[cfg(test)]
            now_fn: Utc::now,
            #[cfg(test)]
            captured: None,
        }
    }

    /// Create a disabled audit logger that also keeps every logged event
    /// in memory, so a use-case test can assert on the exact `AuditEvent`
    /// (including `tool_name`) that a call produced. See `drain_for_test`.
    #[cfg(test)]
    #[must_use]
    pub fn for_test() -> Self {
        Self {
            captured: Some(std::sync::Mutex::new(Vec::new())),
            ..Self::disabled()
        }
    }

    /// Take every event captured so far, leaving the logger empty.
    ///
    /// Panics if this logger was not built with `for_test` — a test that
    /// calls this on a plain `disabled()` logger has a bug in the test
    /// itself, not in the code under test.
    #[cfg(test)]
    pub fn drain_for_test(&self) -> Vec<AuditEvent> {
        let mut guard = self
            .captured
            .as_ref()
            .expect("drain_for_test called on a logger not built with AuditLogger::for_test()")
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Test-only clock override so retention-boundary behavior is
    /// deterministic.
    #[cfg(test)]
    fn set_clock(&mut self, now_fn: fn() -> DateTime<Utc>) {
        self.now_fn = now_fn;
    }

    /// Log an audit event (non-blocking), attributed to `tool`.
    ///
    /// `tool` is mandatory and OVERWRITES any `event.tool_name` the event
    /// already carried: this is the single writer of that field, so two
    /// values can never disagree silently. Both sinks (the `tracing` line
    /// and the file/channel line) carry the name, so a line emitted through
    /// this entry point is never anonymous. `AuditEvent::new` itself still
    /// builds a nameless event, which is why the name is taken here.
    ///
    /// The event is sent to a background task for file writing.
    /// If a sanitizer is configured, `event.command` is masked BEFORE the
    /// tracing emission and BEFORE the channel send (so neither sink ever
    /// sees the unredacted command).
    ///
    /// **The file sink is best-effort and its failures are silent.** The
    /// send is `let _ = sender.send(event)` on an unbounded channel: it can
    /// only fail once the receiver is gone, which is after
    /// [`Self::close`] or once the writer task has ended, and nothing
    /// observes it. An event logged after the shutdown drain therefore
    /// reaches `tracing` and nothing else. The `tracing` sink, by contrast,
    /// is synchronous and always emitted.
    pub fn log(&self, tool: &str, event: AuditEvent) {
        let mut event = event;
        event.tool_name = Some(tool.to_string());
        if let Some(ref s) = self.sanitizer {
            event.command = s.sanitize(&event.command).into_owned();
        }

        // Always log to tracing (fast, synchronous)
        Self::log_to_tracing(&event);

        #[cfg(test)]
        if let Some(ref captured) = self.captured {
            captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event.clone());
        }

        // Send to channel for async file writing. The lock is held for the
        // send alone — `UnboundedSender::send` never blocks and never
        // awaits — so this stays a few nanoseconds on the hot path.
        let guard = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(sender) = guard.as_ref() {
            let _ = sender.send(event);
        }
    }

    /// Log event to tracing (synchronous, fast)
    fn log_to_tracing(event: &AuditEvent) {
        match &event.result {
            CommandResult::Success {
                exit_code,
                duration_ms,
            } => {
                info!(
                    event_type = %event.event_type,
                    tool_name = event.tool_name.as_deref(),
                    host = %event.host,
                    command = %event.command,
                    exit_code = exit_code,
                    duration_ms = duration_ms,
                    "Audit: command executed"
                );
            }
            CommandResult::Error { message } => {
                info!(
                    event_type = %event.event_type,
                    tool_name = event.tool_name.as_deref(),
                    host = %event.host,
                    command = %event.command,
                    error = %message,
                    "Audit: command failed"
                );
            }
            CommandResult::Denied { reason } => {
                info!(
                    event_type = %event.event_type,
                    tool_name = event.tool_name.as_deref(),
                    host = %event.host,
                    command = %event.command,
                    reason = %reason,
                    "Audit: command denied"
                );
            }
            // No `exit_code` field here, on purpose: nothing ran. The field
            // is absent rather than zero, exactly as on the variant.
            CommandResult::StateChanged { duration_ms } => {
                info!(
                    event_type = %event.event_type,
                    tool_name = event.tool_name.as_deref(),
                    host = %event.host,
                    command = %event.command,
                    duration_ms = duration_ms,
                    "Audit: state changed"
                );
            }
            // Neither `exit_code` nor `duration_ms`: the decision is logged at
            // the moment it is taken, so there is nothing yet to time and
            // nothing yet to have exited.
            CommandResult::Confirmed { by } => {
                info!(
                    event_type = %event.event_type,
                    tool_name = event.tool_name.as_deref(),
                    host = %event.host,
                    command = %event.command,
                    confirmed_by = %by,
                    "Audit: destructive call confirmed"
                );
            }
        }
    }

    /// Check if the audit log needs rotation (exceeds max size)
    ///
    /// `#[cfg(test)]` (F6, re-review of the 2026-08-19 audit corrections),
    /// matching what `ResourceRegistry::schemes` got for the same reason.
    /// It has no production caller in any branch or tag — `AuditWriterTask`
    /// owns the open file handle and is the only place that can safely
    /// rotate — and its semantics now actively contradict the writer task's:
    /// `len/(1024*1024) >= max_size_mb` is TRUE for `max_size_mb: 0`, the
    /// exact value that means "rotation disabled" in `rotate_if_needed`. A
    /// consumer polling `needs_rotation()` and calling `rotate()` would also
    /// drive straight into the failure mode `rotate_if_needed` guards
    /// against, since `rotate()` renames without reopening. `pub(crate)`
    /// alone would still be flagged as dead code in a non-test build.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn needs_rotation(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Ok(metadata) = std::fs::metadata(&self.config.path) {
            let size_mb = metadata.len() / (1024 * 1024);
            return size_mb >= self.config.max_size_mb;
        }

        false
    }

    /// Rotate the audit log file
    ///
    /// `#[cfg(test)]` for the same reason as `needs_rotation` — see there.
    /// This renames and never reopens, so anything outside a test that
    /// called it while an `AuditWriterTask` held the handle would leave
    /// every later event appended to the renamed inode.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be renamed during rotation.
    #[cfg(test)]
    pub(crate) fn rotate(&self) -> std::io::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let path = &self.config.path;
        if !path.exists() {
            return Ok(());
        }

        let rotated = rename_with_timestamp(path, Utc::now())?;

        // Clean up old files if retention is configured, never touching the
        // archive this call just created (F8).
        cleanup_old_audit_files(
            &self.config.path,
            self.config.retain_days,
            (self.now_fn)(),
            Some(rotated.as_path()),
        );

        Ok(())
    }

    /// Remove audit files older than retention period
    ///
    /// Uses the injectable clock (`now_fn`) so the retention boundary stays
    /// deterministically testable; the writer task calls the same free
    /// function (`cleanup_old_audit_files`) with the real clock. Test-only
    /// alongside its only callers, `rotate` and the retention tests.
    #[cfg(test)]
    fn cleanup_old_files(&self) {
        cleanup_old_audit_files(
            &self.config.path,
            self.config.retain_days,
            (self.now_fn)(),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::Sanitizer;
    use std::path::{Path, PathBuf};

    /// Check if a path is within the configured audit directory
    fn is_valid_audit_path(path: &Path, config: &AuditConfig) -> bool {
        if let (Some(config_parent), Some(path_parent)) = (config.path.parent(), path.parent()) {
            return path_parent == config_parent;
        }
        false
    }

    #[test]
    fn test_has_sanitizer_reports_wiring() {
        // AuditConfig::default() carries the REAL path
        // (~/.local/share/bridge-mcp/audit.log), which `new` creates and
        // opens.
        let temp_dir = tempfile::tempdir().unwrap();
        let config = AuditConfig {
            path: temp_dir.path().join("audit.log"),
            ..AuditConfig::default()
        };
        let (plain, _task) = AuditLogger::new(&config).unwrap();
        assert!(
            !plain.has_sanitizer(),
            "plain logger must not report a sanitizer"
        );

        let (wired, _task) =
            AuditLogger::new_with_sanitizer(&config, Sanitizer::with_defaults()).unwrap();
        assert!(
            wired.has_sanitizer(),
            "new_with_sanitizer must wire the sanitizer"
        );
    }

    #[test]
    fn test_audit_event_with_tool_name() {
        let event = AuditEvent::new(
            "host1",
            "redis-cli INFO",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 50,
            },
        )
        .with_tool_name("ssh_redis_cli");

        assert_eq!(event.tool_name, Some("ssh_redis_cli".to_string()));
    }

    #[test]
    fn test_audit_event_without_tool_name() {
        let event = AuditEvent::new(
            "host1",
            "ls",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );
        assert_eq!(event.tool_name, None);
    }

    #[test]
    fn serialized_line_carries_the_tool_name() {
        let ev = AuditEvent::new(
            "h",
            "c",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 1,
            },
        );
        let logger = AuditLogger::for_test();
        logger.log("ssh_ls", ev);
        let first = logger.drain_for_test().remove(0);
        let line = serde_json::to_string(&first).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["tool_name"], "ssh_ls");
    }

    #[test]
    fn log_stamps_tool_and_overwrites_a_conflicting_name() {
        let logger = AuditLogger::for_test();
        let ok = CommandResult::Success {
            exit_code: 0,
            duration_ms: 1,
        };
        // Anonymous event: the sink supplies the name.
        logger.log("ssh_upload", AuditEvent::new("h", "c", ok.clone()));
        // Event already named differently: the parameter wins (single writer).
        logger.log(
            "ssh_download",
            AuditEvent::new("h", "c", ok).with_tool_name("ssh_exec"),
        );
        let events = logger.drain_for_test();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].tool_name.as_deref(), Some("ssh_upload"));
        assert_eq!(events[1].tool_name.as_deref(), Some("ssh_download"));
    }

    #[test]
    fn reduction_params_are_serialized_only_when_present() {
        let mut ev = AuditEvent::new(
            "h",
            "kubectl get pods -o json",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 1,
            },
        );
        assert!(!serde_json::to_string(&ev).unwrap().contains("reduction"));
        ev.reduction = vec!["jq_filter", "output_format"];
        let with = serde_json::to_string(&ev).unwrap();
        assert!(
            with.contains(r#""reduction":["jq_filter","output_format"]"#),
            "{with}"
        );
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "test-host",
            "ls -la",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 100,
            },
        );

        assert_eq!(event.host, "test-host");
        assert_eq!(event.command, "ls -la");
        assert_eq!(event.event_type, "ssh_exec");
    }

    #[test]
    fn test_audit_event_denied() {
        let event = AuditEvent::denied("test-host", "rm -rf /", "Matches blacklist");

        assert_eq!(event.event_type, "command_denied");
        match event.result {
            CommandResult::Denied { reason } => {
                assert!(reason.contains("blacklist"));
            }
            _ => panic!("Expected Denied result"),
        }
    }

    #[test]
    fn test_disabled_logger() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::new(
            "test",
            "echo test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );

        // Should not panic
        logger.log("test_tool", event);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(
            "prod-server",
            "docker ps",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 250,
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("prod-server"));
        assert!(json.contains("docker ps"));
        assert!(json.contains("250"));
    }

    #[test]
    fn test_valid_audit_path() {
        let config = AuditConfig {
            enabled: true,
            path: PathBuf::from("/var/log/bridge-mcp/audit.log"),
            max_size_mb: 10,
            retain_days: 30,
        };

        let valid = PathBuf::from("/var/log/bridge-mcp/audit.log.20240101");
        let invalid = PathBuf::from("/tmp/audit.log");

        assert!(is_valid_audit_path(&valid, &config));
        assert!(!is_valid_audit_path(&invalid, &config));
    }

    // ============== CommandResult Tests ==============

    #[test]
    fn test_command_result_success_serialization() {
        let result = CommandResult::Success {
            exit_code: 0,
            duration_ms: 100,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Success\""));
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("\"duration_ms\":100"));
    }

    #[test]
    fn test_command_result_error_serialization() {
        let result = CommandResult::Error {
            message: "Connection refused".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Error\""));
        assert!(json.contains("Connection refused"));
    }

    /// The one value, pinned. `NO_HOST` is a wire convention: it lands in
    /// `audit.log` as `"host":"<no-host>"` and every consumer and every grep
    /// has to tolerate exactly that string, so a change here is a change of
    /// contract and must break a test rather than a downstream parser.
    #[test]
    fn no_host_sentinel_is_pinned_and_cannot_be_a_real_alias() {
        assert_eq!(NO_HOST, "<no-host>");
        // Angle brackets are the reason it cannot collide with a config alias.
        assert!(NO_HOST.starts_with('<') && NO_HOST.ends_with('>'));
    }

    /// A state change is audited under its own `event_type` and **without any
    /// exit code at all** — the serialized line is the proof, because that is
    /// what a consumer reads.
    #[test]
    fn a_state_change_line_carries_no_exit_code_and_its_own_event_type() {
        let logger = AuditLogger::for_test();
        logger.log(
            "ssh_tunnel_close",
            AuditEvent::tagged(
                "state_change",
                "raspberry",
                "ssh_tunnel_close tunnel_id=tunnel-raspberry-8080-80",
                CommandResult::StateChanged { duration_ms: 7 },
            ),
        );
        let line = serde_json::to_string(&logger.drain_for_test().remove(0)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(v["event_type"], "state_change", "{line}");
        assert_eq!(v["tool_name"], "ssh_tunnel_close", "{line}");
        assert_eq!(v["host"], "raspberry", "{line}");
        assert_eq!(
            v["command"], "ssh_tunnel_close tunnel_id=tunnel-raspberry-8080-80",
            "the operation reaches the field every consumer already reads: {line}"
        );
        assert_eq!(v["result"]["StateChanged"]["duration_ms"], 7, "{line}");
        assert!(
            !line.contains("exit_code"),
            "no process ran, so no code may appear — the absence IS the information: {line}"
        );
    }

    /// `tagged` must hard-code NEITHER the `event_type` NOR the `result`:
    /// that is the whole reason it exists, and a later task needs the same
    /// mechanism for a different kind of event. A constructor that took the
    /// type but pinned the result would open a door its own body closes.
    #[test]
    fn tagged_takes_both_the_event_type_and_the_result_from_the_caller() {
        let ev = AuditEvent::tagged(
            "some_other_type",
            NO_HOST,
            "ssh_config_set key=k",
            CommandResult::Denied {
                reason: "a kind of event that is not a state change".to_string(),
            },
        );
        assert_eq!(ev.event_type, "some_other_type");
        assert_eq!(ev.host, NO_HOST);
        assert!(
            matches!(ev.result, CommandResult::Denied { .. }),
            "the result is the caller's too, got {:?}",
            ev.result
        );
        // Like the other two constructors, it leaves the naming to the sink.
        assert_eq!(ev.tool_name, None);
    }

    #[test]
    fn test_command_result_denied_serialization() {
        let result = CommandResult::Denied {
            reason: "Blacklisted command".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"Denied\""));
        assert!(json.contains("Blacklisted command"));
    }

    #[test]
    fn test_command_result_clone() {
        let result = CommandResult::Success {
            exit_code: 42,
            duration_ms: 500,
        };
        let cloned = result.clone();
        match cloned {
            CommandResult::Success {
                exit_code,
                duration_ms,
            } => {
                assert_eq!(exit_code, 42);
                assert_eq!(duration_ms, 500);
            }
            _ => panic!("Expected Success"),
        }
    }

    // ============== AuditEvent Tests ==============

    #[test]
    fn test_audit_event_with_error_result() {
        let event = AuditEvent::new(
            "server1",
            "failing-command",
            CommandResult::Error {
                message: "Command not found".to_string(),
            },
        );

        assert_eq!(event.event_type, "ssh_exec");
        match event.result {
            CommandResult::Error { message } => {
                assert_eq!(message, "Command not found");
            }
            _ => panic!("Expected Error result"),
        }
    }

    #[test]
    fn test_audit_event_timestamp() {
        let event = AuditEvent::new(
            "test",
            "ls",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 10,
            },
        );

        // Timestamp should be recent (within last minute)
        let now = Utc::now();
        let diff = now.signed_duration_since(event.timestamp);
        assert!(diff.num_seconds() < 60);
    }

    #[test]
    fn test_audit_event_clone() {
        let event = AuditEvent::new(
            "host1",
            "echo hello",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 5,
            },
        );

        let cloned = event.clone();
        assert_eq!(event.host, cloned.host);
        assert_eq!(event.command, cloned.command);
        assert_eq!(event.event_type, cloned.event_type);
    }

    #[test]
    fn test_audit_event_debug() {
        let event = AuditEvent::denied("host", "rm -rf /", "blacklisted");
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("AuditEvent"));
        assert!(debug_str.contains("command_denied"));
    }

    // ============== AuditLogger Tests ==============

    #[test]
    fn test_disabled_logger_needs_rotation() {
        let logger = AuditLogger::disabled();
        assert!(!logger.needs_rotation());
    }

    /// `disabled()` used to hold `AuditConfig::default()` under
    /// `#[cfg(test)]`: `enabled: true` and the REAL
    /// `~/.local/share/bridge-mcp/audit.log`. `rotate()` is gated on that
    /// flag alone, so the test that called it on a disabled logger renamed a
    /// developer's live audit log and swept its directory on every
    /// `cargo test` (184 archives, 175 of them empty, and a running `serve`
    /// kept appending to the renamed inode). The path is pointed at a temp
    /// file here so a regression fails an assertion instead of adding one
    /// more archive to the real directory.
    #[test]
    fn test_disabled_logger_never_touches_its_audit_path() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "live log").unwrap();
        let expired = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&expired, "expired archive").unwrap();
        let old_time = SystemTime::now() - Duration::from_hours(2400);
        filetime::set_file_mtime(&expired, filetime::FileTime::from_system_time(old_time)).unwrap();

        let mut logger = AuditLogger::disabled();
        logger.config.path = audit_path.clone();
        logger.rotate().unwrap();

        assert!(
            audit_path.exists(),
            "rotate() on a disabled logger renamed its live audit log"
        );
        assert!(
            expired.exists(),
            "rotate() on a disabled logger swept an archive out of its directory"
        );
        assert_eq!(
            std::fs::read_dir(temp_dir.path()).unwrap().count(),
            2,
            "rotate() on a disabled logger must not create an archive"
        );
        assert!(
            !logger.config.enabled,
            "a disabled logger must not carry an enabled audit config"
        );
    }

    #[test]
    fn test_audit_logger_with_temp_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("test-audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        assert!(task.is_some());

        // Log an event
        let event = AuditEvent::new(
            "test",
            "echo test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 1,
            },
        );
        logger.log("test_tool", event);

        // Check needs_rotation (should be false for small file)
        assert!(!logger.needs_rotation());
    }

    #[test]
    fn test_audit_logger_disabled_config() {
        let config = AuditConfig {
            enabled: false,
            path: PathBuf::from("/tmp/never-created.log"),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        assert!(task.is_none()); // No task for disabled logger

        // Log should not panic
        let event = AuditEvent::denied("test", "rm -rf /", "test");
        logger.log("test_tool", event);
    }

    // ============== Full Event Serialization Tests ==============

    #[test]
    fn test_full_event_json_structure() {
        let event = AuditEvent::new(
            "prod-server",
            "systemctl status nginx",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 150,
            },
        );

        let json = serde_json::to_string(&event).unwrap();

        // Parse back to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("timestamp").is_some());
        assert_eq!(parsed["event_type"], "ssh_exec");
        assert_eq!(parsed["host"], "prod-server");
        assert_eq!(parsed["command"], "systemctl status nginx");
        assert!(parsed.get("result").is_some());
    }

    #[test]
    fn test_denied_event_json_structure() {
        let event = AuditEvent::denied("prod-server", "rm -rf /", "Matches blacklist pattern");

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["event_type"], "command_denied");
        assert!(
            parsed["result"]["Denied"]["reason"]
                .as_str()
                .unwrap()
                .contains("blacklist")
        );
    }

    // ============== Mutation Testing Coverage ==============

    #[tokio::test]
    async fn test_audit_writer_task_writes_events() {
        use std::io::Read;
        use tokio::sync::mpsc;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("writer-test.log");

        // Create file and channel
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel();
        let task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: audit_path.clone(),
            max_bytes: 0, // rotation disabled: this test only checks the write path
            retain_days: 7,
            written_bytes: 0,
        };

        // Send an event
        let event = AuditEvent::new(
            "writer-test-host",
            "echo writer-test",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 42,
            },
        );
        tx.send(event).unwrap();

        // Drop sender to close channel
        drop(tx);

        // Run the task (will complete when channel closes)
        task.run().await;

        // Verify file contents
        let mut contents = String::new();
        std::fs::File::open(&audit_path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        assert!(contents.contains("writer-test-host"));
        assert!(contents.contains("echo writer-test"));
        assert!(contents.contains("42"));
    }

    /// G-26 (audit 2026-08-19): `rotate()` and `needs_rotation()` have existed
    /// since the first release with NO production caller in any branch or tag,
    /// while README.md documents `max_size_mb` / `retain_days` as working
    /// settings. The writer task owns the file handle, so it is the only place
    /// that can rename and reopen; this test drives the real task.
    #[tokio::test]
    async fn test_writer_task_rotates_past_max_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.expect("enabled audit must yield a writer task").run());

        // 24 events x ~64 KiB of command text = ~1.5 MiB: one rotation at the
        // 16th event, then ~0.5 MiB in the fresh file. Exactly one rotation.
        let big_command = "x".repeat(64 * 1024);
        for _ in 0..24 {
            logger.log(
                "test_tool",
                AuditEvent::new(
                    "rotate-host",
                    &big_command,
                    CommandResult::Success {
                        exit_code: 0,
                        duration_ms: 1,
                    },
                ),
            );
        }

        drop(logger); // closes the channel so run() returns
        handle.await.unwrap();

        let rotated: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .collect();

        assert_eq!(
            rotated.len(),
            1,
            "writer task must rotate exactly once past max_size_mb"
        );
        assert!(
            audit_path.exists(),
            "writer task must reopen the live audit log after rotating"
        );

        let live_len = std::fs::metadata(&audit_path).unwrap().len();
        assert!(
            live_len > 0 && live_len < 1024 * 1024,
            "post-rotation log must start fresh and keep receiving events, got {live_len} bytes"
        );
    }

    /// G-26's BREAKING marker rests entirely on `AuditWriterTask`'s
    /// `written_bytes` being SEEDED from the live file's existing length in
    /// `AuditLogger::new`: an operator already carrying a log over
    /// `max_size_mb` gets rotation — and therefore the retention sweep — on
    /// the very FIRST event after upgrading, not gradually. That is the
    /// whole reason the CHANGELOG calls the change a step function rather
    /// than a slow ramp.
    ///
    /// F12 (re-review of the 2026-08-19 audit corrections): replacing that
    /// seeding with `let written_bytes = 0;` left every single test in this
    /// module green. The most consequential behaviour in the change had no
    /// coverage at all. This is that test:
    /// `test_writer_task_rotates_past_max_size` reaches the threshold by
    /// writing 1.5 MiB of events, so it passes with or without the seeding;
    /// here ONE small event is the entire write volume, and only the seed
    /// can carry the counter over the threshold.
    #[tokio::test]
    async fn test_writer_task_seeds_written_bytes_from_existing_log() {
        // A log left behind by a pre-upgrade run, already past max_size_mb.
        const PRE_EXISTING: usize = 2 * 1024 * 1024;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, vec![b'x'; PRE_EXISTING]).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.expect("enabled audit must yield a writer task").run());

        // Exactly one small event: a few hundred bytes, nowhere near 1 MiB.
        logger.log(
            "test_tool",
            AuditEvent::new(
                "seed-host",
                "echo hi",
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: 1,
                },
            ),
        );

        drop(logger); // closes the channel so run() returns
        handle.await.unwrap();

        let archives: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| is_own_rotated_archive(&e.file_name().to_string_lossy(), "audit.log"))
            .collect();

        assert_eq!(
            archives.len(),
            1,
            "a single small event on an already-oversized log must rotate it \
             immediately: written_bytes has to be seeded from the file's \
             existing length, not from zero"
        );

        let archived_len = std::fs::metadata(archives[0].path()).unwrap().len();
        assert!(
            archived_len > PRE_EXISTING as u64,
            "the archive must carry the pre-existing bytes plus the event \
             that tripped rotation, got {archived_len}"
        );

        let live_len = std::fs::metadata(&audit_path).unwrap().len();
        assert_eq!(
            live_len, 0,
            "the reopened live log must start empty after rotation"
        );
    }

    /// IMPORTANT (fix round 1 of the 2026-08-19 audit corrections): before
    /// this fix, a reopen failure after a successful rename left `self.file`
    /// pointing at the RENAMED (now-archived) inode with `written_bytes`
    /// untouched -- so every later event kept landing in a file nobody
    /// tails, AND every later event re-attempted the rename, which fails
    /// every time (the source no longer exists at `self.path`), forever.
    /// The fix must instead permanently disable further rotation attempts
    /// once a reopen fails, logging once rather than looping.
    ///
    /// `reopen_after_rotation` is unit-tested directly (rather than through
    /// the full rename+reopen chain) because a filesystem state where rename
    /// legitimately succeeds but the immediately following create at the
    /// vacated name legitimately fails is not reproducible portably without
    /// racing the OS -- disk-full and inode-exhaustion are the only real
    /// causes, and this test cannot safely manufacture either on a shared
    /// dev VM. A missing parent directory reproduces the reopen failure
    /// deterministically and portably.
    #[test]
    fn test_reopen_after_rotation_failure_disables_further_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist: open_audit_file must fail with
        // ENOENT, deterministically and without touching any OS resource
        // limit or filling the disk.
        let unreachable_path = temp_dir.path().join("missing-dir").join("audit.log");

        // Placeholder handle for the `file` field; its own path is
        // irrelevant to what's under test (open_audit_file's success/failure
        // on `path`).
        let placeholder_path = temp_dir.path().join("placeholder.log");
        let file = open_audit_file(&placeholder_path).unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();
        let mut task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: unreachable_path,
            max_bytes: 1,
            retain_days: 7,
            written_bytes: 999,
        };

        task.reopen_after_rotation();

        assert_eq!(
            task.max_bytes, 0,
            "a reopen failure must permanently disable further rotation \
             attempts instead of retry-looping a rename that can only fail \
             the same way forever"
        );
    }

    /// F1 (re-review of the 2026-08-19 audit corrections): the reopen arm
    /// was hardened to disable rotation after a failure, but the RENAME arm
    /// kept `warn!`-and-return with `written_bytes` and `max_bytes` left
    /// untouched. `rotate_if_needed`'s guard (`written_bytes < max_bytes`)
    /// therefore never short-circuits again, so every subsequent audit
    /// event issues another doomed `rename(2)` plus another `warn!` --
    /// forever. An EROFS remount, a permission change, a moved or deleted
    /// directory, a MAC denial, or an external logrotate removing the live
    /// log all reach this arm. Both arms must degrade identically: log once
    /// at `error!`, then permanently disable rotation for this task.
    #[test]
    fn test_rename_failure_disables_further_rotation() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist, so `rename(2)` on this source
        // fails with ENOENT every single time -- a permanently failing
        // rotation, deterministic and portable, without manufacturing
        // disk-full or a read-only mount on a shared dev VM.
        let unreachable_path = temp_dir.path().join("missing-dir").join("audit.log");

        // Placeholder handle for the `file` field; only `path` is under test.
        let placeholder_path = temp_dir.path().join("placeholder.log");
        let file = open_audit_file(&placeholder_path).unwrap();

        let (_tx, rx) = mpsc::unbounded_channel();
        let mut task = AuditWriterTask {
            rx,
            file,
            sanitizer: None,
            path: unreachable_path,
            max_bytes: 1,
            retain_days: 7,
            written_bytes: 999,
        };

        task.rotate_if_needed();

        assert_eq!(
            task.max_bytes, 0,
            "a rename failure must permanently disable further rotation, \
             not leave the guard armed so that every later event re-issues \
             the same doomed rename(2)"
        );

        // With rotation disabled the guard clause must short-circuit even
        // when the byte counter is back above the (now zero) threshold, so
        // repeated events cannot resurrect the retry loop.
        for _ in 0..4 {
            task.written_bytes = 999;
            task.rotate_if_needed();
            assert_eq!(
                task.max_bytes, 0,
                "rotation must stay permanently disabled once it has failed"
            );
        }
    }

    /// `max_size_mb: 0` must DISABLE rotation in the writer task rather than
    /// rotate on every single event (which would shred the log directory).
    #[tokio::test]
    async fn test_writer_task_treats_zero_max_size_as_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 0,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let handle = tokio::spawn(task.unwrap().run());

        for _ in 0..3 {
            logger.log(
                "test_tool",
                AuditEvent::new(
                    "zero-host",
                    "echo hi",
                    CommandResult::Success {
                        exit_code: 0,
                        duration_ms: 1,
                    },
                ),
            );
        }

        drop(logger);
        handle.await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "max_size_mb=0 must not rotate: expected only audit.log"
        );
    }

    /// Its only assertion used to be `assert!(logger.sender.is_some())`
    /// after logging three events: it checked that a call which does not
    /// clear that field had not cleared it. Nothing observed whether an
    /// event came out the other end — which is what the name promises, and
    /// it was also the only place in the crate that read the field
    /// directly, outside the constructors and `log` itself.
    ///
    /// It now runs the real writer, closes the channel, joins it, and reads
    /// the file. Reading after the join is what makes the assertion
    /// deterministic: the write happens in a `spawn_blocking`, so before the
    /// join there is nothing to poll for.
    #[tokio::test]
    async fn test_audit_logger_log_sends_to_channel() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("log-test.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let task = task.expect("Task should be created for enabled logger");
        let writer = tokio::spawn(task.run());

        // Log multiple events
        for i in 0..3 {
            let event = AuditEvent::new(
                &format!("host-{i}"),
                &format!("cmd-{i}"),
                CommandResult::Success {
                    exit_code: i,
                    duration_ms: u64::from(i) * 10,
                },
            );
            logger.log("test_tool", event);
        }

        // Without this the writer stays parked on `recv()` for ever: the
        // logger still holds the sender.
        logger.close();
        tokio::time::timeout(DRAIN_TIMEOUT, writer)
            .await
            .expect("close() must let the writer's loop end")
            .expect("the writer task must not panic");

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "all three logged events must be on disk, got: {contents}"
        );
        for (i, line) in lines.iter().enumerate() {
            let event: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("audit line must be JSONL: {e} — line was {line:?}"));
            assert_eq!(event["host"], format!("host-{i}"));
            assert_eq!(event["command"], format!("cmd-{i}"));
            assert_eq!(event["tool_name"], "test_tool");
        }
    }

    /// The reason the shutdown JOINS the writer and never `abort()`s it,
    /// pinned on the only configuration where it can be observed: rotation
    /// ON.
    ///
    /// The review of round 1 was right that nothing covered this. The claim
    /// is that an abort would lose the event in its `spawn_blocking` **and**
    /// the rotation that follows it in the same loop iteration — but
    /// `close_ends_the_writer_while_a_clone_of_the_logger_survives` and the
    /// two integration tests all run with `max_size_mb: 0`, which disables
    /// rotation outright, so the second half of that claim had no witness.
    ///
    /// Sized so the LAST event is the one that rotates: `max_size_mb: 1` is
    /// 1 048 576 bytes and each line is ~64 KiB of command plus ~150 bytes
    /// of envelope, so the counter crosses the bound on the 16th. The
    /// rotation therefore happens after `close()` has already been called —
    /// inside the drain — which is exactly the window an `abort()` would cut.
    ///
    /// Counter-proof, measured: replacing the join with `handle.abort()`
    /// leaves no archive at all and the live file at ~1 MiB. See the T12
    /// report.
    #[tokio::test]
    async fn the_drain_lets_the_last_event_rotate_the_log() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let writer = tokio::spawn(task.expect("enabled audit must yield a writer task").run());

        let big_command = "x".repeat(64 * 1024);
        for i in 0..16 {
            logger.log(
                "test_tool",
                AuditEvent::new(
                    "rotate-host",
                    &format!("{big_command} marker-{i}"),
                    CommandResult::Success {
                        exit_code: 0,
                        duration_ms: 1,
                    },
                ),
            );
        }

        logger.close();
        drain_audit_writer(Some(writer)).await;

        let archives: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .collect();
        assert_eq!(
            archives.len(),
            1,
            "the drain must have let the rotation complete: expected exactly              one archive beside the live file"
        );

        let rotated_out = std::fs::read_to_string(archives[0].path()).unwrap();
        assert_eq!(
            rotated_out.lines().count(),
            16,
            "every event must be in the archive the rotation created"
        );
        assert!(
            rotated_out.contains("marker-15"),
            "the event that TRIGGERED the rotation must be in the archive,              not lost with the write that was in flight"
        );

        // Reopened, not left pointing at the renamed inode: that is the other
        // half of what `rotate_if_needed` does after the write, and the half
        // an abort would also cut.
        assert!(audit_path.exists(), "the live log must have been reopened");
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().len(),
            0,
            "the reopened live log starts empty"
        );
    }

    /// Why `close()` exists rather than "drop the logger and let the channel
    /// close itself".
    ///
    /// The drop form works if and only if every clone of the
    /// `Arc<AuditLogger>` dies first, and nothing in the crate establishes
    /// that: background tasks and every `ToolContext` hold one. This test
    /// keeps a clone alive across the shutdown on purpose. Under the drop
    /// form the writer would still be parked on `recv()` and the join would
    /// burn the whole timeout; here it ends.
    ///
    /// The second half is the price: a `log` on the surviving clone after
    /// the close reaches `tracing` and the file not at all. That is the
    /// documented behaviour, and the file length pins it.
    #[tokio::test]
    async fn close_ends_the_writer_while_a_clone_of_the_logger_survives() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let logger = Arc::new(logger);
        let writer = tokio::spawn(task.expect("enabled audit yields a writer").run());

        // The clone the drop form cannot see.
        let survivor = Arc::clone(&logger);

        logger.log(
            "test_tool",
            AuditEvent::new(
                "host-a",
                "cmd-before-close",
                CommandResult::StateChanged { duration_ms: 1 },
            ),
        );
        logger.close();

        tokio::time::timeout(DRAIN_TIMEOUT, writer)
            .await
            .expect("close() must end the writer even with a live clone of the logger")
            .expect("the writer task must not panic");

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert!(
            contents.contains("cmd-before-close"),
            "the event logged before the close must be on disk, got: {contents}"
        );

        let before = std::fs::metadata(&audit_path).unwrap().len();
        survivor.log(
            "test_tool",
            AuditEvent::new(
                "host-b",
                "cmd-after-close",
                CommandResult::StateChanged { duration_ms: 1 },
            ),
        );
        assert_eq!(
            std::fs::metadata(&audit_path).unwrap().len(),
            before,
            "a log after close() must not reach the file (and must not panic)"
        );
    }

    #[test]
    fn test_needs_rotation_true_when_file_exceeds_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("rotation-test.log");

        // Create a file larger than 1 MB (set max_size_mb to 1)
        let large_content = "x".repeat(1024 * 1024 + 100); // 1 MB + 100 bytes
        std::fs::write(&audit_path, large_content).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 1, // 1 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        assert!(
            logger.needs_rotation(),
            "Should need rotation when file exceeds max_size_mb"
        );
    }

    #[test]
    fn test_needs_rotation_false_when_file_under_size() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("small-file.log");

        // Create a small file (much smaller than 1 MB)
        std::fs::write(&audit_path, "small content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10, // 10 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        assert!(
            !logger.needs_rotation(),
            "Should not need rotation when file is small"
        );
    }

    #[test]
    fn test_rotate_renames_file_with_timestamp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("rotate-test.log");

        // Create original file
        std::fs::write(&audit_path, "original content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();

        // Rotate
        logger.rotate().unwrap();

        // Original file should be renamed (no longer exist at original path)
        assert!(!audit_path.exists(), "Original file should be renamed");

        // A rotated file should exist in the same directory
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "Should have exactly one rotated file");

        // Rotated filename should contain timestamp pattern
        let rotated_name = entries[0].file_name().to_string_lossy().to_string();
        assert!(
            rotated_name.starts_with("rotate-test.log."),
            "Rotated file should have timestamp suffix"
        );
    }

    /// MINOR (fix round 1 of the 2026-08-19 audit corrections): the rotated
    /// name is `<file name>.<YYYYmmdd_HHMMSS>` -- one-second resolution.
    /// Two rotations within the same wall-clock second previously collided
    /// on that name and `fs::rename` silently clobbered the first archive.
    /// Drives `rename_with_timestamp` directly with a FIXED `now` twice in
    /// a row (rather than racing the real clock) to deterministically
    /// reproduce the same-second collision.
    #[test]
    fn test_rename_with_timestamp_does_not_clobber_a_same_second_collision() {
        fn fixed_now() -> DateTime<Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        std::fs::write(&audit_path, "first rotation's content").unwrap();
        rename_with_timestamp(&audit_path, fixed_now()).unwrap();

        // A second rotation in the SAME second: a fresh live file appears
        // again at the original path (as the writer task's reopen does),
        // and rotates again with an identical timestamp.
        std::fs::write(&audit_path, "second rotation's content").unwrap();
        rename_with_timestamp(&audit_path, fixed_now()).unwrap();

        let archived: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log."))
            .collect();

        assert_eq!(
            archived.len(),
            2,
            "two same-second rotations must produce two distinct archives, not one clobbered file"
        );

        let contents: std::collections::HashSet<String> = archived
            .iter()
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .collect();
        assert!(
            contents.contains("first rotation's content"),
            "the first archive must survive the second rotation"
        );
        assert!(
            contents.contains("second rotation's content"),
            "the second archive must also be present"
        );
    }

    #[test]
    fn test_cleanup_old_files_removes_expired() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create the main audit file
        std::fs::write(&audit_path, "current log").unwrap();

        // Create an "old" file (we'll set its mtime to the past using filetime)
        let old_file = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&old_file, "old content").unwrap();

        // Set modification time to 100 days ago
        let old_time = SystemTime::now() - Duration::from_hours(2400);
        filetime::set_file_mtime(&old_file, filetime::FileTime::from_system_time(old_time))
            .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30, // Keep files for 30 days
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Old file should be deleted
        assert!(!old_file.exists(), "Old file should be deleted");
    }

    #[test]
    fn test_cleanup_keeps_file_at_exact_cutoff() {
        // Strict `<` in the retention check: a file whose mtime is exactly
        // equal to the cutoff must NOT be deleted. Fixed clock + fixed mtime
        // make the boundary reachable deterministically.
        fn fixed_now() -> DateTime<Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        let boundary_file = temp_dir.path().join("audit.log.20260101_000000");
        std::fs::write(&boundary_file, "boundary content").unwrap();

        let cutoff = fixed_now() - chrono::Duration::days(30);
        filetime::set_file_mtime(
            &boundary_file,
            filetime::FileTime::from_system_time(std::time::SystemTime::from(cutoff)),
        )
        .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (mut logger, _) = AuditLogger::new(&config).unwrap();
        logger.set_clock(fixed_now);
        logger.cleanup_old_files();

        assert!(
            boundary_file.exists(),
            "file with mtime == cutoff must be kept (strict <)"
        );
    }

    #[test]
    fn test_cleanup_old_files_keeps_recent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create the main audit file
        std::fs::write(&audit_path, "current log").unwrap();

        // Create a recent file (default mtime is now)
        let recent_file = temp_dir.path().join("audit.log.20240601_120000");
        std::fs::write(&recent_file, "recent content").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Recent file should still exist
        assert!(recent_file.exists(), "Recent file should be kept");
    }

    #[test]
    fn test_cleanup_old_files_respects_zero_retain_days() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        std::fs::write(&audit_path, "current log").unwrap();

        // A real rotated archive of THIS log, backdated well past any
        // plausible cutoff. F2 (re-review): this fixture used to be named
        // `audit.log.old` with a current mtime, so it survived on BOTH
        // counts and proved nothing about `retain_days: 0`. It now survives
        // only because the sweep is disabled.
        let old_file = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&old_file, "old content").unwrap();
        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        filetime::set_file_mtime(&old_file, filetime::FileTime::from_system_time(old_time))
            .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 0, // 0 means no cleanup
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // File should still exist (retain_days=0 disables cleanup)
        assert!(
            old_file.exists(),
            "Files should not be deleted when retain_days=0"
        );
    }

    #[test]
    fn test_cleanup_old_files_boundary_exact_cutoff_date() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current").unwrap();

        // Create file exactly at the cutoff (should be deleted if using <, kept if using <=).
        // Both fixtures carry the real `<name>.<YYYYmmdd_HHMMSS>` archive
        // shape (F2); the embedded timestamp is never parsed, the mtime set
        // below is what retention decides on.
        let exactly_at_cutoff = temp_dir.path().join("audit.log.20250101_000000");
        std::fs::write(&exactly_at_cutoff, "at cutoff").unwrap();

        // Set mtime to exactly 30 days ago
        let retain_days = 30u32;
        let cutoff_time =
            SystemTime::now() - Duration::from_secs(u64::from(retain_days) * 24 * 60 * 60);
        filetime::set_file_mtime(
            &exactly_at_cutoff,
            filetime::FileTime::from_system_time(cutoff_time),
        )
        .unwrap();

        // Create file just before cutoff (31 days ago, should definitely be deleted)
        let before_cutoff = temp_dir.path().join("audit.log.20241201_000000");
        std::fs::write(&before_cutoff, "31 days old").unwrap();
        let old_time = SystemTime::now() - Duration::from_hours(744);
        filetime::set_file_mtime(
            &before_cutoff,
            filetime::FileTime::from_system_time(old_time),
        )
        .unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // File older than cutoff should be deleted
        assert!(
            !before_cutoff.exists(),
            "File older than retain_days should be deleted"
        );
    }

    /// CRITICAL (fix round 1 of the 2026-08-19 audit corrections):
    /// `cleanup_old_audit_files` deleted EVERY file in `audit.path`'s parent
    /// directory older than `retain_days`, with no filename check at all —
    /// via `let _ = std::fs::remove_file(...)`, silently. It had no
    /// production caller before the G-26 fix wired `rotate_if_needed` into
    /// the writer task; it now runs on every rotation. With a config like
    /// `path: ~/audit.log`, that swept the operator's entire home directory.
    /// Cleanup must only ever touch this log's OWN rotated archives, named
    /// `<file name>.<suffix>` by `rename_with_timestamp` — nothing else in
    /// that directory is this writer's to delete.
    #[test]
    fn test_cleanup_old_files_never_deletes_files_outside_its_own_lineage() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        // A legitimate rotated archive of THIS log: must still be removed
        // once past retention -- the fix must not overcorrect into deleting
        // nothing.
        let own_archive = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&own_archive, "old archive").unwrap();

        // Files this writer never created, sitting in the same directory --
        // exactly the shape of `audit.path: ~/audit.log`, where the parent
        // directory is $HOME.
        let foreign_dotfile = temp_dir.path().join(".bash_history");
        std::fs::write(&foreign_dotfile, "some shell history").unwrap();
        let foreign_doc = temp_dir.path().join("quarterly-report.pdf");
        std::fs::write(&foreign_doc, "not ours").unwrap();
        // Shares the live log's name as a literal prefix but is not one of
        // its rotated archives (no "." separator after "audit.log") --
        // must also survive.
        let lookalike = temp_dir.path().join("audit.log-backup");
        std::fs::write(&lookalike, "not a rotated archive").unwrap();

        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        for f in [&own_archive, &foreign_dotfile, &foreign_doc, &lookalike] {
            filetime::set_file_mtime(f, filetime::FileTime::from_system_time(old_time)).unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            !own_archive.exists(),
            "its own expired rotated archive must still be removed"
        );
        assert!(
            foreign_dotfile.exists(),
            "a file this writer never created must survive no matter how old"
        );
        assert!(
            foreign_doc.exists(),
            "a file this writer never created must survive no matter how old"
        );
        assert!(
            lookalike.exists(),
            "a name that merely starts with the live log's name, but isn't \
             <name>.<timestamp>, must survive"
        );
    }

    /// F2 (re-review of the 2026-08-19 audit corrections): the first fix
    /// scoped the sweep with `starts_with("<live file name>.")` -- i.e.
    /// "anything after a dot". That is not the shape `rename_with_timestamp`
    /// writes, and it captures files that belong to somebody else. A SECOND
    /// bridge-mcp instance configured `audit.path: .../audit.log.staging`
    /// has a LIVE log whose name starts with `audit.log.`, so the busy
    /// instance deletes it on its first rotation -- silently, since removal
    /// is `let _ = std::fs::remove_file(...)`. An external logrotate's
    /// `audit.log.1` and `audit.log.gz` are swept by the same predicate.
    /// Only the exact `<name>.<YYYYmmdd_HHMMSS>` shape, with the optional
    /// `.<n>` same-second collision counter, is this writer's to delete.
    #[test]
    fn test_cleanup_never_deletes_a_sibling_instances_live_log() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        // A second instance's LIVE audit log, and one of ITS rotated
        // archives. Both start with `audit.log.`; neither is ours.
        let sibling_live = temp_dir.path().join("audit.log.staging");
        std::fs::write(&sibling_live, "the other instance's live log").unwrap();
        let sibling_archive = temp_dir.path().join("audit.log.staging.20260101_000000");
        std::fs::write(&sibling_archive, "the other instance's archive").unwrap();

        // An external logrotate's output for the same file.
        let logrotate_numbered = temp_dir.path().join("audit.log.1");
        std::fs::write(&logrotate_numbered, "logrotate copy").unwrap();
        let logrotate_gz = temp_dir.path().join("audit.log.gz");
        std::fs::write(&logrotate_gz, "logrotate compressed").unwrap();

        // Ours, and it must still be swept -- the fix must not overcorrect
        // into deleting nothing.
        let own_archive = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&own_archive, "our archive").unwrap();
        let own_collision_archive = temp_dir.path().join("audit.log.20200101_000000.1");
        std::fs::write(&own_collision_archive, "our same-second archive").unwrap();

        let old_time = SystemTime::now() - Duration::from_hours(2400); // 100 days
        for f in [
            &sibling_live,
            &sibling_archive,
            &logrotate_numbered,
            &logrotate_gz,
            &own_archive,
            &own_collision_archive,
        ] {
            filetime::set_file_mtime(f, filetime::FileTime::from_system_time(old_time)).unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            sibling_live.exists(),
            "another instance's LIVE audit log must never be deleted by this \
             instance's retention sweep"
        );
        assert!(
            sibling_archive.exists(),
            "another instance's rotated archive must never be deleted by this \
             instance's retention sweep"
        );
        assert!(
            logrotate_numbered.exists(),
            "an external logrotate's audit.log.1 is not ours to delete"
        );
        assert!(
            logrotate_gz.exists(),
            "an external logrotate's audit.log.gz is not ours to delete"
        );
        assert!(
            !own_archive.exists(),
            "our own expired archive must still be swept"
        );
        assert!(
            !own_collision_archive.exists(),
            "our own expired same-second-collision archive must still be swept"
        );
    }

    /// F8 (re-review of the 2026-08-19 audit corrections): rotation samples
    /// `Utc::now()` to name the archive, then the sweep compares each
    /// candidate's FILESYSTEM mtime against `now - retain_days` from a
    /// SECOND `Utc::now()`. A forward wall-clock jump larger than
    /// `retain_days` — a VM resumed from a snapshot, a dead RTC, a first NTP
    /// sync on a box that booted at the epoch — puts the archive created
    /// microseconds earlier on the wrong side of the cutoff, so rotation
    /// preserves the events and the sweep immediately deletes them.
    ///
    /// The jump is simulated by handing `cleanup_old_audit_files` a `now`
    /// far in the future rather than by touching this machine's clock. That
    /// is the same arithmetic the real jump produces: the cutoff moves past
    /// a freshly written mtime either way.
    #[test]
    fn test_cleanup_skips_the_archive_rotation_just_created() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "live log with events worth keeping").unwrap();

        let rotated = rename_with_timestamp(&audit_path, Utc::now()).unwrap();
        assert!(rotated.exists(), "precondition: the archive was created");

        // The clock jumps forward by far more than retain_days between the
        // rename and the sweep.
        let jumped = Utc::now() + chrono::Duration::days(400);
        cleanup_old_audit_files(&audit_path, 30, jumped, Some(rotated.as_path()));

        assert!(
            rotated.exists(),
            "the archive rotation created microseconds earlier must survive \
             the sweep unconditionally, whatever its mtime says relative to a \
             jumped clock"
        );

        // Guard against over-correcting into "skip everything": a DIFFERENT
        // archive, not the one just rotated, is still swept by the same call.
        let older_archive = temp_dir.path().join("audit.log.20200101_000000");
        std::fs::write(&older_archive, "genuinely expired").unwrap();
        cleanup_old_audit_files(&audit_path, 30, jumped, Some(rotated.as_path()));
        assert!(
            !older_archive.exists(),
            "an archive that is NOT the one just rotated must still be swept"
        );
        assert!(rotated.exists(), "and the protected one must still survive");
    }

    /// F7 (re-review of the 2026-08-19 audit corrections): removal was
    /// `let _ = std::fs::remove_file(...)` with no log line anywhere, and no
    /// counter. The CHANGELOG names silent deletion as reason (1) for G-26's
    /// BREAKING marker and then leaves it silent. On the first release where
    /// this code path deletes anything at all, a sweep that removed nothing
    /// (EACCES, EBUSY, an already-vanished file) has to be distinguishable
    /// from one that removed every archive in the directory.
    #[test]
    #[tracing_test::traced_test]
    fn test_cleanup_logs_what_it_swept() {
        use std::time::{Duration, SystemTime};

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");
        std::fs::write(&audit_path, "current log").unwrap();

        let expired_a = temp_dir.path().join("audit.log.20200101_000000");
        let expired_b = temp_dir.path().join("audit.log.20200102_000000");
        for f in [&expired_a, &expired_b] {
            std::fs::write(f, "old archive").unwrap();
            filetime::set_file_mtime(
                f,
                filetime::FileTime::from_system_time(
                    SystemTime::now() - Duration::from_hours(2400), // 100 days
                ),
            )
            .unwrap();
        }

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            max_size_mb: 10,
            retain_days: 30,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        assert!(
            !expired_a.exists() && !expired_b.exists(),
            "both expired archives must actually be swept"
        );
        assert!(
            logs_contain("audit retention swept archives"),
            "the retention sweep must leave a log line saying it ran"
        );
        assert!(
            logs_contain("removed=2"),
            "the retention sweep must report HOW MANY archives it deleted"
        );
    }

    #[test]
    fn test_needs_rotation_size_calculation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("size-test.log");

        // Create file exactly at 1 MB boundary
        let one_mb = 1024 * 1024;
        let content = "x".repeat(one_mb);
        std::fs::write(&audit_path, &content).unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 1, // 1 MB threshold
            retain_days: 7,
        };

        let (logger, _) = AuditLogger::new(&config).unwrap();

        // Exactly 1 MB should trigger rotation (>= check)
        assert!(
            logger.needs_rotation(),
            "File exactly at max_size_mb should need rotation"
        );

        // Now create a file just under 1 MB
        let under_one_mb = "x".repeat(one_mb - 100);
        std::fs::write(&audit_path, &under_one_mb).unwrap();

        // Re-check - should not need rotation
        assert!(
            !logger.needs_rotation(),
            "File under max_size_mb should not need rotation"
        );
    }

    #[tokio::test]
    async fn test_log_actually_writes_event_to_file() {
        use std::io::Read;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("log-write-test.log");

        let config = AuditConfig {
            enabled: true,
            path: audit_path.clone(),
            max_size_mb: 10,
            retain_days: 7,
        };

        let (logger, task) = AuditLogger::new(&config).unwrap();
        let task = task.expect("Task should exist for enabled logger");

        // Create a unique event
        let event = AuditEvent::new(
            "log-write-test-host",
            "unique-command-12345",
            CommandResult::Success {
                exit_code: 42,
                duration_ms: 999,
            },
        );

        // Call log() - this should send the event to the channel
        logger.log("test_tool", event);

        // Drop logger to close the channel
        drop(logger);

        // Run the writer task to completion
        task.run().await;

        // Verify the event was written to the file
        let mut contents = String::new();
        std::fs::File::open(&audit_path)
            .expect("Audit file should exist")
            .read_to_string(&mut contents)
            .expect("Should read file");

        assert!(
            contents.contains("log-write-test-host"),
            "File should contain the host: {contents}"
        );
        assert!(
            contents.contains("unique-command-12345"),
            "File should contain the command: {contents}"
        );
        assert!(
            contents.contains("42"),
            "File should contain exit code: {contents}"
        );
        assert!(
            contents.contains("999"),
            "File should contain duration: {contents}"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_trace() {
        // Create a disabled logger (doesn't need file)
        let logger = AuditLogger::disabled();

        // Create an event
        let event = AuditEvent::new(
            "tracing-test-host",
            "tracing-test-command",
            CommandResult::Success {
                exit_code: 0,
                duration_ms: 100,
            },
        );

        // Call log() which internally calls log_to_tracing
        logger.log("test_tool", event);

        // Verify tracing output was captured
        // tracing_test::traced_test captures logs and we can assert on them
        assert!(logs_contain("tracing-test-host"));
        assert!(logs_contain("tracing-test-command"));
        assert!(logs_contain("Audit: command executed"));
        assert!(logs_contain("test_tool"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_denied_trace() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::denied("denied-host", "rm -rf /", "blacklisted pattern");

        logger.log("test_tool", event);

        assert!(logs_contain("denied-host"));
        assert!(logs_contain("Audit: command denied"));
        assert!(logs_contain("blacklisted pattern"));
        assert!(logs_contain("test_tool"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_log_to_tracing_emits_error_trace() {
        let logger = AuditLogger::disabled();
        let event = AuditEvent::new(
            "error-host",
            "failing-cmd",
            CommandResult::Error {
                message: "Connection refused".to_string(),
            },
        );

        logger.log("test_tool", event);

        assert!(logs_contain("error-host"));
        assert!(logs_contain("Audit: command failed"));
        assert!(logs_contain("Connection refused"));
        assert!(logs_contain("test_tool"));
    }

    // ============== Tests to catch previously-missed mutations ==============

    #[test]
    fn test_cleanup_old_files_respects_cutoff_boundary() {
        use std::fs;

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_path = temp_dir.path().join("audit.log");

        // Create a rotated archive of THIS log and backdate it to 31 days
        // ago. Fix round 1 (audit 2026-08-19): these used to be named
        // `old_audit.log` / `recent_audit.log` -- filenames that are NOT
        // `<live file name>.<suffix>`, which only ever passed because
        // `cleanup_old_audit_files` had no filename filter at all (the
        // CRITICAL bug fixed alongside this test). F2 (re-review): the
        // replacements `audit.log.old31` / `audit.log.recent` were not the
        // archive shape either -- they only passed the prefix-only
        // predicate that F2 replaced. These are real
        // `<name>.<YYYYmmdd_HHMMSS>` archives now. The embedded timestamp is
        // never parsed: retention is decided on the file's mtime, set below.
        let old_file = temp_dir.path().join("audit.log.20250701_000000");
        fs::write(&old_file, "old data").unwrap();
        let old_time = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - std::time::Duration::from_hours(744),
        );
        filetime::set_file_mtime(&old_file, old_time).unwrap();

        // Create a recent rotated archive (today)
        let recent_file = temp_dir.path().join("audit.log.20260801_120000");
        fs::write(&recent_file, "recent data").unwrap();

        let config = AuditConfig {
            enabled: true,
            path: audit_path,
            retain_days: 30,
            ..Default::default()
        };

        let (logger, _task) = AuditLogger::new(&config).unwrap();
        logger.cleanup_old_files();

        // Old file (31 days) should be removed (31 > 30)
        assert!(
            !old_file.exists(),
            "File older than retain_days should be cleaned up"
        );

        // Recent file should remain
        assert!(recent_file.exists(), "Recent file should not be cleaned up");
    }
}
