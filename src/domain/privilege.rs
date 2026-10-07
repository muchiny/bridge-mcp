//! Privilege elevation for built-in tool commands.
//!
//! Three of the crate's handlers — `ssh_exec`, `ssh_exec_multi`,
//! `ssh_session_exec` — took a `sudo` argument. The other 473 did not, so on a
//! host where the interesting state is root-owned, every specialised tool
//! failed and the only way through was the escape hatch the server's own
//! instructions tell clients to avoid ("PREFER SPECIALIZED TOOLS over
//! `ssh_exec`"). On a K3s host that meant the whole `cri` group
//! (`crictl.yaml: permission denied`), `ssh_firewall_status`
//! (`iptables: you must be root`), and every systemd write
//! (`Interactive authentication required`).
//!
//! Elevation is handled here, once, for the whole [`StandardTool`] pipeline
//! rather than per handler.
//!
//! [`StandardTool`]: crate::mcp::standard_tool::StandardTool

use crate::config::ShellType;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};

/// Maximum length of a `sudo_user` value.
///
/// `useradd` caps names at 32 on Linux; this only needs to be small enough
/// that a pathological value cannot bloat the command line.
const MAX_SUDO_USER_LEN: usize = 32;

/// Privilege-elevation arguments, extracted from the raw request object before
/// tool-specific deserialization.
///
/// Lifted out of the typed args the way `DataReductionArgs` is, so that adding
/// elevation costs nothing per handler: the 400 `impl_common_args!` structs are
/// untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivilegeArgs {
    /// Run the built command through `sudo`.
    pub sudo: bool,
    /// Target user for `sudo -u`. Ignored unless `sudo` is set.
    pub sudo_user: Option<String>,
}

impl PrivilegeArgs {
    /// Remove and parse `sudo` / `sudo_user` from a raw arguments object.
    ///
    /// They are removed rather than read so they never reach the handler's own
    /// `Args`, which does not declare them.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::McpInvalidRequest`] if `sudo` is not a boolean,
    /// or if `sudo_user` is not a plausible user name — see
    /// [`validate_sudo_user`].
    pub fn extract(value: &mut serde_json::Value) -> Result<Self> {
        let Some(obj) = value.as_object_mut() else {
            return Ok(Self::default());
        };

        let sudo = match obj.remove("sudo") {
            None => false,
            Some(serde_json::Value::Bool(b)) => b,
            Some(other) => {
                return Err(BridgeError::McpInvalidRequest(format!(
                    "'sudo' must be a boolean, got {other}"
                )));
            }
        };

        let sudo_user = match obj.remove("sudo_user") {
            None => None,
            Some(serde_json::Value::String(s)) => {
                validate_sudo_user(&s)?;
                Some(s)
            }
            Some(other) => {
                return Err(BridgeError::McpInvalidRequest(format!(
                    "'sudo_user' must be a string, got {other}"
                )));
            }
        };

        Ok(Self { sudo, sudo_user })
    }

    /// Whether this request asks for elevation.
    #[must_use]
    pub const fn is_elevated(&self) -> bool {
        self.sudo
    }
}

/// Reject a `sudo_user` that is not a plausible user name.
///
/// The value reaches a command line, so it is constrained rather than escaped:
/// a name is a short run of `[A-Za-z0-9._-]`, not starting with `-` (which
/// `sudo` would read as a flag). Anything else is refused rather than quoted,
/// because there is no legitimate user name that needs quoting and accepting
/// one would only widen what the command line can express.
///
/// # Errors
///
/// Returns [`BridgeError::McpInvalidRequest`] when the name is empty, too long,
/// starts with `-`, or contains anything outside the allowed set.
pub fn validate_sudo_user(user: &str) -> Result<()> {
    if user.is_empty() {
        return Err(BridgeError::McpInvalidRequest(
            "'sudo_user' must not be empty".to_string(),
        ));
    }
    if user.len() > MAX_SUDO_USER_LEN {
        return Err(BridgeError::McpInvalidRequest(format!(
            "'sudo_user' is too long (max {MAX_SUDO_USER_LEN} characters)"
        )));
    }
    if user.starts_with('-') {
        return Err(BridgeError::McpInvalidRequest(
            "'sudo_user' must not start with '-': sudo would read it as a flag".to_string(),
        ));
    }
    if !user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(BridgeError::McpInvalidRequest(
            "'sudo_user' may contain only letters, digits, '.', '_' and '-'".to_string(),
        ));
    }
    Ok(())
}

/// Wrap a command so the WHOLE of it runs elevated.
///
/// The obvious form — prefixing `sudo ` — elevates only the first process in
/// the line, so redirections, pipes and `&&` chains still run as the login
/// user. That is not a subtlety: `sudo` plus `echo x > /etc/foo` fails with
/// "Permission denied" on the *redirect*, having successfully elevated the
/// `echo`. Wrapping the whole line in an elevated shell is what a caller
/// passing `sudo=true` means.
///
/// The shell is `bash`, not `sh`, and that is forced by what the builders emit:
/// 43 of them use `&>/dev/null`, which is bash-only. Under dash — Debian's
/// `/bin/sh` — `cmd &>/dev/null` parses as `cmd &` followed by `>/dev/null`, so
/// the command is backgrounded and its output leaks to stdout instead of being
/// discarded. That corrupts any builder wrapping such a probe in a command
/// substitution: `ssh_crictl_ps` under `sh -c` produced
/// `No help topic for '/usr/local/bin/k3s'`, the leaked path having been
/// captured into the command prefix. These commands already run under the
/// caller's login shell, which is bash on any host where they work today, so
/// using bash here matches the existing requirement rather than adding one.
///
/// `-n` is deliberate: without a TTY, a `sudo` that wants a password would hang
/// until the command timeout and then report a timeout, which says nothing
/// about the real cause. `-n` turns that into an immediate, legible
/// "a password is required".
///
/// The command **and** the target user, when one is given, are single-quoted
/// with POSIX escaping, so nothing inside either is interpreted by the outer
/// shell. `sudo_user` reaches here as a plain `String` from three handlers
/// that build their own `PrivilegeArgs` directly — unlike the ~90 tools that
/// go through [`PrivilegeArgs::extract`] and its [`validate_sudo_user`], it is
/// not constrained to `[A-Za-z0-9._-]` before it gets here. Escaping it is
/// what keeps `-u <user>` from being a second injection point beside the
/// command: for an ordinary name escaping is a no-op wrap (`root` becomes
/// `'root'`, which `sudo -u` reads identically), and for anything else it
/// keeps the payload a single, inert argument instead of a shell metacharacter.
///
/// # This function has no password path, and it is the one 399 tools use
///
/// The `StandardTool` pipeline elevates here (`src/mcp/standard_tool.rs`, step
/// 5b), so all 399 pipeline tools get `sudo -n` and nothing else: a
/// `sudo_password` in the host's config is never offered to them. `sudo -n`
/// succeeds only where sudoers grants `NOPASSWD` and otherwise fails at once
/// with "a password is required" — so on a host that genuinely demands a
/// password, `sudo: true` works for the three handlers that build their own
/// `PrivilegeArgs` and call [`elevate_with_password`] (`ssh_exec`,
/// `ssh_exec_multi`, `ssh_session_exec`) and for no other tool.
///
/// That split is deliberate for now, not an oversight: the one-line remedy is
/// to pass the host's `sudo_password` to [`elevate_with_password`] here too,
/// but it would change the behaviour of 399 tools on every password host at
/// once, and only the three above have ever been exercised on one. It is a
/// named known issue in `CHANGELOG.md` waiting for its own measurement.
#[must_use]
pub fn elevate(command: &str, args: &PrivilegeArgs) -> String {
    if !args.sudo {
        return command.to_string();
    }

    let quoted = shell::escape(command, ShellType::Posix);
    args.sudo_user.as_ref().map_or_else(
        || format!("sudo -n bash -c {quoted}"),
        |user| {
            let user = shell::escape(user, ShellType::Posix);
            format!("sudo -n -u {user} bash -c {quoted}")
        },
    )
}

/// The result of [`elevate_with_password`]: the command line to send, and the
/// bytes to hand the remote process on its stdin.
///
/// Keeping the two apart is the whole point. The password used to be spliced
/// into the command text (`printf '%s\n' '<pw>' | sudo -S ...`), and an SSH exec
/// request's command text becomes the argv of `$SHELL -c` on the remote host,
/// so any account there could read the password with `ps -ef` for as long as
/// the call lasted. Now `command` carries no secret and `stdin` is written to
/// the SSH channel (`ConnectionGuard::exec_with_stdin`), where `sudo -S`
/// reads it.
pub struct Elevated {
    /// The command line to send. Never contains the password.
    pub command: String,
    /// The password plus a trailing newline. A `RedactedSecret`: zeroized on
    /// drop and rendered `[REDACTED]` by `Debug`, `Display` and `Serialize`,
    /// so a stray `{:?}` or `tracing` field cannot leak it. `None` when no
    /// password was supplied or no elevation was requested.
    pub stdin: Option<crate::config::RedactedSecret>,
}

/// Like [`elevate`], but for a host whose configuration carries a `sudo`
/// password.
///
/// The password is returned in [`Elevated::stdin`], not in the command: the
/// caller must deliver it over the channel with `exec_with_stdin`. The command
/// is `sudo -S -p '' [-u <user>] bash -c '<command>'`; `sudo -S` reads the
/// password from the channel's stdin.
///
/// For a caller that cannot give the process a stdin of its own (a line typed
/// into an open shell), see [`elevate_with_password_via_pipe`].
///
/// The command is wrapped in a `bash -c` for the same reason as [`elevate`]:
/// without it only the first process of the line is elevated.
#[must_use]
pub fn elevate_with_password(
    command: &str,
    args: &PrivilegeArgs,
    password: Option<&str>,
) -> Elevated {
    if !args.sudo {
        return Elevated {
            command: command.to_string(),
            stdin: None,
        };
    }
    let Some(password) = password else {
        return Elevated {
            command: elevate(command, args),
            stdin: None,
        };
    };
    let quoted = shell::escape(command, ShellType::Posix);
    let command = args.sudo_user.as_ref().map_or_else(
        || format!("sudo -S -p '' bash -c {quoted}"),
        |user| {
            let user = shell::escape(user, ShellType::Posix);
            format!("sudo -S -p '' -u {user} bash -c {quoted}")
        },
    );
    // Built in one allocation: `format!("{password}\n")` starts at capacity 0
    // and the newline push would reallocate, freeing the block that held the
    // plaintext without wiping it.
    let mut line = String::with_capacity(password.len() + 1);
    line.push_str(password);
    line.push('\n');
    Elevated {
        command,
        stdin: Some(crate::config::RedactedSecret::new(line)),
    }
}

/// The pre-stdin form of [`elevate_with_password`]: the password is written
/// into the command text as `printf '%s\n' '<pw>' | sudo -S ...`.
///
/// **Its one legitimate use is `ssh_session_exec`**, which writes the string as
/// a *line* into an already-open shell's stdin. There `printf` is a builtin and
/// the `sudo` it pipes into carries no password of its own, so nothing lands
/// in an argv. Sent as an SSH exec request this string would be readable with
/// `ps` on the remote host: use [`elevate_with_password`] and
/// `exec_with_stdin` there.
#[must_use]
pub fn elevate_with_password_via_pipe(
    command: &str,
    args: &PrivilegeArgs,
    password: Option<&str>,
) -> String {
    if !args.sudo {
        return command.to_string();
    }
    let Some(password) = password else {
        return elevate(command, args);
    };
    let quoted = shell::escape(command, ShellType::Posix);
    let pw = shell::escape(password, ShellType::Posix);
    args.sudo_user.as_ref().map_or_else(
        || format!("printf '%s\\n' {pw} | sudo -S -p '' bash -c {quoted}"),
        |user| {
            let user = shell::escape(user, ShellType::Posix);
            format!("printf '%s\\n' {pw} | sudo -S -p '' -u {user} bash -c {quoted}")
        },
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn extract_defaults_to_no_elevation() {
        let mut v = json!({"host": "pi"});
        let args = PrivilegeArgs::extract(&mut v).expect("plain args must parse");
        assert_eq!(args, PrivilegeArgs::default());
        assert!(!args.is_elevated());
    }

    /// The keys must be *removed*: the handler's own `Args` does not declare
    /// them, and leaving them behind would make every elevated call depend on
    /// serde's tolerance for unknown fields.
    #[test]
    fn extract_removes_the_keys_it_consumes() {
        let mut v = json!({"host": "pi", "sudo": true, "sudo_user": "postgres"});
        let args = PrivilegeArgs::extract(&mut v).expect("valid args");

        assert!(args.sudo);
        assert_eq!(args.sudo_user.as_deref(), Some("postgres"));
        assert_eq!(v, json!({"host": "pi"}), "sudo keys must not reach T::Args");
    }

    #[test]
    fn extract_rejects_wrong_types() {
        let mut v = json!({"sudo": "yes"});
        assert!(PrivilegeArgs::extract(&mut v).is_err());

        let mut v = json!({"sudo_user": 42});
        assert!(PrivilegeArgs::extract(&mut v).is_err());
    }

    #[test]
    fn sudo_user_accepts_ordinary_names() {
        for name in [
            "root",
            "postgres",
            "www-data",
            "user.name",
            "svc_acct",
            "u1",
        ] {
            validate_sudo_user(name).unwrap_or_else(|e| panic!("{name} should be valid: {e}"));
        }
    }

    /// The value lands on a command line. These are the shapes that would
    /// change what that line means.
    #[test]
    fn sudo_user_rejects_anything_that_could_alter_the_command() {
        for name in [
            "",
            "-u",                                   // reads as a sudo flag
            "root; rm -rf /",                       // command separator
            "root && id",                           // chain
            "root$(id)",                            // substitution
            "root`id`",                             // substitution, backticks
            "root|id",                              // pipe
            "root id",                              // argument split
            "root\nid",                             // newline
            "'root'",                               // quoting
            "rootrootrootrootrootrootrootrootroot", // over length
        ] {
            assert!(
                validate_sudo_user(name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn elevate_is_a_no_op_without_sudo() {
        let args = PrivilegeArgs::default();
        assert_eq!(elevate("ls -la", &args), "ls -la");
    }

    #[test]
    fn elevate_wraps_the_whole_command_not_just_the_first_word() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: None,
        };
        let out = elevate("echo x > /etc/foo", &args);

        assert_eq!(out, "sudo -n bash -c 'echo x > /etc/foo'");
        assert!(
            !out.starts_with("sudo -n echo"),
            "a bare prefix would leave the redirect unelevated"
        );
    }

    #[test]
    fn elevate_targets_a_user_when_asked() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("postgres".to_string()),
        };
        assert_eq!(
            elevate("psql -c 'select 1'", &args),
            r"sudo -n -u 'postgres' bash -c 'psql -c '\''select 1'\'''"
        );
    }

    /// `sudo_user` reaches three handlers as a plain `String` that never goes
    /// through [`PrivilegeArgs::extract`]/[`validate_sudo_user`] — it must be
    /// escaped, not just interpolated, or a value like `root; touch
    /// /tmp/pwned` becomes a second command on the remote host, right next to
    /// the command argument that is already escaped.
    #[test]
    fn elevate_escapes_a_malicious_sudo_user() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("root; touch /tmp/pwned".to_string()),
        };
        let got = elevate("id", &args);
        assert!(
            !got.contains("; touch /tmp/pwned bash") && !got.contains("; touch /tmp/pwned\nbash"),
            "the injected `;` must not escape the quoting around sudo_user: {got}"
        );
        assert_eq!(
            got, r"sudo -n -u 'root; touch /tmp/pwned' bash -c 'id'",
            "sudo_user must be single-quoted exactly like command: {got}"
        );
    }

    /// Same injection, through the password-bearing wrapper.
    #[test]
    fn elevate_with_password_escapes_a_malicious_sudo_user() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("root; touch /tmp/pwned".to_string()),
        };
        let got = elevate_with_password("id", &args, Some("hunter2")).command;
        assert!(
            !got.contains("; touch /tmp/pwned bash") && !got.contains("; touch /tmp/pwned\nbash"),
            "the injected `;` must not escape the quoting around sudo_user: {got}"
        );
        assert!(
            got.contains("-u 'root; touch /tmp/pwned' bash -c 'id'"),
            "sudo_user must be single-quoted exactly like command: {got}"
        );
    }

    /// A single quote in the command must not close the wrapper's quoting.
    #[test]
    fn elevate_escapes_quotes_in_the_command() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: None,
        };
        let out = elevate("echo 'hi'; id", &args);

        assert_eq!(out, r"sudo -n bash -c 'echo '\''hi'\''; id'");
        // The dangerous shape: the payload's own quote terminating the wrapper
        // and leaving `id` to run outside it.
        assert!(!out.ends_with("; id"), "payload escaped the quoting: {out}");
    }

    /// `-n` keeps a password prompt from becoming a command timeout, which
    /// would report the wrong cause entirely.
    #[test]
    fn elevate_never_waits_for_a_password() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: None,
        };
        assert!(elevate("id", &args).starts_with("sudo -n "));
    }

    #[test]
    fn elevate_wraps_the_whole_line_not_just_the_first_process() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("root".to_string()),
        };
        let got = elevate("rm -f -- /run/systemd/system/x && echo ok", &args);
        // La forme fautive — `sudo -n -u root rm -f -- … && echo ok` — n'élève que le `rm`.
        assert!(
            got.starts_with("sudo -n -u 'root' bash -c "),
            "l'élévation doit envelopper, pas préfixer : {got}"
        );
        assert!(
            !got.contains("&& echo ok\"") && !got.ends_with("&& echo ok"),
            "le `&&` ne doit pas rester hors de l'enveloppe : {got}"
        );
    }

    /// The password never reaches the command line: it travels in `stdin`.
    #[test]
    fn elevate_with_password_never_puts_the_password_in_the_command_line() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("root".to_string()),
        };
        let got = elevate_with_password("id", &args, Some("hunter2"));
        assert!(
            !got.command.contains("hunter2"),
            "le mot de passe ne doit jamais apparaître dans la ligne de commande : {}",
            got.command
        );
        // Sans cette seconde assertion, une fonction qui jette le mot de passe
        // en silence passerait aussi.
        assert_eq!(
            got.stdin.as_ref().map(|s| s.as_str()),
            Some("hunter2\n"),
            "le mot de passe doit voyager sur stdin"
        );
    }

    /// The pipe form keeps the password in the line: its one caller writes
    /// that line into an open shell, and the stdin form must not regress it.
    #[test]
    fn via_pipe_keeps_the_password_in_the_line() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: None,
        };
        let got = elevate_with_password_via_pipe("id", &args, Some("hunter2"));
        assert_eq!(got, "printf '%s\\n' 'hunter2' | sudo -S -p '' bash -c 'id'");
    }
}
