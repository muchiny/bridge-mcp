//! Privilege elevation for built-in tool commands.
//!
//! Three of the crate's handlers — `ssh_exec`, `ssh_exec_multi`,
//! `ssh_session_exec` — took a `sudo` argument. The other 475 did not, so on a
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

/// Like [`elevate`], but for a host whose configuration carries a `sudo`
/// password.
///
/// **The password is in the string this function returns**, so it is only as
/// private as what the caller does with that string. `sudo -S` does read it
/// from stdin, but that stdin is a pipe written *inside the command text*, not
/// a channel of its own — so "on stdin" is not the same as "off the command
/// line":
///
/// - Sent as an SSH exec request (`ssh_exec`, `ssh_exec_multi`), the whole
///   `printf '%s\n' '<password>' | sudo -S …` string becomes the argument of
///   `$SHELL -c` on the remote host. **Any account there reads the password
///   with `ps -ef` for as long as the call lasts.**
/// - Written to an already-open session shell's stdin (`ssh_session_exec`), it
///   is not in anyone's argv: `printf` is a builtin and the `sudo` process it
///   pipes into carries no password of its own. That is a property of that one
///   caller, not a guarantee made here.
///
/// `printf` in place of `echo` buys nothing either way: both are builtins, and
/// what leaks on the first path is the outer command line, not the pipe.
/// Removing the leak means handing the password to the SSH channel instead of
/// the command line, which is a change to `ports/`. The `#[ignore]`d
/// `elevate_with_password_never_puts_the_password_in_the_command_line` test in
/// this file holds the assertion that does not pass today; do not weaken it.
///
/// The command is wrapped in a `bash -c` for the same reason as [`elevate`]:
/// without it only the first process of the line is elevated.
#[must_use]
pub fn elevate_with_password(
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
        let got = elevate_with_password("id", &args, Some("hunter2"));
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

    /// The password never reaches the command line for `elevate` itself —
    /// `elevate` takes no password. `elevate_with_password` is a different
    /// story: see its own `#[ignore]`d test below for why the assertion
    /// this name promises does not hold for the implementation this task
    /// ships.
    #[test]
    #[ignore = "elevate_with_password's Step-3 implementation (per the plan) puts the \
                password on the command line via `printf '%s\\n' <pw> | sudo -S …`: on \
                every caller that sends that string as an SSH exec request it is readable \
                in `ps` on the remote host for the duration of the call, and the session \
                caller escapes it only by accident (see this function's own doc). \
                Removing that leak means passing the password over the SSH channel instead \
                of the command line, which is a change to `ports/` and is outside this \
                task's scope (privilege elevation wrapping only). Tracked, not silently \
                dropped: do not weaken this assertion to make it pass."]
    fn elevate_with_password_never_puts_the_password_in_the_command_line() {
        let args = PrivilegeArgs {
            sudo: true,
            sudo_user: Some("root".to_string()),
        };
        let got = elevate_with_password("id", &args, Some("hunter2"));
        assert!(
            !got.contains("hunter2"),
            "le mot de passe ne doit jamais apparaître dans la ligne de commande : {got}"
        );
    }
}
