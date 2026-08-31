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
/// The command is single-quoted with POSIX escaping, so nothing inside it is
/// interpreted by the outer shell.
#[must_use]
pub fn elevate(command: &str, args: &PrivilegeArgs) -> String {
    if !args.sudo {
        return command.to_string();
    }

    let quoted = shell::escape(command, ShellType::Posix);
    args.sudo_user.as_ref().map_or_else(
        || format!("sudo -n bash -c {quoted}"),
        |user| format!("sudo -n -u {user} bash -c {quoted}"),
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
            r"sudo -n -u postgres bash -c 'psql -c '\''select 1'\'''"
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
}
