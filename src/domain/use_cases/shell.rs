//! Shell-aware utilities for cross-platform SSH command construction.
//!
//! Provides escaping, command composition, and detection helpers that
//! adapt to the remote host's shell type (POSIX, `cmd.exe`, `PowerShell`).

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a shell command.
///
/// - **Posix**: wraps in single quotes, escapes internal `'` with `'\''`.
/// - **Cmd**: legacy caret form, kept for API compatibility. It cannot quote `%` and
///   corrupts `&` and `^` inside quotes; new code uses [`try_escape`].
/// - **`PowerShell`**: wraps in `'`; each of U+0027, U+2018, U+2019, U+201A and
///   U+201B is doubled, as PowerShell's `CodeGeneration.EscapeSingleQuotedStringContent`
///   does (any of the five ends a verbatim string).
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(shell::escape("hello", ShellType::Posix), "'hello'");
/// assert_eq!(shell::escape("it's", ShellType::Posix), "'it'\\''s'");
/// assert_eq!(shell::escape("a&b", ShellType::Cmd), "\"a^&b\"");
/// assert_eq!(shell::escape("it's", ShellType::PowerShell), "'it''s'");
/// ```
#[must_use]
pub fn escape(s: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("'{}'", s.replace('\'', "'\\''")),
        ShellType::Cmd => {
            let escaped = s
                .replace('^', "^^")
                .replace('%', "%%")
                .replace('&', "^&")
                .replace('|', "^|")
                .replace('<', "^<")
                .replace('>', "^>")
                .replace('"', "^\"");
            format!("\"{escaped}\"")
        }
        ShellType::PowerShell => format!("'{}'", escape_ps_single_quoted_content(s)),
    }
}

/// `word` as one POSIX shell word: as is when it holds only characters a
/// shell leaves alone (letters, digits and `-_./:=@%+,`), quoted otherwise.
///
/// For text a whitelist judges as a shell line (the words a tool passes
/// without a shell), so the line reads the way the words will be passed.
#[must_use]
pub fn posix_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',')
        });
    if plain {
        word.to_string()
    } else {
        escape(word, ShellType::Posix)
    }
}

/// The single-quote characters of the Windows PowerShell Language
/// Specification 3.0, section 2.3.5.2. Any of them opens or closes a verbatim
/// string.
pub const PS_SINGLE_QUOTES: [char; 5] =
    ['\u{0027}', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Escape text for the inside of a `PowerShell` verbatim (single-quoted)
/// string, without adding the outer quotes.
///
/// Every character of `s` is emitted, and a second time when it is one of
/// [`PS_SINGLE_QUOTES`]. This is what
/// `CodeGeneration.EscapeSingleQuotedStringContent` does: U+201C to U+201E
/// are left alone.
///
/// # Examples
///
/// ```
/// use bridge_mcp::domain::use_cases::shell::escape_ps_single_quoted_content;
///
/// assert_eq!(escape_ps_single_quoted_content("it\u{2019}s"), "it\u{2019}\u{2019}s");
/// ```
#[must_use]
pub fn escape_ps_single_quoted_content(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c);
        if PS_SINGLE_QUOTES.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Whether `cmd.exe` cannot hold `c` inert inside double quotes.
///
/// `"` ends the quoted run, `%` and `!` expand, and a control character ends
/// the line. `$`, the backtick and the three PowerShell double-quote
/// characters mean nothing to `cmd.exe`: they are refused so that a value
/// quoted for `cmd.exe` stays inert even when the host's real shell is
/// PowerShell (the declared shell can be wrong).
const fn cmd_cannot_quote(c: char) -> bool {
    matches!(
        c,
        '"' | '%' | '!' | '$' | '`' | '\u{201C}'..='\u{201E}' | '\u{0}'..='\u{1F}' | '\u{7F}'
    )
}

/// Quote `s` for the given shell, or refuse when the shell cannot quote it.
///
/// - **Posix** and **`PowerShell`**: the same as [`escape`]; every string can be
///   quoted.
/// - **Cmd**: wraps in double quotes with no caret and no `%%`, the only form
///   `cmd.exe` reads literally for `& | < > ^ ( )`. The characters it cannot
///   quote are refused: `"`, `%`, `!`, control characters (U+0000 to U+001F
///   and U+007F), `$`, the backtick, and U+201C to U+201E.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] on the first character `cmd.exe` cannot
/// quote.
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(shell::try_escape("C:\\a&b", ShellType::Cmd).unwrap(), "\"C:\\a&b\"");
/// assert!(shell::try_escape("%OS%", ShellType::Cmd).is_err());
/// ```
pub fn try_escape(s: &str, shell: ShellType) -> Result<String> {
    match shell {
        ShellType::Posix | ShellType::PowerShell => Ok(escape(s, shell)),
        ShellType::Cmd => {
            if let Some(c) = s.chars().find(|&c| cmd_cannot_quote(c)) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "cannot quote {c:?} (U+{:04X}) for cmd.exe; if the host's real shell is PowerShell (OpenSSH DefaultShell, WinRM, PSRP), set `shell: powershell` for it, otherwise change directory inside the command",
                        u32::from(c)
                    ),
                });
            }
            Ok(format!("\"{s}\""))
        }
    }
}

/// Build a "change directory then run command" one-liner, refusing a directory
/// the shell cannot quote.
///
/// - **Posix**: `cd -- '/path' && { command` and a newline, then `}`
/// - **Cmd**: `cd /d "C:\path" || exit /b 1 & command`
/// - **`PowerShell`**: `Set-Location -LiteralPath 'C:\path' -ErrorAction Stop; command`
///
/// Every form runs the whole of `command` only once the directory change
/// succeeded, however many commands it holds (`a; b`, `a & b`, a newline):
/// the Posix brace group binds the `command` list to the `&&` (the newline
/// before `}` ends a trailing comment or `&`), Cmd leaves the shell when the
/// `cd` fails, and `-ErrorAction Stop` makes a missing directory a
/// terminating error for `PowerShell`. `--` keeps a directory that starts
/// with `-` from being read as a `cd` option.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] when `dir` holds a character [`try_escape`]
/// refuses for `shell`.
///
/// # Examples
///
/// ```
/// use bridge_mcp::config::ShellType;
/// use bridge_mcp::domain::use_cases::shell;
///
/// assert_eq!(
///     shell::try_cd_and_run("/var/log", "ls", ShellType::Posix).unwrap(),
///     "cd -- '/var/log' && { ls\n}"
/// );
/// ```
pub fn try_cd_and_run(dir: &str, cmd: &str, shell: ShellType) -> Result<String> {
    let q = try_escape(dir, shell)?;
    Ok(match shell {
        ShellType::Posix => format!("cd -- {q} && {{ {cmd}\n}}"),
        ShellType::Cmd => format!("cd /d {q} || exit /b 1 & {cmd}"),
        ShellType::PowerShell => format!("Set-Location -LiteralPath {q} -ErrorAction Stop; {cmd}"),
    })
}

/// Build a "change directory then run command" one-liner.
///
/// Legacy form: the Cmd arm goes through the caret form of [`escape`], which
/// cannot quote every directory. New code uses [`try_cd_and_run`].
///
/// - **Posix**: `cd '/path' && command`
/// - **Cmd**: `cd /d "C:\path" && command`
/// - **`PowerShell`**: `Set-Location 'C:\path'; command`
#[deprecated(
    since = "5.0.0",
    note = "use try_cd_and_run: the cmd form cannot quote every directory"
)]
#[must_use]
pub fn cd_and_run(dir: &str, cmd: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("cd {} && {cmd}", escape(dir, shell)),
        ShellType::Cmd => format!("cd /d {} && {cmd}", escape(dir, shell)),
        ShellType::PowerShell => format!("Set-Location {}; {cmd}", escape(dir, shell)),
    }
}

/// Build a command that checks whether an executable exists.
///
/// - **Posix**: `command -v name`
/// - **Cmd**: `where name`
/// - **`PowerShell`**: `Get-Command name -ErrorAction SilentlyContinue`
#[must_use]
pub fn command_exists(name: &str, shell: ShellType) -> String {
    match shell {
        ShellType::Posix => format!("command -v {}", escape(name, shell)),
        ShellType::Cmd => format!("where {name}"),
        ShellType::PowerShell => {
            format!("Get-Command {name} -ErrorAction SilentlyContinue")
        }
    }
}

/// Return the null device path for the given shell.
///
/// - **Posix**: `/dev/null`
/// - **Cmd**: `NUL`
/// - **`PowerShell`**: `$null`
#[must_use]
pub const fn null_device(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "/dev/null",
        ShellType::Cmd => "NUL",
        ShellType::PowerShell => "$null",
    }
}

/// Return the stderr-to-null redirect suffix for the given shell.
///
/// - **Posix**: `2>/dev/null`
/// - **Cmd**: `2>NUL`
/// - **`PowerShell`**: `2>$null`
#[must_use]
pub const fn stderr_to_null(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "2>/dev/null",
        ShellType::Cmd => "2>NUL",
        ShellType::PowerShell => "2>$null",
    }
}

/// Return the exit-code variable for the given shell.
///
/// - **Posix**: `$?`
/// - **Cmd**: `%ERRORLEVEL%`
/// - **`PowerShell`**: `$LASTEXITCODE`
#[must_use]
pub const fn exit_code_var(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "$?",
        ShellType::Cmd => "%ERRORLEVEL%",
        ShellType::PowerShell => "$LASTEXITCODE",
    }
}

/// Refuse a `command` that a transport typing it into a remote terminal
/// (telnet, a serial console) cannot carry intact.
///
/// Those transports send the command as keystrokes, through the remote
/// terminal's line discipline and line editor, which act on control
/// characters before any shell parses the quoting: `^C` discards the line
/// typed so far and `^U` or `^W` erase it, a tab completes a quoted word and
/// closes its quote, a line break submits the line (to a device CLI, as a
/// command of its own). Each of them can turn a quoted argument into a
/// command. A command over several lines would also answer with several
/// prompts, which the transports' read-until-prompt cannot follow. So any
/// control character ([`char::is_control`], line feed and tab included) is
/// refused.
///
/// # Errors
///
/// [`BridgeError::CommandDenied`] naming `transport` and the first control
/// character found.
pub fn refuse_terminal_controls(transport: &str, command: &str) -> Result<()> {
    match command.chars().find(|c| c.is_control()) {
        None => Ok(()),
        Some(c) => Err(BridgeError::CommandDenied {
            reason: format!(
                "{transport} types the command into the remote terminal, which acts on \
                 the control character U+{:04X} in it before the shell reads the \
                 quoting: refused",
                u32::from(c)
            ),
        }),
    }
}

/// Directories a caller-supplied binary may live in when given as a path:
/// the system ones, where only root can plant a file.
const BINARY_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/sbin",
    "/opt/bin",
    "/snap/bin",
    "/var/lib/rancher/rke2/bin",
];

/// Whether `rest` (what follows a program name in a file name) is empty or a
/// version: an optional `-`, an optional `v`, then digits and dots starting
/// with a digit (`-1.31`, `-v1.31.2`, `3`, `-3.14`).
fn is_version_suffix(rest: &str) -> bool {
    if rest.is_empty() {
        return true;
    }
    let rest = rest.strip_prefix('-').unwrap_or(rest);
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    rest.starts_with(|c: char| c.is_ascii_digit())
        && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Whether `bin` names one of the programs `names`: either a bare name, or an
/// absolute path whose directory is exactly one of `/usr/bin`, `/bin`,
/// `/usr/local/bin`, `/usr/sbin`, `/sbin`, `/usr/local/sbin`, `/opt/bin`,
/// `/snap/bin` and `/var/lib/rancher/rke2/bin` (where RKE2 installs `kubectl`,
/// `crictl` and `ctr`). The file name must be a name of the list, alone or followed by
/// a version only (`kubectl-1.31`, `kubectl-v1.31.2`, `helm3`, `helm-3.14`).
/// The characters are limited to `[A-Za-z0-9/._-]` and the value must not start
/// with `-`.
///
/// A caller-supplied binary is the program the command starts with, often
/// under `sudo`, past the whitelist. So the value must not be a program
/// other than the one named (`/bin/sh`, `python3`, a plugin such as
/// `kubectl-node_shell`), nor a file the caller could have written elsewhere
/// (`/tmp/kubectl`, `./kubectl`, `bin/kubectl`, `/usr/bin/../../tmp/kubectl`).
#[must_use]
pub fn is_named_binary(bin: &str, names: &[&str]) -> bool {
    is_named_binary_in(bin, names, &[])
}

/// [`is_named_binary`] that also accepts an absolute path whose directory is
/// exactly one of `extra_dirs` (written without a trailing `/`).
///
/// For a program that a vendor installs in a root-owned directory of its own,
/// such as the Docker CLI plugins. `extra_dirs` must hold only directories
/// that only root can write to.
#[must_use]
pub fn is_named_binary_in(bin: &str, names: &[&str], extra_dirs: &[&str]) -> bool {
    if bin.is_empty()
        || bin.starts_with('-')
        || !bin
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return false;
    }
    let file = match bin.rsplit_once('/') {
        None => bin,
        Some((dir, file)) => {
            if !bin.starts_with('/') || !(BINARY_DIRS.contains(&dir) || extra_dirs.contains(&dir)) {
                return false;
            }
            file
        }
    };
    names
        .iter()
        .any(|name| file.strip_prefix(name).is_some_and(is_version_suffix))
}

/// Refuse the environment variable `name` of the argument `arg` when it
/// changes which program or library runs, or how a shell starts.
///
/// Such a variable lets a caller run something other than the command a
/// whitelist approved: `PATH` and `LD_*` pick the program or the loaded
/// library, `BASH_ENV`, `ENV`, `SHELLOPTS`, `PS4` and `PROMPT_COMMAND` run
/// code when a shell starts, `BASH_FUNC_*` defines a function that replaces a
/// command, `IFS` changes how words split. The interpreters and tools that
/// load code from a variable are refused too: `PYTHONPATH`, `PYTHONHOME`,
/// `PYTHONSTARTUP`, `PYTHONINSPECT`, `PYTHONBREAKPOINT`, `PYTHONUSERBASE`,
/// `PERL5*`, `PERLLIB`, `RUBYOPT`, `RUBYLIB`, `NODE_OPTIONS`, `NODE_PATH`,
/// `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`,
/// `LUA_INIT*`, `LUA_PATH`, `LUA_CPATH`, `FPATH`, `ZDOTDIR`, `GIT_CONFIG*`,
/// `GIT_EXEC_PATH`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`,
/// `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PAGER`, `GIT_EDITOR`,
/// `GIT_SEQUENCE_EDITOR`, `GIT_EXTERNAL_DIFF`, `EDITOR`, `VISUAL`, `PAGER`,
/// `BROWSER`, `EXECIGNORE`, `OPENSSL_CONF`, `GLIBC_TUNABLES`, `MALLOC_CONF`,
/// `TAR_OPTIONS`, `LESSOPEN`, `LESSCLOSE`, `MANPAGER`, `SYSTEMD_PAGER`,
/// `SUDO_ASKPASS`, `SSH_ASKPASS_REQUIRE` and `PYTHONWARNINGS`. Harmless
/// neighbours (`NODE_ENV`, `PYTHONUNBUFFERED`, `LANG`) pass. Names are
/// compared as given, since the environment is case-sensitive, except that
/// `path`, `fpath`, `cdpath` and `module_path` are refused too: zsh ties them
/// to `PATH` and its siblings. The list cannot name every variable some
/// program reads, so where a whitelist applies the entries are judged with
/// the command too.
///
/// # Errors
///
/// `CommandDenied` naming `arg` when `name` is one of those.
pub fn refuse_sensitive_env_name(arg: &str, name: &str) -> Result<()> {
    const EXACT: &[&str] = &[
        "PATH",
        "IFS",
        "ENV",
        "BASH_ENV",
        "CDPATH",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "GLOBIGNORE",
        "PROMPT_COMMAND",
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
        "HOSTALIASES",
        "RESOLV_HOST_CONF",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PYTHONUSERBASE",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "NODE_OPTIONS",
        "NODE_PATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
        "LUA_PATH",
        "LUA_CPATH",
        "FPATH",
        "ZDOTDIR",
        "GIT_EXEC_PATH",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_EXTERNAL_DIFF",
        "TAR_OPTIONS",
        "LESSOPEN",
        "LESSCLOSE",
        "MANPAGER",
        "SYSTEMD_PAGER",
        "SUDO_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "PYTHONWARNINGS",
        "MALLOC_CONF",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "BROWSER",
        "EXECIGNORE",
        "OPENSSL_CONF",
        "GLIBC_TUNABLES",
    ];
    const PREFIXES: &[&str] = &[
        "LD_",
        "DYLD_",
        "BASH_FUNC_",
        "PERL5",
        "LUA_INIT",
        "GIT_CONFIG",
    ];
    // Environment names are case-sensitive, but zsh ties these lower-case
    // parameters to `PATH`, `FPATH`, `CDPATH` and its module path, and the
    // SSH user's login shell may be zsh.
    const ZSH_TIED: &[&str] = &["path", "fpath", "cdpath", "module_path"];
    let sensitive = EXACT.contains(&name)
        || ZSH_TIED.contains(&name)
        || PREFIXES.iter().any(|prefix| name.starts_with(prefix));
    if sensitive {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "'{arg}' must not set the environment variable '{name}': it changes which \
                 program or library runs, or how a shell starts"
            ),
        });
    }
    Ok(())
}

/// Refuse `value` for the argument `arg` when it starts with `-`.
///
/// Quoting keeps a value one word, but a word that starts with `-` in a slot
/// where the program still reads options is an option: `find '-delete'`,
/// `git log '--output=/etc/x'`, `systemctl status '--help'`. Use this for
/// identifiers that can never start with `-` (Kubernetes, Helm and container
/// names, users, groups, units, numeric ids). For a path or free text, put
/// `--` before it when the program honours it instead.
///
/// # Errors
///
/// `CommandDenied` naming `arg` when `value` starts with `-`.
pub fn refuse_option_like(arg: &str, value: &str) -> Result<()> {
    if value.starts_with('-') {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "'{arg}' must not start with '-': the remote program would read it as an \
                 option"
            ),
        });
    }
    Ok(())
}

/// Whether `host` designates the machine the command runs on: exactly
/// `localhost` (ASCII case-insensitive) or an IP address (no brackets, no
/// port) that is a loopback address once canonicalised (`127.0.0.0/8`, `::1`,
/// and `::ffff:127.x` mapped to `IPv4`).
///
/// Everything else is another machine: other names (a `DNS` name can point
/// anywhere), short forms such as `127.1`, `0.0.0.0`, `[::1]`, `::1%lo`.
/// Used by the tools whose client program presents a credential of the target
/// host: that credential may only go to a local server.
#[must_use]
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== is_loopback_host =====

    #[test]
    fn test_is_loopback_host() {
        for host in [
            "localhost",
            "LOCALHOST",
            "LocalHost",
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "",
            "localhost.",
            "localhost.example.com",
            "redis.example.com",
            "10.0.0.5",
            "127.1",
            "0.0.0.0",
            "[::1]",
            "::2",
            "::ffff:10.0.0.5",
            "::1%lo",
            " localhost",
            "/var/run/postgresql",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }

    // ===== is_named_binary =====

    #[test]
    fn is_named_binary_accepts_the_program_bare_in_a_path_or_versioned() {
        for bin in [
            "kubectl",
            "/usr/local/bin/kubectl",
            "kubectl-1.31",
            "kubectl-v1.31.2",
            "/snap/bin/microk8s.kubectl",
            "/usr/bin/kubectl",
            "/opt/bin/kubectl",
        ] {
            assert!(
                is_named_binary(bin, &["kubectl", "microk8s.kubectl"]),
                "{bin}"
            );
        }
    }

    #[test]
    fn is_named_binary_refuses_other_programs_and_option_shapes() {
        for bin in [
            "/bin/sh",
            "python3",
            "kubectlx",
            "-kubectl",
            "kubectl; id",
            "",
            "kube ctl",
            "$(id)",
            "kubectl-node_shell",
            "kubectl-ns",
            "oc-mirror",
            "kubectl-",
            "kubectl-v",
            "kubectl1.x",
            "/home/u/bin/kubectl",
            "/tmp/kubectl",
            "/var/tmp/kubectl",
            "./kubectl",
            "../x/kubectl",
            "bin/kubectl",
            "/kubectl",
            "//usr/bin/kubectl",
            "/usr/bin/../../tmp/kubectl",
            "/usr/local/bin/sub/kubectl",
            "/usr/bin/",
            "/usr/bin/kubectl-ns",
        ] {
            assert!(!is_named_binary(bin, &["kubectl"]), "{bin}");
        }
    }

    #[test]
    fn is_named_binary_accepts_the_rke2_bin_directory() {
        assert!(is_named_binary(
            "/var/lib/rancher/rke2/bin/kubectl",
            &["kubectl"]
        ));
        assert!(is_named_binary(
            "/var/lib/rancher/rke2/bin/crictl",
            &["crictl"]
        ));
        for bin in [
            "/var/lib/rancher/rke2/bin/sh",
            "/var/lib/rancher/rke2/bin/sub/kubectl",
            "/var/lib/rancher/rke2/kubectl",
            "/var/lib/rancher/k3s/bin/kubectl",
            "/var/lib/rancher/rke2/bin/../../x/kubectl",
        ] {
            assert!(!is_named_binary(bin, &["kubectl"]), "{bin}");
        }
    }

    #[test]
    fn is_named_binary_in_accepts_extra_directories_only_when_given() {
        let plugin = "/usr/libexec/docker/cli-plugins/docker-compose";
        let dirs = ["/usr/libexec/docker/cli-plugins"];
        assert!(!is_named_binary(plugin, &["docker-compose"]));
        assert!(is_named_binary_in(plugin, &["docker-compose"], &dirs));
        assert!(is_named_binary_in(
            "/usr/bin/docker-compose",
            &["docker-compose"],
            &dirs
        ));
        for bin in [
            "/usr/libexec/docker/cli-plugins/sh",
            "/usr/libexec/docker/cli-plugins/docker-buildx",
            "/usr/libexec/docker/cli-plugins/../x/docker-compose",
            "/usr/libexec/docker/docker-compose",
        ] {
            assert!(
                !is_named_binary_in(bin, &["docker-compose"], &dirs),
                "{bin}"
            );
        }
    }

    #[test]
    fn is_named_binary_refuses_helm_plugins_and_accepts_helm_versions() {
        for bin in ["helm", "helm3", "helm-3.14", "/usr/local/bin/helm-v3.14.2"] {
            assert!(is_named_binary(bin, &["helm"]), "{bin}");
        }
        for bin in ["helm-diff", "helm-secrets", "/tmp/helm"] {
            assert!(!is_named_binary(bin, &["helm"]), "{bin}");
        }
    }

    // ===== refuse_sensitive_env_name =====

    /// `TAR_OPTIONS=--to-command=…` runs a program under a whitelisted `tar`;
    /// the pager and askpass variables start one too.
    #[test]
    fn posix_word_quotes_only_what_a_shell_would_read() {
        assert_eq!(posix_word("ls"), "ls");
        assert_eq!(posix_word("/var/log/a-b_c.log"), "/var/log/a-b_c.log");
        assert_eq!(posix_word("a b"), "'a b'");
        assert_eq!(posix_word("x;id"), "'x;id'");
        assert_eq!(posix_word("'a"), r"''\''a'");
        assert_eq!(posix_word(""), "''");
    }

    #[test]
    fn refuse_sensitive_env_name_refuses_option_and_helper_variables() {
        for name in [
            "TAR_OPTIONS",
            "LESSOPEN",
            "LESSCLOSE",
            "MANPAGER",
            "SYSTEMD_PAGER",
            "SUDO_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
            "PYTHONWARNINGS",
        ] {
            assert!(refuse_sensitive_env_name("env", name).is_err(), "{name}");
        }
        for name in [
            "TAR_DIR",
            "LESS",
            "PYTHONUNBUFFERED",
            "TZ",
            "MALLOC_ARENA_MAX",
            "env",
            "tar_options",
            "ld_preload",
        ] {
            assert!(refuse_sensitive_env_name("env", name).is_ok(), "{name}");
        }
        for name in ["path", "fpath", "cdpath", "module_path"] {
            assert!(refuse_sensitive_env_name("env", name).is_err(), "{name}");
        }
        for name in ["Path", "manpath"] {
            assert!(refuse_sensitive_env_name("env", name).is_ok(), "{name}");
        }
    }

    #[test]
    fn refuse_sensitive_env_name_refuses_names_that_change_what_runs() {
        for name in [
            "PATH",
            "IFS",
            "ENV",
            "BASH_ENV",
            "CDPATH",
            "SHELLOPTS",
            "BASHOPTS",
            "PS4",
            "GLOBIGNORE",
            "PROMPT_COMMAND",
            "GCONV_PATH",
            "LOCPATH",
            "NLSPATH",
            "HOSTALIASES",
            "RESOLV_HOST_CONF",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_FUNC_echo%%",
            "MALLOC_CONF",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONINSPECT",
            "PERL5LIB",
            "PERL5OPT",
            "PERLLIB",
            "RUBYOPT",
            "RUBYLIB",
            "NODE_OPTIONS",
            "NODE_PATH",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "LUA_INIT",
            "LUA_INIT_5_4",
            "LUA_PATH",
            "LUA_CPATH",
            "FPATH",
            "ZDOTDIR",
            "GIT_EXEC_PATH",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_PROXY_COMMAND",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "EDITOR",
            "VISUAL",
            "PAGER",
            "BROWSER",
            "GLIBC_TUNABLES",
        ] {
            let err = refuse_sensitive_env_name("env", name).expect_err(name);
            assert!(err.to_string().contains("'env'"), "{err}");
        }
    }

    #[test]
    fn refuse_sensitive_env_name_lets_ordinary_names_through() {
        for name in [
            "FOO",
            "DEBUG",
            "LANG",
            "TZ",
            "MY_PATH",
            "PATHS",
            "LDX",
            "ENVIRON",
            "NODE_ENV",
            "PYTHONUNBUFFERED",
            "GIT_AUTHOR_NAME",
            "GIT_TERMINAL_PROMPT",
            "JAVA_OPTS",
        ] {
            refuse_sensitive_env_name("env", name).expect(name);
        }
    }

    // ===== refuse_option_like =====

    #[test]
    fn refuse_option_like_refuses_a_leading_dash_only() {
        for value in ["-delete", "--output=/etc/x", "-"] {
            let err = refuse_option_like("path", value).expect_err(value);
            assert!(
                err.to_string().contains("'path' must not start with '-'"),
                "{err}"
            );
        }
        for value in ["x", "a-b", "", "./-x", "web-1"] {
            refuse_option_like("path", value).expect(value);
        }
    }

    // ===== refuse_terminal_controls =====

    #[test]
    fn refuse_terminal_controls_lets_printable_text_through() {
        for command in [
            "",
            "git -C '/srv/app' diff -- 'x'\\''; id; #'",
            "echo 'héllo €'",
        ] {
            assert!(
                refuse_terminal_controls("telnet", command).is_ok(),
                "{command}"
            );
        }
    }

    /// The characters a line discipline or line editor acts on, each of which
    /// can end a quoted argument before the shell sees it.
    #[test]
    fn refuse_terminal_controls_refuses_every_control_character() {
        for c in [
            '\u{0}', '\u{3}', '\t', '\n', '\r', '\u{15}', '\u{17}', '\u{1b}', '\u{7f}', '\u{85}',
        ] {
            let command = format!("cat '/var/log/x{c}id'");
            match refuse_terminal_controls("serial", &command) {
                Err(BridgeError::CommandDenied { reason }) => {
                    assert!(reason.starts_with("serial "), "{reason}");
                    assert!(
                        reason.contains(&format!("U+{:04X}", u32::from(c))),
                        "{reason}"
                    );
                }
                other => panic!("{c:?} must be refused, got {other:?}"),
            }
        }
    }

    // ===== escape =====

    #[test]
    fn test_posix_escape_simple() {
        assert_eq!(escape("hello", ShellType::Posix), "'hello'");
    }

    #[test]
    fn test_posix_escape_with_single_quote() {
        assert_eq!(escape("it's", ShellType::Posix), "'it'\\''s'");
    }

    #[test]
    fn test_cmd_escape_simple() {
        assert_eq!(escape("hello", ShellType::Cmd), "\"hello\"");
    }

    #[test]
    fn test_cmd_escape_special_chars() {
        assert_eq!(escape("a&b|c", ShellType::Cmd), "\"a^&b^|c\"");
    }

    #[test]
    fn test_cmd_escape_double_quote() {
        assert_eq!(escape("say \"hi\"", ShellType::Cmd), "\"say ^\"hi^\"\"");
    }

    #[test]
    fn test_cmd_escape_caret() {
        assert_eq!(escape("a^b", ShellType::Cmd), "\"a^^b\"");
    }

    #[test]
    fn test_cmd_escape_angle_brackets() {
        assert_eq!(escape("a<b>c", ShellType::Cmd), "\"a^<b^>c\"");
    }

    #[test]
    fn test_cmd_escape_percent_sign() {
        assert_eq!(escape("%TEMP%", ShellType::Cmd), "\"%%TEMP%%\"");
    }

    #[test]
    fn test_cmd_escape_percent_in_path() {
        assert_eq!(escape("%PATH%\\evil", ShellType::Cmd), "\"%%PATH%%\\evil\"");
    }

    #[test]
    fn test_powershell_escape_simple() {
        assert_eq!(escape("hello", ShellType::PowerShell), "'hello'");
    }

    #[test]
    fn test_powershell_escape_with_single_quote() {
        assert_eq!(escape("it's", ShellType::PowerShell), "'it''s'");
    }

    #[test]
    fn ps_single_quotes_are_the_five_of_the_grammar() {
        assert_eq!(
            PS_SINGLE_QUOTES,
            ['\u{0027}', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}']
        );
    }

    #[test]
    fn powershell_escape_doubles_every_single_quote_character() {
        for q in PS_SINGLE_QUOTES {
            assert_eq!(
                escape(&format!("a{q}b"), ShellType::PowerShell),
                format!("'a{q}{q}b'"),
                "U+{:04X}",
                u32::from(q)
            );
        }
    }

    #[test]
    fn powershell_escape_mixed_quotes_at_both_ends() {
        assert_eq!(
            escape("'\u{2019}x\u{2018}\u{201A}\u{201B}'", ShellType::PowerShell),
            "'''\u{2019}\u{2019}x\u{2018}\u{2018}\u{201A}\u{201A}\u{201B}\u{201B}'''"
        );
    }

    #[test]
    fn powershell_escape_leaves_double_quote_characters_alone() {
        let s = "a\"\u{201C}\u{201D}\u{201E}b";
        assert_eq!(escape(s, ShellType::PowerShell), format!("'{s}'"));
    }

    #[test]
    fn powershell_escape_hostile_value_stays_one_literal() {
        assert_eq!(
            escape(
                "a\u{2019}; Write-Output pwned; \u{2019}",
                ShellType::PowerShell
            ),
            "'a\u{2019}\u{2019}; Write-Output pwned; \u{2019}\u{2019}'"
        );
    }

    #[test]
    fn powershell_escape_edge_values() {
        assert_eq!(escape("", ShellType::PowerShell), "''");
        assert_eq!(escape("a'", ShellType::PowerShell), "'a'''");
        assert_eq!(
            escape("\u{201B}\u{201B}\u{201B}", ShellType::PowerShell),
            "'\u{201B}\u{201B}\u{201B}\u{201B}\u{201B}\u{201B}'"
        );
        assert_eq!(
            escape("\u{2018}", ShellType::PowerShell),
            "'\u{2018}\u{2018}'"
        );
        assert_eq!(
            escape("\u{201A}", ShellType::PowerShell),
            "'\u{201A}\u{201A}'"
        );
        assert_eq!(
            escape("\u{201B}", ShellType::PowerShell),
            "'\u{201B}\u{201B}'"
        );
    }

    #[test]
    fn powershell_escape_keeps_other_characters_as_they_are() {
        assert_eq!(escape("a`b", ShellType::PowerShell), "'a`b'");
        assert_eq!(escape("a\nb", ShellType::PowerShell), "'a\nb'");
        assert_eq!(escape("\u{1F600}", ShellType::PowerShell), "'\u{1F600}'");
        assert_eq!(
            escape("\u{1F600}\u{2019}", ShellType::PowerShell),
            "'\u{1F600}\u{2019}\u{2019}'"
        );
    }

    #[test]
    fn escape_ps_single_quoted_content_adds_no_outer_quotes() {
        assert_eq!(
            escape_ps_single_quoted_content("it\u{2019}s"),
            "it\u{2019}\u{2019}s"
        );
        assert_eq!(escape_ps_single_quoted_content(""), "");
    }

    // ===== cd_and_run =====

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_posix() {
        assert_eq!(
            cd_and_run("/var/log", "ls -la", ShellType::Posix),
            "cd '/var/log' && ls -la"
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_cmd() {
        assert_eq!(
            cd_and_run("C:\\Users", "dir", ShellType::Cmd),
            "cd /d \"C:\\Users\" && dir"
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_powershell() {
        assert_eq!(
            cd_and_run("C:\\Users", "Get-ChildItem", ShellType::PowerShell),
            "Set-Location 'C:\\Users'; Get-ChildItem"
        );
    }

    // ===== try_escape / try_cd_and_run =====

    #[test]
    fn cmd_try_escape_specials_literal_inside_quotes() {
        assert_eq!(
            try_escape("C:\\a&b|c<d>e^f(g)", ShellType::Cmd).unwrap(),
            "\"C:\\a&b|c<d>e^f(g)\""
        );
    }

    #[test]
    fn cmd_try_escape_refuses_each_char() {
        for c in [
            '"', '%', '!', '\0', '\t', '\r', '\n', '\u{1F}', '\u{7F}', '$', '`', '\u{201C}',
            '\u{201D}', '\u{201E}',
        ] {
            let err = try_escape(&format!("C:\\a{c}b"), ShellType::Cmd).unwrap_err();
            let needle = format!("U+{:04X}", u32::from(c));
            assert!(
                matches!(&err, BridgeError::CommandDenied { reason } if reason.contains(&needle)),
                "{needle}: {err:?}"
            );
        }
    }

    #[test]
    fn try_escape_posix_and_powershell_match_escape() {
        for s in ["it's", "a\u{2019}b", "%PATH%"] {
            assert_eq!(
                try_escape(s, ShellType::Posix).unwrap(),
                escape(s, ShellType::Posix)
            );
            assert_eq!(
                try_escape(s, ShellType::PowerShell).unwrap(),
                escape(s, ShellType::PowerShell)
            );
        }
    }

    #[test]
    fn try_cd_and_run_cmd_quotes_without_carets() {
        assert_eq!(
            try_cd_and_run("C:\\a&b^c", "dir", ShellType::Cmd).unwrap(),
            "cd /d \"C:\\a&b^c\" || exit /b 1 & dir"
        );
    }

    #[test]
    fn try_cd_and_run_powershell_uses_literal_path() {
        assert_eq!(
            try_cd_and_run("C:\\[x]*", "Get-ChildItem", ShellType::PowerShell).unwrap(),
            "Set-Location -LiteralPath 'C:\\[x]*' -ErrorAction Stop; Get-ChildItem"
        );
    }

    #[test]
    fn try_cd_and_run_posix_guards_the_whole_command_list() {
        assert_eq!(
            try_cd_and_run("/var/log", "ls -la", ShellType::Posix).unwrap(),
            "cd -- '/var/log' && { ls -la\n}"
        );
    }

    #[test]
    fn try_cd_and_run_posix_puts_a_dash_directory_after_double_dash() {
        let line = try_cd_and_run("-ZQXdash", "x", ShellType::Posix).unwrap();
        assert!(line.starts_with("cd -- '-ZQXdash' && "), "{line}");
    }

    /// Finding F30: after a failed `cd`, `;` used to start a new list item
    /// that ran in the login directory.
    #[cfg(unix)]
    #[test]
    fn try_cd_and_run_posix_runs_nothing_after_a_failed_cd() {
        for command in [
            "echo ran; echo ran2",
            "echo ran & wait",
            "echo ran\necho ran2",
            "echo ran # c",
        ] {
            let line =
                try_cd_and_run("/nonexistent-bridge-mcp-dir", command, ShellType::Posix).unwrap();
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&line)
                .output()
                .unwrap();
            assert!(out.stdout.is_empty(), "{command}: {out:?}");
            assert!(!out.status.success(), "{command}");
        }
    }

    #[test]
    fn try_cd_and_run_cmd_leaves_the_shell_when_cd_fails() {
        let line = try_cd_and_run("C:\\x", "a & b", ShellType::Cmd).unwrap();
        assert_eq!(line, "cd /d \"C:\\x\" || exit /b 1 & a & b");
    }

    #[test]
    fn try_cd_and_run_refuses_before_building_a_cmd_line() {
        assert!(try_cd_and_run("C:\\%OS%", "dir", ShellType::Cmd).is_err());
    }

    proptest::proptest! {
        #[test]
        fn cmd_try_escape_output_is_inert(s in proptest::prelude::any::<String>()) {
            // Independent statement of the refused set.
            let refused = |c: char| matches!(c, '"' | '%' | '!' | '$' | '`' | '\u{201C}'..='\u{201E}' | '\u{0}'..='\u{1F}' | '\u{7F}');
            match try_escape(&s, ShellType::Cmd) {
                Ok(q) => {
                    proptest::prop_assert_eq!(q, format!("\"{s}\""));
                    proptest::prop_assert!(!s.chars().any(refused));
                }
                Err(_) => proptest::prop_assert!(s.chars().any(refused)),
            }
        }
    }

    /// Every `.rs` file under `dir`, recursively.
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn no_production_code_escapes_for_cmd() {
        // `shell.rs` holds the function and its own tests, and `utils.rs` its
        // wrapper; no other line may reach the legacy cmd form.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 100, "the walk found {} files", files.len());
        for path in files {
            let rel = path.strip_prefix(&src).expect("under src");
            if rel == std::path::Path::new("domain/use_cases/shell.rs")
                || rel == std::path::Path::new("mcp/tool_handlers/utils.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (i, line) in text.lines().enumerate() {
                assert!(
                    !(line.contains("escape(") && line.contains("ShellType::Cmd")),
                    "{}:{}: {line}",
                    path.display(),
                    i + 1
                );
            }
        }
    }

    // ===== command_exists =====

    #[test]
    fn test_command_exists_posix() {
        assert_eq!(
            command_exists("docker", ShellType::Posix),
            "command -v 'docker'"
        );
    }

    #[test]
    fn test_command_exists_cmd() {
        assert_eq!(command_exists("docker", ShellType::Cmd), "where docker");
    }

    #[test]
    fn test_command_exists_powershell() {
        assert_eq!(
            command_exists("docker", ShellType::PowerShell),
            "Get-Command docker -ErrorAction SilentlyContinue"
        );
    }

    // ===== null_device =====

    #[test]
    fn test_null_device() {
        assert_eq!(null_device(ShellType::Posix), "/dev/null");
        assert_eq!(null_device(ShellType::Cmd), "NUL");
        assert_eq!(null_device(ShellType::PowerShell), "$null");
    }

    // ===== stderr_to_null =====

    #[test]
    fn test_stderr_to_null() {
        assert_eq!(stderr_to_null(ShellType::Posix), "2>/dev/null");
        assert_eq!(stderr_to_null(ShellType::Cmd), "2>NUL");
        assert_eq!(stderr_to_null(ShellType::PowerShell), "2>$null");
    }

    // ===== exit_code_var =====

    #[test]
    fn test_exit_code_var() {
        assert_eq!(exit_code_var(ShellType::Posix), "$?");
        assert_eq!(exit_code_var(ShellType::Cmd), "%ERRORLEVEL%");
        assert_eq!(exit_code_var(ShellType::PowerShell), "$LASTEXITCODE");
    }

    // ===== Edge Cases =====

    #[test]
    fn test_escape_multibyte_utf8() {
        let emoji = escape("hello 🎉 world", ShellType::Posix);
        assert_eq!(emoji, "'hello 🎉 world'");

        let cjk = escape("日本語テスト", ShellType::PowerShell);
        assert_eq!(cjk, "'日本語テスト'");

        let mixed = escape("café résumé naïve", ShellType::Cmd);
        assert!(mixed.starts_with('"'));
        assert!(mixed.ends_with('"'));
        assert!(mixed.contains("café résumé naïve"));
    }

    #[test]
    fn test_escape_very_long_string() {
        let long = "x".repeat(10_000);
        let escaped = escape(&long, ShellType::Posix);
        assert_eq!(escaped.len(), 10_002); // 10_000 + 2 quotes
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    #[expect(
        deprecated,
        reason = "the legacy form stays pinned until it is removed"
    )]
    fn test_cd_and_run_with_relative_path() {
        let cmd = cd_and_run("./subdir", "ls", ShellType::Posix);
        assert_eq!(cmd, "cd './subdir' && ls");

        let cmd2 = cd_and_run("../parent", "pwd", ShellType::Posix);
        assert_eq!(cmd2, "cd '../parent' && pwd");

        let cmd3 = cd_and_run(".\\subdir", "dir", ShellType::Cmd);
        assert!(cmd3.starts_with("cd /d"));
        assert!(cmd3.contains(".\\subdir"));
    }
}
