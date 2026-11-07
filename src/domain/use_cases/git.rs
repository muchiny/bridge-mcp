//! Git Command Builder
//!
//! Builds Git CLI commands for remote execution via SSH.
//! Uses `git -C {path}` to operate on repositories at specific paths.
//!
//! # Ambient credentials
//!
//! `git clone` (the URL) and `git pull` (the remote) connect to a server
//! chosen by the caller, from a client that runs as the SSH user of the target
//! host. The credential sources that git keys by host stay in place: a
//! credential helper (`store`, `cache`, `libsecret`, a manager), a `~/.netrc`
//! `machine` entry and an `http.<url>.extraHeader` are only presented to the
//! server they name. Two sources that git applies to every server are hidden
//! on every command that contacts a server: an unscoped `http.extraHeader`
//! (cleared by `-c http.extraHeader=`) and the TLS client certificate
//! variables `GIT_SSL_CERT`, `GIT_SSL_KEY` and `GIT_SSL_CERT_PASSWORD_PROTECTED`
//! (dropped from the environment of the command, see
//! `GIT_SSL_CLIENT_CERT_UNSET`).
//!
//! What is left to the configuration of the host, and is not hidden: an
//! unscoped `http.sslCert` / `http.sslKey` in the git configuration (git has
//! no per-command reset for them: an empty `-c http.sslCert=` makes git
//! abort), a credential helper that answers for any host, a `~/.netrc`
//! `default` entry, `core.sshCommand`, `GIT_SSH_COMMAND` and the `ssh`
//! configuration (`ForwardAgent`, `StrictHostKeyChecking`, `IdentityFile`
//! under `Host *`). Keep those host-keyed, or absent, on the hosts that this
//! tool is allowed to reach.
//!
//! # Bare repositories
//!
//! Every command runs `git` with `-c safe.bareRepository=explicit`. With the
//! default (`all`) git discovers a bare repository from the working directory,
//! so a bare repository planted inside a cloned tree (and carrying its own
//! configuration: hooks, `core.fsmonitor`) would be picked up by a later
//! `git -C <that directory> ...`. With `explicit`, git only uses a bare
//! repository named by `--git-dir` or `GIT_DIR`. The command line is a
//! protected configuration scope, so the value cannot be overridden by the
//! repository.
//!
//! Consequences:
//!
//! - A bare repository given as `path` is refused by git itself
//!   (`fatal: cannot use bare repository ... (safe.bareRepository is
//!   'explicit')`); use a working-tree path, or `ssh_exec` with `--git-dir`.
//!   Cloning from, or pulling from, a bare remote is not affected.
//! - The key appeared in Git 2.38 (release notes of v2.38: "Introduce a
//!   safe.barerepository configuration variable that allows users to forbid
//!   discovery of bare repositories", read in
//!   `Documentation/RelNotes/2.38.0.adoc` of the git repository). A git older
//!   than 2.38 does not know the key. An unknown `-c section.key=value` is not
//!   an error (checked on git 2.56 with `-c totally.unknownkey=1`; older
//!   versions parse `-c` the same way, not re-tested), so on such a host the
//!   option is silently ignored and the protection is absent. Nothing is
//!   refused there: the fix fails open on git older than 2.38.
//!
//! # Clone destination
//!
//! `git clone` creates its target and fills it with files chosen by whoever
//! controls the repository. A relative target lands in the home directory of
//! the SSH user, where the configuration directories live (`~/.ssh`,
//! `~/.config/git`, `~/.config/systemd/user`, `~/.bashrc.d`, ...), and `~` is
//! not expanded (the value is shell-quoted). [`validate_clone_destination`]
//! therefore requires an absolute `destination` none of whose components
//! starts with `.`, and, when `destination` is absent, refuses a URL from
//! which git would derive a name that starts with `.` (the derivation is a
//! port of git's `git_url_basename`, see the function). A legitimate hidden
//! target (`~/.dotfiles`) goes through `ssh_exec`.
//!
//! The rule refuses a superset of what git would create. It over-refuses:
//!
//! - a `destination` with a `\` before a `.` (`/a\.b`): `\` is not a path
//!   separator for git on Linux, the component is `a\.b`; the check treats it
//!   as one;
//! - a `url` holding a byte `<= 0x20` or `0x7f` when `destination` is absent
//!   (git rewrites whitespace and the bytes below 0x20 in the name it derives,
//!   and refusing them keeps the port exact; `0x7f`, which git keeps, goes
//!   with them as a control byte; no legitimate repository URL has one);
//! - a `url` from which git derives no name at all (empty, `https://`, `.git`):
//!   git itself stops there with `No directory name could be guessed`.
//!
//! # What the dot rule does not cover
//!
//! The rule keeps a clone out of the default configuration locations under
//! the home directory, which all sit below a hidden component. It does not
//! cover:
//!
//! - paths that the account's own configuration names, and that need not be
//!   hidden: `core.hooksPath`, `include.path` / `includeIf.<cond>.path`,
//!   `init.templateDir`, `core.excludesFile` and `core.attributesFile` of
//!   git, and an `XDG_CONFIG_HOME` that points outside a hidden directory
//!   (git then reads `$XDG_CONFIG_HOME/git/config`, `ignore` and
//!   `attributes`, and other tools read their own files below it);
//! - a symlink that points at an empty configuration directory (git fills an
//!   existing empty directory, and follows a symlink to one);
//! - non-hidden directories with a meaning for the account (`$HOME/bin`,
//!   when `PATH` lists it);
//! - empty system directories, when the command runs under `sudo` (the
//!   `destination` may be absolute and hidden-free, for example a directory
//!   below `/etc` that exists and is empty).
//!
//! These are left to the host: do not point such settings at a visible path
//! for the account the bridge logs in as, and treat `sudo` on a git tool as
//! the ability to fill any empty directory the target user can write.
//!
//! [`validate_clone_destination`]: GitCommandBuilder::validate_clone_destination

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Top-level `git` option that empties the list of `http.extraHeader` values
/// inherited from the configuration files (an empty value resets the list,
/// see `git-config(1)`). Without it an unscoped header of the host's
/// `~/.gitconfig` or `/etc/gitconfig` (typically `Authorization: ...`) is sent
/// to whichever server the caller names. A header scoped to a URL
/// (`http.<url>.extraHeader`) is host-keyed and is not affected when it
/// matches the server; see the residual note in `SECURITY.md`.
///
/// It is a top-level option (before the subcommand), so it also applies to
/// the `git fetch` that `git pull` runs and to the transport of `git clone`,
/// and it is not written to the configuration of the cloned repository (unlike
/// `git clone --config`).
const GIT_NO_EXTRA_HEADER: &str = "-c http.extraHeader=";

/// Top-level `git` option on every command: git does not discover a bare
/// repository implicitly (`safe.bareRepository=explicit`), see the module
/// documentation. It is placed after `-C <path>` and before any other `-c`,
/// so every command starts with `git -C ` (or `git -c ` for `clone`).
///
/// The key exists since Git 2.38; an older git ignores it silently.
const GIT_BARE_EXPLICIT: &str = "-c safe.bareRepository=explicit";

/// Shell prefix of a `git` that connects to a server the caller chose: drops
/// the environment variables that make git present a TLS client certificate
/// of the SSH host (`GIT_SSL_CERT`, `GIT_SSL_KEY`, and
/// `GIT_SSL_CERT_PASSWORD_PROTECTED` that goes with them; they override
/// `http.sslCert`, `http.sslKey` and `http.sslCertPasswordProtected`, see
/// `git-config(1)`), so that nothing of the host is presented to that server.
/// `unset` is a POSIX builtin; the command runs in the SSH user's shell, so
/// nothing outlives it. It is joined with `&&`, not `;`: `unset` of a
/// `readonly` variable fails, and git must not start then (a surviving
/// variable would be presented to the server). `unset` of a variable that is
/// not set succeeds.
///
/// It does not cover an unscoped `http.sslCert` / `http.sslKey` in the git
/// configuration, which has no per-command reset (see the module
/// documentation).
const GIT_SSL_CLIENT_CERT_UNSET: &str =
    "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && ";

/// Whether `name` can be the name of a configured remote as this tool
/// accepts it: ASCII letters, digits, `.`, `-` and `_`, not starting with `.`
/// or `-`. A URL (`:`, `//`, `@`) and a path (`/`, `\`) fall outside it.
fn is_remote_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The directory name `git clone <url>` creates when no directory is given:
/// a port of `git_url_basename` (`dir.c`, called from `builtin/clone.c`),
/// checked against git 2.56 (see the tests of
/// [`GitCommandBuilder::validate_clone_destination`]).
///
/// The steps, in git's order: skip the scheme (`://`); skip the userinfo, up
/// to the last `@` before the first `/`; drop trailing `/` and a `/.git`
/// suffix; when what is left has no `/`, drop a `:port` (a `:` followed by
/// digits at the end); keep the last component after a `/` or a `:`; drop a
/// `.git` suffix. Only `/` is a separator (git on Linux).
///
/// Two things git also does are left out because the caller refuses their
/// input first: trimming trailing whitespace before the `/.git` check, and
/// rewriting every run of whitespace and control bytes in the name to one
/// space. The caller refuses a `url` holding a byte `<= 0x20`. The `.bundle`
/// variant (a local file that is a bundle) strips `.bundle` instead of
/// `.git`; it cannot turn a name that does not start with `.` into one that
/// does, and the empty name it produces for `.bundle` is refused here too
/// because `.bundle` starts with `.`.
///
/// The result is empty when git would stop with `No directory name could be
/// guessed`.
fn git_clone_directory_name(url: &str) -> &str {
    let mut rest = url.find("://").map_or(url, |i| &url[i + 3..]);
    let authority_end = rest.find('/').unwrap_or(rest.len());
    if let Some(at) = rest[..authority_end].rfind('@') {
        rest = &rest[at + 1..];
    }
    last_url_component(rest, true)
}

/// The directory name git before 2.6 creates: the same steps as
/// [`git_clone_directory_name`] without the scheme, userinfo and port steps,
/// which git 2.6 added (`guess_dir_name` of `builtin/clone.c` in 2.5). Hosts
/// with an older git (RHEL/CentOS 7 ships 1.8.3) derive `.x@host` from
/// `https://.x@host`, where git 2.6 and later derive `host`.
fn git_clone_directory_name_before_2_6(url: &str) -> &str {
    last_url_component(url, false)
}

/// The steps shared by both derivations, from the drop of trailing `/` on.
fn last_url_component(mut rest: &str, strip_port: bool) -> &str {
    rest = rest.trim_end_matches('/');
    if rest.len() > 5
        && let Some(head) = rest.strip_suffix(".git")
        && head.ends_with('/')
    {
        rest = head.trim_end_matches('/');
    }
    if strip_port && !rest.contains('/') && rest.contains(':') {
        let without_port = rest.trim_end_matches(|c: char| c.is_ascii_digit());
        if let Some(host) = without_port.strip_suffix(':') {
            rest = host;
        }
    }
    let name = rest.rsplit(['/', ':']).next().unwrap_or_default();
    name.strip_suffix(".git").unwrap_or(name)
}

/// At most this many characters of a refused value are shown in a message.
const MAX_SHOWN_CHARS: usize = 120;

/// `value` escaped for a message (no control character reaches the audit
/// log) and cut to [`MAX_SHOWN_CHARS`] characters.
fn shown(value: &str) -> String {
    let escaped: String = value.escape_debug().collect();
    if escaped.chars().count() <= MAX_SHOWN_CHARS {
        return escaped;
    }
    let cut: String = escaped.chars().take(MAX_SHOWN_CHARS).collect();
    format!("{cut}... (cut)")
}

/// Builds Git CLI commands for remote execution.
pub struct GitCommandBuilder;

impl GitCommandBuilder {
    /// Build a `git status` command.
    ///
    /// Shows the working tree status of a repository at the given path.
    /// If `short` is true, gives output in short-format.
    #[must_use]
    pub fn build_status_command(path: &str, short: bool) -> String {
        let escaped_path = shell_escape(path);
        if short {
            format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} status --short")
        } else {
            format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} status")
        }
    }

    /// Build a `git log` command.
    ///
    /// Shows commit history for a repository. Supports filtering by
    /// branch, author, date, and formatting options.
    #[must_use]
    pub fn build_log_command(
        path: &str,
        max_count: Option<u32>,
        oneline: bool,
        branch: Option<&str>,
        author: Option<&str>,
        since: Option<&str>,
        log_format: Option<&str>,
    ) -> String {
        let escaped_path = shell_escape(path);
        let mut cmd = format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} log");

        if let Some(n) = max_count {
            let _ = write!(cmd, " --max-count={n}");
        }
        if oneline {
            cmd.push_str(" --oneline");
        }
        if let Some(a) = author {
            let _ = write!(cmd, " --author={}", shell_escape(a));
        }
        if let Some(s) = since {
            let _ = write!(cmd, " --since={}", shell_escape(s));
        }
        if let Some(f) = log_format {
            let _ = write!(cmd, " --format={}", shell_escape(f));
        }
        if let Some(b) = branch {
            let _ = write!(cmd, " {}", shell_escape(b));
        }

        cmd
    }

    /// Build a `git diff` command.
    ///
    /// Shows changes between commits, commit and working tree, etc.
    /// If `staged` is true, shows staged changes (--staged).
    /// If `commit` is provided, diffs against that commit.
    /// If `file` is provided, limits diff to that file.
    #[must_use]
    pub fn build_diff_command(
        path: &str,
        staged: bool,
        file: Option<&str>,
        commit: Option<&str>,
    ) -> String {
        let escaped_path = shell_escape(path);
        let mut cmd = format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} diff");

        if staged {
            cmd.push_str(" --staged");
        }
        if let Some(c) = commit {
            let _ = write!(cmd, " {}", shell_escape(c));
        }
        if let Some(f) = file {
            let _ = write!(cmd, " -- {}", shell_escape(f));
        }

        cmd
    }

    /// Build a `git pull` command.
    ///
    /// Fetches and integrates remote changes. Supports `--rebase`
    /// and `--ff-only` flags, optional remote and branch.
    ///
    /// The command starts with the `unset` of `GIT_SSL_CLIENT_CERT_UNSET` and
    /// git runs with `-c safe.bareRepository=explicit -c http.extraHeader=`.
    /// The remote and the branch come
    /// after `--`; `git pull` reads its first positional argument as the
    /// repository, so a `branch` without a `remote` is not emitted
    /// ([`validate_pull_target`](Self::validate_pull_target) refuses that
    /// combination before any command is built).
    #[must_use]
    pub fn build_pull_command(
        path: &str,
        remote: Option<&str>,
        branch: Option<&str>,
        rebase: bool,
        ff_only: bool,
    ) -> String {
        let escaped_path = shell_escape(path);
        let mut cmd = format!(
            "{GIT_SSL_CLIENT_CERT_UNSET}git -C {escaped_path} {GIT_BARE_EXPLICIT} \
             {GIT_NO_EXTRA_HEADER} pull"
        );

        if rebase {
            cmd.push_str(" --rebase");
        }
        if ff_only {
            cmd.push_str(" --ff-only");
        }
        if let Some(r) = remote {
            let _ = write!(cmd, " -- {}", shell_escape(r));
            if let Some(b) = branch {
                let _ = write!(cmd, " {}", shell_escape(b));
            }
        }

        cmd
    }

    /// Build a `git clone` command.
    ///
    /// Clones a repository from the given URL. Supports shallow clones
    /// via `depth`, branch selection, and `single_branch`.
    ///
    /// The command starts with the `unset` of `GIT_SSL_CLIENT_CERT_UNSET` and
    /// git runs with `-c http.extraHeader=`: the URL is the caller's choice, so neither a
    /// header nor a client certificate that the host applies to every server
    /// is sent to it.
    #[must_use]
    pub fn build_clone_command(
        url: &str,
        destination: Option<&str>,
        branch: Option<&str>,
        depth: Option<u32>,
        single_branch: bool,
    ) -> String {
        let mut cmd = format!(
            "{GIT_SSL_CLIENT_CERT_UNSET}git {GIT_BARE_EXPLICIT} {GIT_NO_EXTRA_HEADER} clone"
        );

        if let Some(b) = branch {
            let _ = write!(cmd, " --branch {}", shell_escape(b));
        }
        if let Some(d) = depth {
            let _ = write!(cmd, " --depth {d}");
        }
        if single_branch {
            cmd.push_str(" --single-branch");
        }
        // `--` ends the options: a destination (or url) read as an option
        // would be `--config=core.sshCommand=...` or `--upload-pack=...`.
        let _ = write!(cmd, " -- {}", shell_escape(url));
        if let Some(dest) = destination {
            let _ = write!(cmd, " {}", shell_escape(dest));
        }

        cmd
    }

    /// Build a `git branch` command.
    ///
    /// Manages branches in a repository. Action must be validated first
    /// via [`validate_branch_action`](Self::validate_branch_action).
    ///
    /// - `list`: `git -C {path} branch [-r]`
    /// - `create`: `git -C {path} branch {name}`
    /// - `delete`: `git -C {path} branch -d {name}`
    #[must_use]
    pub fn build_branch_command(
        path: &str,
        action: &str,
        name: Option<&str>,
        remote: bool,
    ) -> String {
        let escaped_path = shell_escape(path);

        match action {
            "create" => {
                let branch_name = shell_escape(name.unwrap_or("new-branch"));
                format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} branch {branch_name}")
            }
            "delete" => {
                let branch_name = shell_escape(name.unwrap_or(""));
                format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} branch -d {branch_name}")
            }
            // "list" and any other action default to branch listing
            _ => {
                if remote {
                    format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} branch -r")
                } else {
                    format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} branch")
                }
            }
        }
    }

    /// Build a `git checkout` command.
    ///
    /// Switches branches or restores working tree files.
    /// If `create` is true, creates a new branch with `-b`.
    #[must_use]
    pub fn build_checkout_command(path: &str, target: &str, create: bool) -> String {
        let escaped_path = shell_escape(path);
        let escaped_target = shell_escape(target);

        if create {
            format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} checkout -b {escaped_target}")
        } else {
            format!("git -C {escaped_path} {GIT_BARE_EXPLICIT} checkout {escaped_target}")
        }
    }

    /// Validate the `destination` of a `git clone`, given the `url` git will
    /// derive a name from when `destination` is absent.
    ///
    /// - `destination` present: it must start with `/` (an empty value does
    ///   not), and none of its components, split on `/` and `\`, may start with
    ///   `.` (`.`, `..`, `.ssh`, `.config`, ...). Empty components are ignored.
    ///   Git on Linux splits on `/` only, so a `\` followed by a `.` is
    ///   refused although git would not create a hidden component there.
    /// - `destination` absent: `url` must not hold a byte `<= 0x20` or `0x7f`
    ///   (git rewrites whitespace and the bytes below 0x20 in the name it
    ///   derives; 0x7f, which it keeps, is refused with them as a control
    ///   byte; no repository URL has any of them), and the name git derives from `url` (see
    ///   `git_clone_directory_name`) must be neither empty (git stops with
    ///   `No directory name could be guessed`) nor start with `.`.
    ///
    /// The rule refuses a superset of what git would create; the module
    /// documentation lists what it does not cover.
    ///
    /// [`build_clone_command`](Self::build_clone_command) stays infallible;
    /// the handler calls this function from `validate`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] naming `destination`.
    pub fn validate_clone_destination(destination: Option<&str>, url: &str) -> Result<()> {
        let Some(dest) = destination else {
            if let Some(byte) = url.bytes().find(|&b| b <= 0x20 || b == 0x7f) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "'destination' is not set and 'url' holds a whitespace or control \
                         character (byte {byte:#04x}): git rewrites those when it derives the \
                         directory name, so the name cannot be checked. Set 'destination' to \
                         an absolute path, for example /srv/repos/name"
                    ),
                });
            }
            let derived = git_clone_directory_name(url);
            if derived.is_empty() {
                return Err(BridgeError::CommandDenied {
                    reason: "'destination' is not set and git can derive no directory name \
                             from 'url': set 'destination' to an absolute path, for example \
                             /srv/repos/name"
                        .to_string(),
                });
            }
            // A git older than 2.6 derives another name from some URLs; refuse
            // when either derivation is hidden.
            let legacy = git_clone_directory_name_before_2_6(url);
            if let Some(hidden) = [derived, legacy].into_iter().find(|n| n.starts_with('.')) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "'destination' is not set and the directory git derives from 'url' \
                         ('{}') starts with '.': the clone would create a hidden directory. \
                         Set 'destination' to an absolute path, for example /srv/repos/name",
                        shown(hidden)
                    ),
                });
            }
            return Ok(());
        };
        if !dest.starts_with('/') {
            return Err(BridgeError::CommandDenied {
                reason: "'destination' must be an absolute path (start with '/'): a relative \
                         path is resolved against the SSH user's home directory and '~' is not \
                         expanded. Use the full path, for example /srv/repos/name"
                    .to_string(),
            });
        }
        if let Some(component) = dest.split(['/', '\\']).find(|c| c.starts_with('.')) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "'destination' must not contain a component starting with '.' ('{}'): the \
                     clone would create or fill hidden configuration directories (~/.ssh, \
                     ~/.config, ...). Choose a path without hidden components; for a hidden \
                     target, use ssh_exec",
                    shown(component)
                ),
            });
        }
        Ok(())
    }

    /// Refuse a ref, remote, url or branch name that starts with `-`.
    ///
    /// None of them can legitimately start with `-`, and git would read the
    /// value as an option (`--output=<file>` writes a file, `--upload-pack=<cmd>`
    /// runs a command).
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] naming `arg` when `value` starts
    /// with `-`.
    pub fn validate_not_option(arg: &str, value: Option<&str>) -> Result<()> {
        value.map_or(Ok(()), |v| super::shell::refuse_option_like(arg, v))
    }

    /// Validate the `remote` and `branch` of a `git pull`.
    ///
    /// - `remote` must be the name of a remote configured in the repository:
    ///   ASCII letters, digits, `.`, `-` and `_`, not starting with `.` or
    ///   `-`. `git pull` takes any URL or path in its place and would contact
    ///   that server as the SSH user of the host, so neither is accepted.
    /// - `branch` must not start with `-`, and needs a `remote`: without one,
    ///   `git pull` reads the branch as the repository.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] naming the argument.
    pub fn validate_pull_target(remote: Option<&str>, branch: Option<&str>) -> Result<()> {
        if let Some(r) = remote
            && !is_remote_name(r)
        {
            return Err(BridgeError::CommandDenied {
                reason: "'remote' must be the name of a remote configured in the repository: \
                         ASCII letters, digits and . - _ only, not starting with '.' or '-' \
                         (a URL or a path is not accepted; use ssh_git_clone for a URL)"
                    .to_string(),
            });
        }
        Self::validate_not_option("branch", branch)?;
        if branch.is_some() && remote.is_none() {
            return Err(BridgeError::CommandDenied {
                reason: "'branch' needs 'remote': without a remote name, git reads the branch \
                         as the repository to pull from"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Validate a branch action.
    ///
    /// Only allows: `list`, `create`, `delete`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn validate_branch_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["list", "create", "delete"];
        if ALLOWED.contains(&action) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Branch action '{}' is not allowed. Allowed actions: {}",
                    action,
                    ALLOWED.join(", ")
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_status_command ────────────────────────────────────────

    #[test]
    fn test_status_basic() {
        let cmd = GitCommandBuilder::build_status_command("/opt/repo", false);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit status"
        );
    }

    #[test]
    fn test_status_short() {
        let cmd = GitCommandBuilder::build_status_command("/opt/repo", true);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit status --short"
        );
    }

    #[test]
    fn test_status_shell_escape() {
        let cmd = GitCommandBuilder::build_status_command("/opt/my repo; rm -rf /", false);
        assert!(cmd.contains("'/opt/my repo; rm -rf /'"));
    }

    // ── build_log_command ──────────────────────────────────────────

    #[test]
    fn test_log_basic() {
        let cmd =
            GitCommandBuilder::build_log_command("/opt/repo", None, false, None, None, None, None);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit log"
        );
    }

    #[test]
    fn test_log_max_count() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            Some(10),
            false,
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit log --max-count=10"
        );
    }

    #[test]
    fn test_log_oneline() {
        let cmd =
            GitCommandBuilder::build_log_command("/opt/repo", None, true, None, None, None, None);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit log --oneline"
        );
    }

    #[test]
    fn test_log_branch() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            None,
            false,
            Some("main"),
            None,
            None,
            None,
        );
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit log 'main'"
        );
    }

    #[test]
    fn test_log_author() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            None,
            false,
            None,
            Some("john@example.com"),
            None,
            None,
        );
        assert!(cmd.contains("--author='john@example.com'"));
    }

    #[test]
    fn test_log_since() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            None,
            false,
            None,
            None,
            Some("2024-01-01"),
            None,
        );
        assert!(cmd.contains("--since='2024-01-01'"));
    }

    #[test]
    fn test_log_format() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            None,
            false,
            None,
            None,
            None,
            Some("%H %s"),
        );
        assert!(cmd.contains("--format='%H %s'"));
    }

    #[test]
    fn test_log_all_options() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            Some(5),
            true,
            Some("develop"),
            Some("alice"),
            Some("1 week ago"),
            Some("%h %s"),
        );
        assert!(cmd.contains("git -C '/opt/repo' -c safe.bareRepository=explicit log"));
        assert!(cmd.contains("--max-count=5"));
        assert!(cmd.contains("--oneline"));
        assert!(cmd.contains("--author='alice'"));
        assert!(cmd.contains("--since='1 week ago'"));
        assert!(cmd.contains("--format='%h %s'"));
        assert!(cmd.contains("'develop'"));
    }

    #[test]
    fn test_log_shell_escape() {
        let cmd = GitCommandBuilder::build_log_command(
            "/opt/repo",
            None,
            false,
            Some("main; echo pwned"),
            None,
            None,
            None,
        );
        assert!(cmd.contains("'main; echo pwned'"));
    }

    // ── build_diff_command ─────────────────────────────────────────

    #[test]
    fn test_diff_basic() {
        let cmd = GitCommandBuilder::build_diff_command("/opt/repo", false, None, None);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit diff"
        );
    }

    #[test]
    fn test_diff_staged() {
        let cmd = GitCommandBuilder::build_diff_command("/opt/repo", true, None, None);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit diff --staged"
        );
    }

    #[test]
    fn test_diff_file() {
        let cmd =
            GitCommandBuilder::build_diff_command("/opt/repo", false, Some("src/main.rs"), None);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit diff -- 'src/main.rs'"
        );
    }

    #[test]
    fn test_diff_commit() {
        let cmd = GitCommandBuilder::build_diff_command("/opt/repo", false, None, Some("HEAD~3"));
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit diff 'HEAD~3'"
        );
    }

    #[test]
    fn test_diff_all_options() {
        let cmd = GitCommandBuilder::build_diff_command(
            "/opt/repo",
            true,
            Some("README.md"),
            Some("abc123"),
        );
        assert!(cmd.contains("--staged"));
        assert!(cmd.contains("'abc123'"));
        assert!(cmd.contains("-- 'README.md'"));
    }

    #[test]
    fn test_diff_shell_escape() {
        let cmd = GitCommandBuilder::build_diff_command(
            "/opt/repo",
            false,
            Some("file'; rm -rf /"),
            None,
        );
        assert!(cmd.contains("'file'\\''; rm -rf /'"));
    }

    // ── build_pull_command ─────────────────────────────────────────

    #[test]
    fn test_pull_basic() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, false, false);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= pull"
        );
    }

    #[test]
    fn test_pull_rebase() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, true, false);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= pull --rebase"
        );
    }

    #[test]
    fn test_pull_ff_only() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, false, true);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= pull --ff-only"
        );
    }

    #[test]
    fn test_pull_remote_branch() {
        let cmd = GitCommandBuilder::build_pull_command(
            "/opt/repo",
            Some("origin"),
            Some("main"),
            false,
            false,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= \
             pull -- 'origin' 'main'"
        );
    }

    #[test]
    fn test_pull_all_options() {
        let cmd = GitCommandBuilder::build_pull_command(
            "/opt/repo",
            Some("upstream"),
            Some("develop"),
            true,
            true,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= \
             pull --rebase --ff-only -- 'upstream' 'develop'"
        );
    }

    #[test]
    fn test_pull_shell_escape() {
        let cmd = GitCommandBuilder::build_pull_command(
            "/opt/repo",
            Some("origin; echo pwned"),
            None,
            false,
            false,
        );
        assert!(cmd.contains("-- 'origin; echo pwned'"));
    }

    #[test]
    fn test_pull_remote_only() {
        let cmd =
            GitCommandBuilder::build_pull_command("/opt/repo", Some("origin"), None, false, false);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= \
             pull -- 'origin'"
        );
    }

    #[test]
    fn test_pull_never_emits_a_branch_without_a_remote() {
        // `git pull <x>` reads <x> as the repository.
        let cmd = GitCommandBuilder::build_pull_command(
            "/opt/repo",
            None,
            Some("https://rogue.example/r.git"),
            true,
            false,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c safe.bareRepository=explicit -c http.extraHeader= pull --rebase"
        );
    }

    #[test]
    fn test_pull_clears_the_unscoped_extra_header_before_the_subcommand() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, false, false);
        let header = cmd.find("-c http.extraHeader=").expect("header reset");
        assert!(header < cmd.find(" pull").expect("subcommand"), "{cmd}");
    }

    #[test]
    fn test_pull_drops_the_client_certificate_variables_before_git_starts() {
        for (remote, branch) in [(None, None), (Some("origin"), Some("main"))] {
            let cmd =
                GitCommandBuilder::build_pull_command("/opt/repo", remote, branch, true, true);
            assert!(
                cmd.starts_with(
                    "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && git -C "
                ),
                "{cmd}"
            );
        }
    }

    // ── validate_pull_target ───────────────────────────────────────

    #[test]
    fn test_validate_pull_target_accepts_remote_names() {
        for remote in [
            "origin",
            "upstream",
            "my-remote",
            "my_remote",
            "r.1",
            "a..b",
            "O1",
        ] {
            GitCommandBuilder::validate_pull_target(Some(remote), Some("feature/x")).expect(remote);
            GitCommandBuilder::validate_pull_target(Some(remote), None).expect(remote);
        }
        GitCommandBuilder::validate_pull_target(None, None).expect("no remote, no branch");
    }

    #[test]
    fn test_validate_pull_target_refuses_urls_paths_and_odd_names() {
        for remote in [
            "https://rogue.example/r.git",
            "http://127.0.0.1:8080/x",
            "git@rogue.example:o/r.git",
            "rogue.example:o/r.git",
            "ssh://rogue.example/r",
            "user:pw@rogue.example",
            "host::addr",
            "ext::sh -c x",
            "/srv/repo",
            "../repo",
            "./repo",
            ".hidden",
            "..",
            "dir/remote",
            "C:\\repo",
            "\\\\server\\share",
            "with space",
            "semi;colon",
            "dollar$x",
            "new\nline",
            "--upload-pack=x",
            "-o",
            "",
            "é",
        ] {
            let err =
                GitCommandBuilder::validate_pull_target(Some(remote), None).expect_err(remote);
            let msg = err.to_string();
            assert!(msg.contains("'remote'"), "{msg}");
            assert!(msg.contains("configured in the repository"), "{msg}");
        }
    }

    #[test]
    fn test_validate_pull_target_refuses_a_branch_without_remote() {
        let err = GitCommandBuilder::validate_pull_target(None, Some("main")).unwrap_err();
        assert!(err.to_string().contains("'branch' needs 'remote'"), "{err}");
    }

    #[test]
    fn test_validate_pull_target_refuses_an_option_shaped_branch() {
        let err = GitCommandBuilder::validate_pull_target(Some("origin"), Some("--output=/x"))
            .unwrap_err();
        assert!(
            err.to_string().contains("'branch' must not start with '-'"),
            "{err}"
        );
    }

    // ── build_clone_command ────────────────────────────────────────

    #[test]
    fn test_clone_basic() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            None,
            None,
            None,
            false,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone \
             -- 'https://github.com/user/repo.git'"
        );
    }

    #[test]
    fn test_clone_destination() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            Some("/opt/myrepo"),
            None,
            None,
            false,
        );
        assert!(cmd.contains("'https://github.com/user/repo.git'"));
        assert!(cmd.ends_with("'/opt/myrepo'"));
    }

    #[test]
    fn test_clone_branch() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            None,
            Some("develop"),
            None,
            false,
        );
        assert!(cmd.contains("--branch 'develop'"));
    }

    #[test]
    fn test_clone_depth() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            None,
            None,
            Some(1),
            false,
        );
        assert!(cmd.contains("--depth 1"));
    }

    #[test]
    fn test_clone_single_branch() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            None,
            None,
            None,
            true,
        );
        assert!(cmd.contains("--single-branch"));
    }

    #[test]
    fn test_clone_all_options() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://github.com/user/repo.git",
            Some("/opt/dest"),
            Some("main"),
            Some(5),
            true,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone --branch 'main' \
             --depth 5 --single-branch -- 'https://github.com/user/repo.git' '/opt/dest'"
        );
    }

    #[test]
    fn test_clone_clears_the_unscoped_extra_header_before_the_subcommand() {
        let cmd = GitCommandBuilder::build_clone_command("ssh://x/y", None, None, None, false);
        assert!(
            cmd.starts_with(
                "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
                 git -c safe.bareRepository=explicit -c http.extraHeader= clone "
            ),
            "{cmd}"
        );
    }

    #[test]
    fn test_clone_drops_the_client_certificate_variables_before_git_starts() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://git.example.org/o/r.git",
            Some("/srv/x"),
            Some("main"),
            Some(1),
            true,
        );
        assert!(cmd.starts_with("unset "), "{cmd}");
        // Joined with `&&` so that a `readonly` variable stops the command.
        assert!(
            cmd.find(" && git ").expect("and-list") < cmd.find(" clone ").expect("subcommand"),
            "{cmd}"
        );
        assert!(!cmd.contains(';'), "{cmd}");
    }

    #[test]
    fn test_git_commands_that_contact_no_server_only_gain_the_bare_repository_option() {
        // Only the commands that connect to a server chosen by the caller get
        // the `unset` prefix and the header reset; all of them get the
        // bare-repository option.
        for cmd in [
            GitCommandBuilder::build_status_command("/srv/x", false),
            GitCommandBuilder::build_log_command("/srv/x", None, false, None, None, None, None),
            GitCommandBuilder::build_diff_command("/srv/x", false, None, None),
        ] {
            assert!(!cmd.contains("unset"), "{cmd}");
            assert!(!cmd.contains("extraHeader"), "{cmd}");
            assert!(
                cmd.starts_with("git -C '/srv/x' -c safe.bareRepository=explicit "),
                "{cmd}"
            );
        }
        assert_eq!(
            GitCommandBuilder::build_status_command("/srv/x", false),
            "git -C '/srv/x' -c safe.bareRepository=explicit status"
        );
        assert_eq!(
            GitCommandBuilder::build_log_command("/srv/x", None, false, None, None, None, None),
            "git -C '/srv/x' -c safe.bareRepository=explicit log"
        );
        assert_eq!(
            GitCommandBuilder::build_diff_command("/srv/x", false, None, None),
            "git -C '/srv/x' -c safe.bareRepository=explicit diff"
        );
    }

    #[test]
    fn test_every_builder_carries_the_bare_repository_option_once_before_the_subcommand() {
        let option = "-c safe.bareRepository=explicit";
        for cmd in [
            GitCommandBuilder::build_status_command("/r", true),
            GitCommandBuilder::build_log_command(
                "/r",
                Some(1),
                true,
                Some("b"),
                Some("a"),
                Some("s"),
                Some("f"),
            ),
            GitCommandBuilder::build_diff_command("/r", true, Some("f"), Some("c")),
            GitCommandBuilder::build_pull_command("/r", Some("o"), Some("b"), true, true),
            GitCommandBuilder::build_clone_command(
                "ssh://x/y",
                Some("/d"),
                Some("b"),
                Some(1),
                true,
            ),
            GitCommandBuilder::build_branch_command("/r", "list", None, true),
            GitCommandBuilder::build_branch_command("/r", "create", Some("n"), false),
            GitCommandBuilder::build_branch_command("/r", "delete", Some("n"), false),
            GitCommandBuilder::build_checkout_command("/r", "t", true),
        ] {
            assert_eq!(cmd.matches(option).count(), 1, "{cmd}");
            // Before the subcommand, so that it applies to it.
            let subcommand = [
                "status", "log", "diff", "pull", "clone", "branch", "checkout",
            ]
            .iter()
            .filter_map(|s| cmd.find(&format!(" {s}")))
            .min()
            .expect("subcommand");
            assert!(cmd.find(option).expect("option") < subcommand, "{cmd}");
        }
    }

    #[test]
    fn test_clone_keeps_the_credential_helper_and_ssh_command() {
        // Host-keyed helpers must keep working, and a custom ssh setup is the
        // host's business: nothing here overrides either.
        let cmd = GitCommandBuilder::build_clone_command(
            "https://u:p@example.org/r.git",
            Some("/opt/d"),
            Some("main"),
            Some(1),
            true,
        );
        for forbidden in ["credential", "sshCommand", "GIT_SSH", "GIT_CONFIG"] {
            assert!(!cmd.contains(forbidden), "{cmd}");
        }
    }

    #[test]
    fn test_clone_shell_escape() {
        let cmd = GitCommandBuilder::build_clone_command(
            "https://evil.com/repo'; rm -rf /",
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("'https://evil.com/repo'\\''; rm -rf /'"));
    }

    // ── build_branch_command ───────────────────────────────────────

    #[test]
    fn test_branch_list() {
        let cmd = GitCommandBuilder::build_branch_command("/opt/repo", "list", None, false);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit branch"
        );
    }

    #[test]
    fn test_branch_list_remote() {
        let cmd = GitCommandBuilder::build_branch_command("/opt/repo", "list", None, true);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit branch -r"
        );
    }

    #[test]
    fn test_branch_create() {
        let cmd = GitCommandBuilder::build_branch_command(
            "/opt/repo",
            "create",
            Some("feature-x"),
            false,
        );
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit branch 'feature-x'"
        );
    }

    #[test]
    fn test_branch_create_default_name() {
        let cmd = GitCommandBuilder::build_branch_command("/opt/repo", "create", None, false);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit branch 'new-branch'"
        );
    }

    #[test]
    fn test_branch_delete() {
        let cmd = GitCommandBuilder::build_branch_command(
            "/opt/repo",
            "delete",
            Some("old-branch"),
            false,
        );
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit branch -d 'old-branch'"
        );
    }

    #[test]
    fn test_branch_shell_escape() {
        let cmd = GitCommandBuilder::build_branch_command(
            "/opt/repo",
            "create",
            Some("branch'; echo pwned"),
            false,
        );
        assert!(cmd.contains("'branch'\\''; echo pwned'"));
    }

    // ── build_checkout_command ─────────────────────────────────────

    #[test]
    fn test_checkout_basic() {
        let cmd = GitCommandBuilder::build_checkout_command("/opt/repo", "main", false);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit checkout 'main'"
        );
    }

    #[test]
    fn test_checkout_create() {
        let cmd = GitCommandBuilder::build_checkout_command("/opt/repo", "new-feature", true);
        assert_eq!(
            cmd,
            "git -C '/opt/repo' -c safe.bareRepository=explicit checkout -b 'new-feature'"
        );
    }

    #[test]
    fn test_checkout_shell_escape() {
        let cmd = GitCommandBuilder::build_checkout_command("/opt/repo", "main; rm -rf /", false);
        assert!(cmd.contains("'main; rm -rf /'"));
    }

    // ── validate_branch_action ─────────────────────────────────────

    #[test]
    fn test_validate_branch_action_allowed() {
        for action in &["list", "create", "delete"] {
            assert!(
                GitCommandBuilder::validate_branch_action(action).is_ok(),
                "Action '{action}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_branch_action_denied() {
        for action in &["rename", "force-delete", "invalid", ""] {
            let result = GitCommandBuilder::validate_branch_action(action);
            assert!(result.is_err(), "Action '{action}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(action));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_validate_branch_action_case_sensitive() {
        assert!(GitCommandBuilder::validate_branch_action("List").is_err());
        assert!(GitCommandBuilder::validate_branch_action("CREATE").is_err());
    }

    // ── option injection ───────────────────────────────────────────

    #[test]
    fn test_clone_puts_url_and_destination_after_double_dash() {
        let cmd = GitCommandBuilder::build_clone_command(
            "ssh://x/y",
            Some("--config=core.sshCommand=touch /tmp/p"),
            None,
            None,
            false,
        );
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -c safe.bareRepository=explicit -c http.extraHeader= clone -- 'ssh://x/y' \
             '--config=core.sshCommand=touch /tmp/p'"
        );
    }

    #[test]
    fn test_validate_not_option_refuses_a_leading_dash() {
        let err =
            GitCommandBuilder::validate_not_option("branch", Some("--output=/tmp/x")).unwrap_err();
        assert!(
            err.to_string().contains("'branch' must not start with '-'"),
            "{err}"
        );
        assert!(GitCommandBuilder::validate_not_option("branch", Some("main")).is_ok());
        assert!(GitCommandBuilder::validate_not_option("branch", None).is_ok());
    }

    // ── validate_clone_destination ─────────────────────────────────

    #[test]
    fn test_validate_clone_destination_accepts_absolute_paths_without_hidden_components() {
        for dest in [
            "/srv/repos/name",
            "/opt/r",
            "/a/b.c/d",
            "/a//b",
            "/a/b/",
            "/",
            "/a/b..c",
            "/a/-x",
        ] {
            GitCommandBuilder::validate_clone_destination(Some(dest), "https://h/r.git")
                .expect(dest);
        }
    }

    #[test]
    fn test_validate_clone_destination_refuses_relative_and_empty_paths() {
        for dest in ["rel", "rel/x", "~/x", "~", "", "./x", "x/", " /x", "C:\\x"] {
            let err = GitCommandBuilder::validate_clone_destination(Some(dest), "https://h/r.git")
                .expect_err(dest);
            assert_eq!(
                err.to_string(),
                "Command denied: 'destination' must be an absolute path (start with '/'): a \
                 relative path is resolved against the SSH user's home directory and '~' is \
                 not expanded. Use the full path, for example /srv/repos/name",
                "{dest:?}"
            );
        }
    }

    #[test]
    fn test_validate_clone_destination_refuses_hidden_components() {
        for (dest, component) in [
            ("/a/.ssh", ".ssh"),
            ("/home/u/.config/git", ".config"),
            ("/a/./b", "."),
            ("/a/../b", ".."),
            ("/.x", ".x"),
            ("/a/.", "."),
            // Documented over-refusal: `\` is not a separator for git on Linux.
            ("/a\\.b", ".b"),
            ("/a/b/.git", ".git"),
            ("/a/.bashrc.d/x", ".bashrc.d"),
        ] {
            let err = GitCommandBuilder::validate_clone_destination(Some(dest), "https://h/r.git")
                .expect_err(dest);
            assert_eq!(
                err.to_string(),
                format!(
                    "Command denied: 'destination' must not contain a component starting with \
                     '.' ('{component}'): the clone would create or fill hidden configuration \
                     directories (~/.ssh, ~/.config, ...). Choose a path without hidden \
                     components; for a hidden target, use ssh_exec"
                ),
                "{dest:?}"
            );
        }
    }

    // Evidence for `git_clone_directory_name`. Every pair below was checked
    // against git 2.56.0 on 2026-11-07: `git clone -- <url>` in an empty
    // directory with `GIT_SSH_COMMAND=/bin/false`, reading the name in the
    // `Cloning into '<name>'...` line (a `None` is `fatal: No directory name
    // could be guessed`), and 300 random URLs built from `a b . / : @ \ .git`,
    // digits, `://`, spaces, tabs, newlines and control bytes agreed with an
    // independent port. The pairs that matter for the rule:
    // `https://h/.ssh/ ` (trailing space), `https://h/ .ssh`, `https://h/<0x01>.ssh`
    // and `https://h/<LF>.ssh` all create `.ssh` (the reason the validator
    // refuses bytes <= 0x20); `https://h/<0x7f>.ssh` creates `<0x7f>.ssh` (git
    // keeps 0x7f, the validator refuses it anyway); `https://x@.ssh`,
    // `ssh://x@.config` and `git@.ssh:` create `.ssh` / `.config` / `.ssh`;
    // `https://h/.ssh/.git` creates `.ssh`; `https://h/a\.cfg` creates the
    // single component `a\.cfg` (a `\` is not a separator on Linux).
    const GIT_DERIVED_NAMES: &[(&str, &str)] = &[
        ("https://h/r.git", "r"),
        ("https://h/o/r/", "r"),
        ("git@h:o/r.git", "r"),
        ("ssh://x/y", "y"),
        ("host:r", "r"),
        ("https://h/o/r.d/x.y", "x.y"),
        ("https://h/.hidden/r.git", "r"),
        ("host:", "host"),
        ("https://h:8080", "h"),
        ("https://h:8080/", "h"),
        ("ssh://u@h:22", "h"),
        ("h:2222", "h"),
        ("https://h/a:2222.git", "2222"),
        ("https://h/a\\.cfg", "a\\.cfg"),
        ("C:\\x\\.cfg", "\\x\\.cfg"),
        ("https://h/.git", "h"),
        ("https://h/x.git.git", "x.git"),
        ("https://h/r/.git/", "r"),
        ("https://h/r//.git", "r"),
        ("https://u:p@h/r.git", "r"),
        ("https://h/r/.cfg", ".cfg"),
        ("host:.x", ".x"),
        ("git@h:.ssh", ".ssh"),
        ("https://h/r/.cfg/", ".cfg"),
        ("https://x@.ssh", ".ssh"),
        ("ssh://x@.config", ".config"),
        ("git@.ssh:", ".ssh"),
        ("https://a@b@.ssh", ".ssh"),
        ("https://h/.ssh/.git", ".ssh"),
        ("https://h/r/:.ssh", ".ssh"),
        ("user@host:.ssh/.git", ".ssh"),
        ("https://h/..git", "."),
        ("https://h/a/.git.git", ".git"),
        ("://.ssh", ".ssh"),
        ("https:///.ssh", ".ssh"),
        ("https://@/.ssh", ".ssh"),
        ("https://h@/.ssh", ".ssh"),
        ("https://h/.ssh?x", ".ssh?x"),
        ("https://h/.ssh#f", ".ssh#f"),
        ("https://h/.ssh/", ".ssh"),
        // Not run through git (it stops later: `destination path '..' already
        // exists`), the name is the one `git_url_basename` returns.
        ("https://h/r/..", ".."),
        // `fatal: No directory name could be guessed`.
        ("https://h/.ssh:", ""),
        ("https://", ""),
        ("://", ""),
        (".git", ""),
        ("", ""),
    ];

    #[test]
    fn test_git_clone_directory_name_matches_what_git_creates() {
        for (url, name) in GIT_DERIVED_NAMES {
            assert_eq!(git_clone_directory_name(url), *name, "{url:?}");
        }
    }

    #[test]
    fn test_validate_clone_destination_derived_name_must_not_be_hidden() {
        let mut refused = 0;
        for (url, derived) in GIT_DERIVED_NAMES
            .iter()
            .filter(|(_, name)| name.starts_with('.'))
        {
            let err = GitCommandBuilder::validate_clone_destination(None, url).expect_err(url);
            assert_eq!(
                err.to_string(),
                format!(
                    "Command denied: 'destination' is not set and the directory git derives \
                     from 'url' ('{derived}') starts with '.': the clone would create a hidden \
                     directory. Set 'destination' to an absolute path, for example \
                     /srv/repos/name"
                ),
                "{url:?}"
            );
            refused += 1;
        }
        assert!(refused >= 20, "{refused}");
    }

    #[test]
    fn test_validate_clone_destination_refuses_a_url_git_derives_no_name_from() {
        for (url, _) in GIT_DERIVED_NAMES.iter().filter(|(_, name)| name.is_empty()) {
            let err = GitCommandBuilder::validate_clone_destination(None, url).expect_err(url);
            assert_eq!(
                err.to_string(),
                "Command denied: 'destination' is not set and git can derive no directory \
                 name from 'url': set 'destination' to an absolute path, for example \
                 /srv/repos/name",
                "{url:?}"
            );
        }
    }

    #[test]
    fn test_validate_clone_destination_refuses_whitespace_and_control_bytes_in_the_url() {
        // Git rewrites these in the name it derives, so each of them creates
        // `.ssh` / `.config` although a naive last-segment check sees a
        // visible name (see the evidence above `GIT_DERIVED_NAMES`).
        for (url, byte) in [
            ("https://h/.ssh/ ", "0x20"),
            ("https://h/.ssh/\t", "0x09"),
            ("https://h/ .ssh", "0x20"),
            ("https://h/\u{1}.ssh", "0x01"),
            ("https://h/\u{7f}.ssh", "0x7f"),
            ("https://h/.ssh\u{1}", "0x01"),
            ("https://h/\n.ssh", "0x0a"),
            ("https://h/x\u{b}.y", "0x0b"),
            (" ", "0x20"),
            ("host: r", "0x20"),
        ] {
            let err = GitCommandBuilder::validate_clone_destination(None, url).expect_err(url);
            assert_eq!(
                err.to_string(),
                format!(
                    "Command denied: 'destination' is not set and 'url' holds a whitespace or \
                     control character (byte {byte}): git rewrites those when it derives the \
                     directory name, so the name cannot be checked. Set 'destination' to an \
                     absolute path, for example /srv/repos/name"
                ),
                "{url:?}"
            );
        }
        // With a destination the URL is not inspected for them.
        GitCommandBuilder::validate_clone_destination(Some("/srv/x"), "https://h/.ssh/ ")
            .expect("the name is not derived when a destination is given");
    }

    #[test]
    fn test_validate_clone_destination_accepts_visible_derived_names() {
        let mut accepted = 0;
        for (url, _) in GIT_DERIVED_NAMES
            .iter()
            .filter(|(_, name)| !name.is_empty() && !name.starts_with('.'))
        {
            GitCommandBuilder::validate_clone_destination(None, url).expect(url);
            accepted += 1;
        }
        assert!(accepted >= 15, "{accepted}");
    }

    #[test]
    fn test_validate_clone_destination_does_not_read_a_backslash_as_a_separator() {
        // Not a separator for git on Linux: the target is `a\.cfg`, which is a
        // visible name in the home directory, not `.cfg`.
        for url in ["https://h/a\\.cfg", "h\\.x", "C:\\x\\.cfg"] {
            GitCommandBuilder::validate_clone_destination(None, url).expect(url);
        }
    }

    #[test]
    fn test_validate_clone_destination_ignores_the_url_when_a_destination_is_given() {
        GitCommandBuilder::validate_clone_destination(Some("/srv/x"), "https://h/r/.cfg")
            .expect("a visible destination overrides the derived name");
    }

    #[test]
    fn test_validate_clone_destination_escapes_control_characters_in_the_message() {
        let err = GitCommandBuilder::validate_clone_destination(Some("/a/.x\ny"), "u").unwrap_err();
        assert!(err.to_string().contains("('.x\\ny')"), "{err}");
    }

    #[test]
    fn test_validate_clone_destination_refuses_a_name_git_before_2_6_would_hide() {
        // git 2.6 and later skip the userinfo and derive `host`; git 1.8.3
        // (RHEL/CentOS 7) keeps it and creates `.x@host`.
        let url = "https://.x@host";
        assert_eq!(git_clone_directory_name(url), "host");
        assert_eq!(git_clone_directory_name_before_2_6(url), ".x@host");
        let err = GitCommandBuilder::validate_clone_destination(None, url).unwrap_err();
        assert!(
            err.to_string().contains("('.x@host') starts with '.'"),
            "{err}"
        );
        // The two derivations agree on ordinary URLs, which still pass.
        for url in [
            "https://h/u/repo.git",
            "git@h:u/repo.git",
            "ssh://git@h:2222/repo",
        ] {
            assert_eq!(git_clone_directory_name(url), "repo", "{url}");
            assert_eq!(git_clone_directory_name_before_2_6(url), "repo", "{url}");
            assert!(
                GitCommandBuilder::validate_clone_destination(None, url).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn test_validate_clone_destination_cuts_a_long_component_in_the_message() {
        let long = format!("/srv/.{}", "a".repeat(300));
        let err = GitCommandBuilder::validate_clone_destination(Some(&long), "https://h/r.git")
            .unwrap_err();
        let shown = format!("('.{}... (cut)')", "a".repeat(119));
        assert!(err.to_string().contains(&shown), "{err}");
    }
}
