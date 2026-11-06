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
            format!("git -C {escaped_path} status --short")
        } else {
            format!("git -C {escaped_path} status")
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
        let mut cmd = format!("git -C {escaped_path} log");

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
        let mut cmd = format!("git -C {escaped_path} diff");

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
    /// git runs with `-c http.extraHeader=`. The remote and the branch come
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
        let mut cmd =
            format!("{GIT_SSL_CLIENT_CERT_UNSET}git -C {escaped_path} {GIT_NO_EXTRA_HEADER} pull");

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
        let mut cmd = format!("{GIT_SSL_CLIENT_CERT_UNSET}git {GIT_NO_EXTRA_HEADER} clone");

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
                format!("git -C {escaped_path} branch {branch_name}")
            }
            "delete" => {
                let branch_name = shell_escape(name.unwrap_or(""));
                format!("git -C {escaped_path} branch -d {branch_name}")
            }
            // "list" and any other action default to branch listing
            _ => {
                if remote {
                    format!("git -C {escaped_path} branch -r")
                } else {
                    format!("git -C {escaped_path} branch")
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
            format!("git -C {escaped_path} checkout -b {escaped_target}")
        } else {
            format!("git -C {escaped_path} checkout {escaped_target}")
        }
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
        assert_eq!(cmd, "git -C '/opt/repo' status");
    }

    #[test]
    fn test_status_short() {
        let cmd = GitCommandBuilder::build_status_command("/opt/repo", true);
        assert_eq!(cmd, "git -C '/opt/repo' status --short");
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
        assert_eq!(cmd, "git -C '/opt/repo' log");
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
        assert_eq!(cmd, "git -C '/opt/repo' log --max-count=10");
    }

    #[test]
    fn test_log_oneline() {
        let cmd =
            GitCommandBuilder::build_log_command("/opt/repo", None, true, None, None, None, None);
        assert_eq!(cmd, "git -C '/opt/repo' log --oneline");
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
        assert_eq!(cmd, "git -C '/opt/repo' log 'main'");
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
        assert!(cmd.contains("git -C '/opt/repo' log"));
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
        assert_eq!(cmd, "git -C '/opt/repo' diff");
    }

    #[test]
    fn test_diff_staged() {
        let cmd = GitCommandBuilder::build_diff_command("/opt/repo", true, None, None);
        assert_eq!(cmd, "git -C '/opt/repo' diff --staged");
    }

    #[test]
    fn test_diff_file() {
        let cmd =
            GitCommandBuilder::build_diff_command("/opt/repo", false, Some("src/main.rs"), None);
        assert_eq!(cmd, "git -C '/opt/repo' diff -- 'src/main.rs'");
    }

    #[test]
    fn test_diff_commit() {
        let cmd = GitCommandBuilder::build_diff_command("/opt/repo", false, None, Some("HEAD~3"));
        assert_eq!(cmd, "git -C '/opt/repo' diff 'HEAD~3'");
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
             git -C '/opt/repo' -c http.extraHeader= pull"
        );
    }

    #[test]
    fn test_pull_rebase() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, true, false);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c http.extraHeader= pull --rebase"
        );
    }

    #[test]
    fn test_pull_ff_only() {
        let cmd = GitCommandBuilder::build_pull_command("/opt/repo", None, None, false, true);
        assert_eq!(
            cmd,
            "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
             git -C '/opt/repo' -c http.extraHeader= pull --ff-only"
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
             git -C '/opt/repo' -c http.extraHeader= pull -- 'origin' 'main'"
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
             git -C '/opt/repo' -c http.extraHeader= pull --rebase --ff-only \
             -- 'upstream' 'develop'"
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
             git -C '/opt/repo' -c http.extraHeader= pull -- 'origin'"
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
             git -C '/opt/repo' -c http.extraHeader= pull --rebase"
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
             git -c http.extraHeader= clone -- 'https://github.com/user/repo.git'"
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
             git -c http.extraHeader= clone --branch 'main' --depth 5 --single-branch \
             -- 'https://github.com/user/repo.git' '/opt/dest'"
        );
    }

    #[test]
    fn test_clone_clears_the_unscoped_extra_header_before_the_subcommand() {
        let cmd = GitCommandBuilder::build_clone_command("ssh://x/y", None, None, None, false);
        assert!(
            cmd.starts_with(
                "unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED && \
                 git -c http.extraHeader= clone "
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
    fn test_git_commands_that_contact_no_server_are_unchanged() {
        // Only the commands that connect to a server chosen by the caller get
        // the prefix.
        assert_eq!(
            GitCommandBuilder::build_status_command("/srv/x", false),
            "git -C '/srv/x' status"
        );
        assert_eq!(
            GitCommandBuilder::build_log_command("/srv/x", None, false, None, None, None, None),
            "git -C '/srv/x' log"
        );
        assert_eq!(
            GitCommandBuilder::build_diff_command("/srv/x", false, None, None),
            "git -C '/srv/x' diff"
        );
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
        assert_eq!(cmd, "git -C '/opt/repo' branch");
    }

    #[test]
    fn test_branch_list_remote() {
        let cmd = GitCommandBuilder::build_branch_command("/opt/repo", "list", None, true);
        assert_eq!(cmd, "git -C '/opt/repo' branch -r");
    }

    #[test]
    fn test_branch_create() {
        let cmd = GitCommandBuilder::build_branch_command(
            "/opt/repo",
            "create",
            Some("feature-x"),
            false,
        );
        assert_eq!(cmd, "git -C '/opt/repo' branch 'feature-x'");
    }

    #[test]
    fn test_branch_create_default_name() {
        let cmd = GitCommandBuilder::build_branch_command("/opt/repo", "create", None, false);
        assert_eq!(cmd, "git -C '/opt/repo' branch 'new-branch'");
    }

    #[test]
    fn test_branch_delete() {
        let cmd = GitCommandBuilder::build_branch_command(
            "/opt/repo",
            "delete",
            Some("old-branch"),
            false,
        );
        assert_eq!(cmd, "git -C '/opt/repo' branch -d 'old-branch'");
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
        assert_eq!(cmd, "git -C '/opt/repo' checkout 'main'");
    }

    #[test]
    fn test_checkout_create() {
        let cmd = GitCommandBuilder::build_checkout_command("/opt/repo", "new-feature", true);
        assert_eq!(cmd, "git -C '/opt/repo' checkout -b 'new-feature'");
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
             git -c http.extraHeader= clone -- 'ssh://x/y' '--config=core.sshCommand=touch /tmp/p'"
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
}
