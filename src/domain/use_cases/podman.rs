//! Podman Command Builder
//!
//! Builds Podman CLI commands. Mirrors Docker builder but uses podman binary.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// What follows a compose flag.
#[derive(Clone, Copy)]
enum ComposeValue {
    /// The flag takes no value.
    Switch,
    /// A count: ASCII digits only.
    Number,
    /// A line count: digits, or `all`.
    Tail,
    /// A signal name or number: ASCII letters and digits only.
    Signal,
    /// One of a fixed set of words.
    OneOf(&'static [&'static str]),
    /// A point in time or a span: digits and a unit (`10m`), an RFC 3339
    /// timestamp or a date. See [`compose_time_ok`].
    Time,
}

/// The flags a compose subcommand accepts after its name, with their values.
///
/// Anything absent is refused: `-o`/`--output` (writes a file), `-f`/`--file`,
/// `--env-file`, `--project-directory`, `-p` (they read or choose a path) and
/// `logs -f` (never ends). `logs --since`/`--until` take a plain time value
/// only. `rm` takes `--force` only, never the short `-f`.
fn compose_flags(sub: &str) -> &'static [(&'static str, ComposeValue)] {
    use ComposeValue::{Number, OneOf, Signal, Switch, Tail, Time};
    match sub {
        "up" => &[
            ("-d", Switch),
            ("--detach", Switch),
            ("--build", Switch),
            ("--no-build", Switch),
            ("--force-recreate", Switch),
            ("--no-recreate", Switch),
            ("--no-deps", Switch),
            ("--remove-orphans", Switch),
            ("--wait", Switch),
            ("--wait-timeout", Number),
        ],
        "down" => &[
            ("-v", Switch),
            ("--volumes", Switch),
            ("--remove-orphans", Switch),
            ("--rmi", OneOf(&["all", "local"])),
            ("-t", Number),
            ("--timeout", Number),
        ],
        "stop" | "restart" => &[("-t", Number), ("--timeout", Number)],
        "ps" => &[
            ("-a", Switch),
            ("--all", Switch),
            ("-q", Switch),
            ("--quiet", Switch),
            ("--services", Switch),
            ("--format", OneOf(&["json", "table"])),
        ],
        "logs" => &[
            ("--tail", Tail),
            ("--since", Time),
            ("--until", Time),
            ("-t", Switch),
            ("--timestamps", Switch),
            ("--no-color", Switch),
            ("--no-log-prefix", Switch),
        ],
        "pull" => &[
            ("-q", Switch),
            ("--quiet", Switch),
            ("--ignore-pull-failures", Switch),
        ],
        "push" => &[
            ("-q", Switch),
            ("--quiet", Switch),
            ("--ignore-push-failures", Switch),
        ],
        "build" => &[
            ("--no-cache", Switch),
            ("--pull", Switch),
            ("-q", Switch),
            ("--quiet", Switch),
        ],
        "config" => &[
            ("-q", Switch),
            ("--quiet", Switch),
            ("--services", Switch),
            ("--volumes", Switch),
            ("--images", Switch),
        ],
        "images" => &[("-q", Switch), ("--quiet", Switch)],
        "ls" => &[
            ("-q", Switch),
            ("--quiet", Switch),
            ("-a", Switch),
            ("--all", Switch),
        ],
        "create" => &[
            ("--build", Switch),
            ("--no-build", Switch),
            ("--force-recreate", Switch),
            ("--no-recreate", Switch),
        ],
        "kill" => &[
            ("-s", Signal),
            ("--signal", Signal),
            ("--remove-orphans", Switch),
        ],
        "rm" => &[
            ("--force", Switch),
            ("-s", Switch),
            ("--stop", Switch),
            ("-v", Switch),
            ("--volumes", Switch),
        ],
        "port" => &[("--protocol", OneOf(&["tcp", "udp"])), ("--index", Number)],
        "version" => &[("--short", Switch)],
        _ => &[],
    }
}

/// Whether `value` is acceptable for a flag taking `kind`.
fn compose_value_ok(kind: ComposeValue, value: &str) -> bool {
    match kind {
        ComposeValue::Switch => true,
        ComposeValue::Number => {
            !value.is_empty() && value.len() <= 9 && value.bytes().all(|b| b.is_ascii_digit())
        }
        ComposeValue::Tail => value == "all" || compose_value_ok(ComposeValue::Number, value),
        ComposeValue::Signal => {
            !value.is_empty()
                && value.len() <= 12
                && value.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        ComposeValue::OneOf(set) => set.contains(&value),
        ComposeValue::Time => compose_time_ok(value),
    }
}

/// Whether `value` is a plain time for `logs --since`/`--until`.
///
/// At most 32 bytes, starting with an ASCII digit (so never an option), then
/// either digits followed by one unit letter `s`, `m`, `h` or `d` (`10m`), or
/// only digits and `T`, `Z`, `:`, `-`, `.`, `+` (a date, an RFC 3339
/// timestamp, a Unix time).
fn compose_time_ok(value: &str) -> bool {
    if value.len() > 32 || !matches!(value.as_bytes().first(), Some(b'0'..=b'9')) {
        return false;
    }
    let span = value
        .strip_suffix(['s', 'm', 'h', 'd'])
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let stamp = value
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'T' | b'Z' | b':' | b'-' | b'.' | b'+'));
    span || stamp
}

/// Whether `word` can be a compose service name: `[A-Za-z0-9._-]`, not
/// starting with `-` (an option) and not empty.
fn compose_is_service_name(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Builds Podman CLI commands for remote execution.
pub struct PodmanCommandBuilder;

impl PodmanCommandBuilder {
    /// Build a `podman ps` command.
    #[must_use]
    pub fn build_ps_command(all: bool, filter: Option<&str>, format: Option<&str>) -> String {
        let mut cmd = String::from("podman ps");
        if all {
            cmd.push_str(" -a");
        }
        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }
        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }
        cmd
    }

    /// Build a `podman logs` command.
    #[must_use]
    pub fn build_logs_command(
        container: &str,
        tail: Option<u64>,
        since: Option<&str>,
        follow: bool,
    ) -> String {
        let mut cmd = String::from("podman logs");
        if let Some(t) = tail {
            let _ = write!(cmd, " --tail {t}");
        }
        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }
        if follow {
            cmd.push_str(" -f");
        }
        let _ = write!(cmd, " {}", shell_escape(container));
        cmd
    }

    /// Build a `podman inspect` command.
    #[must_use]
    pub fn build_inspect_command(target: &str) -> String {
        format!("podman inspect {}", shell_escape(target))
    }

    /// Build a `podman exec` command.
    #[must_use]
    pub fn build_exec_command(container: &str, command: &str, interactive: bool) -> String {
        let mut cmd = String::from("podman exec");
        if interactive {
            cmd.push_str(" -it");
        }
        let _ = write!(
            cmd,
            " {} sh -c {}",
            shell_escape(container),
            shell_escape(command)
        );
        cmd
    }

    /// Build a `podman images` command.
    #[must_use]
    pub fn build_images_command(filter: Option<&str>) -> String {
        let mut cmd = String::from("podman images");
        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }
        cmd
    }

    /// Validate a compose action: an allowed subcommand, then only the flags
    /// that subcommand is allowed and service names.
    ///
    /// The action is a subcommand followed by its flags and services
    /// (`up -d web`), split on whitespace and never unquoted, so a quote or a
    /// backslash is refused. After the subcommand only a short allowlist of
    /// flags per subcommand may follow, with their values checked: the
    /// compose provider honours options that write or read a file the caller
    /// chooses (`config -o FILE`, `--env-file`, `--project-directory`), and
    /// `logs -f` never ends. Every other word must be a service name made of
    /// `[A-Za-z0-9._-]` that does not start with `-`. `exec`, `run` and `cp`
    /// are not allowed: they run arbitrary commands.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `action` contains a quote or
    /// a backslash, if its first word is not an allowed subcommand, or if a
    /// later word is a flag the subcommand does not allow, a flag with a bad
    /// value, or not a service name.
    pub fn validate_compose_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &[
            "up", "down", "start", "stop", "restart", "ps", "logs", "pull", "push", "build",
            "config", "images", "top", "pause", "unpause", "create", "kill", "rm", "port",
            "version", "ls",
        ];
        if action.contains(['\'', '"', '\\']) {
            return Err(BridgeError::CommandDenied {
                reason: "Compose action must not contain a quote or a backslash: its words are \
                         split on whitespace and are not unquoted"
                    .to_string(),
            });
        }
        let mut words = action.split_whitespace();
        let sub = match words.next() {
            Some(sub) if ALLOWED.contains(&sub) => sub,
            _ => {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Compose action '{action}' is not allowed. The first word must be one \
                         of: {}",
                        ALLOWED.join(", ")
                    ),
                });
            }
        };
        let flags = compose_flags(sub);
        while let Some(word) = words.next() {
            if word.starts_with('-') {
                let Some((_, kind)) = flags.iter().find(|(name, _)| *name == word) else {
                    return Err(BridgeError::CommandDenied {
                        reason: format!(
                            "Compose action: flag '{word}' is not allowed for '{sub}'. \
                             Allowed flags: {}",
                            if flags.is_empty() {
                                "none".to_string()
                            } else {
                                flags
                                    .iter()
                                    .map(|(name, _)| *name)
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            }
                        ),
                    });
                };
                if !matches!(kind, ComposeValue::Switch) {
                    match words.next() {
                        Some(value) if compose_value_ok(*kind, value) => {}
                        _ => {
                            return Err(BridgeError::CommandDenied {
                                reason: format!(
                                    "Compose action: flag '{word}' needs a plain value \
                                     (digits, a name, a time such as 10m or 2026-11-05T10:00:00Z, or one of a \
                                     fixed set)"
                                ),
                            });
                        }
                    }
                }
            } else if !compose_is_service_name(word) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Compose action: '{word}' is not a service name (letters, digits, \
                         '.', '_' and '-' only)"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validate the `file` argument of a compose command: a path on the
    /// target host, never a remote resource.
    ///
    /// The compose provider behind `podman compose` (`docker-compose` or
    /// `podman-compose`) reads URLs, Git and OCI references and `host:path`
    /// forms in place of a file. See [`validate_compose_path`] for the rule.
    ///
    /// [`validate_compose_path`]: super::docker::DockerCommandBuilder::validate_compose_path
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] naming `file` when it is not a
    /// local path.
    pub fn validate_compose_file(file: &str) -> Result<()> {
        super::docker::DockerCommandBuilder::validate_compose_path("file", file)
    }

    /// Build a `podman-compose` or `podman compose` command.
    ///
    /// The command starts with the compose remote-loader switches
    /// (`COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false`,
    /// shell prefix assignments for the one command): `podman compose` hands
    /// its environment to the compose provider, and a provider that is Docker
    /// Compose would otherwise load a Git or OCI resource named by an
    /// `include:` in a compose file already on the host, with the host's own
    /// credential sources. See `COMPOSE_REMOTE_OFF` in the docker module.
    ///
    /// Every word of `action` is quoted on its own, so `up -d` keeps working
    /// and `ps; id` stays one inert word. Quoting does not stop a word from
    /// being read as an option: run `validate_compose_action` first, and
    /// `validate_compose_file` on `file`.
    #[must_use]
    pub fn build_compose_command(action: &str, file: Option<&str>) -> String {
        let mut cmd = format!("{}podman compose", super::docker::COMPOSE_REMOTE_OFF);
        if let Some(f) = file {
            let _ = write!(cmd, " -f {}", shell_escape(f));
        }
        for word in action.split_whitespace() {
            let _ = write!(cmd, " {}", shell_escape(word));
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_default() {
        let cmd = PodmanCommandBuilder::build_ps_command(false, None, None);
        assert_eq!(cmd, "podman ps");
    }

    #[test]
    fn test_ps_all_with_filter() {
        let cmd = PodmanCommandBuilder::build_ps_command(true, Some("status=running"), None);
        assert!(cmd.contains("-a"));
        assert!(cmd.contains("--filter"));
    }

    #[test]
    fn test_logs() {
        let cmd = PodmanCommandBuilder::build_logs_command("myapp", Some(100), None, false);
        assert!(cmd.contains("podman logs"));
        assert!(cmd.contains("--tail 100"));
        assert!(cmd.contains("myapp"));
    }

    #[test]
    fn test_inspect() {
        let cmd = PodmanCommandBuilder::build_inspect_command("mycontainer");
        assert!(cmd.contains("podman inspect"));
    }

    #[test]
    fn test_exec() {
        let cmd = PodmanCommandBuilder::build_exec_command("myapp", "bash", true);
        assert!(cmd.contains("-it"));
        assert!(cmd.contains("bash"));
    }

    #[test]
    fn test_images() {
        let cmd = PodmanCommandBuilder::build_images_command(None);
        assert_eq!(cmd, "podman images");
    }

    #[test]
    fn test_compose() {
        let cmd =
            PodmanCommandBuilder::build_compose_command("up -d", Some("docker-compose.prod.yml"));
        assert!(cmd.contains("podman compose"));
        assert!(cmd.contains("-f"));
        assert!(cmd.contains("'up' '-d'"));
        assert_eq!(
            cmd,
            "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
             podman compose -f 'docker-compose.prod.yml' 'up' '-d'"
        );
    }

    #[test]
    fn test_exec_command_is_one_quoted_word_for_sh_c() {
        let cmd = PodmanCommandBuilder::build_exec_command("c", "true; id; #", false);
        assert_eq!(cmd, "podman exec 'c' sh -c 'true; id; #'");
    }

    #[test]
    fn test_compose_action_words_are_quoted() {
        let cmd = PodmanCommandBuilder::build_compose_command("ps; id", None);
        assert_eq!(
            cmd,
            "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
             podman compose 'ps;' 'id'"
        );
        let cmd = PodmanCommandBuilder::build_compose_command("up -d", None);
        assert_eq!(
            cmd,
            "COMPOSE_EXPERIMENTAL_GIT_REMOTE=false COMPOSE_EXPERIMENTAL_OCI_REMOTE=false \
             podman compose 'up' '-d'"
        );
    }

    #[test]
    fn test_validate_compose_action_allows_subcommands_only() {
        for ok in ["up -d", "down", "ps", "logs --tail 5"] {
            assert!(
                PodmanCommandBuilder::validate_compose_action(ok).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "",
            "ps; id",
            "exec web sh",
            "run web sh",
            "-f x up",
            "$(id)",
        ] {
            assert!(
                PodmanCommandBuilder::validate_compose_action(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_validate_compose_action_allows_listed_flags_and_services() {
        for ok in [
            "up -d --build --force-recreate --no-deps --remove-orphans web db",
            "up --detach",
            "down -v --remove-orphans",
            "down --rmi local -t 10",
            "stop -t 5 web",
            "restart web",
            "ps -a -q",
            "ps --format json",
            "logs --tail 100 --no-color web",
            "logs --tail all -t app_1.x",
            "logs --since 10m web",
            "logs --since 2h --until 30m",
            "logs --since 2026-11-05T10:00:00Z --until 2026-11-05T11:00:00Z",
            "logs --since 2026-11-05 web",
            "logs --since 2026-11-05T10:00:00+02:00",
            "up -d --wait",
            "up --wait --wait-timeout 60 web",
            "pull -q",
            "build --no-cache web",
            "config --services",
            "images -q",
            "kill -s SIGKILL web",
            "kill --signal 9",
            "rm --force -s -v web",
            "port --protocol udp web 53",
            "version --short",
            "ls -a",
            "top web",
        ] {
            assert!(
                PodmanCommandBuilder::validate_compose_action(ok).is_ok(),
                "{ok}"
            );
        }
    }

    #[test]
    fn test_validate_compose_action_refuses_flags_outside_the_allowlist() {
        for bad in [
            "config -o /home/deploy/.ssh/authorized_keys",
            "config --output /home/deploy/.ssh/authorized_keys",
            "config --output=/x",
            "config -o",
            "up -f other.yaml",
            "up --file other.yaml",
            "up --env-file /etc/shadow",
            "ps --project-directory /",
            "ps -p other",
            "up --project-name x",
            "config --lock-image-digests",
            "logs -f",
            "logs --follow",
            "logs --tail=5",
            "logs --since=10m",
            "logs -n 5",
            "start --wait",
            "rm -f web",
            "rm -fv web",
            "version -f json",
            "up -- web",
            "up -d -",
            "top -d",
        ] {
            let err = PodmanCommandBuilder::validate_compose_action(bad).unwrap_err();
            assert!(err.to_string().contains("Compose action"), "{bad}: {err}");
        }
    }

    #[test]
    fn test_validate_compose_action_checks_flag_values_and_service_names() {
        for bad in [
            "logs --tail",
            "logs --tail -f",
            "logs --tail 5x",
            "logs --tail 99999999999",
            "logs --since",
            "logs --since -1h",
            "logs --since --until",
            "logs --since -f",
            "logs --since 10x",
            "logs --since m",
            "logs --since 1h30m;id",
            "logs --since $(id)",
            "logs --until web;id",
            "logs --since 2026-11-05T10:00:00Z2026-11-05T10:00:00Z2026",
            "up --wait-timeout",
            "up --wait-timeout 1m",
            "up --wait-timeout -1",
            "down -t -1",
            "down --rmi everything",
            "ps --format {{.Name}}",
            "kill -s -9",
            "kill -s KILL;id",
            "port --protocol icmp web",
            "up web;id",
            "up $(id)",
            "up -d /etc/passwd",
            "up ../x",
            "up web&",
        ] {
            assert!(
                PodmanCommandBuilder::validate_compose_action(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_validate_compose_action_refuses_quotes_and_backslashes() {
        for bad in [
            "logs 'web'",
            "logs \"web\"",
            "ps --format '{{.Name}} {{.Status}}'",
            "up web\\ db",
        ] {
            let err = PodmanCommandBuilder::validate_compose_action(bad).unwrap_err();
            assert!(err.to_string().contains("quote"), "{bad}: {err}");
        }
    }

    #[test]
    fn test_validate_compose_file_accepts_local_paths_only() {
        for ok in [
            "compose.yaml",
            "/srv/app/compose.yml",
            "./a/b.yml",
            "../b.yml",
        ] {
            assert!(
                PodmanCommandBuilder::validate_compose_file(ok).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "https://example.com/org/repo.git",
            "git@example.com:org/repo.git",
            "oci://registry.example.com/stack",
            "example.com:compose.yml",
            "github.com/org/repo",
            "-",
            "",
            "a b.yml",
        ] {
            let err = PodmanCommandBuilder::validate_compose_file(bad).unwrap_err();
            assert!(matches!(err, BridgeError::CommandDenied { .. }), "{bad:?}");
            assert!(err.to_string().contains("'file'"), "{bad:?}: {err}");
        }
    }
}
