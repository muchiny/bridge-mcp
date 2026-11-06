//! Ansible Command Builder
//!
//! Builds `ansible-playbook`, `ansible-inventory`, and `ansible` (ad-hoc)
//! CLI commands for remote execution via SSH.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Write verbose flags (`-v`, `-vv`, `-vvv`, `-vvvv`) capped at 4.
fn write_verbose_flags(cmd: &mut String, level: u8) {
    let capped = level.min(4);
    if capped > 0 {
        cmd.push_str(" -");
        for _ in 0..capped {
            cmd.push('v');
        }
    }
}

/// Environment assignment put in front of the Ansible program of every
/// command that names an inventory.
///
/// `INVENTORY_ENABLED` defaults to `host_list,script,auto,yaml,ini,toml`, and
/// the `script` plugin runs any `-i` source the user can execute (every file
/// of a directory source is tried). With this value the caller's source is
/// parsed as data (a comma-separated host list, YAML, INI or TOML), never run.
/// Without an inventory argument the command is left alone and the operator's
/// configured inventory applies.
const INVENTORY_ENV: &str = "ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml";

/// The inventory assignment to put before the program, with its trailing
/// space, or nothing when the caller named no inventory.
fn inventory_env(inventory: Option<&str>) -> String {
    inventory.map_or_else(String::new, |_| format!("{INVENTORY_ENV} "))
}

/// Vault sources for which Ansible asks the terminal instead of reading a
/// file.
const VAULT_PROMPT_SOURCES: &[&str] = &["prompt", "prompt_ask_vault_pass"];

/// The file a `--vault-id` value reads its password from, or `None` for a
/// prompt. `CLI.split_vault_id` splits on the first `@`; a value without one
/// is the source itself.
fn vault_id_source(vault_id: &str) -> Option<&str> {
    let source = vault_id.split_once('@').map_or(vault_id, |(_, s)| s);
    (!VAULT_PROMPT_SOURCES.contains(&source)).then_some(source)
}

/// The caller-given vault password file sources, in command-line order and
/// without duplicates.
fn vault_sources<'a>(
    vault_password_file: Option<&'a str>,
    vault_id: Option<&'a str>,
) -> Vec<&'a str> {
    let mut sources: Vec<&str> = Vec::new();
    for source in vault_password_file
        .into_iter()
        .chain(vault_id.and_then(vault_id_source))
    {
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    sources
}

/// One word for the shell naming `source`: quoted once, with a leading `~/`
/// left to the shell as `"$HOME"/` (Ansible expands it, a quoted `~` would
/// not be).
fn vault_path_word(source: &str) -> String {
    match source.strip_prefix("~/") {
        Some(rest) => format!("\"$HOME\"/{}", shell_escape(rest)),
        None => shell_escape(source),
    }
}

/// A POSIX `if` that stops the shell with status 2 and a message on stderr
/// unless `source` is a regular file (symlinks followed) with no execute bit
/// for anyone. Ansible runs a vault password file when any execute bit is set.
/// The file passes only when `find` names it, so a missing or failing `find`
/// refuses it too.
fn vault_source_guard(source: &str) -> String {
    let tested = vault_path_word(source);
    // `find` reads a first operand starting with `!`, `(`, `)` or `,` as part
    // of its expression; `./` keeps it a path.
    let found = if source.starts_with(['!', '(', ')', ',']) {
        format!("./{tested}")
    } else {
        tested.clone()
    };
    let message = shell_escape(&format!(
        "bridge-mcp: vault password file {source} must be a plain file without execute \
         permission (Ansible runs an executable one); configure vault scripts in \
         ansible.cfg instead"
    ));
    format!(
        r#"if [ -f {tested} ] && [ -n "$(find -L {found} -prune ! -perm -100 ! -perm -010 ! -perm -001 -print 2>/dev/null)" ]; then :; else echo {message} >&2; exit 2; fi"#
    )
}

/// The `key=` words that `parse_kv` keeps as options of a command module
/// (`chdir`, `executable`, `stdin`) and not as part of its command line.
const COMMAND_MODULE_OPTIONS: &[&str] = &["executable=", "chdir=", "stdin="];

/// The first escape in `args` that `ansible.parsing.splitter` decodes by
/// number or name: a backslash followed by `U` and 8 hexadecimal digits, `u`
/// and 4, `x` and 2, or `N{`. Any backslash starts a candidate, paired or not.
fn decoded_escape(args: &str) -> Option<&'static str> {
    let mut rest = args;
    while let Some((_, after)) = rest.split_once('\\') {
        let mut chars = after.chars();
        let found = match chars.next() {
            Some('N') => (chars.next() == Some('{')).then_some("\\N{"),
            Some('U') => hex_escape(chars, 8, "\\U"),
            Some('u') => hex_escape(chars, 4, "\\u"),
            Some('x') => hex_escape(chars, 2, "\\x"),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
        rest = after;
    }
    None
}

/// `name` when `digits` starts with `count` hexadecimal digits.
fn hex_escape(
    digits: std::str::Chars<'_>,
    count: usize,
    name: &'static str,
) -> Option<&'static str> {
    (digits.take(count).filter(char::is_ascii_hexdigit).count() == count).then_some(name)
}

/// Allowed Ansible stdout callback plugins (whitelist for injection prevention).
const ALLOWED_CALLBACKS: &[&str] = &[
    "json", "yaml", "dense", "minimal", "tree", "default", "oneline", "debug", "null",
];

/// Builds Ansible CLI commands for remote execution.
pub struct AnsibleCommandBuilder;

impl AnsibleCommandBuilder {
    /// Build an `ansible-playbook` command.
    ///
    /// Constructs a shell command string like:
    /// `[cd -- {working_dir} && ][{vault guards} && ]
    /// [ANSIBLE_STDOUT_CALLBACK={callback} ][ANSIBLE_INVENTORY_ENABLED=... ]
    /// ansible-playbook {playbook} [-i {inventory}]
    /// [--limit {limit}] [--tags {tags}] [--skip-tags {skip}]
    /// [-e key=value ...] [--check] [--diff] [-v..vvvv] [-f {forks}]
    /// [-b] [--become-user {user}]`
    ///
    /// With an `inventory`, `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`
    /// goes in front of the program: the `script` inventory plugin is off, so
    /// the source is parsed as data and never run. For each caller-given vault
    /// password file (`vault_password_file`, or the source of a `vault_id`
    /// other than a prompt) a shell guard runs first, in the directory
    /// `ansible-playbook` resolves the path from (see
    /// [`Self::vault_guards`]).
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_playbook_command(
        playbook: &str,
        inventory: Option<&str>,
        limit: Option<&str>,
        tags: Option<&str>,
        skip_tags: Option<&str>,
        extra_vars: Option<&HashMap<String, String>>,
        check: bool,
        diff: bool,
        verbose: Option<u8>,
        forks: Option<u32>,
        use_become: bool,
        become_user: Option<&str>,
        working_dir: Option<&str>,
        callback: Option<&str>,
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        if let Some(dir) = working_dir {
            let _ = write!(cmd, "cd -- {} && ", shell_escape(dir));
        }

        // After the `cd`, in the directory Ansible resolves the paths from, and
        // before Ansible starts. Each guard is a compound command whose status
        // is 0 when it lets the run go on, so the `&&` chain holds.
        for guard in Self::vault_guards(vault_password_file, vault_id) {
            let _ = write!(cmd, "{guard} && ");
        }

        // After the `cd`: a `VAR=value` prefix applies to the one command that
        // follows it, and that must be `ansible-playbook`, not `cd`.
        if let Some(cb) = callback {
            let _ = write!(cmd, "ANSIBLE_STDOUT_CALLBACK={} ", shell_escape(cb));
        }
        cmd.push_str(&inventory_env(inventory));

        let _ = write!(cmd, "ansible-playbook {}", shell_escape(playbook));

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if let Some(lim) = limit {
            let _ = write!(cmd, " --limit {}", shell_escape(lim));
        }

        if let Some(t) = tags {
            let _ = write!(cmd, " --tags {}", shell_escape(t));
        }

        if let Some(st) = skip_tags {
            let _ = write!(cmd, " --skip-tags {}", shell_escape(st));
        }

        // One JSON document: `ansible-playbook -e key=value` would re-split the
        // value on whitespace and re-read a leading `{`, `[` or `@`.
        if let Some(vars) = extra_vars
            && !vars.is_empty()
        {
            let sorted: BTreeMap<&str, &str> =
                vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            if let Ok(json) = serde_json::to_string(&sorted) {
                let _ = write!(cmd, " -e {}", shell_escape(&json));
            }
        }

        if check {
            cmd.push_str(" --check");
        }

        if diff {
            cmd.push_str(" --diff");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(user) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(user));
        }

        if let Some(vpf) = vault_password_file {
            let _ = write!(cmd, " --vault-password-file {}", shell_escape(vpf));
        }

        if let Some(vid) = vault_id {
            let _ = write!(cmd, " --vault-id {}", shell_escape(vid));
        }

        cmd
    }

    /// Build an `ansible-inventory` command.
    ///
    /// Constructs a shell command string like:
    /// `[ANSIBLE_INVENTORY_ENABLED=... ]ansible-inventory [-i {inventory}]
    /// [--list] [--graph [{group}]] [--host {host}] [--yaml] [--vars]`
    ///
    /// If none of `list`, `graph`, or `host_pattern` is set, defaults to `--list`.
    /// With an `inventory`, `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`
    /// goes in front of the program, so the source is parsed as data and never
    /// run (the `script` plugin is off).
    #[must_use]
    #[expect(clippy::fn_params_excessive_bools)]
    pub fn build_inventory_command(
        inventory: Option<&str>,
        list: bool,
        graph: bool,
        host_pattern: Option<&str>,
        group: Option<&str>,
        yaml: bool,
        vars: bool,
    ) -> String {
        let mut cmd = inventory_env(inventory);
        cmd.push_str("ansible-inventory");

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        let has_action = list || graph || host_pattern.is_some();

        if list {
            cmd.push_str(" --list");
        }

        if graph {
            if let Some(g) = group {
                let _ = write!(cmd, " --graph {}", shell_escape(g));
            } else {
                cmd.push_str(" --graph");
            }
        }

        if let Some(host) = host_pattern {
            let _ = write!(cmd, " --host {}", shell_escape(host));
        }

        if !has_action {
            cmd.push_str(" --list");
        }

        if yaml {
            cmd.push_str(" --yaml");
        }

        if vars {
            cmd.push_str(" --vars");
        }

        cmd
    }

    /// Build an `ansible` ad-hoc command.
    ///
    /// Constructs a shell command string like:
    /// `[{vault guards} && ][ANSIBLE_INVENTORY_ENABLED=... ]ansible {pattern}
    /// -m {module} [-a {args}] [-i {inventory}] [-b] [--become-user {user}]
    /// [-u {user}] [-f {forks}] [-v..vvvv] [-C]`
    ///
    /// With an `inventory`, `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`
    /// goes in front of the program, so the source is parsed as data and never
    /// run. For each caller-given vault password file a shell guard runs first
    /// (see [`Self::vault_guards`]).
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_adhoc_command(
        pattern: &str,
        module: &str,
        args: Option<&str>,
        inventory: Option<&str>,
        use_become: bool,
        become_user: Option<&str>,
        user: Option<&str>,
        forks: Option<u32>,
        verbose: Option<u8>,
        check: bool,
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        for guard in Self::vault_guards(vault_password_file, vault_id) {
            let _ = write!(cmd, "{guard} && ");
        }
        cmd.push_str(&inventory_env(inventory));

        let _ = write!(
            cmd,
            "ansible {} -m {}",
            shell_escape(pattern),
            shell_escape(module)
        );

        if let Some(a) = args {
            let _ = write!(cmd, " -a {}", shell_escape(a));
        }

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(bu) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(bu));
        }

        if let Some(u) = user {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if check {
            cmd.push_str(" -C");
        }

        if let Some(vpf) = vault_password_file {
            let _ = write!(cmd, " --vault-password-file {}", shell_escape(vpf));
        }

        if let Some(vid) = vault_id {
            let _ = write!(cmd, " --vault-id {}", shell_escape(vid));
        }

        cmd
    }

    /// Build an `ansible -m setup` command to gather facts.
    ///
    /// Constructs: `[ANSIBLE_INVENTORY_ENABLED=... ]ansible {pattern} -m setup
    /// [-a "filter={filter}"] [-i {inventory}] [-b] [--become-user {user}]`
    ///
    /// With an `inventory`, `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`
    /// goes in front of the program, so the source is parsed as data and never
    /// run.
    #[must_use]
    pub fn build_facts_command(
        pattern: &str,
        filter: Option<&str>,
        inventory: Option<&str>,
        use_become: bool,
        become_user: Option<&str>,
    ) -> String {
        let mut cmd = inventory_env(inventory);

        let _ = write!(cmd, "ansible {} -m setup", shell_escape(pattern));

        if let Some(f) = filter {
            let _ = write!(cmd, " -a {}", shell_escape(&format!("filter={f}")));
        }

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(user) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(user));
        }

        cmd
    }

    /// Build an `ansible-lint` command.
    ///
    /// Constructs: `ansible-lint {target} [--format {format}] [-p]`
    #[must_use]
    pub fn build_lint_command(target: &str, format: Option<&str>, parseable: bool) -> String {
        let mut cmd = String::new();

        let _ = write!(cmd, "ansible-lint {}", shell_escape(target));

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        if parseable {
            cmd.push_str(" -p");
        }

        cmd
    }

    /// Build an `ansible-config dump` command.
    ///
    /// Constructs: `ansible-config dump [--only-changed] [--format {format}]`
    #[must_use]
    pub fn build_config_command(only_changed: bool, format: Option<&str>) -> String {
        let mut cmd = String::from("ansible-config dump");

        if only_changed {
            cmd.push_str(" --only-changed");
        }

        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }

        cmd
    }

    /// The shell guards for the vault password files a command names, one
    /// `if ...; fi` per file, to run in the directory Ansible resolves the
    /// path from and before it starts.
    ///
    /// Ansible RUNS a vault password file when any execute bit is set
    /// (`--vault-password-file`, or the source of `--vault-id LABEL@SOURCE`;
    /// the sources `prompt` and `prompt_ask_vault_pass` ask the terminal and
    /// get no guard), and reads it as text otherwise. Each guard stops the
    /// shell with a message on stderr and exit status 2 unless the source is a
    /// regular file (symlinks followed) with no execute bit for anyone. A
    /// leading `~/` is expanded by the shell, as Ansible does; `~user/` is
    /// not, and is refused as a missing file. A file that is given twice is
    /// guarded once. Each guard is a compound command with status 0 when it
    /// lets the run go on, so it chains with `&&`.
    #[must_use]
    pub fn vault_guards(vault_password_file: Option<&str>, vault_id: Option<&str>) -> Vec<String> {
        vault_sources(vault_password_file, vault_id)
            .into_iter()
            .map(vault_source_guard)
            .collect()
    }

    /// The vault guards ([`Self::vault_guards`]) as a foreground prefix for a
    /// command that is launched in the background, or an empty string without
    /// a vault file.
    ///
    /// The guards run in a subshell, in `working_dir` when there is one (a
    /// `cd` that fails ends the call with the status of `cd`), and the call
    /// ends with the status of the subshell (2 when a file is refused) before
    /// anything is launched, so the caller sees the refusal instead of a
    /// `started` reply.
    #[must_use]
    pub fn vault_precheck(
        working_dir: Option<&str>,
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> String {
        let guards = Self::vault_guards(vault_password_file, vault_id);
        if guards.is_empty() {
            return String::new();
        }
        let mut inner = String::new();
        if let Some(dir) = working_dir {
            let _ = write!(inner, "cd -- {} && ", shell_escape(dir));
        }
        inner.push_str(&guards.join(" && "));
        format!("( {inner} ) || exit $?; ")
    }

    /// Validate the `inventory` of a tool that hands it to `-i`.
    ///
    /// A value starting with `-` would be read as an option. (The inventory
    /// source itself is parsed as data, never run, because the built command
    /// restricts the inventory plugins: see [`Self::build_playbook_command`].)
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `inventory` when the value
    /// starts with `-`.
    pub fn validate_inventory(inventory: &str) -> Result<()> {
        super::shell::refuse_option_like("inventory", inventory)
    }

    /// Validate `vault_password_file` and `vault_id`.
    ///
    /// Each value must not start with `-`, hold a control character or a Jinja
    /// delimiter (`{{`, `{%`, `{#`). The file a `vault_id` reads (the part
    /// after the first `@`, or the whole value without one, unless it is
    /// `prompt` or `prompt_ask_vault_pass`) must not start with `-` either.
    /// Whether the file is executable is checked on the host by the guards of
    /// [`Self::vault_guards`], when the command runs.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming the offending argument.
    pub fn validate_vault_args(
        vault_password_file: Option<&str>,
        vault_id: Option<&str>,
    ) -> Result<()> {
        for (arg, value) in [
            ("vault_password_file", vault_password_file),
            ("vault_id", vault_id),
        ] {
            let Some(value) = value else { continue };
            Self::refuse_jinja(arg, value)?;
            if value.chars().any(char::is_control) {
                return Err(BridgeError::CommandDenied {
                    reason: format!("Invalid '{arg}': control characters are not allowed"),
                });
            }
            super::shell::refuse_option_like(arg, value)?;
        }
        if let Some(source) = vault_id.and_then(vault_id_source) {
            super::shell::refuse_option_like("vault_id", source)?;
        }
        // Ansible expands `$VAR` and `~user` and folds `..` before it looks at
        // the file, while the guard tests the text as the kernel resolves
        // it; refused, so both name the same file.
        for (arg, source) in [
            ("vault_password_file", vault_password_file),
            ("vault_id", vault_id.and_then(vault_id_source)),
        ] {
            let Some(source) = source else { continue };
            let tilde_user = source.starts_with('~') && !source.starts_with("~/");
            if source.contains('$') || tilde_user || source.split('/').any(|c| c == "..") {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Invalid '{arg}': '$', '~user' and '..' are not allowed in a vault \
                         file path"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validate a playbook path.
    ///
    /// Rejects paths with `..` (directory traversal).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path contains `..` or
    /// starts with `-` (the playbook is read as an option).
    pub fn validate_playbook_path(playbook: &str) -> Result<()> {
        super::shell::refuse_option_like("playbook", playbook)?;
        if playbook.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in playbook path".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an Ansible host pattern.
    ///
    /// The pattern is a positional argument of `ansible`, so a leading `-`
    /// would be read as an option. Host patterns never start with `-`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the pattern starts with `-`.
    pub fn validate_pattern(pattern: &str) -> Result<()> {
        super::shell::refuse_option_like("pattern", pattern)
    }

    /// Validate the `filter` of `ansible -m setup`.
    ///
    /// The value is handed to Ansible as `-a filter=<value>`, which Ansible
    /// parses a second time: it splits on whitespace (`* fact_path=/dir` adds
    /// a setup parameter) and templates `{{ ... }}`. A filter is a fact-name
    /// glob, so only `A-Za-z0-9_`, `*`, `?`, `,` (several globs) and `[...]`
    /// character classes are accepted (`!` and `-` too, inside a class).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `filter` for any other
    /// character, for a `!` outside a class, or for an unbalanced bracket.
    pub fn validate_facts_filter(filter: &str) -> Result<()> {
        let mut in_class = false;
        for c in filter.chars() {
            let ok = match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '*' | '?' | ',' => true,
                '[' if !in_class => {
                    in_class = true;
                    true
                }
                ']' if in_class => {
                    in_class = false;
                    true
                }
                '!' | '-' => in_class,
                _ => false,
            };
            if !ok {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Invalid filter: '{c}' is not allowed; a filter is a fact-name glob \
                         made of letters, digits, '_', '*', '?', ',' and [...] classes"
                    ),
                });
            }
        }
        if in_class {
            return Err(BridgeError::CommandDenied {
                reason: "Invalid filter: unclosed '[' in the fact-name glob".to_string(),
            });
        }
        Ok(())
    }

    /// Refuse a Jinja expression (`{{`, `{%`, `{#`) in a value Ansible
    /// templates on the control host (module arguments, host pattern, limit,
    /// tags, inventory, module name). Evaluating one runs code there
    /// (`lookup('pipe', ...)`). This is a scan for the three delimiters in the
    /// raw text, nothing more.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `arg` when `value` holds a
    /// Jinja delimiter.
    pub fn refuse_jinja(arg: &str, value: &str) -> Result<()> {
        if ["{{", "{%", "{#"].iter().any(|t| value.contains(t)) {
            return Err(BridgeError::CommandDenied {
                reason: format!("Invalid '{arg}': Jinja expressions are not allowed"),
            });
        }
        Ok(())
    }

    /// Refuse a Jinja delimiter in each present value of a list of
    /// `(argument name, value)` pairs (host pattern, limit, tags, inventory,
    /// module name, ...): Ansible puts them in the play it runs.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming the first offending
    /// argument.
    pub fn refuse_jinja_in(fields: &[(&str, Option<&str>)]) -> Result<()> {
        for (name, value) in fields {
            if let Some(v) = value {
                Self::refuse_jinja(name, v)?;
            }
        }
        Ok(())
    }

    /// Validate a user name given to `--become-user` or `-u`.
    ///
    /// Ansible's `sudo` and `su` become plugins paste `become_user` into a
    /// command line that `/bin/sh -c` runs, unquoted. Only
    /// `^([A-Za-z0-9][A-Za-z0-9_.-]{0,62}\\)?[A-Za-z_][A-Za-z0-9_.@-]{0,63}\$?$`
    /// is accepted: a name, optionally preceded by a Windows domain and one
    /// backslash (`CORP\svc`) and followed by one `$` (a group managed
    /// service account, `svc$`). No leading `-`, no whitespace, no other shell
    /// or Jinja character.
    ///
    /// Both additions stay inert on the `sudo` command line Ansible builds on
    /// a POSIX target: the shell reads a backslash before a name character as
    /// that character (it can neither quote nor end the word), and a `$`
    /// followed by a space (the next word of the command line) is a literal
    /// `$`, not an expansion.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `arg` when `value` is not
    /// such a user name.
    pub fn validate_user_name(arg: &str, value: &str) -> Result<()> {
        let (domain, name) = value
            .split_once('\\')
            .map_or((None, value), |(d, n)| (Some(d), n));
        let name = name.strip_suffix('$').unwrap_or(name);
        let mut chars = name.chars();
        let valid_name = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().count() <= 64
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'));
        let valid_domain = domain.is_none_or(|d| {
            let mut chars = d.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
                && d.chars().count() <= 63
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        });
        if !(valid_name && valid_domain) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid '{arg}': must match [DOMAIN\\]NAME[$] with NAME \
                     [A-Za-z_][A-Za-z0-9_.@-]{{0,63}} and DOMAIN \
                     [A-Za-z0-9][A-Za-z0-9_.-]{{0,62}}"
                ),
            });
        }
        Ok(())
    }

    /// Validate the `-a` argument string of an ad-hoc command run with
    /// `module`.
    ///
    /// Ansible parses `-a` itself (`parse_kv` in `ansible.parsing.splitter`,
    /// also in AWX), and these are refused because that parse would make the
    /// text something else than what the caller wrote:
    ///
    /// - any Jinja delimiter (`{{`, `{%`, `{#`);
    /// - text that, once trimmed, starts with `{` (the JSON form, which
    ///   decodes `\u007b` into a brace after the Jinja check);
    /// - the escapes Ansible decodes by number or name: a backslash followed
    ///   by `U` and 8 hexadecimal digits, `u` and 4, `x` and 2, or `N{`. The
    ///   backslash is not paired, so `\\x41` is refused too. Other backslash
    ///   sequences (`C:\Users`, `C:\x\y`, `\0` to `\7`) pass;
    /// - the substring `\=`, and any backslash when an Ansible token may start
    ///   with `=` (the text starts with `=`, or holds ` =` or a line feed
    ///   followed by `=`): `parse_kv` hands such a token to a command module
    ///   decoded (with `\n` as a real line feed) as part of its command line.
    ///   A `=` or `==` word without a backslash in the text
    ///   (`[ "$a" = b ]`) decodes to itself and passes;
    /// - for a module that runs a command ([`Self::runs_a_command`]): a word
    ///   starting with `executable=`, `chdir=` or `stdin=`, which `parse_kv`
    ///   keeps as module options and not as part of the command. `creates=`,
    ///   `removes=`, `warn=`, `stdin_add_newline=` and `strip_empty_ends=`
    ///   stay allowed.
    ///
    /// For the `executable=` / `chdir=` / `stdin=` check, words are split at
    /// any whitespace, a superset of the spaces and line feeds Ansible splits
    /// at, so no spacing hides such a word.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `args`.
    pub fn validate_adhoc_args(module: &str, args: &str) -> Result<()> {
        Self::refuse_jinja("args", args)?;
        if args.trim().starts_with('{') {
            return Err(BridgeError::CommandDenied {
                reason: "Invalid 'args': the JSON form (starting with '{') is not allowed; \
                         use key=value"
                    .to_string(),
            });
        }
        if let Some(escape) = decoded_escape(args) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid 'args': the escape '{escape}' is decoded by Ansible and is not \
                     allowed"
                ),
            });
        }
        if args.contains("\\=") {
            return Err(BridgeError::CommandDenied {
                reason: "Invalid 'args': the sequence '\\=' is not allowed".to_string(),
            });
        }
        // An Ansible token starts at the start of the text or after a space
        // or a line feed (a quoted run joins several pieces but still starts
        // there). When one may start with `=`, no backslash may be decoded.
        let a_token_may_open_with_equals =
            args.starts_with('=') || args.contains(" =") || args.contains("\n=");
        if a_token_may_open_with_equals && args.contains('\\') {
            return Err(BridgeError::CommandDenied {
                reason: "Invalid 'args': a backslash is not allowed when a word starts with '='"
                    .to_string(),
            });
        }
        if Self::runs_a_command(module)
            && let Some(option) = args.split(char::is_whitespace).find_map(|word| {
                COMMAND_MODULE_OPTIONS
                    .iter()
                    .find(|option| word.starts_with(*option))
            })
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid 'args': '{option}' changes how Ansible runs a command module and \
                     is not allowed"
                ),
            });
        }
        Ok(())
    }

    /// The text an ad-hoc command is judged by as an `ssh_exec` command
    /// (whitelist and blacklist), or `None` when nothing needs judging.
    ///
    /// - a module that runs a command ([`Self::runs_a_command`]): the `args`
    ///   alone;
    /// - `ping` (bare or collection-qualified) without `args`: `None`;
    /// - any other module: `"ansible-module {module} {args}"`, or
    ///   `"ansible-module {module}"` without `args`, the module spelled as the
    ///   caller gave it. In strict and standard mode such a module must
    ///   therefore be whitelisted explicitly, by a pattern that starts with
    ///   `ansible-module`: `cron`, `pip`, `at`, ... can all start a program of
    ///   the caller's choosing, and the prefix keeps a pattern written for a
    ///   shell command from matching a module.
    #[must_use]
    pub fn adhoc_policy_text(module: &str, args: Option<&str>) -> Option<String> {
        if Self::runs_a_command(module) {
            return args.map(str::to_owned);
        }
        let name = module.trim().to_ascii_lowercase();
        let short = name.rsplit('.').next().unwrap_or(&name);
        let given = args.map(str::trim).filter(|a| !a.is_empty());
        match given {
            None if short == "ping" => None,
            None => Some(format!("ansible-module {module}")),
            Some(a) => Some(format!("ansible-module {module} {a}")),
        }
    }

    /// Whether an Ansible module executes its arguments as a command line
    /// (`command`, `shell`, `raw`, `script`, `expect`, `win_command`,
    /// `win_shell`, `win_powershell`), bare or collection-qualified
    /// (`ansible.builtin.shell`, `ansible.legacy.raw`, `ansible.windows.win_shell`).
    #[must_use]
    pub fn runs_a_command(module: &str) -> bool {
        let name = module.trim().to_ascii_lowercase();
        let short = name.rsplit('.').next().unwrap_or(&name);
        matches!(
            short,
            "command"
                | "shell"
                | "raw"
                | "script"
                | "expect"
                | "win_command"
                | "win_shell"
                | "win_powershell"
        )
    }

    /// Validate playbook extra variables.
    ///
    /// The variables are passed to `ansible-playbook -e` as one JSON
    /// document. Keys must be plain identifiers and must not start with
    /// `ansible_` (connection variables such as `ansible_ssh_common_args`
    /// run local commands); values must not hold a Jinja expression
    /// (`{{`, `{%`, `{#`), which Ansible would evaluate.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` naming `extra_vars` for a bad key
    /// or value.
    pub fn validate_extra_vars(vars: &HashMap<String, String>) -> Result<()> {
        for (key, value) in vars {
            let mut chars = key.chars();
            let valid_key = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid_key {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Invalid extra_vars key '{key}': must match [A-Za-z_][A-Za-z0-9_]*"
                    ),
                });
            }
            if key.starts_with("ansible_") {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Invalid extra_vars key '{key}': 'ansible_' connection variables \
                         are not allowed"
                    ),
                });
            }
            if ["{{", "{%", "{#"].iter().any(|t| value.contains(t)) {
                return Err(BridgeError::CommandDenied {
                    reason: format!(
                        "Invalid extra_vars value for '{key}': Jinja expressions are not \
                         allowed"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validate an Ansible stdout callback name.
    ///
    /// Only allows known callback names to prevent command injection.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the callback is not in the
    /// allow list.
    pub fn validate_callback(callback: &str) -> Result<()> {
        if !ALLOWED_CALLBACKS.contains(&callback) {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Unknown callback '{}'. Allowed: {}",
                    callback,
                    ALLOWED_CALLBACKS.join(", ")
                ),
            });
        }
        Ok(())
    }

    /// Validate a lint target path.
    ///
    /// Rejects paths with `..` (directory traversal).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path contains `..` or
    /// starts with `-` (the target is read as an option).
    pub fn validate_lint_target(target: &str) -> Result<()> {
        super::shell::refuse_option_like("target", target)?;
        if target.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in lint target".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an ansible module for safety.
    ///
    /// Blocks the modules that run a command line (see
    /// [`Self::runs_a_command`], collection-qualified names included) when
    /// args contain dangerous patterns such as `rm -rf`, `mkfs`, `dd if=`,
    /// `> /dev/`, or `chmod 777`. This is a floor: the tool also judges the
    /// args like an `ssh_exec` command (whitelist) before it runs.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if a dangerous combination is
    /// detected.
    pub fn validate_adhoc_module(module: &str, args: Option<&str>) -> Result<()> {
        let dangerous_patterns = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777"];

        if Self::runs_a_command(module)
            && let Some(a) = args
        {
            let lower = a.to_lowercase();
            for pattern in &dangerous_patterns {
                if lower.contains(pattern) {
                    return Err(BridgeError::CommandDenied {
                        reason: format!(
                            "Dangerous pattern '{pattern}' not \
                             allowed with module '{module}'"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Playbook Command Tests ==============

    #[test]
    fn test_build_playbook_minimal() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml", None, None, None, None, None, false, false, None, None, false, None, None,
            None, None, None,
        );
        assert_eq!(cmd, "ansible-playbook 'site.yml'");
    }

    #[test]
    fn test_build_playbook_all_options() {
        let mut vars = HashMap::new();
        vars.insert("env".to_string(), "prod".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            Some("/etc/ansible/hosts"),
            Some("webservers"),
            Some("deploy,config"),
            Some("slow"),
            Some(&vars),
            true,
            true,
            Some(2),
            Some(10),
            true,
            Some("deploy_user"),
            Some("/opt/ansible"),
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("cd -- '/opt/ansible' && "));
        assert!(cmd.contains("ansible-playbook 'deploy.yml'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--tags 'deploy,config'"));
        assert!(cmd.contains("--skip-tags 'slow'"));
        assert!(cmd.contains(r#"-e '{"env":"prod"}'"#));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("--diff"));
        assert!(cmd.contains("-vv"));
        assert!(cmd.contains("-f 10"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'deploy_user'"));
    }

    #[test]
    fn test_build_playbook_with_extra_vars() {
        let mut vars = HashMap::new();
        vars.insert("version".to_string(), "1.2.3".to_string());
        vars.insert("env".to_string(), "staging".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // One JSON document, keys sorted: env comes before version
        assert!(cmd.contains(r#"-e '{"env":"staging","version":"1.2.3"}'"#));
    }

    #[test]
    fn test_build_playbook_with_working_dir() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/home/deploy/playbooks"),
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("cd -- '/home/deploy/playbooks' && "));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
    }

    #[test]
    fn test_build_playbook_verbose_levels() {
        for level in 0u8..=4 {
            let cmd = AnsibleCommandBuilder::build_playbook_command(
                "site.yml",
                None,
                None,
                None,
                None,
                None,
                false,
                false,
                Some(level),
                None,
                false,
                None,
                None,
                None,
                None,
                None,
            );
            if level == 0 {
                assert!(!cmd.contains("-v"), "level 0 should not have -v");
            } else {
                let expected_v = format!("-{}", "v".repeat(level as usize));
                assert!(
                    cmd.contains(&expected_v),
                    "level {level} should contain {expected_v}, \
                     got: {cmd}"
                );
            }
        }
    }

    #[test]
    fn test_build_playbook_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            Some(10),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // Should be capped at -vvvv (4)
        assert!(cmd.contains("-vvvv"));
        assert!(!cmd.contains("-vvvvv"));
    }

    #[test]
    fn test_build_playbook_shell_escape() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "my playbook's.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(cmd.contains("'my playbook'\\''s.yml'"));
    }

    // ============== Inventory Command Tests ==============

    #[test]
    fn test_build_inventory_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            Some("/etc/ansible/hosts"),
            true,
            false,
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, true, None, None, false, false,
        );
        assert!(cmd.contains("--graph"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph_with_group() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            true,
            None,
            Some("webservers"),
            false,
            false,
        );
        assert!(cmd.contains("--graph 'webservers'"));
    }

    #[test]
    fn test_build_inventory_host() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            false,
            Some("server1"),
            None,
            false,
            false,
        );
        assert!(cmd.contains("--host 'server1'"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_default_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, false, None, None, false, false,
        );
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_yaml() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, true, false, None, None, true, false,
        );
        assert!(cmd.contains("--list"));
        assert!(cmd.contains("--yaml"));
    }

    // ============== Adhoc Command Tests ==============

    #[test]
    fn test_build_adhoc_ping() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all", "ping", None, None, false, None, None, None, None, false, None, None,
        );
        assert_eq!(cmd, "ansible 'all' -m 'ping'");
    }

    #[test]
    fn test_build_adhoc_all_options() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "webservers",
            "shell",
            Some("uptime"),
            Some("/etc/ansible/hosts"),
            true,
            Some("root"),
            Some("admin"),
            Some(5),
            Some(3),
            true,
            None,
            None,
        );
        assert!(cmd.contains("ansible 'webservers' -m 'shell'"));
        assert!(cmd.contains("-a 'uptime'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
        assert!(cmd.contains("-u 'admin'"));
        assert!(cmd.contains("-f 5"));
        assert!(cmd.contains("-vvv"));
        assert!(cmd.contains("-C"));
    }

    #[test]
    fn test_build_adhoc_shell_module() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "shell",
            Some("cat /etc/hostname"),
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        assert!(cmd.contains("-m 'shell'"));
        assert!(cmd.contains("-a 'cat /etc/hostname'"));
    }

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_playbook_path_ok() {
        assert!(AnsibleCommandBuilder::validate_playbook_path("site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("playbooks/deploy.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("/opt/ansible/site.yml").is_ok());
        // `./` keeps a name that starts with `-` a path.
        assert!(AnsibleCommandBuilder::validate_playbook_path("./-x").is_ok());
    }

    #[test]
    fn test_validate_playbook_path_traversal() {
        let result = AnsibleCommandBuilder::validate_playbook_path("../../../etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }

        assert!(AnsibleCommandBuilder::validate_playbook_path("roles/../site.yml").is_err());
    }

    #[test]
    fn test_validate_adhoc_safe_modules() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("ping", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("setup", None).is_ok());
        assert!(
            AnsibleCommandBuilder::validate_adhoc_module("copy", Some("src=/tmp/a dest=/tmp/b"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_adhoc_raw_with_rm() {
        let result = AnsibleCommandBuilder::validate_adhoc_module("raw", Some("rm -rf /"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rm -rf"));
                assert!(reason.contains("raw"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_with_mkfs() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("mkfs.ext4 /dev/sda1"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("mkfs"));
                assert!(reason.contains("shell"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_safe_args() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", Some("ls -la /tmp")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", Some("whoami")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", Some("uptime")).is_ok());
    }

    #[test]
    fn test_validate_adhoc_command_with_dd() {
        let result = AnsibleCommandBuilder::validate_adhoc_module(
            "command",
            Some("dd if=/dev/zero of=/dev/sda"),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("dd if="));
                assert!(reason.contains("command"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    // ============== Additional Edge Case Tests ==============

    #[test]
    fn test_validate_adhoc_redirect_to_dev() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("echo x > /dev/sda"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("> /dev/"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_chmod_777() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("raw", Some("chmod 777 /etc/passwd"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("chmod 777"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_dangerous_module_no_args() {
        // Dangerous module with no args should be OK (no pattern to match)
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", None).is_ok());
    }

    #[test]
    fn test_build_adhoc_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            Some(10), // Should be capped at 4
            false,
            None,
            None,
        );
        // Should have -vvvv (4 v's max), not -vvvvvvvvvv
        assert!(cmd.contains("-vvvv"));
        let count = cmd.matches("-vvvv").count();
        assert_eq!(count, 1); // Exactly one -vvvv, not more
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_extra_vars_key_injection_prevented() {
        let mut vars = HashMap::new();
        vars.insert("$(whoami)".to_string(), "bar".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        // Key should be escaped, not interpreted
        assert!(cmd.contains(r#"-e '{"$(whoami)":"bar"}'"#));
        assert!(!cmd.contains("-e $(whoami)"));
    }

    #[test]
    fn test_build_inventory_vars_without_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,  // inventory
            false, // list
            false, // graph
            None,  // host
            None,  // group
            false, // yaml
            true,  // vars
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("--vars"));
    }

    // ============== Callback Tests ==============

    #[test]
    fn test_build_playbook_with_callback() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            Some("json"),
            None,
            None,
        );
        assert!(cmd.starts_with("ANSIBLE_STDOUT_CALLBACK='json' "));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
    }

    #[test]
    fn test_build_playbook_callback_with_working_dir() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/opt/ansible"),
            Some("dense"),
            None,
            None,
        );
        // The variable must prefix `ansible-playbook`, not `cd`.
        assert!(
            cmd.starts_with(
                "cd -- '/opt/ansible' && ANSIBLE_STDOUT_CALLBACK='dense' ansible-playbook "
            ),
            "{cmd}"
        );
    }

    #[test]
    fn test_callback_is_not_attached_to_cd() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/opt/ansible"),
            Some("json"),
            None,
            None,
        );
        assert!(!cmd.contains("'json' cd"), "{cmd}");
        assert_eq!(
            cmd,
            "cd -- '/opt/ansible' && ANSIBLE_STDOUT_CALLBACK='json' ansible-playbook 'site.yml'"
        );
    }

    #[test]
    fn test_validate_facts_filter_accepts_fact_globs() {
        for f in [
            "",
            "ansible_distribution*",
            "ansible_eth*,ansible_memory*",
            "ansible_default_ipv4",
            "ansible_?ounts",
            "ansible_[a-c]*",
            "ansible_[!x]*",
        ] {
            assert!(
                AnsibleCommandBuilder::validate_facts_filter(f).is_ok(),
                "{f}"
            );
        }
    }

    #[test]
    fn test_validate_facts_filter_refuses_jinja_and_extra_parameters() {
        for f in [
            "{{ lookup('pipe','id') }}",
            "{% if 1 %}x{% endif %}",
            "{#x#}",
            "* fact_path=/var/tmp/d",
            "a b",
            "a=b",
            "a%b",
            "a#b",
            "a;id",
            "$(id)",
            "a'b",
            "!x",
            "a-b",
            "ansible_[x",
            "ansible_x]",
            "a\nb",
        ] {
            let err = AnsibleCommandBuilder::validate_facts_filter(f).expect_err(f);
            assert!(err.to_string().contains("filter"), "{f}: {err}");
        }
    }

    #[test]
    fn test_refuse_jinja() {
        for v in ["{{ x }}", "a{%b", "{#c", "msg={{ lookup('pipe','id') }}"] {
            let err = AnsibleCommandBuilder::refuse_jinja("args", v).expect_err(v);
            assert!(err.to_string().contains("'args'"), "{err}");
        }
        for v in [
            "",
            "name=nginx state=restarted",
            "{ a }",
            "{ {",
            "root",
            "a}}",
        ] {
            assert!(
                AnsibleCommandBuilder::refuse_jinja("args", v).is_ok(),
                "{v}"
            );
        }
    }

    #[test]
    fn test_runs_a_command_matches_command_modules_only() {
        for m in [
            "command",
            "shell",
            "raw",
            "script",
            "expect",
            "win_command",
            "win_shell",
            "win_powershell",
            "ansible.builtin.shell",
            "ansible.legacy.raw",
            "ansible.windows.win_shell",
            "ANSIBLE.LEGACY.RAW",
            " Shell ",
        ] {
            assert!(AnsibleCommandBuilder::runs_a_command(m), "{m}");
        }
        for m in ["ping", "copy", "setup", "service", "debug", ""] {
            assert!(!AnsibleCommandBuilder::runs_a_command(m), "{m}");
        }
    }

    #[test]
    fn test_validate_adhoc_module_is_fqcn_aware() {
        let err =
            AnsibleCommandBuilder::validate_adhoc_module("ansible.builtin.shell", Some("rm -rf /"))
                .expect_err("fqcn shell");
        assert!(err.to_string().contains("rm -rf"), "{err}");
        assert!(
            AnsibleCommandBuilder::validate_adhoc_module("ansible.builtin.shell", Some("uptime"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_adhoc_module_judges_every_command_module() {
        for module in [
            "command",
            "shell",
            "raw",
            "script",
            "expect",
            "win_command",
            "win_shell",
            "win_powershell",
            "ansible.builtin.shell",
            "ansible.windows.win_shell",
            "ANSIBLE.LEGACY.RAW",
            " Shell ",
        ] {
            assert!(
                AnsibleCommandBuilder::validate_adhoc_module(module, Some("uptime")).is_ok(),
                "{module:?}"
            );
            assert!(
                AnsibleCommandBuilder::validate_adhoc_module(module, None).is_ok(),
                "{module:?}"
            );
            assert!(
                AnsibleCommandBuilder::validate_adhoc_module(module, Some("rm -rf /")).is_err(),
                "{module:?}"
            );
        }
    }

    #[test]
    fn test_validate_adhoc_module_does_not_judge_other_modules() {
        // A module that runs no command line is not judged by the dangerous
        // patterns (the tool still judges its policy text).
        for module in ["ping", "copy", "setup", "service", "debug", ""] {
            for args in [
                "src=a dest=b",
                "rm -rf /",
                "mkfs",
                "dd if=/dev/zero",
                "echo > /dev/null",
                "chmod 777 x",
                "$(id)",
                "a; b",
            ] {
                assert!(
                    AnsibleCommandBuilder::validate_adhoc_module(module, Some(args)).is_ok(),
                    "{module:?} {args:?}"
                );
            }
        }
    }

    #[test]
    fn test_validate_callback_allowed() {
        for callback in [
            "json", "yaml", "dense", "minimal", "tree", "default", "oneline", "debug", "null",
        ] {
            assert!(
                AnsibleCommandBuilder::validate_callback(callback).is_ok(),
                "{callback}"
            );
        }
    }

    #[test]
    fn test_validate_callback_rejected() {
        for callback in ["", "json;id", "$(id)", "nosuchcallback"] {
            assert!(
                AnsibleCommandBuilder::validate_callback(callback).is_err(),
                "{callback}"
            );
        }
        let result = AnsibleCommandBuilder::validate_callback("$(whoami)");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Unknown callback"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== Facts Command Tests ==============

    #[test]
    fn test_build_facts_minimal() {
        let cmd = AnsibleCommandBuilder::build_facts_command("all", None, None, false, None);
        assert_eq!(cmd, "ansible 'all' -m setup");
    }

    #[test]
    fn test_build_facts_with_filter() {
        let cmd = AnsibleCommandBuilder::build_facts_command(
            "webservers",
            Some("ansible_distribution*"),
            Some("hosts.ini"),
            true,
            Some("root"),
        );
        assert!(cmd.contains("ansible 'webservers' -m setup"));
        assert!(cmd.contains("-a 'filter=ansible_distribution*'"));
        assert!(cmd.contains("-i 'hosts.ini'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
    }

    // ============== Lint Command Tests ==============

    #[test]
    fn test_build_lint_minimal() {
        let cmd = AnsibleCommandBuilder::build_lint_command("site.yml", None, false);
        assert_eq!(cmd, "ansible-lint 'site.yml'");
    }

    #[test]
    fn test_build_lint_with_format() {
        let cmd = AnsibleCommandBuilder::build_lint_command("roles/", Some("json"), true);
        assert!(cmd.contains("ansible-lint 'roles/'"));
        assert!(cmd.contains("--format 'json'"));
        assert!(cmd.contains("-p"));
    }

    #[test]
    fn test_validate_lint_target_ok() {
        assert!(AnsibleCommandBuilder::validate_lint_target("site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_lint_target("roles/webserver").is_ok());
        assert!(AnsibleCommandBuilder::validate_lint_target("playbooks/site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_lint_target("/opt/ansible/site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_lint_target("./-x").is_ok());
    }

    #[test]
    fn test_validate_lint_target_traversal() {
        assert!(AnsibleCommandBuilder::validate_lint_target("../../etc/passwd").is_err());
        assert!(AnsibleCommandBuilder::validate_lint_target("../x").is_err());
        assert!(AnsibleCommandBuilder::validate_lint_target("roles/../site.yml").is_err());
    }

    // ============== Vault Passthrough Tests ==============

    #[test]
    fn test_build_playbook_with_vault() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        );
        assert!(cmd.contains("--vault-password-file '/etc/ansible/pass'"));
        assert!(cmd.contains("--vault-id 'prod@/etc/ansible/prod-pass'"));
    }

    #[test]
    fn test_build_adhoc_with_vault() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        );
        assert!(cmd.contains("--vault-password-file '/etc/ansible/pass'"));
        assert!(cmd.contains("--vault-id 'prod@/etc/ansible/prod-pass'"));
    }

    // ============== Config Command Tests ==============

    #[test]
    fn test_build_config_minimal() {
        let cmd = AnsibleCommandBuilder::build_config_command(false, None);
        assert_eq!(cmd, "ansible-config dump");
    }

    #[test]
    fn test_build_config_only_changed_json() {
        let cmd = AnsibleCommandBuilder::build_config_command(true, Some("json"));
        assert!(cmd.contains("--only-changed"));
        assert!(cmd.contains("--format 'json'"));
    }

    // ============== Injection hardening ==============

    #[test]
    fn test_facts_filter_is_one_quoted_word() {
        let cmd = AnsibleCommandBuilder::build_facts_command(
            "all",
            Some("x; id #'$(id)"),
            None,
            false,
            None,
        );
        assert!(cmd.contains(" -a 'filter=x; id #'\\''$(id)'"), "{cmd}");
    }

    #[test]
    fn test_playbook_working_dir_after_double_dash() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("-x"),
            None,
            None,
            None,
        );
        assert!(cmd.starts_with("cd -- '-x' && "), "{cmd}");
    }

    #[test]
    fn test_extra_vars_whitespace_stays_in_one_json_value() {
        let mut vars = HashMap::new();
        vars.insert(
            "x".to_string(),
            "1 ansible_ssh_common_args=-oProxyCommand=id".to_string(),
        );
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            cmd.contains(r#"-e '{"x":"1 ansible_ssh_common_args=-oProxyCommand=id"}'"#),
            "{cmd}"
        );
    }

    #[test]
    fn test_validate_extra_vars_refuses_hostile_input() {
        let one = |k: &str, v: &str| {
            let mut m = HashMap::new();
            m.insert(k.to_string(), v.to_string());
            AnsibleCommandBuilder::validate_extra_vars(&m)
        };
        assert!(AnsibleCommandBuilder::validate_extra_vars(&HashMap::new()).is_ok());
        assert!(one("env", "prod value").is_ok());
        assert!(one("app_version", "1.2.3").is_ok());
        for (k, v) in [
            ("ansible_ssh_common_args", "x"),
            ("{\"a\":\"", "\"}"),
            ("a b", "x"),
            ("", "x"),
            ("1x", "x"),
            ("k", "{{ lookup('pipe','id') }}"),
            ("k", "{% set a=1 %}"),
            ("k", "{%x"),
            ("k", "{#x"),
        ] {
            let err = one(k, v).unwrap_err().to_string();
            assert!(err.contains("extra_vars"), "{k}={v}: {err}");
        }
    }

    #[test]
    fn test_option_like_positionals_refused() {
        for r in [
            AnsibleCommandBuilder::validate_pattern("-ZQXdash"),
            AnsibleCommandBuilder::validate_playbook_path("-ZQXdash"),
            AnsibleCommandBuilder::validate_lint_target("-ZQXdash"),
        ] {
            assert!(r.is_err());
        }
        assert!(
            AnsibleCommandBuilder::validate_pattern("-x")
                .unwrap_err()
                .to_string()
                .contains("pattern")
        );
        assert!(AnsibleCommandBuilder::validate_pattern("web:!db").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("./-x.yml").is_ok());
        // A double dash is an option too, for every positional.
        for value in ["-site.yml", "--extra-vars=x", "--list", "-i"] {
            assert!(
                AnsibleCommandBuilder::validate_playbook_path(value).is_err(),
                "playbook {value}"
            );
            assert!(
                AnsibleCommandBuilder::validate_lint_target(value).is_err(),
                "lint target {value}"
            );
            assert!(
                AnsibleCommandBuilder::validate_inventory(value).is_err(),
                "inventory {value}"
            );
            assert!(
                AnsibleCommandBuilder::validate_pattern(value).is_err(),
                "pattern {value}"
            );
        }
    }

    #[test]
    fn test_validate_pattern_accepts_host_patterns() {
        for ok in ["all", "web*", "web:&db", "web:!db", "web-1"] {
            assert!(AnsibleCommandBuilder::validate_pattern(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn test_validate_user_name() {
        for ok in [
            "root",
            "_svc",
            "deploy.ops",
            "j.doe@corp",
            "a-b_c9",
            "a234567890123456789012345678901234567890123456789012345678901234",
            // A Windows domain, one backslash, then the name.
            "CORP\\svc",
            "a\\b",
            "corp.example.com\\j.doe",
            "9corp\\admin",
            // A group managed service account.
            "svc$",
            "CORP\\gmsa-web$",
            "a234567890123456789012345678901234567890123456789012345678901234$",
        ] {
            assert!(
                AnsibleCommandBuilder::validate_user_name("become_user", ok).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "",
            "-root",
            "9lives",
            "root; id",
            "root&&id",
            "root id",
            "root\tid",
            "$(id)",
            "`id`",
            "{{ x }}",
            "a'b",
            "a\"b",
            "a|b",
            "a>b",
            "a\nb",
            "a2345678901234567890123456789012345678901234567890123456789012345",
            // The domain prefix and the `$` suffix stay narrow.
            "\\svc",
            "CORP\\",
            "CORP\\\\svc",
            "CORP\\sv\\c",
            "-CORP\\svc",
            "_CORP\\svc",
            "CORP svc\\x",
            "CORP;id\\x",
            "CORP\\9svc",
            "CORP\\-svc",
            "a\\b\\c",
            "$",
            "$svc",
            "sv$c",
            "svc$$",
            "svc$ ",
            "svc\\$",
            "CORP$\\svc",
            "CORP\\svc$x",
            "a2345678901234567890123456789012345678901234567890123456789012345$",
            "a123456789012345678901234567890123456789012345678901234567890123\\svc",
        ] {
            let err = AnsibleCommandBuilder::validate_user_name("become_user", bad).expect_err(bad);
            assert!(err.to_string().contains("become_user"), "{bad}");
        }
    }

    #[test]
    fn test_refuse_jinja_in_names_the_field() {
        assert!(
            AnsibleCommandBuilder::refuse_jinja_in(&[("limit", Some("web*")), ("tags", None)])
                .is_ok()
        );
        let err = AnsibleCommandBuilder::refuse_jinja_in(&[
            ("limit", Some("web*")),
            ("tags", Some("{{ x }}")),
        ])
        .expect_err("jinja");
        assert!(err.to_string().contains("tags"));
    }

    #[test]
    fn test_validate_adhoc_args() {
        let check = |args: &str| AnsibleCommandBuilder::validate_adhoc_args("shell", args);
        for bad in [
            "{\"msg\": \"x\"}",
            "  {\"msg\": \"x\"}",
            "\n{\"msg\": \"x\"}",
            "msg={{ x }}",
            "msg=\\u007b",
            "msg=\\U0000007b",
            "msg=\\x7b",
            "msg=\\x7B",
            "msg=\\N{LEFT CURLY BRACKET}",
            "msg=\\N{",
            "msg=a\\ub33fb",
            "msg=\\\\x41",
            // `\=` anywhere, and a word that opens with `=` and holds a
            // backslash (Ansible decodes it into the command line).
            "a\\=b",
            "a\\nb\\=c",
            "\\=",
            "=b\\n",
            "a =x\\t",
            "a\n=\\a",
            // A quoted run joins pieces into one Ansible token that still
            // opens with `=`.
            "echo =\"a b\"\\nid",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
        for ok in [
            "name=nginx state=restarted",
            "msg=a\\nb",
            "path=C:\\dir",
            "echo {a,b}",
            "echo 8\\9",
            // Backslash sequences Ansible does not decode by number or name.
            "msg=\\173",
            "msg=\\0",
            "msg=\\7",
            "dir C:\\Users\\Public",
            "dir C:\\x\\y",
            "msg=\\x1",
            "msg=\\u12",
            "msg=\\U1234567",
            "msg=\\N",
            "msg=\\Nx",
            "msg=\\xZZ",
            "echo a==b",
            "key=v=w",
            "a= b",
            // Shell comparisons: a bare `=` decodes to itself.
            "[ \"$(hostname)\" = web1 ] && uptime",
            "test a == b",
            "=b",
            "msg=1 =2",
            // A tab does not start an Ansible token: one `a<TAB>=…` token.
            "a\t=\\n",
            "",
        ] {
            assert!(check(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn test_validate_adhoc_args_command_module_options() {
        for module in ["command", "shell", "ansible.builtin.raw", "win_shell"] {
            for bad in [
                "executable=/tmp/x echo hi",
                "echo hi executable=/tmp/x",
                "echo hi\nchdir=/tmp",
                "chdir=/tmp ls",
                "stdin=data cat",
                "ls stdin=x",
                // Any whitespace separates words for the check.
                "\tchdir=/tmp ls",
                "ls\r\nexecutable=/tmp/x",
                "ls\x0bstdin=x",
                "ls\tchdir=/tmp",
                "ls\nchdir=/tmp",
            ] {
                let err = AnsibleCommandBuilder::validate_adhoc_args(module, bad)
                    .expect_err(&format!("{module}: {bad}"));
                assert!(err.to_string().contains("'args'"), "{err}");
            }
            for ok in [
                "creates=/tmp/x echo hi",
                "removes=/tmp/x rm /tmp/x",
                "warn=false uptime",
                "stdin_add_newline=false cat",
                "strip_empty_ends=false ls",
                "ls --chdir=/tmp",
                "echo notexecutable=1",
                "uptime",
            ] {
                assert!(
                    AnsibleCommandBuilder::validate_adhoc_args(module, ok).is_ok(),
                    "{module}: {ok}"
                );
            }
        }
        // Any other module keeps its `chdir`, `executable` and `stdin`
        // parameters (they are ordinary module parameters there).
        for module in ["copy", "ansible.builtin.file", "ping"] {
            assert!(
                AnsibleCommandBuilder::validate_adhoc_args(module, "chdir=/tmp executable=x")
                    .is_ok(),
                "{module}"
            );
        }
        // The Jinja, JSON, escape and `=` rules apply to every module.
        for module in ["copy", "ping"] {
            for bad in [
                "msg={{ x }}",
                "msg={%x",
                "msg={#x",
                "{\"msg\": \"x\"}",
                " \t{a=b}",
                "msg=\\x41",
                "msg=\\u007b",
                "msg=\\U00000041",
                "msg=\\N{DIGIT ONE}",
                "\\\\x41",
                "a\\=b",
                "=b\\n",
                "x =b\\n",
                "x =y\\n",
                "x\n=y\\t",
            ] {
                assert!(
                    AnsibleCommandBuilder::validate_adhoc_args(module, bad).is_err(),
                    "{module}: {bad}"
                );
            }
        }
    }

    #[test]
    fn test_adhoc_policy_text() {
        let text = AnsibleCommandBuilder::adhoc_policy_text;
        assert_eq!(text("ping", None), None);
        assert_eq!(text("ansible.builtin.PING", Some("  ")), None);
        assert_eq!(
            text("ping", Some("data=x")).as_deref(),
            Some("ansible-module ping data=x")
        );
        assert_eq!(text("setup", None).as_deref(), Some("ansible-module setup"));
        assert_eq!(
            text("ansible.builtin.cron", Some("name=x job=id")).as_deref(),
            Some("ansible-module ansible.builtin.cron name=x job=id")
        );
        // The module is spelled as the caller gave it; args are trimmed.
        assert_eq!(
            text("Cron", Some("  name=x ")).as_deref(),
            Some("ansible-module Cron name=x")
        );
        // A command module is judged by its args alone.
        assert_eq!(text("shell", Some("uptime")).as_deref(), Some("uptime"));
        assert_eq!(
            text("ansible.builtin.command", Some("ls /tmp")).as_deref(),
            Some("ls /tmp")
        );
        assert_eq!(text("ansible.legacy.raw", None), None);
    }

    // ============== Inventory plugins ==============

    #[test]
    fn test_inventory_given_disables_the_script_plugin() {
        let env = "ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml";

        let adhoc = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            Some("/tmp/inv"),
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        assert_eq!(
            adhoc,
            format!("{env} ansible 'all' -m 'ping' -i '/tmp/inv'")
        );

        let facts =
            AnsibleCommandBuilder::build_facts_command("all", None, Some("/tmp/inv"), false, None);
        assert_eq!(facts, format!("{env} ansible 'all' -m setup -i '/tmp/inv'"));

        let inventory = AnsibleCommandBuilder::build_inventory_command(
            Some("/tmp/inv"),
            true,
            false,
            None,
            None,
            false,
            false,
        );
        assert_eq!(
            inventory,
            format!("{env} ansible-inventory -i '/tmp/inv' --list")
        );

        let playbook = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            Some("/tmp/inv"),
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            playbook,
            format!("{env} ansible-playbook 'site.yml' -i '/tmp/inv'")
        );
    }

    #[test]
    fn test_inventory_env_follows_cd_and_callback_and_precedes_the_program() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            Some("hosts.ini"),
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/opt/ansible"),
            Some("json"),
            None,
            None,
        );
        assert_eq!(
            cmd,
            "cd -- '/opt/ansible' && ANSIBLE_STDOUT_CALLBACK='json' \
             ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml \
             ansible-playbook 'site.yml' -i 'hosts.ini'"
        );
    }

    #[test]
    fn test_no_inventory_leaves_the_operator_inventory_alone() {
        let adhoc = AnsibleCommandBuilder::build_adhoc_command(
            "all", "ping", None, None, false, None, None, None, None, false, None, None,
        );
        let facts = AnsibleCommandBuilder::build_facts_command("all", None, None, false, None);
        let inventory = AnsibleCommandBuilder::build_inventory_command(
            None, true, false, None, None, false, false,
        );
        let playbook = AnsibleCommandBuilder::build_playbook_command(
            "site.yml", None, None, None, None, None, false, false, None, None, false, None, None,
            None, None, None,
        );
        for cmd in [adhoc, facts, inventory, playbook] {
            assert!(!cmd.contains("INVENTORY_ENABLED"), "{cmd}");
        }
    }

    #[test]
    fn test_validate_inventory() {
        assert!(AnsibleCommandBuilder::validate_inventory("-i").is_err());
        assert!(
            AnsibleCommandBuilder::validate_inventory("--list")
                .unwrap_err()
                .to_string()
                .contains("inventory")
        );
        for ok in [
            "hosts.ini",
            "/etc/ansible/hosts",
            "a,b,",
            "./-x",
            "localhost,",
        ] {
            assert!(
                AnsibleCommandBuilder::validate_inventory(ok).is_ok(),
                "{ok}"
            );
        }
    }

    // ============== Vault password files ==============

    const GUARD_P: &str = "if [ -f '/etc/ansible/pass' ] && [ -n \"$(find -L '/etc/ansible/pass' \
        -prune ! -perm -100 ! -perm -010 ! -perm -001 -print 2>/dev/null)\" ]; then :; else \
        echo 'bridge-mcp: vault password file /etc/ansible/pass must be a plain file without \
        execute permission (Ansible runs an executable one); configure vault scripts in \
        ansible.cfg instead' >&2; exit 2; fi";

    /// The one guard for a single vault password file.
    fn guard_of(source: Option<&str>) -> String {
        AnsibleCommandBuilder::vault_guards(source, None).remove(0)
    }

    #[test]
    fn test_vault_guard_text() {
        let guards = AnsibleCommandBuilder::vault_guards(Some("/etc/ansible/pass"), None);
        assert_eq!(guards, vec![GUARD_P.to_string()]);
    }

    #[test]
    fn test_vault_guards_pick_the_right_sources() {
        let sources = |vpf: Option<&str>, vid: Option<&str>| -> Vec<String> {
            AnsibleCommandBuilder::vault_guards(vpf, vid)
                .iter()
                .map(|g| {
                    let start = g.find("[ -f ").map_or(0, |i| i + "[ -f ".len());
                    g.get(start..)
                        .and_then(|rest| rest.split(" ]").next())
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(sources(None, None), Vec::<String>::new());
        assert_eq!(sources(Some("/p"), None), ["'/p'"]);
        // `label@path`: the part after the first `@`.
        assert_eq!(
            sources(None, Some("prod@/etc/prod-pass")),
            ["'/etc/prod-pass'"]
        );
        assert_eq!(sources(None, Some("a@b@c")), ["'b@c'"]);
        // Without `@`, the whole value is the source.
        assert_eq!(sources(None, Some("passfile")), ["'passfile'"]);
        // Prompts are not files.
        assert_eq!(sources(None, Some("prompt")), Vec::<String>::new());
        assert_eq!(sources(None, Some("prod@prompt")), Vec::<String>::new());
        assert_eq!(
            sources(None, Some("prompt_ask_vault_pass")),
            Vec::<String>::new()
        );
        assert_eq!(
            sources(None, Some("prod@prompt_ask_vault_pass")),
            Vec::<String>::new()
        );
        // `prompt` as a file name inside a path is a file.
        assert_eq!(sources(None, Some("x@/tmp/prompt")), ["'/tmp/prompt'"]);
        // Both arguments, in command-line order; the same file once.
        assert_eq!(sources(Some("/a"), Some("v@/b")), ["'/a'", "'/b'"]);
        assert_eq!(sources(Some("/a"), Some("v@/a")), ["'/a'"]);
        // A file and a prompt: only the file.
        assert_eq!(sources(Some("/a"), Some("v@prompt")), ["'/a'"]);
    }

    #[test]
    fn test_vault_guard_quotes_the_path_once() {
        let guard = guard_of(Some("it's a $(id) file"));
        let quoted = "'it'\\''s a $(id) file'";
        assert!(guard.contains(&format!("[ -f {quoted} ]")), "{guard}");
        assert!(
            guard.contains(&format!("find -L {quoted} -prune")),
            "{guard}"
        );
        // The message is one quoted word that holds the path.
        assert!(
            guard.contains("echo 'bridge-mcp: vault password file it'\\''s a $(id) file must be"),
            "{guard}"
        );
        assert!(guard.ends_with(">&2; exit 2; fi"), "{guard}");
    }

    #[test]
    fn test_vault_guard_keeps_find_from_reading_a_path_as_an_expression() {
        for source in ["!x", "(x", ")x", ",x"] {
            let guard = guard_of(Some(source));
            assert!(guard.contains(&format!("[ -f '{source}' ]")), "{guard}");
            assert!(
                guard.contains(&format!("find -L ./'{source}' -prune")),
                "{guard}"
            );
        }
    }

    #[test]
    fn test_vault_guard_expands_a_leading_tilde_like_ansible() {
        let guard = guard_of(Some("~/.vault pass"));
        assert!(guard.contains("[ -f \"$HOME\"/'.vault pass' ]"), "{guard}");
        assert!(
            guard.contains("find -L \"$HOME\"/'.vault pass' -prune"),
            "{guard}"
        );
        // `~user/` is not expanded: the guard refuses it as a missing file.
        let other = guard_of(Some("~bob/pass"));
        assert!(other.contains("[ -f '~bob/pass' ]"), "{other}");
    }

    #[test]
    fn test_vault_guards_run_after_cd_and_before_ansible() {
        let playbook = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/opt/ansible"),
            Some("json"),
            Some("/etc/ansible/pass"),
            Some("prod@/etc/ansible/prod-pass"),
        );
        let cd = playbook.find("cd -- '/opt/ansible' && ").expect("cd");
        let first = playbook
            .find("[ -f '/etc/ansible/pass' ]")
            .expect("guard 1");
        let second = playbook
            .find("[ -f '/etc/ansible/prod-pass' ]")
            .expect("guard 2");
        let program = playbook
            .find("ANSIBLE_STDOUT_CALLBACK='json' ansible-playbook")
            .expect("program");
        assert_eq!(cd, 0, "{playbook}");
        assert!(
            cd < first && first < second && second < program,
            "{playbook}"
        );
        // The guards chain with `&&`: a failed `cd` still stops the run.
        assert!(playbook.contains("; fi && if [ -f '/etc/ansible/prod-pass' ]"));
        assert!(playbook.contains("; fi && ANSIBLE_STDOUT_CALLBACK='json' ansible-playbook "));
        assert!(playbook.contains("--vault-password-file '/etc/ansible/pass'"));
    }

    #[test]
    fn test_vault_guard_in_adhoc_precedes_the_program() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            Some("hosts"),
            false,
            None,
            None,
            None,
            None,
            false,
            Some("/etc/ansible/pass"),
            None,
        );
        assert!(
            cmd.starts_with(&format!(
                "{GUARD_P} && ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml ansible 'all' -m 'ping'"
            )),
            "{cmd}"
        );
    }

    #[test]
    fn test_no_vault_argument_means_no_guard() {
        let adhoc = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            Some("prompt"),
        );
        assert_eq!(adhoc, "ansible 'all' -m 'ping' --vault-id 'prompt'");
        let playbook = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            Some("prod@prompt_ask_vault_pass"),
        );
        assert!(!playbook.contains("find -L"), "{playbook}");
        assert!(!playbook.contains("exit 2"), "{playbook}");
        assert_eq!(
            AnsibleCommandBuilder::vault_precheck(Some("/d"), None, Some("prompt")),
            ""
        );
        assert_eq!(AnsibleCommandBuilder::vault_precheck(None, None, None), "");
    }

    #[test]
    fn test_vault_precheck_runs_in_a_subshell_in_the_working_directory() {
        let with_dir = AnsibleCommandBuilder::vault_precheck(
            Some("/opt/a b"),
            Some("/etc/pass"),
            Some("v@/x"),
        );
        assert!(
            with_dir.starts_with("( cd -- '/opt/a b' && if [ -f '/etc/pass' ]"),
            "{with_dir}"
        );
        assert!(with_dir.contains("; fi && if [ -f '/x' ]"), "{with_dir}");
        assert!(with_dir.ends_with("; fi ) || exit $?; "), "{with_dir}");
        let without = AnsibleCommandBuilder::vault_precheck(None, Some("/etc/pass"), None);
        assert!(without.starts_with("( if [ -f '/etc/pass' ]"), "{without}");
        assert!(!without.contains("cd --"), "{without}");
    }

    #[test]
    fn test_validate_vault_args() {
        let check = AnsibleCommandBuilder::validate_vault_args;
        assert!(check(None, None).is_ok());
        assert!(
            check(
                Some("/etc/ansible/pass"),
                Some("prod@/etc/ansible/prod-pass")
            )
            .is_ok()
        );
        assert!(check(Some("pass"), Some("prompt")).is_ok());
        assert!(check(None, Some("dev@prompt_ask_vault_pass")).is_ok());
        assert!(check(Some("./-pass"), Some("v@./-pass")).is_ok());
        assert!(check(Some("~/.vault_pass"), Some("v@keys/a..b")).is_ok());
        // `~/` and `..` inside a name are fine in either argument.
        assert!(check(Some("~/vault.txt"), None).is_ok());
        assert!(check(None, Some("prod@~/vault.txt")).is_ok());
        assert!(check(Some("keys/a..b"), None).is_ok());
        for (vpf, vid, arg) in [
            (Some("-x"), None, "vault_password_file"),
            (Some("--vault-id=x"), None, "vault_password_file"),
            (None, Some("-x"), "vault_id"),
            (None, Some("-x@/p"), "vault_id"),
            (None, Some("prod@-x"), "vault_id"),
            (Some("{{ x }}"), None, "vault_password_file"),
            (Some("a{%b"), None, "vault_password_file"),
            (None, Some("p@{#x"), "vault_id"),
            (Some("a\nb"), None, "vault_password_file"),
            (Some("a\tb"), None, "vault_password_file"),
            (None, Some("p@/a\rb"), "vault_id"),
            (None, Some("p@/a\u{7f}b"), "vault_id"),
            // Ansible expands and folds these before it looks at the file.
            (
                Some("/proc/self/cwd/../../usr/bin/python3"),
                None,
                "vault_password_file",
            ),
            (Some("$HOME/pass"), None, "vault_password_file"),
            (None, Some("p@${SHELL}"), "vault_id"),
            (Some("~root/pass"), None, "vault_password_file"),
            (None, Some("p@~"), "vault_id"),
            // A `..` segment at the start or at the end of the path.
            (Some("../x"), None, "vault_password_file"),
            (Some("a/.."), None, "vault_password_file"),
            // The file a `vault_id` reads gets the same rules as the
            // file argument.
            (None, Some("p@a/../b"), "vault_id"),
            (None, Some("p@~root/x"), "vault_id"),
            (None, Some("p@a\nb"), "vault_id"),
            (None, Some("p@{{x"), "vault_id"),
            (None, Some("p@{%x"), "vault_id"),
            (Some("{%x"), None, "vault_password_file"),
            (Some("{#x"), None, "vault_password_file"),
        ] {
            let err = check(vpf, vid).expect_err(&format!("{vpf:?} {vid:?}"));
            assert!(err.to_string().contains(arg), "{err}");
        }
    }
}
