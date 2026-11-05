# Security Policy

## Supported Versions

Only the latest major release gets security fixes.

| Version | Supported |
|---------|-----------|
| 6.x     | Yes       |
| < 6.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Bridge MCP, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: Send details to the project maintainer (see git log for contact)
2. GitHub: Use [GitHub Security Advisories](../../security/advisories/new) to report privately

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix and release**: Depends on severity
  - Critical: Within 72 hours
  - High: Within 1 week
  - Medium/Low: Next release cycle

## Security Model

Bridge MCP acts as a security boundary between an AI client (Claude Code) and remote SSH hosts.

### Key Security Controls

| Control | Description |
|---------|-------------|
| Command Validation | Whitelist/blacklist with regex patterns (`CommandValidator`) |
| Argument Quoting | Each argument is quoted once for the shell of the host: POSIX single quotes, or `PowerShell` verbatim strings. A tool runs only on hosts whose shell matches its quoting (`HostConfig::effective_shell`; WinRM and PSRP always run `PowerShell`). Identifiers that would read as options are refused, and paths go after `--`. A test sends hostile values to every non-enum string argument of the tools it can reach through the mock executor and lexes the resulting commands (`src/mcp/injection_sweep.rs`) |
| Output Sanitization | 63 patterns masking secrets in command output (`Sanitizer`) |
| Rate Limiting | Per-host token bucket rate limiter (`RateLimiter`) |
| Destructive-op Confirmation | Opt-in `security.require_elicitation_on_destructive` asks the client via MCP `elicitation/create` before any tool annotated `destructive_hint: true` executes. Fail-closed when the client does not advertise the elicitation capability. |
| Audit Logging | Async JSON-lines audit trail (`AuditLogger`) |
| Host Key Verification | Strict mode by default (MITM protection) |
| Memory Safety | `#![forbid(unsafe_code)]`, `Zeroizing<String>` for credentials |
| Path Validation | Traversal prevention on file operations |
| Dependency Auditing | `cargo-deny` + `cargo-audit` in CI |

### Security Modes

The whitelist applies to the tools that take a command to run: `ssh_exec`,
`ssh_exec_multi`, `ssh_session_exec` (a command in a persistent session),
`ssh_canary_exec`, `ssh_rolling_exec`, `ssh_fleet_diff`, `ssh_pty_exec`,
`ssh_cron_add` (its command is run later by cron), the container and pod
`exec` tools, and the Ansible modules described below. The other typed tools
build their own command from validated, quoted arguments; in every mode they
check the blacklist only. `ssh_net_equip_config` is the one tool that sends
raw request text and is not whitelisted: its `commands` are a device CLI
(Cisco, Juniper, ...), not a shell command line, and are sent as-is. It runs
only on a host whose `tags` list in `config.yaml` holds `network-equipment`,
which an operator sets to declare that the far end is a device CLI and not a
shell; the blacklist still applies to the command it builds.

- `ssh_ansible_adhoc` judges the module like an `ssh_exec` command. For a
  module that runs a command line (`command`, `shell`, `raw`, `script`,
  `expect` and their Windows or collection-qualified forms) the whitelist is
  matched against `args`. For every other module it is matched against the
  text `ansible-module <module> <args>` (`ansible-module <module>` without
  `args`), with the module spelled as the caller gave it. In strict and
  standard modes any other module, `cron` and `pip` included, must therefore
  be whitelisted explicitly, by a pattern that names `ansible-module`; a
  pattern written for a shell command line does not match it. The one
  exemption is `ping` without `args`. Permissive mode does not use the
  whitelist.
- `ssh_awx_adhoc_launch` follows the same rule as `ssh_ansible_adhoc`: a
  command module's `module_args` alone, any other module as
  `ansible-module MODULE ARGS`, `ping` without arguments exempt. Its `limit`
  (the play's host pattern) and `module_name` refuse Jinja, and `limit`
  refuses a leading `-`.

Beyond the whitelist, the Ansible tools refuse the following. This is a
literal scan of the text the tool receives, not a model of everything Ansible
evaluates, and it does not make a whitelisted or permitted module safe.

- Jinja delimiters (`{{`, `{%`, `{#`) in the `ssh_ansible_adhoc` module
  arguments, host pattern, module name and inventory; in the host pattern and
  inventory of `ssh_ansible_facts`; in the inventory, `limit`, `tags` and
  `skip_tags` of the playbook tools (`ssh_ansible_playbook`,
  `ssh_ansible_recap`, `ssh_ansible_run_background`) and in their
  `extra_vars` values; and in `vault_password_file` and `vault_id` of the
  ad-hoc and playbook tools. A bare expression that Ansible evaluates without
  delimiters (the `var` of `debug`, the `that` of `assert`) is not detected as
  such: only the whitelist stands between it and the control host in strict
  and standard modes.
- Ad-hoc `args` (`ssh_ansible_adhoc`, and `module_args` of
  `ssh_awx_adhoc_launch`, which AWX hands to the same Ansible parser) that
  Ansible would read as something else than the text the caller wrote:
  - text that starts with `{` once trimmed (Ansible's JSON form);
  - the escapes Ansible decodes by number or name: a backslash followed by
    `U` and 8 hexadecimal digits, `u` and 4, `x` and 2, or `N{`. The
    backslash is not paired, so `\\x41` is refused too. Other backslash
    sequences pass (`C:\Users`, `C:\x\y`, `\0` to `\7`);
  - the sequence `\=` anywhere, and any backslash when an Ansible word may
    start with `=` (the text starts with `=`, or holds a space or a line feed
    followed by `=`): with those, Ansible takes the decoded word (a `\n`
    turned into a real line feed) as the command line of a command module.
    A bare `=` or `==`, as in `[ "$a" = b ]`, passes when the text holds no
    backslash;
  - for a module that runs a command, a word (the text splits at any
    whitespace) that starts with `executable=`, `chdir=` or `stdin=`, which
    Ansible keeps as options of the module and not as part of its command.
    `creates=`, `removes=`, `warn=`, `stdin_add_newline=` and
    `strip_empty_ends=` stay allowed.
- A `become_user` or ad-hoc `user` that is not a plain user name. A name is
  `[A-Za-z_][A-Za-z0-9_.@-]{0,63}`, optionally preceded by a Windows domain
  (`[A-Za-z0-9][A-Za-z0-9_.-]{0,62}` and one backslash) and optionally
  followed by one `$` (a group managed service account), because Ansible
  pastes it unquoted into a shell line on the targets. The domain and the `$`
  stay inert in the `sudo` command line Ansible builds on a POSIX target: a
  backslash before a name character is read as that character, and a `$`
  followed by a space is a literal `$`.
- An `inventory` that starts with `-` (all tools that take one:
  `ssh_ansible_adhoc`, `ssh_ansible_facts`, `ssh_ansible_inventory` and the
  playbook tools).
- A `vault_password_file`, or a `vault_id` as a whole or the file after its
  first `@`, that starts with `-` or holds a control character; and a vault
  file path holding `$`, a `..` segment or a `~user` prefix, which Ansible
  expands or folds before it looks at the file while the check below would
  test the text as written. This covers `ssh_ansible_adhoc` and the playbook
  tools.

Two protections work on the command the tool builds, not on the arguments:

- **Inventory plugins.** When the caller names an `inventory`, the command
  starts with `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`, placed
  directly in front of the Ansible program (after any `cd`, and inside the
  `bash -c` of `ssh_ansible_run_background`). Ansible's default list also
  holds the `script` plugin, which runs any `-i` source the user can execute
  (every file of a directory) and `auto`, so the source the caller names is
  parsed as data and never run. Without an `inventory` argument the command is
  unchanged and the operator's configured inventory applies. This covers
  `ssh_ansible_adhoc`, `ssh_ansible_playbook`, `ssh_ansible_facts`,
  `ssh_ansible_inventory`, `ssh_ansible_recap` and
  `ssh_ansible_run_background`.
- **Vault password files.** Ansible runs a vault password file when any
  execute bit is set on it (following symlinks) and reads it as text
  otherwise. For each file the caller names (`vault_password_file`, and the
  file of a `vault_id`: the part after the first `@`, or the whole value
  without one; the sources `prompt` and `prompt_ask_vault_pass` ask the
  terminal and have no file), the command first runs a POSIX shell check, in
  the directory Ansible resolves the path from (after any `cd` of
  `working_dir`) and before Ansible starts. It stops with a message on stderr
  and exit status 2 unless the file is a regular file with no execute bit for
  anyone; the file passes only when `find` names it, so a missing or failing
  `find` refuses it. A leading `~/` is expanded by the shell as Ansible does. For `ssh_ansible_run_background`
  the check also runs in the foreground, before the background launch, so the
  call itself reports the refusal, and again inside the background shell. A
  vault script is configured in `ansible.cfg`, not through these arguments.
  This covers `ssh_ansible_adhoc`, `ssh_ansible_playbook`,
  `ssh_ansible_recap` and `ssh_ansible_run_background`.

By design, the playbook tools (`ssh_ansible_playbook`, `ssh_ansible_recap`,
`ssh_ansible_run_background`) run the playbook the caller names, in the
`working_dir` the caller names (and so with the `ansible.cfg` found there),
and `ssh_ansible_lint` lints the target the caller names. The whitelist does
not judge a playbook, its tasks, its roles or an `ansible.cfg`: they are files
on the control host, and what they run is limited by what the host's own
account may do. Keep playbooks and directories that an untrusted party can
write out of reach of these tools.

- **Standard** (default) and **Strict**: command tools need a whitelist match
  (the validator treats the two modes the same)
- **Permissive**: command tools run anything the blacklist does not match

### What This Project Does NOT Protect Against

- Compromise of the MCP client (Claude Code) itself
- Compromise of the SSH host being connected to
- Physical access to the machine running the bridge
- Side-channel attacks on the SSH transport (handled by the SSH library)
