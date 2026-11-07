# Security Policy

## Supported Versions

Only the latest major release gets security fixes.

| Version | Supported |
|---------|-----------|
| 7.x     | Yes       |
| < 7.0   | No        |

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
- **An `inventory`, an ad-hoc `user` or a `working_dir` that the operator did
  not list.** Ansible connects to every host the inventory names, with the SSH
  credentials of the account on the control host, logs in as the `user`, and
  reads the `ansible.cfg` of the working directory, which can set the
  inventory, the remote user, the keys and the plugin paths. So the operator
  chooses these values, in `hosts.<host>.ansible` of `config.yaml`: the
  `inventory` of `ssh_ansible_playbook`, `ssh_ansible_recap`,
  `ssh_ansible_run_background`, `ssh_ansible_adhoc`, `ssh_ansible_facts` and
  `ssh_ansible_inventory` must be equal to an entry of `inventories`, the
  `user` of `ssh_ansible_adhoc` to an entry of `remote_users`, and the
  `working_dir` of the three playbook tools to an entry of `working_dirs`.
  The comparison is on the exact string (case-sensitive, no trimming, no glob,
  no expansion): a value that only resolves to a listed one (`..`, `$VAR`,
  `~`, a symlink, another spelling of the same path) is refused, and only the
  listed text passes. What a listed entry names is the operator's choice and
  responsibility (see "Limits of this protection" under "Destination
  Arguments and Stored Credentials"). An absent or empty list refuses the
  argument. A call that leaves the argument out is not affected and uses
  `ansible.cfg`. The entries are checked when the configuration loads:
  - in every list: not empty, no control character, no leading `-`, no Jinja
    delimiter;
  - `remote_users`: a valid user name;
  - `working_dirs`: an absolute path with no `.` or `..` segment and no
    trailing `/`;
  - `inventories`: an entry with `,` is a host list and must not hold `/`;
    any other entry is a path, absolute, with no `$`, no `~`, no `.` or `..`
    segment and no trailing `/` (Ansible expands `$VAR` and `~` in an
    inventory path and joins a relative one to the current directory).

  The refusal names the allowed values and the key to edit, shows the value
  of the call escaped and cut to its first 120 characters, and is recorded in
  the audit log as a denied command.
- An `extra_vars` key (`ssh_ansible_playbook`, `ssh_ansible_recap`,
  `ssh_ansible_run_background`) that starts with `ansible_` or is one of
  Ansible's other special variable names: `delegated_vars`, `group_names`,
  `groups`, `hostvars`, `inventory_dir`, `inventory_file`,
  `inventory_hostname`, `inventory_hostname_short`, `omit`, `play_hosts`,
  `playbook_dir`, `role_name`, `role_names` and `role_path`. Ansible sets
  them itself and a connection plugin or the inventory may read them (the
  `ssh` plugin takes its host from `inventory_hostname`). The match is exact.
- A `vault_password_file`, or a `vault_id` as a whole or the file after its
  first `@`, that starts with `-` or holds a control character; and a vault
  file path holding `$`, a `..` segment or a `~user` prefix, which Ansible
  expands or folds before it looks at the file while the check below would
  test the text as written. This covers `ssh_ansible_adhoc` and the playbook
  tools.

Two protections work on the command the tool builds, not on the arguments:

- **Inventory plugins.** When the caller names an `inventory` without `,`, the
  command starts with `ANSIBLE_INVENTORY_ENABLED=host_list,yaml,ini,toml`, placed
  directly in front of the Ansible program (after any `cd`, and inside the
  `bash -c` of `ssh_ansible_run_background`). Ansible's default list also
  holds the `script` plugin, which runs any `-i` source the user can execute
  (every file of a directory) and `auto`, so the source the caller names is
  parsed as data and never run. When the `inventory` holds `,` (a host list),
  the command starts with `ANSIBLE_INVENTORY_ENABLED=host_list` alone:
  Ansible does not resolve such a value to a path, and the `host_list` plugin
  refuses it when a file or directory of that name exists, so no plugin reads
  a file named like the list. Ansible's vars plugins would still read the
  `group_vars` and `host_vars` of such a path, so the command also starts with
  a shell guard, in the working directory, that stops it with exit status 2
  and a message on stderr when a file, directory or symlink of that name
  exists (`ssh_ansible_run_background` runs it in the foreground too, before
  the launch). Without an `inventory` argument the command is
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
`ssh_ansible_run_background`) run the playbook the caller names, and
`ssh_ansible_lint` lints the target the caller names. They run in the
`working_dir` the caller names only when the operator listed that directory
in `hosts.<host>.ansible.working_dirs`; otherwise they run in the directory
the SSH session starts in, with the `ansible.cfg` found there, and the
operator's own inventory applies unless the call names a listed one. The
whitelist does not judge a playbook, its tasks, its roles or an `ansible.cfg`:
they are files on the control host, and what they run is limited by what the
host's own account may do. Keep playbooks and directories that an untrusted
party can write out of reach of these tools (see "Limits of this protection"
under "Destination Arguments and Stored Credentials"). `ssh_ansible_recap` and
`ssh_ansible_run_background` run a whole playbook like `ssh_ansible_playbook`,
so they are annotated destructive and go through the same confirmation, as
does `ssh_git_clone`.

- **Standard** (default) and **Strict**: command tools need a whitelist match
  (the validator treats the two modes the same)
- **Permissive**: command tools run anything the blacklist does not match

### Destination Arguments and Stored Credentials

A tool argument that chooses where a program connects must not cause a
credential of the target host (a password in an option file, a password file
or an environment variable; a token, certificate, key or configuration file;
a cloud profile) to be presented to that destination, nor read or write such
a file of the host. Three ways to keep this true:

- **Drop the argument,** or limit it to values that cannot name a destination
  or a credential file:

  - The Vault tools take no server address: the host's own `VAULT_ADDR`
    applies.

  - `ssh_aws_cli` takes no endpoint, profile, CA bundle or signing argument:
    it runs with the AWS identity and endpoint configured on the host
    (environment, `~/.aws`, instance role). `args` is split into words and
    each word is quoted on its own. An option must be one of a fixed list of
    resource selectors and paging options, matched exactly, because the AWS
    CLI reads any unambiguous prefix of a global option. The CLI may also
    read an allowed name as a longer option of the same operation; none of
    those chooses the endpoint, the profile, the signing or a file (checked
    against awscli 1.46.3). A word that is neither an option nor the value
    of one must be an `s3://` location with no `.` or `..` segment, and the
    operations that write an output file (`s3api
    get-object`, `lambda invoke`, `eks update-kubeconfig` and the like) are
    refused: the tool reads and writes no file of the host. Parameter values
    that the AWS CLI would load from a file or URL (`file://`, `fileb://`,
    `http://`, `https://`) are refused, and `--region` must be a region
    name. The services that read or write the identity of the host
    (`configure`, `sso`, `sso-oidc`, `login`, `logout`, `history`) are
    refused, and so are the operations that print or issue a credential or a
    bearer token (for example `sts get-session-token`, `sts assume-role`,
    `ecr get-login-password`, `s3 presign`, `eks get-token`,
    `iam create-access-key`, `apigateway get-api-keys` and the `lightsail`
    key pair, access-details and master-password operations).

  - The compose tools (`ssh_docker_compose`, `ssh_podman_compose`) accept
    only a local path for `file`. The compose client may read Git URLs,
    `oci://` references, `host:path` forms, `github.com/...` shorthands
    (version-dependent) and standard input in place of a file, and fetching
    one makes the Git or registry client of the host present its own
    credentials to a server the caller chose. `file` is therefore limited to
    `[A-Za-z0-9/._-]`, not starting with `-`, and anchored: absolute,
    starting with `./` or `../`, or a bare file name. The same client loads
    Git and OCI resources named by an `include:` of a compose file already on
    the host, so both tools put `COMPOSE_EXPERIMENTAL_GIT_REMOTE=false
    COMPOSE_EXPERIMENTAL_OCI_REMOTE=false` in front of the compose program.

  - `ssh_git_pull` accepts only the name of a remote configured in the
    repository (ASCII letters, digits, `.`, `-`, `_`, not starting with `.`
    or `-`), never a URL or a path. It requires a remote when a branch is
    given, because git reads the first positional argument as the
    repository.

  - `ssh_k8s_port_forward` binds loopback addresses only (`address` is
    `localhost` in lower case, `127.0.0.1`, `::1`, another loopback address,
    or a comma list of those). A Helm `kubeconfig` is accepted only from the
    system directories (`/etc/rancher/k3s/`, `/etc/rancher/rke2/`,
    `/etc/kubernetes/`, `/var/snap/microk8s/current/credentials/`,
    `/var/lib/k0s/pki/`) or as exactly `/root/.kube/config`,
    `~/.kube/config` or `$HOME/.kube/config`. Any other file of a `.kube`
    directory is refused, because a kubeconfig names the server and the
    credential files (`tokenFile`, client certificate, `exec` plugin) the
    client uses, and another tool can write such a file.

- **Tie the credential to the destination.**

  - The database tools (`ssh_db_query`, `ssh_db_dump`, `ssh_db_restore`) take
    a `db_host`. The credentials stored on the host (`~/.my.cnf`,
    `~/.mylogin.cnf`, `~/.pgpass`, `PGPASSWORD`, `PGSERVICE` and the like)
    are used for the local server only: `localhost`, a loopback address
    (`127.0.0.0/8`, `::1`, `::ffff:127.x.y.z`) or, for PostgreSQL, the two
    default socket directories. A call to any other server needs a
    `db_password` in the call, and the command the tool builds hides the
    stored sources from the client: the `unset` of the password variables, an
    option file or password file built from the call, and, for MySQL, a
    changed `HOME` and a client that reads that option file only, for
    PostgreSQL, a client certificate file that does not exist (`PGSSLCERT`).
    PostgreSQL clients always run with `-w` (never prompt for a password).
    `db_host` is one host name or address and nothing else (no list, no
    connection parameters), like the PostgreSQL `database`, which is refused
    when it is a connection string.

  - The Redis tools (`ssh_redis_cli`, `ssh_redis_info`, `ssh_redis_keys`)
    take a `redis_host`. The `REDISCLI_AUTH` (or `VALKEYCLI_AUTH`, for
    `valkey-cli`) of the SSH user is used for the local server only (no
    `redis_host`, `localhost` or a loopback address); for any other server
    the command starts with `unset REDISCLI_AUTH VALKEYCLI_AUTH &&`, so
    `redis-cli` sends no password unless the call gives a `redis_password`
    (read from standard input with `--askpass`, never `-a`). A Redis server
    without a password needs no argument. `redis_host` is one host name or
    address and nothing else.

  - `ssh_storage_mount` applies the same rule to network file systems. For
    `cifs`, `smb3`, `nfs`, `nfs4`, `ceph`, and for a mount with no type (or
    `auto`) of a `//server/share` or `host:path` device, the
    options that choose a credential source of the host are refused:
    `credentials`, `cred`, `cruid`, `multiuser`, `upcall_target`, `sec=` with
    a `krb5*`, `lkey*` or `spkm3` flavor, `xprtsec=mtls` (the certificate of
    `tlshd`), `secretfile`, `conf` and `key`. A `ceph` mount must give
    exactly one `secret=` whose value is a CephX key of at most 40 base64
    characters, because `mount.ceph` otherwise (or with a value it does not
    keep) takes the key of the client name from a keyring of the host. A
    quote character in `options` is refused, because the mount helpers do not
    read a quoted key or value as written. `none` is refused for a device of
    a network form, and so is a device with `@` when no type is fixed: both
    make `mount` try the types listed in `/etc/filesystems` (a bind or move
    mount, which runs no helper, is exempt). For `cifs`,
    `smb3` and a `//server/share` device the command starts with
    `unset PASSWD PASSWD_FD PASSWD_FILE PASSWD2 PASSWD2_FD PASSWD2_FILE USER &&`,
    the variables `mount.cifs` reads before `-o` (`USER` is its user name
    when the call gives none). Credentials given in the
    call (`username=`, `password=`, `domain=`, `secret=`, `sec=ntlmssp`,
    `xprtsec=tls`) are used.

  - The `ssh_ldap_*` tools bind with `-x` (a simple anonymous bind: no bind
    DN, no password, no SASL). The one credential of the host that can go out
    is the TLS client certificate named by `TLS_CERT` and `TLS_KEY` of a user
    `ldaprc`, or by `LDAPTLS_CERT` and `LDAPTLS_KEY`. It is presented only to
    a server of the host: an `ldapi://` socket, or `ldap://` or `ldaps://`
    with `localhost` or a loopback address. For any other `uri` the command
    starts with `LDAPTLS_CERT= LDAPTLS_KEY=`, which overrides every `ldaprc`
    and every ambient value. `uri` is one `scheme://host[:port]` and nothing
    else (no list, no user information, no path; an `ldapi` socket path is
    %-escaped).

- **Hide the credential source from the program.**

  - The webhook tools (`ssh_webhook_send`, `ssh_notify`) take a URL and need
    no credential of the host: `curl` runs with `-q` as its first argument,
    so `~/.curlrc` (and `$CURL_HOME/.curlrc`) is not read and none of its
    `user`, `header`, `oauth2-bearer` or `netrc` lines reaches that URL. A
    proxy comes from the `https_proxy` environment variable. The probe of
    `ssh_k8s_port_forward` and the request of `ssh_traefik_introspect` run
    `curl -q` for the same reason.

  - `ssh_git_clone` and `ssh_git_pull` start git with `-c http.extraHeader=`,
    so a header that the git configuration of the host applies to every
    server is not sent to the server the caller picked, and with
    `unset GIT_SSL_CERT GIT_SSL_KEY GIT_SSL_CERT_PASSWORD_PROTECTED &&`, so
    the client certificate of those variables is not presented either.
    Credentials that git keys by host stay in effect for the server they
    name: credential helpers (`store`, `cache`, `libsecret`, a manager),
    `~/.netrc` `machine` entries and `http.<url>.extraHeader`.

  - `ssh_git_clone` writes only to a visible, absolute path, and is annotated
    destructive (it goes through the confirmation gate). A `destination` must
    start with `/`, and none of its components, split on `/` and `\`, may
    start with `.` (`.ssh`, `.config`, `.git`, `..`); `~` is not expanded.
    Without `destination`, the directory name must not start with `.`, and it
    is the one git computes (`git_url_basename` in git's `dir.c`: scheme,
    user information, a trailing `/` and `/.git`, a `:port`, then what
    follows the last `/` or `:`, and a `.git` suffix; `\` is not a
    separator), so `https://host/r/.git` derives `r` and is accepted, while
    `https://host/r/.cfg` and `host:.x` are refused. A URL with a byte
    `<= 0x20` or `0x7f` is refused when `destination` is absent, and so is a
    URL from which git derives no name. A git older than 2.6 skips neither the
    scheme nor the user information, so the name it would derive is checked
    too. A clone therefore does not create or
    fill the default configuration locations under the home directory of the
    SSH user, which all sit below a hidden component. A hidden target needs
    `ssh_exec`, under its own policy.
  - All seven git tools (`ssh_git_status`, `ssh_git_log`, `ssh_git_diff`,
    `ssh_git_pull`, `ssh_git_clone`, `ssh_git_branch`, `ssh_git_checkout`) run
    git with `-c safe.bareRepository=explicit`, so git does not discover a
    bare repository by itself (one placed inside a working tree, for example
    by a clone, would otherwise be used with its own configuration). A bare
    repository given as `path` fails; cloning from or pulling from a bare
    remote does not.

The tools `ssh_mysql_query`, `ssh_postgresql_query`, `ssh_mysql_status` and
`ssh_postgresql_status` take no host and no password: they connect to the
local server with the stored credentials.

Limits of this protection:

- The stored credentials are used for whatever listens on the loopback address
  and port the call names (`db_port` is the caller's choice; `redis_port` for
  the Redis tools; the port of an `ldap://` or `ldaps://` `uri` for the LDAP
  tools), so a process able to listen on the host's loopback interface
  receives them.
- Kerberos/GSSAPI tickets held by the SSH user are not hidden from another
  server. The one option a tool refuses is `sec=krb5*` of `ssh_storage_mount`,
  and that does not close the NFS routes: when `sec=` is absent the NFS
  client negotiates a flavor with the server, which can be Kerberos, and when
  the host has an `/etc/krb5.keytab` NFSv4 lease management uses its `host/`
  or `nfs/` principal whatever `sec=` says.
- The git tools hide only an unscoped `http.extraHeader` and the `GIT_SSL_*`
  client certificate variables. An unscoped `http.sslCert` and `http.sslKey`
  in the git configuration (git has no per-command reset for them), a
  credential helper that answers for any host, a `~/.netrc` `default` entry,
  `GIT_ASKPASS`, `SSH_ASKPASS`, `core.sshCommand`, `GIT_SSH_COMMAND` and the
  `ssh` configuration (`ForwardAgent`, `StrictHostKeyChecking`,
  `IdentityFile` under `Host *`) are configuration of the host, not hidden by
  the tools: key them to the servers the host is meant to reach.
  `ssh_git_clone` can still be pointed at any repository of a forge for which
  the host holds a token or deploy key keyed to that forge, and a header keyed
  to a server (`http.<url>.extraHeader`) still goes to it. When the git
  configuration holds an unscoped `extraHeader` followed by a scoped one that
  matches the destination, both are sent. `branch` of `ssh_git_pull` is still
  a free refspec: it can name a local ref, not a server.
- The Ansible allow-lists choose where Ansible connects and with which
  configuration; they do not judge what a file does. A playbook or an
  `ansible.cfg` that the caller can write is still code on the control host
  (`add_host`, `delegate_to`, a plugin path, a callback), and the whitelist
  does not see inside it. A listed inventory file or directory, and a listed
  working directory, must not be writable by the SSH account or by another
  tool of the bridge (`ssh_file_write`, a clone, an upload): a caller that can
  change a listed inventory can change where Ansible connects, and one that can
  write an `ansible.cfg` or a playbook in a listed directory can run it. A
  listed path must exist: one that is missing is a path the caller may create.
  Matching is on the string in `config.yaml`, not on the file behind it:
  keep listed paths free of symlinks that others can repoint.
- The host-list guard checks the working directory when the command starts.
  A path of that name created between the check and Ansible's read is not
  seen; its `group_vars` and `host_vars` would load for the implicit
  `localhost` and the `all` group.
- A call that passes the bridge `sudo` or `sudo_user` parameters runs Ansible
  as that account on the control host: with its SSH keys, its `ssh_config`
  and the `ansible.cfg` it finds. The lists in `hosts.<host>.ansible` do not
  change that. This is documented, not refused: grant `sudo` on a control host
  knowing which account it reaches.
- The AWX tools (`ssh_awx_*`, including `ssh_awx_adhoc_launch`) are governed by
  AWX, not by `hosts.<host>.ansible`: the inventories, credentials and
  projects of a job are those of AWX and of the AWX account the bridge uses,
  and AWX permissions decide what they may use.
- Git older than 2.38 ignores `safe.bareRepository`: on such a host the git
  tools still discover a bare repository by themselves, and nothing is
  refused. Check `git --version` on the hosts you use them on.
- The `ssh_git_clone` destination rule is read on the text of the path and of
  the URL. It keeps a clone out of the default configuration locations below
  the home directory; it does not cover:
  - paths that the account's own git configuration names and that need not be
    hidden: `core.hooksPath`, `include.path` and `includeIf.<condition>.path`,
    `init.templateDir`, `core.excludesFile` and `core.attributesFile`, and an
    `XDG_CONFIG_HOME` that points outside a hidden directory (git and other
    tools then read their files below it);
  - symlinks: a visible path whose parent or target is a symlink to a hidden
    or configuration directory is accepted, and the clone follows it (git
    fills an empty directory, symlink targets included);
  - non-hidden directories that mean something to the account, such as
    `$HOME/bin` when `PATH` lists it;
  - empty system directories, when the call runs under `sudo`: an absolute
    `destination` that exists, is empty and is writable by the target user.

  Do not point such settings at a visible path that other tools can write,
  keep the directories you clone into free of symlinks that others can
  create, and grant `sudo` on a git tool knowing it.
- `ssh_aws_cli` runs with the AWS identity of the host and reads whatever
  that identity can read, stored secrets included (`secretsmanager
  get-secret-value`, `ssm get-parameter`): any API call that identity may make
  through the permitted options is made. The refused services and operations
  are those that print or issue a credential or a token; the list is not a
  model of everything an identity can read.
- For the Kubernetes tools, `~/.kube/config` is accepted as a Helm
  `kubeconfig`, because the client reads it by default: a file written there
  by another tool still points Helm at that file's server. The system
  directories are taken to be root-owned. A `KUBECONFIG` or `~/.kube/config`
  set in the environment of the SSH user applies to every `ssh_k8s_*` tool
  and is the operator's configuration. The probe of `ssh_k8s_port_forward`
  still honours `http_proxy`, and a loopback port is reachable by the other
  local users. `ssh_k8s_kubeconfig_generate` prints a `server_url` named by
  the caller with a new token in its output; it connects to nothing.
- The `ssh_ldap_*` tools without `uri` use the server, and so the client
  certificate, of the host's own `ldap.conf`. `TLS_CACERT` and `TLS_REQCERT`
  still apply to every server, so a relaxed `TLS_REQCERT` on the host is not
  overridden.
- The compose tools do not judge the content of a compose file, in the same
  way as the playbook tools above. The Git and OCI loaders are off, but the
  registry credentials used to pull an image (`~/.docker/config.json`) are
  not hidden, and the switches act only on compose versions that read them
  (confirmed on v5.7.0; `docker-compose` v1 and `podman-compose` have no such
  loader).
- `ssh_storage_mount` filters the options of the file system types listed
  above; the options of other network file system types are not examined.
- `redis-cli` connects without TLS: a `redis_password` crosses the network in
  clear to a remote server. Like `db_password`, it is part of the command line
  the remote shell runs and of the command text in the bridge's audit log.
- `ssh_db_restore` runs its input file as a client script: `psql` backslash
  commands act on the host and can open another connection, and the file's
  statements go to the server named by `db_host`.

### What This Project Does NOT Protect Against

- Compromise of the MCP client (Claude Code) itself
- Compromise of the SSH host being connected to
- Physical access to the machine running the bridge
- Side-channel attacks on the SSH transport (handled by the SSH library)
