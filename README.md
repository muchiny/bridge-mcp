# Bridge MCP

<!-- markdownlint-disable MD033 -->
<div align="center">

<img src="dxt/icon.svg" alt="Bridge MCP" width="96" height="96">

[![CI](https://github.com/muchiny/bridge-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/muchiny/bridge-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/muchiny/bridge-mcp?style=flat-square&logo=rust)](https://github.com/muchiny/bridge-mcp/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/muchiny/bridge-mcp/total?style=flat-square)](https://github.com/muchiny/bridge-mcp/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2026--07--28-blueviolet?style=flat-square)](https://modelcontextprotocol.io)

**An MCP server that lets an AI assistant manage your machines over SSH — safely.**
476 tools in 77 groups, a command whitelist and blacklist, secret redaction, an
audit log, and a confirmation before anything destructive.

```
MCP client (Claude Code, …)  ◄── MCP over stdio ──►  bridge-mcp  ◄── SSH ──►  your hosts
```

</div>

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start) — from download to a first tool call
- [Using it from an MCP client](#using-it-from-an-mcp-client)
- [Upgrading to 4.0.0](#upgrading-to-400)
- [Examples](#examples)
- [Configuration reference](#configuration-reference)
- [Tool parameters](#tool-parameters)
- [Tool Groups](#tool-groups)
- [MCP Prompts & Resources](#mcp-prompts--resources)
- [CLI](#cli)
- [Daemon Mode](#daemon-mode)
- [Protocol Support](#protocol-support)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Features

- **476 tools, 77 groups** — Linux, Windows, Docker, Kubernetes/K3s, Podman, AWX, Ansible, databases, LDAP, network equipment, certificates and more. Only 8 core groups are on by default; you opt into the rest.
- **SSH everywhere, more transports when built in** — every build speaks SSH. WinRM, PSRP (PowerShell Remoting), Telnet, Kubernetes exec, serial, AWS SSM, Azure and GCP are cargo features. **The release binaries and the Docker image are built with `--features full`: they are SSH only** (see [Install](#1-install)).
- **Security first** — command whitelist and blacklist, built-in secret-redaction patterns plus entropy detection on every output, an audit log, and a confirmation before any destructive tool runs (on by default, over MCP and on the CLI).
- **Token-efficient output** — server-side `jq_filter` / `yq_filter` / `columns` / `limit`, TSV output (60-80% fewer tokens on lists), pagination of truncated output with `ssh_output_fetch`, per-client size limits.
- **Two ways to list tools** — `full` (default: every enabled tool's schema) or `progressive` (four meta-tools to search, describe and call tools on demand).
- **MCP 2026-07-28 (Modern) only** — `server/discover` opens the connection; a pre-Modern client sending `initialize` gets `-32022`. See [Protocol Support](#protocol-support).
- **CLI + MCP** — every tool is also a CLI command (`bridge-mcp tool <name> key=value`), for scripts and for agents that prefer a shell.
- **Daemon mode** — a Unix-socket daemon keeps SSH connections warm between CLI calls.
- **10,000+ tests** — `#![forbid(unsafe_code)]`, Rust 2024 edition, strict clippy.

---

## Quick Start

Five steps, about five minutes. You need: a Linux or macOS machine to run
bridge-mcp on (there is no Windows build of the bridge itself), and SSH key
access to at least one host.

### 1. Install

```bash
# Linux x86_64. Other builds: bridge-mcp-linux-arm64, bridge-mcp-macos-arm64, bridge-mcp-macos-x86_64
curl -fsSLO https://github.com/muchiny/bridge-mcp/releases/latest/download/bridge-mcp-linux-x86_64.tar.gz
curl -fsSLO https://github.com/muchiny/bridge-mcp/releases/latest/download/bridge-mcp-linux-x86_64.tar.gz.sha256
sha256sum -c bridge-mcp-linux-x86_64.tar.gz.sha256   # macOS: shasum -a 256 -c …
tar xzf bridge-mcp-linux-x86_64.tar.gz
sudo install -m 0755 bridge-mcp /usr/local/bin/
bridge-mcp --version
```

> **Windows hosts over WinRM or PSRP need a source build.** The release
> binaries and the Docker image are SSH only: a config with `protocol: winrm`
> or `protocol: psrp` fails to load in them. Windows hosts that run OpenSSH work
> with any build (`os_type: windows`). For WinRM/PSRP, do step 2 first, then:
>
> ```bash
> git clone https://github.com/muchiny/bridge-mcp && cd bridge-mcp
> make install      # Rust 1.99+; builds --features full,winrm,psrp into ~/.local/bin/bridge-mcp
> ```
>
> `make install` refuses to install a binary that cannot load your config, which
> is why the config comes first.

<details>
<summary>Docker, Claude Code plugin, Claude Desktop bundle</summary>

**Docker** (`linux/amd64`, SSH only). The image runs `bridge-mcp` as user
`bridge` (home `/home/bridge`) and contains no config. Mount yours, and write
key paths as the container sees them:

```bash
docker pull ghcr.io/muchiny/bridge-mcp:latest
docker run -i --rm \
  -v ~/.config/bridge-mcp:/home/bridge/.config/bridge-mcp:ro \
  -v ~/.ssh:/home/bridge/.ssh:ro \
  ghcr.io/muchiny/bridge-mcp:latest serve
# in config.yaml: auth: { type: key, path: /home/bridge/.ssh/id_ed25519 }
```

The mounted config and key must be readable by the container user and keep
their strict modes (`0600`).

**Claude Code plugin.** It adds the `/bridge-mcp:bridge` and
`/bridge-mcp:discover` skills and a session hook that downloads the release
binary when `bridge-mcp` is not on your `PATH`, and it registers the MCP
server itself — skip step 4's `claude mcp add`, or you get the server twice. It
uses your default config path (step 2).

```bash
claude plugin marketplace add muchiny/bridge-mcp
claude plugin install bridge-mcp@muchiny
```

**Claude Desktop bundle.** Each release also ships `.dxt` and `.mcpb` bundles,
one per platform. If yours does not install, use the JSON configuration in
step 4 instead.

</details>

### 2. Write a config

bridge-mcp reads one YAML file:

| Platform | Default path |
|---|---|
| Linux | `~/.config/bridge-mcp/config.yaml` (or `$XDG_CONFIG_HOME/bridge-mcp/config.yaml`) |
| macOS | `~/Library/Application Support/bridge-mcp/config.yaml` |
| Any | the path given with `bridge-mcp --config <path> …` |

A complete starting config (Linux path shown):

```bash
mkdir -p ~/.config/bridge-mcp
cat > ~/.config/bridge-mcp/config.yaml <<'YAML'
hosts:
  my-server:                        # the name you pass as host=my-server
    hostname: 192.168.1.100
    user: admin
    auth:
      type: key
      path: ~/.ssh/id_ed25519       # must exist, chmod 600
    description: "My server"

security:
  mode: standard                    # the default: ssh_exec runs only whitelisted commands
  whitelist:
    - '^(uptime|hostname|whoami|df -h|free -m)$'
    - '^(ls|cat|head|tail|grep|journalctl)( [^;&|`$<>]*)?$'
YAML
chmod 600 ~/.config/bridge-mcp/config.yaml
```

Three rules the loader enforces, each of which stops the server with exit code 5:

- **The file must be private** — no group-write and no access for others (`0600` or `0640`).
- **Every key file must exist and be `0600`** (or `0400`).
- **Every key must be spelled exactly** — unknown keys are rejected, not ignored.

And one the SSH layer enforces: **host keys are checked strictly by default.**
Connect once by hand so the host is in `~/.ssh/known_hosts`:

```bash
ssh admin@192.168.1.100 true
```

> **Why a whitelist?** `ssh_exec` runs any command you give it, so in the
> default `standard` mode it only runs commands that match a `whitelist` entry —
> with an empty whitelist it refuses everything. The specialised tools
> (`ssh_metrics`, `ssh_service_status`, `ssh_docker_ps`, …) build their own
> commands and are checked against the blacklist only. Anchor every entry
> (`^…$`): the whole command line is matched, so `^ls` alone would also accept
> `ls; rm -rf ~`. `mode: permissive` drops the whitelist check entirely.

### 3. Check it from the shell

```bash
bridge-mcp validate                                          # config loads? prints host and tool counts
bridge-mcp tool ssh_metrics host=my-server 'metrics=["load","memory"]'   # SSH and auth work?
```

`validate` opens no connection; `ssh_metrics` does. If either fails, see
[Troubleshooting](#troubleshooting).

### 4. Connect your MCP client

**Claude Code:**

```bash
claude mcp add --scope user ssh-bridge -- bridge-mcp serve
claude mcp list          # ssh-bridge should read ✔ Connected
```

Add `--config /absolute/path/config.yaml` before `serve` for a non-default
config. Everything after `--` is the server's command line.

> **Connected but no tools?** bridge-mcp only speaks MCP 2026-07-28. Recent
> Claude Code negotiates it by default (its changelog says so from 2.1.292).
> Older versions open with the Legacy handshake and see zero tools: set
> `MCP_PROTOCOL_NEGOTIATION=auto` in **Claude Code's** environment — the `env`
> block of `~/.claude/settings.json` (or a project's `.claude/settings.json`), or
> `export` it before starting `claude` —
> then restart. Passing it with `claude mcp add -e` sets it for bridge-mcp,
> which ignores it.

**Claude Desktop and other stdio clients** — add a server entry (for Claude
Desktop on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ssh-bridge": {
      "command": "/usr/local/bin/bridge-mcp",
      "args": ["serve"]
    }
  }
}
```

Use the absolute path: desktop apps do not inherit your shell's `PATH`. The
client must speak MCP 2026-07-28 — a client that opens with `initialize` gets
`-32022 Unsupported protocol version` and no tools. If yours does not yet,
**v1.20.0** is the last release that speaks the Legacy handshake (2.x was never
published). The CLI (`bridge-mcp tool …`) works either way.

### 5. Use it

Ask your assistant: *"What is the load and memory use on my-server?"* It calls
`ssh_metrics` for you. From here:

- Turn on the tool groups you need (Docker, Kubernetes, Windows, …) — see
  [Enabling tool groups](#enabling-tool-groups).
- Read [Destructive tools](#destructive-tools-and-confirmation) before
  relying on confirmations: they depend on your client.

---

## Using it from an MCP client

### What the client sees

| `tool_groups.listing` | `tools/list` returns | Use it when |
|---|---|---|
| `full` (default) | every tool of the enabled groups (43 with the defaults), plus the four meta-tools below | few groups enabled; the model sees every schema up front |
| `progressive` | only the four meta-tools | many groups enabled; schemas are fetched on demand instead of costing tokens in every session |

```yaml
tool_groups:
  listing: progressive
```

The four meta-tools, available in both modes:

| Tool | Arguments | Purpose |
|---|---|---|
| `mcp_list_tool_groups` | — | Enabled groups with their tool counts |
| `mcp_search_tools` | `query` (required), `group`, `limit` (default 20, max 200) | Keyword search over enabled tools, with read-only / destructive hints |
| `mcp_describe_tool` | `name` | One tool's full schema, output kind and reduction strategy |
| `mcp_call_tool` | `name`, `arguments` | Calls any enabled tool by name — the tool's own confirmation and filters apply |

Groups that are not enabled are invisible to all four.

### Enabling tool groups

Only `core`, `file_ops`, `directory`, `process`, `monitoring`, `network`,
`systemd` and `sessions` are on by default. Turn others on, or defaults off,
then restart the MCP server (reconnect it in your client):

```yaml
tool_groups:
  groups:
    docker: true
    kubernetes: true
    journald: true
    sessions: false     # turn a default group off
```

Names are listed under [Tool Groups](#tool-groups). **A misspelled group name is
silently ignored**, so check with `bridge-mcp list-tools --groups-only`. Calling
a tool whose group is off returns "registered but its group … is not enabled".

### Destructive tools and confirmation

45 tools are annotated destructive (`destructiveHint: true`), **`ssh_exec`
among them**: `ssh_file_write`, `ssh_process_kill`, `ssh_service_stop`,
`ssh_k8s_delete`, `ssh_helm_rollback`, `ssh_win_service_stop`, … With
`security.require_elicitation_on_destructive: true` (the default):

- **Over MCP**, the server asks the client to confirm before running the tool
  (the 2026-07-28 *elicitation* round trip). A client that does not declare the
  `elicitation` capability gets a refusal saying so — the tool never runs
  unconfirmed. Going through `mcp_call_tool` does not bypass this.
- **On the CLI**, `bridge-mcp tool` prompts `Proceed? [y/N]` on a terminal.
  Without a terminal (scripts, CI) it refuses with exit code 4 unless you pass
  `--yes`. Every decision is written to the audit log.
- **Over HTTP** (`serve-http`), destructive tools are refused outright.

`ssh_exec_multi`, `ssh_session_exec` and `ssh_pty_exec` also run commands you
write but are not annotated destructive, so they are never asked about — the
whitelist is their only gate.

The blacklist is checked **after** the confirmation: a blacklisted command
asks, then is refused anyway. The built-in blacklist denies `systemctl stop` and
`systemctl disable`, so `ssh_service_stop` (after asking) and
`ssh_service_disable` are refused unless you replace the blacklist.

Setting `require_elicitation_on_destructive: false` turns confirmations off for
MCP **and** the CLI. Don't, unless every caller is trusted.

### Output size

Most tools take filters that run on the server, before truncation — see
[Tool parameters](#tool-parameters). Output past `max_output` (default 40,000
characters; Claude clients get 80,000) is cut, and over MCP the result carries
an `output_id`: `ssh_output_fetch output_id=… offset=…` returns the rest.
`save_output=/path` writes the full output to a file **on the machine running
bridge-mcp**.

---

## Upgrading to 4.0.0

4.0.0 changes behaviour that scripts and configs rely on. The protocol does not
change (still MCP 2026-07-28 only). Read the
[`### BREAKING` list in the changelog](CHANGELOG.md#400---2026-10-16) first; the
items most people hit:

- **Configs that used to load may not:** sanitizer patterns over 512 bytes, more
  than 50 of them, or a set that does not compile together; `ssh_net_equip_config`
  now requires the host to be tagged `network-equipment`.
- **Undeclared arguments are refused**, over MCP and on the CLI (exit 1), instead
  of being dropped — a typo like `jq_fitler=` used to return unfiltered output.
- **A failed remote command is reported:** `bridge-mcp tool` exits 6, and the MCP
  result carries `isError: true` for tools whose command the bridge built.
- **Destructive tools prompt on the CLI** (exit 4 without a terminal; `--yes` for scripts).
- **`audit.log` format and the library API changed** — see the changelog.

---

## Examples

CLI calls; the same tools are what your MCP client calls. Global flags go
**before** the first `key=value`.

**Diagnose a Linux service** (`systemd` is on by default; `journald` is not):

```bash
bridge-mcp tool ssh_service_status host=web1 service=nginx
bridge-mcp tool ssh_service_logs   host=web1 service=nginx lines=200
bridge-mcp tool ssh_journal_query  host=web1 unit=nginx priority=err since="-1h"
```

**Inspect Kubernetes with a fraction of the tokens** (enable `kubernetes`). Ask
kubectl for JSON, filter it on the server, return TSV:

```bash
bridge-mcp --jq '.items[] | [.metadata.name, .status.phase, .spec.nodeName]' --output-format tsv \
  tool ssh_k8s_get host=k8s resource=pods namespace=default output=json
bridge-mcp tool ssh_k8s_describe host=k8s resource=pod name=api-7d-xyz namespace=default
bridge-mcp tool ssh_k8s_logs     host=k8s pod=api-7d-xyz container=app tail=100
```

**Windows and Linux from one CLI** (enable `windows_services`, `windows_events`,
`iis`; the host needs `os_type: windows`, and WinRM/PSRP need a
[source build](#1-install)):

```bash
bridge-mcp tool ssh_service_status     host=web1 service=postgres
bridge-mcp tool ssh_win_service_status host=appsrv name=W3SVC
bridge-mcp tool ssh_win_event_query    host=appsrv log=System count=20
```

**Scripted, audited change.** `ssh_helm_rollback` is destructive: on a terminal
it asks, in a script it needs `--yes`, and the audit log records the decision,
the arguments, the sanitized output and the exit code:

```bash
bridge-mcp --yes tool ssh_helm_rollback host=k8s release=api revision=7
```

---

## Configuration reference

One YAML file, looked up in this order:

1. `--config <path>` / `-c <path>` (a global flag; every subcommand accepts it);
2. `<config_dir>/bridge-mcp/config.yaml` — `~/.config/bridge-mcp/` on Linux (`$XDG_CONFIG_HOME` if set), `~/Library/Application Support/bridge-mcp/` on macOS;
3. `<config_dir>/mcp-ssh-bridge/config.yaml`, the location before the rename, used only when (2) does not exist.

No environment variable selects the file. Every subcommand loads and validates
it before doing anything, and exits **5** if it cannot. `bridge-mcp validate`
checks a file without contacting any host; `bridge-mcp config-diff` shows what
it changes from the defaults. [`config/config.example.yaml`](config/config.example.yaml)
is a commented example of nearly every key.

File-level rules:

- **Unknown keys are rejected** at every level — a typo stops the server rather than being ignored.
- **Permissions:** no group-write, no access for others (`0600` or `0640`). Key files: `0600` or `0400`.
- **No `${VAR}` interpolation** — `${WIN_PASSWORD}` is sent as those exact characters.
- **`~` is expanded** only in `hosts.*.auth.path` (key auth), `audit.path` and `ssh_config.path`.
- **Hot reload:** `bridge-mcp serve` watches the file. `security.mode`, `whitelist` and `blacklist` apply live; `security.sanitize` needs a restart. `serve-http` does not watch it.
- **Size:** at most 1 MiB, 50 levels of nesting, 100 anchors, 1,000 aliases, 10,000 nodes.

Top-level sections: `hosts` (required), `security`, `limits`, `audit`,
`sessions`, `tool_groups`, `ssh_config`, `http`, `awx`, `rbac`. There is no
`recording:` section — session recording is driven by the `recording` tool
group and the `MCP_RECORDING_KEY` environment variable — and OpenTelemetry is
configured with `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_SERVICE_NAME`.

### `hosts.<alias>`

At least one host is required (hosts imported through `ssh_config` count).

| Key | Values | Default | What it does |
|---|---|---|---|
| `hostname` | string, required | — | Address to connect to |
| `user` | string, required | — | Remote login user |
| `auth` | map, required | — | How to authenticate — see the next table |
| `port` | integer | `22` | TCP port. Not remapped for WinRM/PSRP: set `5985` or `5986` yourself |
| `description` | string | — | Free text shown to the model in the host list |
| `host_key_verification` | `strict`, `acceptnew`, `"off"` | `strict` | `strict` refuses hosts missing from `~/.ssh/known_hosts`; `acceptnew` records them on first use and refuses a changed key; `"off"` skips the check (testing only — quote it, YAML reads a bare `off` as a boolean). Lowercase only: `AcceptNew` is rejected |
| `proxy_jump` | alias of another host | — | Tunnels SSH through that host (bastion). Not with `socks_proxy`, not on WinRM/PSRP hosts |
| `socks_proxy` | map: `hostname` (required), `port` (`1080`), `version` (`socks5`/`socks4`, default `socks5`), `username`, `password` | — | Tunnels SSH through a SOCKS proxy |
| `sudo_password` | string | — | Sent to `sudo` on stdin (never on the command line), over SSH only. Without it, `sudo=true` needs passwordless sudo |
| `tags` | list of strings | `[]` | Free-form labels. `network-equipment` is required by `ssh_net_equip_config` |
| `os_type` | `linux`, `windows` | `linux` | Selects command semantics and which tools accept the host. Not inferred from `protocol` |
| `shell` | `posix`, `cmd`, `powershell` (alias `pwsh`) | `posix` on Linux, `cmd` on Windows | Shell used for escaping |
| `protocol` | `ssh`; `winrm`, `psrp`, `telnet`, `k8sexec`, `serial`, `ssm`, `azure`, `gcp` with the matching cargo feature | `ssh` | Transport. Release binaries only have `ssh` |
| `winrm_use_tls` | bool (feature `winrm`) | `true` only on port `5986` | HTTPS or HTTP for WinRM/PSRP |
| `winrm_accept_invalid_certs` | bool (feature `winrm`) | `false` | Accept self-signed certificates |
| `winrm_operation_timeout_secs` | integer (feature `winrm`) | `60` | WS-Management operation timeout |
| `winrm_max_envelope_size` | integer (feature `winrm`) | `153600` | Maximum SOAP envelope, bytes |
| `retry` | map | — | Accepted but not used in 4.0.0; use `limits.retry_*` |

**`auth`** is a map tagged by `type`:

| `type` | Other keys | Notes |
|---|---|---|
| `key` | `path` (required), `passphrase` | Recommended. The file must exist and be `0600`/`0400` |
| `agent` | — | Uses `SSH_AUTH_SOCK` |
| `password` | `password` (required) | SSH password. On WinRM/PSRP this is HTTP Basic — use TLS |
| `ntlm` | `password` (required), `domain` | WinRM/PSRP only (feature `winrm`) |
| `certificate` | `cert_path`, `key_path` (both required, PEM, not `~`-expanded) | WinRM/PSRP only (feature `winrm`) |
| `kerberos` | — | Accepted, but no current build can connect with it |

`key` and `agent` are rejected on WinRM/PSRP hosts.

<details>
<summary><strong>Host examples: bastion, SOCKS proxy, Windows, WinRM, sudo, network equipment</strong></summary>

```yaml
hosts:
  bastion:
    hostname: bastion.example.com
    user: admin
    auth: { type: agent }

  internal-db:                      # reached through the bastion
    hostname: 10.0.0.5
    user: deploy
    proxy_jump: bastion
    auth: { type: key, path: ~/.ssh/id_ed25519 }

  behind-proxy:
    hostname: 10.0.0.50
    user: deploy
    socks_proxy: { hostname: proxy.corp.com, port: 1080, version: socks5 }
    auth: { type: key, path: ~/.ssh/id_ed25519 }

  windows-dc:                       # Windows with OpenSSH: works with any build
    hostname: 192.168.1.200
    user: Administrator
    os_type: windows
    shell: powershell
    auth: { type: key, path: ~/.ssh/id_ed25519 }

  windows-app:                      # WinRM over HTTPS: needs a --features winrm build
    hostname: 192.168.1.201
    port: 5986
    user: Administrator
    protocol: winrm
    os_type: windows
    auth: { type: ntlm, password: "change-me", domain: CORP }

  prod-server:
    hostname: 192.168.1.100
    user: deploy
    sudo_password: "your-sudo-password"   # used by tools called with sudo=true
    auth: { type: key, path: ~/.ssh/id_ed25519 }

  core-switch:
    hostname: 10.0.0.2
    user: netadmin
    tags: [network-equipment]       # required by ssh_net_equip_config
    auth: { type: password, password: "change-me" }
```

</details>

### `security`

| Key | Values | Default | What it does |
|---|---|---|---|
| `mode` | `strict`, `standard` (alias `normal`), `permissive` | `standard` | `strict` and `standard` (identical in 4.0.0): free-form commands must match the whitelist. `permissive`: only the blacklist is checked |
| `whitelist` | list of regexes | `[]` | Applies to free-form command tools: `ssh_exec`, `ssh_exec_multi`, `ssh_session_exec`, `ssh_canary_exec`, `ssh_rolling_exec`, `ssh_fleet_diff`. Matched against the whole command line — anchor with `^…$` |
| `blacklist` | list of regexes | 32 built-in patterns | Checked for **every** tool; a match is denied. **Setting it replaces the built-in patterns** (`rm -rf /`, `mkfs`, `dd if=`, `reboot`, `shutdown`, `systemctl stop/disable`, `curl … \| sh`, `Remove-Item -Recurse`, `diskpart`, …) — copy them from `default_blacklist` in [`src/config/types.rs`](src/config/types.rs) if you want to extend them |
| `require_elicitation_on_destructive` | bool | `true` | Confirmation before destructive tools, over MCP and on the CLI — see [Destructive tools](#destructive-tools-and-confirmation) |
| `sanitize` | map | see below | Secret masking in tool output |
| `sanitize_patterns` | list of regexes | `[]` | Legacy masking patterns, replaced with `[REDACTED]`. Count toward the `sanitize.custom_patterns` limits |

**`security.sanitize`:**

| Key | Values | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `true` | Masks secrets in every tool output |
| `custom_patterns` | list of `{pattern, replacement, description}` | `[]` | Extra regexes; `replacement` defaults to `[REDACTED]` and accepts `$1` groups. At most 50 patterns (with `sanitize_patterns`), 512 bytes each, and the set must compile together, or the config does not load |
| `disable_builtin` | list of categories | `[]` | Turns off built-in families: `ansible`, `aws`, `azure`, `certificates`, `database`, `discord`, `docker`, `gcp`, `generic`, `github`, `gitlab`, `hashicorp`, `jwt`, `k3s`, `kubeconfig`, `openai`, `slack` |
| `entropy_detection` | bool | `true` | Also masks high-entropy tokens no pattern matched |
| `entropy_threshold` | number, 0–8 | `4.5` | Bits per character. Tokens shorter than `2^threshold` (23 by default) are never flagged |
| `entropy_min_length` | integer | `16` | Minimum token length checked (the effective floor is the larger of this and `2^threshold`) |
| `entropy_whitelist` | list of strings | `[]` | Strings never flagged |
| `entropy_hex_threshold` | number, 0–8 | unset | Separate threshold for hex-only tokens; 40-character git SHAs are skipped |

### `limits`

| Key | Default | What it does |
|---|---|---|
| `command_timeout_seconds` | `1800` | Timeout of one command (tools accept `timeout_seconds` to override it) |
| `connection_timeout_seconds` | `10` | Timeout to open an SSH connection |
| `keepalive_interval_seconds` | `30` | SSH keepalive interval, also the inactivity timeout |
| `max_concurrent_commands` | `5` | Commands running at once, across the whole server |
| `rate_limit_per_second` | `10` | Requests per second per host; `0` turns it off |
| `retry_attempts` | `3` | Attempts for a failed connection or command |
| `retry_initial_delay_ms` | `100` | First delay between retries |
| `max_output_chars` | `40000` | Characters returned per call before truncation; `0` = no limit |
| `client_overrides` | built-in list | Per-client `max_output_chars`, matched on the MCP client name: entries `{name_contains, match_mode: prefix\|exact\|contains, max_output_chars}`, first match wins. Built in: `claude`/`cline` 80000, `cursor`/`windsurf`/`copilot`/`zed` 50000, `continue` 30000. **Setting it replaces the built-in list** |
| `max_output_bytes` | `10485760` | Bytes collected from one command (10 MiB) |
| `output_cache_ttl_seconds` | `300` | How long truncated output stays fetchable with `ssh_output_fetch` |
| `output_cache_max_entries` | `100` | Truncated outputs kept |
| `sftp_write_threshold_bytes` | `65536` | Above this, `ssh_file_write` uses SFTP; `0` = always |
| `max_tasks` | `50` | Concurrent async MCP tasks |
| `max_task_ttl_ms` | `3600000` | Longest task TTL a client may request |
| `task_poll_interval_ms` | `2000` | Poll interval suggested to clients for tasks |
| `client_request_timeout_seconds`, `sampling_max_tokens` | `120`, `4096` | Accepted but not used in 4.0.0 |

### `audit`

| Key | Default | What it does |
|---|---|---|
| `enabled` | `true` | Writes one JSON line per tool call (arguments, sanitized output, exit code, duration, confirmations) |
| `path` | `~/.local/share/bridge-mcp/audit.log` (macOS: `~/Library/Application Support/bridge-mcp/audit.log`) | Log location; `~` is expanded |
| `max_size_mb` | `100` | Rotates the log at this size; `0` turns rotation off |
| `retain_days` | `30` | At each rotation, **deletes** this log's rotated archives older than N days; `0` keeps them all |

### `sessions`

Persistent shells opened with `ssh_session_create`:

| Key | Default | What it does |
|---|---|---|
| `max_sessions` | `10` | Open shells at most |
| `idle_timeout_seconds` | `300` | Closes a shell idle this long |
| `max_age_seconds` | `3600` | Closes a shell this old, even in use |

### `tool_groups`

| Key | Values | Default | What it does |
|---|---|---|---|
| `groups` | map of group name to `true`/`false` | `{}` | Turns groups on or off. Unlisted groups are on only if they are among the 8 defaults (`core`, `file_ops`, `directory`, `process`, `monitoring`, `network`, `systemd`, `sessions`). **Unknown names are silently ignored** |
| `listing` | `full`, `progressive` | `full` | What `tools/list` returns — see [What the client sees](#what-the-client-sees) |

### `ssh_config`

| Key | Default | What it does |
|---|---|---|
| `enabled` | `false` | Imports hosts from your OpenSSH client config. **Off by default**: it would hand your whole SSH inventory to the model |
| `path` | `~/.ssh/config` | File to read |
| `exclude` | `[]` | Aliases not to import |

Only `Host`, `HostName`, `Port`, `User`, `IdentityFile` and `ProxyJump` are
read; wildcard `Host` blocks and blocks without `HostName` are skipped. An
`IdentityFile` that exists becomes key auth, otherwise the agent is used.
Imported hosts get `host_key_verification: acceptnew`. A host defined in YAML
wins over an imported one with the same alias.

### `http` (only for `serve-http`)

| Key | Default | What it does |
|---|---|---|
| `bind` | `127.0.0.1:3000` | Listen address (`serve-http --bind` overrides it). A non-loopback address is refused unless `oauth.enabled` or `allow_unsafe_bind` |
| `max_body_size` | `1048576` | Largest request body, bytes |
| `allowed_origins` | `http(s)://localhost`, `http(s)://127.0.0.1`, `http(s)://[::1]` | Accepted `Origin` values (DNS-rebinding protection) |
| `allow_unsafe_bind` | `false` | Allows a non-loopback bind without OAuth (same as `--insecure-bind`) |
| `oauth` | disabled | Bearer-token auth. camelCase keys: `enabled`, `issuer`, `audience`, `clientId`, `requiredScopes`, `staticKeys` (list of `{kid, publicKeyPem}`, required when enabled), `jwksUri` (not implemented: refused without `staticKeys`) |

`http.session_timeout_seconds` and `http.max_sessions` were retired in 3.0.0
and are rejected.

### `awx` (for the `awx` tool group)

| Key | Default | What it does |
|---|---|---|
| `ssh_host` | required | Host alias the AWX API calls run from (as `curl` over SSH) |
| `url` | required | AWX base URL, e.g. `https://awx.internal` |
| `token` | required | AWX OAuth2 token; masked in output |
| `api_timeout` | `30` | Seconds per API request (tools accept `timeout_seconds`, 1–3600) |
| `verify_ssl` | `true` | `false` for self-signed certificates |

### `rbac`

Not enforced. `rbac.enabled: true` is **rejected at load** so that nobody
believes roles protect anything; `default_role` and `roles` are accepted and
ignored.

---

## Tool parameters

Every tool documents its own arguments: `bridge-mcp describe-tool <name>` on
the CLI, `mcp_describe_tool` over MCP. On top of those, most tools accept the
parameters below. They behave the same over MCP and on the CLI (where each one
is a `key=value` pair; arrays and objects are written as JSON). A parameter the
tool does not declare is refused — check `describe-tool` first.

| Parameter | Type | Declared by | Default | What it does |
|---|---|---|---|---|
| `host` | string | 415 of 476 tools | required where declared | Host alias from the config |
| `timeout_seconds` | integer | 432 | `limits.command_timeout_seconds` | Per-call timeout |
| `max_output` | integer (characters) | 404 | `limits.max_output_chars` or the client override | Truncation limit for this call; `0` = none |
| `save_output` | path | 372 | — | Writes the full, untruncated output to this file **on the machine running bridge-mcp** (mode `0600`, overwritten, `..` refused) |
| `sudo` | bool | 327 | `false` | Runs the command under `sudo -n` (or with the host's `sudo_password` on stdin) |
| `sudo_user` | string | 327 | `root` | User to sudo to (`[A-Za-z0-9._-]`) |
| `jq_filter` | jq expression | 141 | — | Filters JSON output on the server, before truncation |
| `yq_filter` | jq expression | 81 | — | Same, on YAML output |
| `columns` | array of header names | 106 | — | Keeps only these columns of tabular output (case-insensitive) |
| `limit` | integer ≥ 1 | 173 | — | Caps rows, array items, YAML documents or filter results |
| `output_format` | `json`, `tsv` | 142 | `json` | `tsv` prints each array the filter returns as a tab-separated row — 60-80% fewer tokens on lists |

Which reduction parameters a tool takes depends on its **output kind**, shown by
`describe-tool` with its reduction strategy:

| Output kind | Tools | `jq_filter` | `yq_filter` | `columns` | `limit` | `output_format` |
|---|---|---|---|---|---|---|
| `RawText` | 308 | — | — | — | — | — |
| `Tabular` | 26 | — | — | ✓ | ✓ | — |
| `Json` | 61 | ✓ | — | — | ✓ | ✓ |
| `Yaml` | 1 | — | ✓ | — | ✓ | ✓ |
| `Auto` | 80 | ✓ | ✓ | ✓ | ✓ | ✓ |

A reduction parameter the output kind does not support is refused. For a
`RawText` tool, narrow the command itself, or use `save_output`. Some tools
produce JSON only when asked: `ssh_k8s_get` needs `output=json` for `jq_filter`.

**Pagination.** Truncated output is cut keeping its start and end. Over MCP (or
on the CLI with the [daemon](#daemon-mode) running), the result carries an
`output_id`; `ssh_output_fetch output_id=<id> offset=<chars>` (optional `limit`)
returns the rest, for `limits.output_cache_ttl_seconds` (300 s). A plain CLI
call has no cache: use `save_output=` or `max_output=0` instead.

---

## Tool Groups

476 tools organized in 77 groups. Only the eight core groups (`core`,
`file_ops`, `directory`, `process`, `monitoring`, `network`, `systemd`,
`sessions`) are enabled out of the box — everything else (containers, K8s,
Windows, cloud, …) is opt-in ([how](#enabling-tool-groups)):

```yaml
tool_groups:
  groups:
    docker: true       # opt in to a non-default group
    kubernetes: true
    sessions: false    # opt out of a default group
```

<details>
<summary><strong>Linux & cross-platform groups (43 groups)</strong></summary>

Representative tools per group — larger groups (e.g. `kubernetes` has 83,
`awx` 43) list only the common ones. For the full set, enable the group and run
`bridge-mcp list-tools --group <name>`.

| Group | Tools |
|-------|-------|
| `core` | ssh_exec, ssh_exec_multi (with `diff` / `diff_baseline` / `normalize` for cross-host drift detection), ssh_status, ssh_health, ssh_history, ssh_output_fetch |
| `config` | ssh_config_get, ssh_config_set |
| `file_transfer` | ssh_upload, ssh_download, ssh_sync |
| `file_ops` | ssh_file_read, ssh_file_write, ssh_files_write, ssh_file_chmod, ssh_file_chown, ssh_file_stat, ssh_file_diff, ssh_file_patch, ssh_file_template |
| `sessions` | ssh_session_create, ssh_session_exec, ssh_session_list, ssh_session_close |
| `monitoring` | ssh_metrics, ssh_metrics_multi, ssh_tail, ssh_disk_usage |
| `tunnels` | ssh_tunnel_create, ssh_tunnel_list, ssh_tunnel_close |
| `directory` | ssh_ls, ssh_find |
| `database` | ssh_db_query, ssh_db_dump, ssh_db_restore |
| `redis` | ssh_redis_info, ssh_redis_cli, ssh_redis_keys |
| `postgresql` | ssh_postgresql_query, ssh_postgresql_status |
| `mysql` | ssh_mysql_query, ssh_mysql_status |
| `mongodb` | ssh_mongodb_status |
| `backup` | ssh_backup_create, ssh_backup_list, ssh_backup_restore, ssh_backup_snapshot, ssh_backup_verify, ssh_backup_schedule |
| `docker` | ssh_docker_ps, ssh_docker_logs, ssh_docker_inspect, ssh_docker_exec, ssh_docker_compose, ssh_docker_images, ssh_docker_stats, ssh_docker_volume_ls, ssh_docker_network_ls, ssh_docker_volume_inspect, ssh_docker_network_inspect |
| `podman` | ssh_podman_ps, ssh_podman_logs, ssh_podman_inspect, ssh_podman_exec, ssh_podman_images, ssh_podman_compose |
| `esxi` | ssh_esxi_vm_list, ssh_esxi_vm_info, ssh_esxi_vm_power, ssh_esxi_snapshot, ssh_esxi_host_info, ssh_esxi_datastore_list, ssh_esxi_network_list |
| `cri` | ssh_crictl_ps, ssh_crictl_pods, ssh_crictl_images, ssh_crictl_logs, ssh_crictl_inspect, ssh_crictl_stats, ssh_crictl_info, ssh_crictl_exec, ssh_crictl_rmi (works when the apiserver is down) |
| `k3s` | ssh_k3s_status, ssh_k3s_check_config, ssh_k3s_etcd_status, ssh_k3s_etcd_snapshot_save/list/restore, ssh_k3s_ctr_images, ssh_k3s_kubeconfig_get, ssh_k3s_config_get, ssh_k3s_servicelb_status, ssh_k3s_addon_manifests, ssh_k3s_upgrade, ssh_k3s_uninstall, ssh_k3s_killall, ssh_k3s_cert_rotate |
| `kubernetes` | ssh_k8s_get, ssh_k8s_logs, ssh_k8s_describe, ssh_k8s_apply, ssh_k8s_delete, ssh_k8s_rollout, ssh_k8s_scale, ssh_k8s_exec, ssh_k8s_top, ssh_helm_list, ssh_helm_status, ssh_helm_upgrade, ssh_helm_install, ssh_helm_rollback, ssh_helm_history, ssh_helm_uninstall, … (83 total — `list-tools --group kubernetes`) |
| `git` | ssh_git_status, ssh_git_log, ssh_git_diff, ssh_git_pull, ssh_git_clone, ssh_git_branch, ssh_git_checkout |
| `ansible` | ssh_ansible_playbook, ssh_ansible_inventory, ssh_ansible_adhoc |
| `awx` | ssh_awx_status, ssh_awx_inventories, ssh_awx_inventory_hosts, ssh_awx_templates, ssh_awx_template_detail, ssh_awx_job_launch, ssh_awx_job_status, ssh_awx_job_summary, ssh_awx_job_stdout, ssh_awx_job_events, ssh_awx_job_follow, ssh_awx_job_cancel, ssh_awx_project_sync, … (43 total — workflows, approvals, relaunch) |
| `terraform` | ssh_terraform_init, ssh_terraform_plan, ssh_terraform_apply, ssh_terraform_state, ssh_terraform_output |
| `vault` | ssh_vault_status, ssh_vault_read, ssh_vault_list, ssh_vault_write |
| `systemd` | ssh_service_status, ssh_service_start, ssh_service_stop, ssh_service_restart, ssh_service_list, ssh_service_logs, ssh_service_enable, ssh_service_disable, ssh_service_daemon_reload |
| `systemd_timers` | ssh_timer_list, ssh_timer_info, ssh_timer_enable, ssh_timer_disable, ssh_timer_trigger |
| `network` | ssh_net_connections, ssh_net_interfaces, ssh_net_routes, ssh_net_ping, ssh_net_traceroute, ssh_net_dns |
| `process` | ssh_process_list, ssh_process_kill, ssh_process_top |
| `package` | ssh_pkg_list, ssh_pkg_search, ssh_pkg_install, ssh_pkg_update, ssh_pkg_remove |
| `firewall` | ssh_firewall_status, ssh_firewall_list, ssh_firewall_allow, ssh_firewall_deny |
| `cron` | ssh_cron_list, ssh_cron_add, ssh_cron_remove |
| `cron_analysis` | ssh_cron_analyze, ssh_cron_history, ssh_at_jobs |
| `certificates` | ssh_cert_check, ssh_cert_info, ssh_cert_expiry |
| `letsencrypt` | ssh_letsencrypt_status |
| `nginx` | ssh_nginx_status, ssh_nginx_test, ssh_nginx_reload, ssh_nginx_list_sites |
| `apache` | ssh_apache_status, ssh_apache_vhosts |
| `user_management` | ssh_user_list, ssh_user_info, ssh_user_add, ssh_user_modify, ssh_user_delete, ssh_group_list, ssh_group_add, ssh_group_delete |
| `storage` | ssh_storage_lsblk, ssh_storage_df, ssh_storage_mount, ssh_storage_umount, ssh_storage_lvm, ssh_storage_fdisk, ssh_storage_fstab |
| `journald` | ssh_journal_query, ssh_journal_follow, ssh_journal_boots, ssh_journal_disk_usage |
| `security_modules` | ssh_selinux_status, ssh_selinux_booleans, ssh_apparmor_status, ssh_apparmor_profiles, ssh_security_audit |
| `network_equipment` | ssh_net_equip_show_run, ssh_net_equip_show_interfaces, ssh_net_equip_show_routes, ssh_net_equip_show_arp, ssh_net_equip_show_version, ssh_net_equip_show_vlans, ssh_net_equip_config, ssh_net_equip_save |
| `ldap` | ssh_ldap_search, ssh_ldap_user_info, ssh_ldap_group_members, ssh_ldap_add, ssh_ldap_modify |

</details>

<details>
<summary><strong>Windows groups (13 groups)</strong></summary>

| Group | Tools |
|-------|-------|
| `windows_services` | ssh_win_service_list, ssh_win_service_status, ssh_win_service_start, ssh_win_service_stop, ssh_win_service_restart, ssh_win_service_enable, ssh_win_service_disable, ssh_win_service_config |
| `windows_events` | ssh_win_event_query, ssh_win_event_logs, ssh_win_event_sources, ssh_win_event_tail, ssh_win_event_export |
| `active_directory` | ssh_ad_user_list, ssh_ad_user_info, ssh_ad_group_list, ssh_ad_group_members, ssh_ad_computer_list, ssh_ad_domain_info |
| `scheduled_tasks` | ssh_schtask_list, ssh_schtask_info, ssh_schtask_run, ssh_schtask_enable, ssh_schtask_disable |
| `windows_firewall` | ssh_win_firewall_status, ssh_win_firewall_list, ssh_win_firewall_allow, ssh_win_firewall_deny, ssh_win_firewall_remove |
| `iis` | ssh_iis_list_sites, ssh_iis_list_pools, ssh_iis_status, ssh_iis_start, ssh_iis_stop, ssh_iis_restart |
| `windows_updates` | ssh_win_update_list, ssh_win_update_search, ssh_win_update_install, ssh_win_update_history, ssh_win_update_reboot |
| `windows_perf` | ssh_win_perf_overview, ssh_win_perf_cpu, ssh_win_perf_memory, ssh_win_perf_disk, ssh_win_perf_network, ssh_win_disk_usage |
| `hyperv` | ssh_hyperv_vm_list, ssh_hyperv_vm_info, ssh_hyperv_vm_start, ssh_hyperv_vm_stop, ssh_hyperv_host_info, ssh_hyperv_switch_list, ssh_hyperv_snapshot_list, ssh_hyperv_snapshot_create |
| `windows_registry` | ssh_reg_query, ssh_reg_list, ssh_reg_set, ssh_reg_delete, ssh_reg_export |
| `windows_features` | ssh_win_feature_list, ssh_win_feature_info, ssh_win_feature_install, ssh_win_feature_remove |
| `windows_network` | ssh_win_net_ip, ssh_win_net_adapters, ssh_win_net_connections, ssh_win_net_routes, ssh_win_net_ping, ssh_win_net_dns |
| `windows_process` | ssh_win_process_list, ssh_win_process_top, ssh_win_process_info, ssh_win_process_by_name, ssh_win_process_kill |

</details>

<details>
<summary><strong>Advanced groups (21 groups)</strong></summary>

| Group | Tools | Description |
|-------|-------|-------------|
| `diagnostics` | ssh_diagnose, ssh_incident_triage, ssh_compare_state | Intelligent single-call diagnostics with symptom-based triage |
| `runbooks` | ssh_runbook_list, ssh_runbook_execute, ssh_runbook_validate | YAML-defined multi-step operational procedures ([docs](config/runbooks/README.md)) |
| `orchestration` | ssh_canary_exec, ssh_rolling_exec, ssh_fleet_diff | Canary deployments, rolling updates, fleet-wide comparison |
| `recording` | ssh_recording_start, ssh_recording_stop, ssh_recording_list, ssh_recording_replay, ssh_recording_verify | Tamper-proof session recording (SOC2/HIPAA/PCI-DSS) |
| `drift` | ssh_env_snapshot, ssh_env_diff, ssh_env_drift | Environment state capture and drift detection |
| `security_scan` | ssh_sbom_generate, ssh_vuln_scan, ssh_compliance_check | SBOM, vulnerability scanning, CIS compliance checks |
| `performance` | ssh_perf_trace, ssh_io_trace, ssh_latency_test, ssh_benchmark | Performance profiling, I/O tracing, benchmarks |
| `container_logs` | ssh_container_log_search, ssh_container_log_stats, ssh_container_events, ssh_container_health_history | Container log analysis and health tracking |
| `network_security` | ssh_port_scan, ssh_ssl_audit, ssh_network_capture, ssh_fail2ban_status | Port scanning, SSL audit, traffic capture, fail2ban |
| `compliance` | ssh_cis_benchmark, ssh_stig_check, ssh_compliance_score, ssh_compliance_report | CIS/STIG benchmarks and compliance reporting |
| `cloud` | ssh_aws_cli, ssh_cloud_metadata, ssh_cloud_tags, ssh_cloud_cost | Cloud provider interaction |
| `inventory` | ssh_discover_hosts, ssh_inventory_sync, ssh_host_tags | Host discovery and CMDB sync |
| `multicloud` | ssh_multicloud_list, ssh_multicloud_sync, ssh_multicloud_compare | Multi-cloud resource management |
| `alerting` | ssh_alert_check, ssh_alert_list, ssh_alert_set | Metric monitoring, threshold checking, alert rules |
| `capacity` | ssh_capacity_collect, ssh_capacity_trend, ssh_capacity_predict | Capacity data collection, trending, prediction |
| `incident` | ssh_incident_timeline, ssh_incident_correlate | Incident response timeline and log correlation |
| `log_aggregation` | ssh_log_aggregate, ssh_log_search_multi, ssh_log_tail_multi | Cross-host log aggregation, search, tail |
| `key_management` | ssh_key_generate, ssh_key_distribute, ssh_key_audit | SSH key generation, distribution, audit |
| `chatops` | ssh_webhook_send, ssh_notify | Slack/Teams/webhook notifications |
| `templates` | ssh_template_list, ssh_template_show, ssh_template_apply, ssh_template_validate, ssh_template_diff | Config template management |
| `pty` | ssh_pty_exec, ssh_pty_interact, ssh_pty_resize | Interactive PTY sessions |

</details>

---

## MCP Prompts & Resources

<details>
<summary><strong>Pre-built prompts</strong></summary>

| Prompt | Description | Arguments (* = required) |
|--------|-------------|--------------------------|
| `system-health` | Full system health check (CPU, memory, disk, services) | `host`* |
| `deploy` | Step-by-step deployment workflow | `host`*, `app`*, `version` |
| `security-audit` | Security posture assessment | `host`*, `scope` |
| `troubleshoot` | Systematic troubleshooting guide | `host`* |
| `docker-health` | Docker/container health assessment | `host`* |
| `k8s-overview` | Kubernetes cluster state overview | `host`*, `namespace` |
| `backup-verify` | Backup integrity verification | `host`*, `path` |

</details>

<details>
<summary><strong>Direct data resources</strong></summary>

| URI pattern | Description |
|-------------|-------------|
| `metrics://{host}` | System metrics (CPU, memory, disk, network, load) as JSON |
| `file://{host}/{+path}` | Remote file content |
| `log://{host}/{+path}` | Last lines of a log file (`?lines=N`) |
| `health://{host}` | Health check summary for a host (connectivity, load, key services) |
| `history://recent` | Recent command history captured by the bridge (`?host=<alias>&since=<duration>&limit=N`) |
| `services://{host}` | Snapshot of active systemd services on the host |

</details>

---

## CLI

The same binary runs every tool from a shell — for scripts, and for agents that
would rather call a command than load MCP schemas (10-32x fewer tokens).

```bash
bridge-mcp tool ssh_docker_ps host=prod                       # any enabled tool, key=value arguments
bridge-mcp tool ssh_k8s_get --json-args '{"host":"k8s","resource":"pods","namespace":"default"}'
bridge-mcp --json tool ssh_docker_ps host=prod                # the whole MCP result as JSON
bridge-mcp list-tools --groups-only                           # enabled groups
bridge-mcp list-tools --search kubernetes                     # keyword search
bridge-mcp describe-tool ssh_docker_ps                        # schema, output kind, reduction strategy
```

### Subcommands

| Subcommand | What it does |
|---|---|
| `serve` | MCP server over stdio. Also what `bridge-mcp` with no subcommand runs |
| `serve-http` | MCP server over Streamable HTTP (`POST /mcp`). `-b/--bind`, `--insecure-bind` |
| `tool` (alias `t`) | Runs one enabled tool: `<name> [key=value …]` or `--json-args '<json>'` |
| `describe-tool` (alias `dt`) | One tool's schema, output kind, reduction strategy and annotations |
| `list-tools` | Enabled tools: `--groups-only`, `-g/--group <g>`, `-s/--search <kw>` |
| `validate` | Checks the config without contacting a host; prints host and tool counts and security warnings |
| `config-diff` | What your config changes from the defaults |
| `status` | Configured hosts and security settings (no connection) |
| `exec` | `<host> "<command>"` — one shell command. `-t/--timeout` (default 120 s), `-w/--working-dir`. Goes through the whitelist/blacklist but not the destructive prompt |
| `upload`, `download` | SFTP: `<host> <local> <remote>` / `<host> <remote> <local>`; `--mode overwrite\|append\|resume\|fail-if-exists`, `--chunk-size`, `--verify-checksum`, `-p/--progress` |
| `history` | In-memory history of the current process — empty for a fresh CLI call; read the audit log instead |
| `daemon start\|stop\|status` | See [Daemon Mode](#daemon-mode) |
| `completions <shell>` | `bash`, `zsh`, `fish`, `elvish` or `powershell` |

Every subcommand loads the config first, so even `list-tools` needs a valid one.

### Global flags

| Flag | Effect |
|---|---|
| `-c, --config <path>` | Config file to use |
| `--yes` | Confirms destructive tools in advance (scripts, CI). Recorded in the audit log |
| `--dry-run` | `tool` and `exec` only: print what would run, without checking or running it |
| `--json` | JSON output; with `tool`, the whole MCP result (`content`, `isError`, …) |
| `--jq <expr>` | Same as `jq_filter=<expr>` |
| `--columns a,b,c` | Same as `columns='["a","b","c"]'` |
| `--limit <n>` | Same as `limit=<n>` |
| `--output-format json\|tsv` | Same as `output_format=…` |

**Put flags before the first `key=value`.** `tool` reads everything after it as
tool arguments, so `bridge-mcp tool ssh_docker_ps host=prod --json` fails with
exit 5 (`Invalid argument '--json'`). `bridge-mcp --json tool …` and
`bridge-mcp tool ssh_docker_ps --json host=prod` both work. Write `columns` as
JSON (`columns='["NAMES","STATUS"]'`) or use `--columns NAMES,STATUS`: a bare
`columns=NAMES,STATUS` is not split.

There is no `--timeout`, `--max-output` or `--save-output` flag: use the tool
parameters `timeout_seconds=`, `max_output=` and `save_output=`. Logs go to
stderr; `RUST_LOG=error` silences them.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Tool or bridge error — including an undeclared argument or a value of the wrong type |
| 2 | Usage error — unknown tool (or a tool whose group is off), bad flag |
| 3 | Unknown host or SSH connection error |
| 4 | Security denial — whitelist/blacklist, or a destructive tool not confirmed (no terminal and no `--yes`) |
| 5 | Configuration error — config fails to load; also a malformed `key=value` or `--json-args` |
| 6 | The remote command ran and exited non-zero |

Codes 3, 4 and 6 are specific to `tool`; other subcommands exit 1 on their own
errors. Not every tool reports 6, and through a daemon 2, 3 and 4 become 1 — see
[docs/cli-exit-codes.md](docs/cli-exit-codes.md) before a script relies on it.

### Shell completions

```bash
bridge-mcp completions bash > ~/.bash_completion.d/bridge-mcp
bridge-mcp completions zsh  > ~/.zfunc/_bridge-mcp
bridge-mcp completions fish > ~/.config/fish/completions/bridge-mcp.fish
```

### Claude Code: prefer the CLI

To have Claude Code call the CLI through Bash instead of MCP tools (fewer
tokens), copy the provided rule and skill into your project:

```bash
mkdir -p .claude/rules .claude/skills/bridge
cp config/claude-code/rules/cli-bridge.md .claude/rules/
cp config/claude-code/skills/bridge/SKILL.md .claude/skills/bridge/
```

This adds the `/bridge` command (`/bridge config` for guided setup,
`/bridge docker` to explore a group).

---

## Daemon Mode

A long-lived daemon keeps SSH connections, the output cache and connection
pools warm between CLI calls:

```bash
bridge-mcp daemon start      # foreground; Ctrl-C to stop
bridge-mcp daemon status
bridge-mcp daemon stop
```

The socket is `$XDG_RUNTIME_DIR/bridge-mcp.sock`, or `/tmp/bridge-mcp-$UID.sock`
when `XDG_RUNTIME_DIR` is unset. `bridge-mcp tool` forwards its calls to a
daemon **at that default path only** — a daemon started with a custom
`--socket-path` is not used by the CLI. Through the daemon:

- truncated output gets an `output_id`, and `ssh_output_fetch` works;
- exit codes 2, 3 and 4 become 1 ([details](docs/cli-exit-codes.md));
- destructive tools are refused even with `--yes`, because the daemon's own
  confirmation gate applies and the CLI cannot answer it.

MCP clients do not connect to the daemon: they start their own `bridge-mcp serve`.
After upgrading, restart the daemon — the CLI warns on stderr when the daemon
was built from a different revision.

With the matching cargo features, two pools amortize handshakes: `WinRmPool`
(`--features winrm`, 120 s TTL, reuses the HTTP client per host) and
`K8sExecPool` (`--features k8s-exec`, 300 s TTL, caches the Kubernetes client).

---

## Protocol Support

Since 3.0, bridge-mcp implements **MCP revision `2026-07-28`** and only that
revision. This section is for client implementers; using the server needs none of it.

| | |
|---|---|
| Opens the connection | `server/discover` (there is no `initialize`, no `notifications/initialized`) |
| Revision + client identity + client capabilities | per-request `_meta`, keys `io.modelcontextprotocol/protocolVersion`, `…/clientInfo`, `…/clientCapabilities` |
| Notifications | opt-in via `subscriptions/listen`; every notification carries `_meta["io.modelcontextprotocol/subscriptionId"]` |
| Async execution | the `io.modelcontextprotocol/tasks` extension, declared under `capabilities.extensions` |
| Server needs something from the client | Multi Round-Trip Requests — the server RETURNS `resultType: "input_required"` and the client retries under a NEW id. It never sends `elicitation/create`, `sampling/createMessage` or `roots/list` as its own request; that pattern is deleted in this revision |
| Older client sends `initialize` | `-32022`, with `data.supported = ["2026-07-28"]` |

### Transports

**stdio** (default, `bridge-mcp serve`) — one JSON-RPC message per line on
stdin/stdout. The `_meta` envelope is the only place the protocol revision
appears; there are no headers here.

**Streamable HTTP** (`bridge-mcp serve-http`, requires the `http` feature) —
`POST /mcp` only. Requests MUST carry `MCP-Protocol-Version` and
`Mcp-Method`, plus `Mcp-Name` for `tools/call`, `resources/read` and
`prompts/get`, so gateways and WAFs can route without parsing the body. A value
that cannot travel as plain ASCII — a `file://` URI with an accent, a name with
edge whitespace — arrives wrapped as `=?base64?…?=` and is decoded before the
header is compared to the body, which matters here because `Mcp-Name` mirrors
`params.uri` on `resources/read`. A
missing header, or one that contradicts the body, is refused `400` with
JSON-RPC `-32020` — the request is REJECTED rather than resolved in favour of
the body, so a gateway can never route on a header that lies. JSON-RPC
batching is not accepted on any transport: an array is refused with `-32600`
(`400` here, and the same code on stdio and the daemon socket).
`GET /mcp` and
`DELETE /mcp` return **405** — the standalone SSE stream and the session
lifecycle are gone. There is no `Mcp-Session-Id`, no `Last-Event-ID`, and no
redelivery: a broken stream means the client re-issues with a new request id.
Server-to-client notifications arrive on the response stream of a
`subscriptions/listen` POST.

Anything that used to be keyed off the HTTP session is now an explicit handle
in tool arguments — `ssh_session_create` returns a `session_id` you pass to
`ssh_session_exec`, and a truncated response returns an `output_id` you pass
to `ssh_output_fetch`.

### Multi Round-Trip Requests

Three things make the server ask the client for something, and all three now
travel the same way: the server returns `input_required` and the client retries
the original call under a new id with `inputResponses` and the `requestState`
attached, as siblings of `_meta` on `params`.

| Trigger | Asks for | Costs |
|---|---|---|
| A `destructive_hint: true` tool, with the confirmation gate on | `elicitation/create` | one round trip before the tool runs |
| A path-scoped tool (`ssh_ls`, `ssh_find`, `ssh_upload`, `ssh_download`, `ssh_sync`, `ssh_file_write`, `ssh_files_write`) from a client that declared `roots` | `roots/list` | one round trip **per call** — a Modern server may not reuse a previous request's answer |
| `summarize=true` on a diagnostic tool, from a client that declared `sampling` | `sampling/createMessage` | one round trip, and the remote command runs ONCE — the finished result is sealed into the `requestState` rather than the call being replayed |

Nothing is asked for a capability the client did not declare: a client that
declares no `sampling` gets its raw output with no summary, and one that
declares no `roots` runs unscoped. That is the spec's rule, not a fallback.

`requestState` is HMAC-SHA256 over base64url JSON. It binds a 5-minute TTL and
a digest of the originating call — the tool name AND its arguments, so a
confirmation for one call cannot authorise another. It also binds the
authenticated principal, which is **empty on every transport that reaches the
gate today**: stdio and the daemon socket authenticate nobody, and HTTP
dispatches ordinary POSTs with no session, so the gate refuses destructive tools
there before issuing any state. The field is signed and checked regardless, so
the cross-user check activates the day a transport supplies a principal. **Set
`MCP_REQUEST_STATE_KEY` on any deployment running more than one bridge-mcp
process behind one address** — without it each process signs with its own
startup key, so a retry landing on another instance is refused and the user
confirms forever. A single stdio process needs nothing.

---

## Troubleshooting

Logs go to **stderr** (your MCP client usually keeps them in its server log);
set `RUST_LOG=debug` for more, `RUST_LOG=error` for less.

<details>
<summary><strong>Startup and configuration</strong></summary>

**`Failed to load config from …` (exit 5)** — the line below it says why:

- `Configuration file not found` — wrong path. On macOS the default is
  `~/Library/Application Support/bridge-mcp/config.yaml`, not `~/.config`.
- `has permissions 0644; expected no group-write/other access` — `chmod 600` the config.
- `SSH key file … has permissions …; expected 0600` — `chmod 600` the key; a
  missing key file also stops the load.
- ``unknown field `…` `` — a misspelled or retired key (`rbac.enabled: true`,
  `http.max_sessions` and `http.session_timeout_seconds` are rejected too).
- ``unknown variant `…` `` — a value in the wrong case, e.g. `AcceptNew` instead of `acceptnew`.
- `At least one host must be defined` — `hosts:` is empty (and `ssh_config` import is off by default).

**The MCP server shows "connected" but the model has no tools** — the client
used the Legacy handshake: see the note in [step 4](#4-connect-your-mcp-client).
With `listing: progressive` you see four `mcp_*` tools: that is expected.

**`-32022 Unsupported protocol version`** — the client opened with `initialize`
or declared a revision this server does not speak; `data.supported` lists the
one it does (`2026-07-28`).

**`-32602 missing _meta[…/protocolVersion]`** — every request in this revision
must carry `protocolVersion` and `clientCapabilities` in `_meta`.

</details>

<details>
<summary><strong>Tool calls</strong></summary>

**`Command denied: Command not in whitelist (standard mode)`** — `ssh_exec` (and
the other free-form command tools) run only whitelisted commands. Add an
anchored regex under `security.whitelist`, or use a specialised tool.

**`Command denied: Command matches blacklist pattern: …`** — the command, or the
command a tool built, matches the blacklist. Built-in examples:
`ssh_service_stop` and `ssh_service_disable` (`systemctl stop|disable`).

**``Unknown argument `x` for tool `y`. Did you mean `z`?``** — check the tool's
arguments with `describe-tool` / `mcp_describe_tool`. Note that some tools name
the same thing differently (`ssh_service_status service=…`, `ssh_service_disable name=…`).

**``Tool `x` is registered but its group `y` is not enabled``** (on the CLI:
`MCP unknown tool`, exit 2) — enable the group under `tool_groups.groups`.

**``… did not declare the `elicitation` capability``** — the tool is destructive
and your client cannot show a confirmation. Use a client that supports MCP
elicitation, or the CLI, where you confirm on the terminal or with `--yes`.

**CLI exits 4 on a destructive tool** — no terminal to ask on: add `--yes`
(before the tool name) once you mean it.

**`Unknown host: x`** (exit 3) — the alias is not in your config:
`bridge-mcp status` lists them.

**SSH connection failed / unknown host key** — check `ssh user@host` works by
hand first: that also records the host key in `~/.ssh/known_hosts`, which the
default `strict` verification requires (or set `host_key_verification:
acceptnew` on that host).

**`Output cache is not available`** — `ssh_output_fetch` from a plain CLI call:
use `save_output=` or `max_output=0`, or run the [daemon](#daemon-mode).

**`-32602 requestState is not valid for this request`** — a confirmation was
replayed onto a different call, arrived after its 5-minute TTL, or was signed by
another process. Without `MCP_REQUEST_STATE_KEY`, each process signs with its
own startup key, so several instances behind one address refuse each other's
retries. Re-send the original request without `requestState` and
`inputResponses` to start over.

</details>

---

## Development

```bash
make build              # Debug build
make release            # Optimized build with RELEASE_FEATURES (full,winrm,psrp) into target/release/
make install            # make release, check it loads your config, copy to ~/.local/bin
make test               # Tests (nextest if installed) + doctests
make ci                 # fmt-check, lint (pinned + stable + no-default), test, doc, audit, deny, typos, markdownlint
make help               # Every target
```

Rust edition 2024, MSRV 1.99+, `#![forbid(unsafe_code)]`, 10,000+ tests.

**Adding a new tool — 3 steps:** annotate the struct with `#[mcp_tool]` (or
`#[mcp_standard_tool]`), add the `mod` + `pub use` line, and (only if
introducing a new group) update `ToolGroupsConfig`. The `inventory` crate
auto-registers the handler at compile time.

Two things are NOT automatic, and both fail loudly rather than silently:

- Any new tool changes the total in `.migration-baseline.json`. Regenerate it
  with `python3 scripts/extract_tool_metadata.py` and check the diff;
  `python3 scripts/validate_baseline.py` is what compares the two. No workflow
  runs it, so nothing in CI will catch the drift for you.
- A new *group* must also be added to the hardcoded `known_groups` list in
  `tests/tool_filtering.rs`, which enumerates all 77 by name.

See [CHANGELOG.md](CHANGELOG.md) for version history and
[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for releases. There is no
separate threat-model document: the security design lives in
[`security`](#security), [Destructive tools](#destructive-tools-and-confirmation)
and [Protocol Support](#protocol-support).

---

## License

[MIT](LICENSE)
