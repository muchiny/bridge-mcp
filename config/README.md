# Configuration

Configuration files for MCP SSH Bridge.

## Location

Configuration is loaded from:

```
~/.config/bridge-mcp/config.yaml
```

Or specified via `--config`:

```bash
bridge-mcp --config /path/to/config.yaml
```

## Structure

The configuration file is organised in these top-level sections:

- **hosts** — SSH host definitions (hostname, port, user, auth, jump, etc.)
- **security** — Command validation (mode, whitelist, blacklist, RBAC)
- **limits** — Timeouts, output limits, retry, rate-limit settings
- **audit** — Audit logging configuration (path, format, redaction)
- **sessions** — Persistent tmux session configuration
- **tool_groups** — Per-group feature flags (disable what you don't need)
- **ssh_config** — Auto-discovery from `~/.ssh/config`
- **http** — Optional Streamable HTTP transport + OAuth 2.1 settings
- **rbac** — Role-based access control
- **awx** — Optional AWX/Ansible Tower integration

Observability (OpenTelemetry tracing + Prometheus metrics) is configured
via **environment variables**, not YAML — see the Observability section
below.

## Quick Start

```bash
mkdir -p ~/.config/bridge-mcp
cp config/config.example.yaml ~/.config/bridge-mcp/config.yaml
vim ~/.config/bridge-mcp/config.yaml
```

## Minimal Example

```yaml
hosts:
  my-server:
    hostname: "192.168.1.100"
    user: "admin"
    auth:
      type: key
      path: "~/.ssh/id_ed25519"

security:
  mode: strict
  whitelist:
    - "^ls\\b"
    - "^cat\\b"
    - "^docker\\s+"
```

## Authentication Methods

### SSH Key (recommended)

```yaml
auth:
  type: key
  path: "~/.ssh/id_ed25519"
  passphrase: "optional"  # only if the key is passphrase-protected
```

### SSH Agent (recommended)

```yaml
auth:
  type: agent
```

Requires `SSH_AUTH_SOCK` environment variable (Unix only).

### Password (not recommended)

```yaml
auth:
  type: password
  password: "secret"
```

## Host Key Verification

| Mode | Unknown host | Key changed | Use case |
|------|-------------|-------------|----------|
| `strict` (default) | Rejected | Rejected | Production |
| `acceptnew` | Auto-added | Rejected | First-time setup |
| `off` | Accepted | Accepted | Testing only |

```yaml
host_key_verification: strict  # default
```

## Jump Hosts

Connect to internal hosts via a bastion server:

```yaml
hosts:
  bastion:
    hostname: bastion.example.com
    user: admin
    auth:
      type: agent

  internal-db:
    hostname: 10.0.0.5
    user: deploy
    proxy_jump: bastion
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## SOCKS Proxy

Alternative to jump hosts. `proxy_jump` and `socks_proxy` are mutually exclusive.

```yaml
hosts:
  remote-via-proxy:
    hostname: 10.0.0.5
    user: deploy
    socks_proxy:
      hostname: proxy.example.com
      port: 1080
      version: socks5
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## Windows Hosts

```yaml
hosts:
  windows-dc:
    hostname: 192.168.1.200
    user: Administrator
    os_type: windows
    shell: powershell
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## Security Modes

- **strict** (default): Only whitelisted commands are allowed. Blacklist is checked first.
- **permissive**: All commands are allowed except those matching the blacklist.

## Tool Groups

All 74 tool groups (357 tools) are enabled by default. Disable groups you don't need:

```yaml
tool_groups:
  groups:
    database: false
    terraform: false
    hyperv: false
```

Run `bridge-mcp list-tools --groups-only` to see the current list of
groups and tool counts for your installed version.

## Observability (feature `otel`)

The bridge always tracks Prometheus-style counters (tool calls, SSH
connections, token consumption — see `src/metrics.rs`). With the optional
`otel` feature compiled in, it also exports distributed traces to any
OTLP/gRPC collector (Jaeger, Tempo, Grafana Agent, OTel Collector…).

Spans emitted:

| Span                   | Fields                                               |
|------------------------|------------------------------------------------------|
| `mcp.tool.execute`     | `tool`, `host`, `exit_code`, `bytes_out`, `duration_ms` |
| `ssh.connect`          | `host`, `port`, `duration_ms`                        |
| `ssh.connect_via_jump` | `host`, `jump`, `port`, `duration_ms`                |
| `ssh.pool.get`         | `host`, `has_jump`, `from_cache`, `duration_ms`      |

Environment variables read at startup:

| Variable                      | Default            | Purpose                               |
|-------------------------------|--------------------|---------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (unset → disabled) | OTLP/gRPC collector URL               |
| `OTEL_SERVICE_NAME`           | `bridge-mcp`   | Service name reported in spans        |
| `RUST_LOG`                    | `info`             | `tracing-subscriber` filter directive |

Build with:

```bash
cargo build --release --features "cli,otel"
# or include in the "full" bundle:
cargo build --release --features full
```

Local smoke test with Jaeger:

```bash
docker run -d --name jaeger -p 16686:16686 -p 4317:4317 \
  -e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one:latest

OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
  ./target/release/bridge-mcp tool ssh_status

# → open http://localhost:16686 and search service "bridge-mcp"
```

## Daemon mode (shared SSH pool)

Each CLI invocation normally starts a fresh process that builds its own
SSH connection pool, pays the ~95 ms handshake, runs the command, and
dies. For workflows that launch many commands in a row against the same
host, those handshakes add up — measured overhead in Sprint 1 was
**~120 ms per invocation** on a LAN-direct Raspberry Pi.

A local daemon amortizes that cost by keeping the pool alive between
invocations. The daemon listens on a Unix socket
(`$XDG_RUNTIME_DIR/bridge-mcp.sock` by default, or
`/tmp/bridge-mcp-$UID.sock` on systems without XDG runtime). CLI
commands detect the socket and forward their `tools/call` requests over
it; if the socket is absent, they transparently fall back to the
stateless path.

### Usage

```bash
# Start the daemon in the foreground (blocks until Ctrl+C)
bridge-mcp daemon start

# In another terminal: issue tool calls — they route through the daemon
bridge-mcp tool ssh_exec host=raspberry command="uptime"
bridge-mcp tool ssh_docker_ps host=raspberry
# The first call pays the handshake; subsequent calls reuse the pool.

# Check daemon status
bridge-mcp daemon status

# Stop the daemon (sends SIGTERM)
bridge-mcp daemon stop
```

Override the socket path with `--socket-path` on any `daemon`
subcommand. Useful for testing or multi-user systems where you need to
avoid the default `/tmp` fallback.

### What the daemon supports in this release

- `tools/call`, `tools/list`, `resources/read`, `prompts/get`, all
  standard read/execute methods.
- Full cancellation via `notifications/cancelled` (thanks to the Sprint
  2 cancellation work).
- Structured tracing / OTLP export (requires `--features otel`).

### What the daemon does NOT support yet

- **Server-initiated notifications** (elicitation, sampling, logging).
  These need per-connection notification channels that the daemon
  doesn't yet plumb. If your tool requires elicitation, use the
  stateless path (stop the daemon, run the tool directly).
- **Batch requests**. JSON-RPC batches are rejected in daemon mode.
- **Config hot-reload from inside the daemon**. Restart the daemon
  after editing `config.yaml`.

These limitations are tracked for Sprint 3, which will unify the
`Transport` trait and bring the daemon to feature parity with stdio
mode.

### Security notes

- The socket inherits the permissions of `$XDG_RUNTIME_DIR` — on modern
  Linux, that directory is `0700` and owned by your user, so only you
  can connect.
- The daemon uses a PID lock file (`<socket>.pid`) to prevent
  double-start. If the daemon crashes, the next `daemon start` detects
  the stale PID and takes over automatically.

## CLI data-reduction flags

Three ergonomic global flags short-circuit the universal data-reduction
tool parameters so you don't have to type `jq_filter=` / `columns=` /
`limit=` on every invocation:

```bash
# jq filter (requires tool output to be JSON)
bridge-mcp --json --jq '.items[].name' tool ssh_k8s_get host=k8s resource=pods

# Column selection + row limit on tabular output
bridge-mcp --json --columns user,pid,command --limit 10 tool ssh_process_list host=prod
```

Explicit `key=value` arguments always win — the flags only fill in
parameters you did NOT set explicitly. So `--limit 20` combined with
`limit=2` yields `limit=2`.

## SSH Config Auto-Discovery

When enabled (default), hosts from `~/.ssh/config` are automatically imported. YAML-defined hosts take precedence.

```yaml
ssh_config:
  enabled: true
  exclude_patterns:
    - "*.internal"
```

## Validation

The configuration file is validated on load:

- At least one host must be defined
- `hostname` and `user` must not be empty
- SSH key files must exist (for key auth)
- Regex patterns must be valid (invalid patterns are skipped with a warning)

## Testing

```bash
bridge-mcp status         # verify config loads and list hosts
bridge-mcp exec my-server "echo test"  # test a connection
```

## Full Reference

See `config.example.yaml` for all available options with comments.
