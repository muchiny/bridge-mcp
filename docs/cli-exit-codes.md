# CLI exit codes

`bridge-mcp tool …` reports what happened through its exit code, so a script can
tell "the bridge could not run my command" from "my command ran and failed".
This page is the detail behind the short table in the
[README](../README.md#exit-codes).

| Code | Meaning | Typical trigger under `tool` |
|------|---------|------------------------------|
| 0 | Success | The tool ran and the remote command exited 0 |
| 1 | Tool or bridge error | An undeclared argument (`pathh=/`), a value of the wrong type (`limit=abc`, `limit=0`), a reduction parameter the tool cannot use, a result marked `isError`, and any error of a subcommand other than `tool` |
| 2 | Usage error | An unknown tool name, a tool whose group is not enabled, and every clap error (missing argument, unknown flag, bad `--output-format`) |
| 3 | Unknown host or SSH connection error | `host=` names no configured alias, or the connection fails |
| 4 | Security denial | The destructive-tool confirmation was refused (no terminal and no `--yes`, or an answer other than `y`/`yes`), or a blacklist/whitelist match |
| 5 | Configuration error | The config file fails to load (every subcommand). Under `tool`, also a word that is not `key=value` (for example a flag written after the arguments) and `--json-args` that is not valid JSON |
| 6 | The remote command ran on the target host and exited non-zero | See below |

**With a daemon running, codes 2, 3 and 4 become 1**: the daemon answers an
unknown tool with a JSON-RPC error and an unknown host or a denial with an
`isError` result, and the CLI maps both to 1. Codes 0 and 6 survive the daemon
path, and so do the refusals the CLI makes before forwarding (argument checks,
exit 1 or 5; the destructive prompt, exit 4).

**Codes 3, 4 and 6 are specific to `bridge-mcp tool`.** Code 2 is also clap's
usage-error code, so every subcommand exits 2 on a bad flag or subcommand name.
Beyond that, every other subcommand exits 1 for any error of its own
(`bridge-mcp exec …` on an unknown host is 1, not 3). The one other exception
is code 5 for a configuration file that fails to load, which applies to every
subcommand. Details below.

Codes 1-5 are the bridge's *own* failures: it could not run your command.
Code 6 means the opposite — the command ran on the target host and exited
non-zero. The distinction matters because before 4.0.0 `bridge-mcp tool`
exited **0** in that case, so `bridge-mcp tool … && next` ran `next` after a
failure.

In the CLI's output the remote command's own exit code is not a separate
field; it appears in the result text as the `[exit:N]` prefix (an MCP result
also carries it in `_meta`, see below). `--json` marks the call
`"isError": true` — **except for the tools whose command you wrote yourself**,
which report the code without the verdict. See the next section.

**Which tools emit 6 — read this before relying on it.** Code 6 comes from the
shared `StandardTool` pipeline, which is most of the catalogue but not all of
it. 52 handlers run their remote command outside that pipeline; seven of them
now report a code of their own, 42 of the `ssh_awx_*` family raise a **bridge
error** instead (see below the tables), and the remaining three **still exit 0
when the remote command fails**:

| Emits 6 outside the pipeline | When |
|---|---|
| `ssh_exec` | any non-zero exit |
| `ssh_exec_multi` | **single host only** — see below |
| `ssh_file_write` | any non-zero exit **on the shell path** — content whose length reaches `sftp_write_threshold_bytes` (64 KiB by default; `0` means every write) goes over SFTP, which runs no remote process and so has no code to report |
| `ssh_disk_usage` | only without `path` (with one, the command is `du … && df …`, which exits 1 from an unreadable subdirectory while still answering) |
| `ssh_tail` | only without `grep` (with one, exit 1 means "no match", which is not a failure) |
| `ssh_session_exec` | any non-zero exit **that the bridge read and that fits an `i32`**. When no code representable as an unsigned 32-bit integer was read (begin marker missing, or a code line that is not a decimal `u32`, such as a negative PowerShell `$LASTEXITCODE`), the JSON `exit_code` is `null` and nothing is reported: exit 0, not a guess. A code that was read but is larger than `i32::MAX` is in the JSON but is likewise not reported, so the CLI exits 0 for it |
| `ssh_awx_job_follow` | the job it followed did not finish `successful` (`failed`, `error`, `canceled`, a refused status request, or still running at `max_wait`). Unlike `ssh_exec`, it also marks the call an error: the script is the bridge's own |

| Still exits 0 on a remote failure | Count | When |
|---|---|---|
| `ssh_find`, `ssh_metrics`, `ssh_metrics_multi` | 3 | any non-zero exit |
| `ssh_exec_multi` across 2+ hosts | — | see below |

**The other 42 `ssh_awx_*` tools are not in that table, and never emit 6
either.** They route their response through
`AwxCommandBuilder::parse_checked_response` and propagate its error with `?`. An
HTTP status >= 400 has always raised `BridgeError::AwxApi`; since 4.0.0 a **curl transport failure** (connection refused, timeout, DNS — curl
writes `%{http_code}` = `000`) raises it too, as `AwxApi { status: 0 }`, where
`status` is not an HTTP status but the mark of "curl obtained none". That is a
bridge error, so it **exits 1**, not 6. The call is arguable — curl did run on
the target host and exit non-zero — but the curl command is the bridge's own, not
one you wrote, so failing to reach the AWX API is counted as the bridge failing
to run your request rather than as your request failing. Non-zero either way.

The live-host sweep that found this measured 44 affected tools, and all 44 are
pipeline tools, so the measured defect is closed — but the defect *class* is
not, and the handlers still listed above as exiting 0 are its unmeasured
remainder (CHANGELOG has the chain). The seven that now emit 6 were brought into
line later in the 4.0.0 cycle, by unit test (mutation testing covers only some of
them; the CHANGELOG says which) rather than on a host — so they have left the remainder without ever having been measured on one. Until
it is closed, treat exit 6 as "this tool told me the remote command failed",
never exit 0 as "the remote command succeeded".

**Tools whose command you wrote emit 6 without marking the call an error.**
You wrote their command, and plenty of ordinary commands exit non-zero *as
their answer*: `grep` matching nothing exits 1, `diff` finding a difference
exits 1, `test` exits 1 for false, `systemctl is-active` exits 3 for a stopped
unit. So the code reaches `$?` — your `&&` stops, which is what a shell caller
expects — but the MCP result does **not** carry `"isError": true`, because
nothing here can establish that your command failed. The criterion is who wrote the
command and whether a non-zero exit is an answer, not the tool name, and it has
three positions. Where the command is the caller's (`ssh_exec`,
`ssh_exec_multi`, `ssh_session_exec`), the code is a fact and no verdict is set.
Where the bridge built the command and counts a non-zero exit as a failure, both
the code and the verdict are set. Where the bridge built the command but a
non-zero exit is an answer (`systemctl is-active` exits 3 for a stopped unit),
or the handler reports nothing (`ssh_find`, `ssh_metrics`,
`ssh_metrics_multi`), neither is set.

**`ssh_exec_multi` reports a code only for a single host.** Across two or more
it reports nothing, deliberately: the per-host `failed` counter cannot tell
"the command exited non-zero" from "the host was unreachable", and mapping it
onto exit 6 would make 6 mean "the bridge could not reach a host" — the exact
conflation 6 was created to remove. Read the per-host `exit_code` values in the
JSON result instead.

Two further limits:

- **Only the `tool` subcommand distinguishes 6, and only `tool` maps the
  bridge's own failures onto 3 and 4** (2 is clap's usage code on every subcommand). `bridge-mcp exec` exits 1 on a failed remote
  command, as it always has. Every other subcommand (`exec`, `status`,
  `history`, `describe-tool`, `list-tools`, `validate`, `config-diff`, `upload`,
  `download`, `daemon`, `serve`) exits 1 for any error of its own, whatever its
  class — an unknown host under `exec` is 1, not 3. A configuration file that
  fails to load for any reason — absent, unreadable, malformed, a referenced
  SSH key file missing — exits 5 for every subcommand, `completions` included, since that happens
  before any of them runs.
- **Under a daemon, the code travels in a vendor `_meta` key.** With
  `bridge-mcp daemon` running, the CLI forwards the call and reads the MCP
  result back. The remote exit code is carried on that result under
  `_meta["io.github.muchiny/remote-exit-code"]` (also when `summarize=true`),
  and the CLI reads it, so the daemon path gives the same exit codes as the
  direct path — 6 for a remote failure, 1 for a bridge refusal, including for
  `ssh_exec` and `ssh_exec_multi`. The guarantee is for this project's own
  CLI-over-daemon path: an MCP client that does not read that vendor key still
  sees only `"isError"`. **It also requires the daemon serving the call to be
  4.0.0 or later.** A daemon started from an earlier build accepts the same
  protocol revision and reports the same crate version, but answers without the
  key, and `ssh_exec` then exits 0 again. The CLI compares the daemon's build
  revision to its own and prints a `warning:` on stderr when they differ (or
  when the daemon reports none); restart the daemon when you see it.
