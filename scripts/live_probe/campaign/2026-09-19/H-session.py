#!/usr/bin/env python3
"""The three session cases of the 2026-09-19 root-cause plan that
`run.py` structurally cannot run, against ONE long-lived `bridge-mcp serve`.

A session lives in the `SessionManager` of the server process that created it,
and `run.py` spawns one process per case — so `H04`, `H05` and `H06` cannot be
`run.py` cases, for the same reason `mcp_probe.py` exists ("Sessions, tunnels
and the output cache live inside ONE server process"). Two further reasons they
cannot: `ssh_session_exec` requires a `session_id` minted at run time, which a
committed `vars` block cannot hold; and it answers with a JSON envelope, so the
assertion is on its `output` field, not on the raw text `run.py` compares.

Cases:
  H04  output without a trailing newline survives      `printf sans-nl`
  H05  a `cd` still persists between two calls         `cd /tmp` then `pwd`
  H06  a timeout no longer kills the session           `sleep 8` @ timeout 2, then `echo vivant`
  H02b generates the audit FAILURE trail               exec on an unknown session_id
  H02c generates the audit DENIED trail                a blacklisted command

H02b and H02c are TRAIL GENERATORS first: the property under test is that the
resulting line in the bridge host's audit log carries `tool_name`, and that log
is not reachable from here, so the proof is the audit line and the caller asserts
it. But a generator that prints PASS on any error at all cannot even show the
trail it produced is the right one, so both now assert the error KIND, and so
does H06b. Needles: "Session not found" (H02b), "blacklist" (H02c), "timeout"
(H06b). A lost reply, a server that never started, and a refusal of the wrong
kind therefore FAIL where all three used to pass. H02c additionally RAISES when
the H04/H05 session is missing instead of falling back to an unknown session id:
with a fallback it would degrade into a second H02b, never reach the blacklist,
and — before the kind assertion — still print PASS.

Read-only on the host: nothing is written, no file and no process survives.
`sleep 8` against `timeout_seconds=2` overruns by 6 s, inside the 10 s
`STALE_OUTPUT_DRAIN_TIMEOUT_SECS` grace — `open_shell()` requests no PTY, so a
timed-out command cannot be interrupted and an open-ended one (`sleep 300`)
would leave the drain unable to complete. Both sessions are closed in `finally`.

`clientCapabilities` is `{}` on purpose: this probe has no channel to answer an
elicitation. None of the session tools is annotated destructive, so no gate
fires; a destructive tool would be refused fail-closed, which is the honest
outcome for a client that cannot answer.

Usage: H-session.py BIN [--host raspberry]
Exit code = number of FAILs.
"""
import argparse
import json
import os
import subprocess
import sys
import threading

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "H-session", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
FAILS = 0


class Server:
    def __init__(self, binary):
        env = dict(os.environ, RUST_LOG="error")
        self.p = subprocess.Popen(
            [binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.n = 0
        self.watchdog = threading.Timer(300, self.p.kill)
        self.watchdog.daemon = True
        self.watchdog.start()

    def call(self, method, params=None):
        self.n += 1
        req = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": dict(params or {})}
        req["params"]["_meta"] = META
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        for _ in range(200):
            line = self.p.stdout.readline()
            if not line:
                return {"error": {"code": -1, "message": "server closed stdout"}}
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == self.n:
                return msg
        return {"error": {"code": -2, "message": "no answer"}}

    def tool(self, name, arguments):
        return self.call("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        self.watchdog.cancel()
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            self.p.kill()


def text_of(msg):
    r = msg.get("result", {})
    return "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")


def envelope(msg):
    """The `{session_id, exit_code, cwd, output}` object ssh_session_exec returns,
    or None when the call failed (JSON-RPC error, isError, or no JSON at all)."""
    if "error" in msg or msg.get("result", {}).get("isError"):
        return None
    try:
        return json.loads(text_of(msg))
    except ValueError:
        return None


def error_text(msg):
    """Everything the server said about a call that did not succeed.

    A refusal reaches us in one of two shapes and the case should not have to
    know which: `handle_tools_call` turns a handler's `Err` into a *successful*
    result carrying `isError: true` with the message in its text content
    (src/mcp/server.rs), while a malformed or unroutable request comes back as a
    JSON-RPC `error`. Both are concatenated here.

    This is also why a lost reply is fatal rather than a pass: `Server.call`
    answers a dead or silent server with its own "server closed stdout" / "no
    answer", which contains none of the kind needles below, so the case FAILS.
    `envelope(m) is None` — what H06b used to assert — could not tell those
    apart, and a missing reply passed as "timed out as designed".
    """
    parts = []
    err = msg.get("error")
    if isinstance(err, dict):
        parts.append(str(err.get("message", err)))
    elif err is not None:
        parts.append(str(err))
    if msg.get("result", {}).get("isError"):
        parts.append(text_of(msg))
    return "\n".join(parts)


def check(cid, cond, detail):
    global FAILS
    print(f"{cid} {'PASS' if cond else 'FAIL'} — {str(detail)[:300]!r}")
    if not cond:
        FAILS += 1


def new_session(s, host, cid):
    raw = text_of(s.tool("ssh_session_create", {"host": host}))
    try:
        sid = json.loads(raw)["id"]
    except (ValueError, KeyError):
        sid = None
    check(cid, sid is not None, f"session_create -> {raw}")
    return sid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    a = ap.parse_args()
    H = a.host
    s = Server(a.binary)
    sid = sid2 = None
    try:
        # --- H04 / H05: one session, three commands -------------------------
        sid = new_session(s, H, "H04a")
        if sid:
            m = s.tool("ssh_session_exec", {"session_id": sid, "command": "printf sans-nl"})
            env = envelope(m)
            check("H04b", env is not None and env.get("output") == "sans-nl",
                  f"printf sans-nl -> {env if env is not None else json.dumps(m)[:300]}")

            s.tool("ssh_session_exec", {"session_id": sid, "command": "cd /tmp"})
            m = s.tool("ssh_session_exec", {"session_id": sid, "command": "pwd"})
            env = envelope(m)
            check("H05", env is not None and env.get("output") == "/tmp",
                  f"cd /tmp then pwd -> {env if env is not None else json.dumps(m)[:300]}")

        # --- H06: its own session, so a timeout cannot poison H04/H05 -------
        sid2 = new_session(s, H, "H06a")
        if sid2:
            m = s.tool("ssh_session_exec",
                       {"session_id": sid2, "command": "sleep 8", "timeout_seconds": 2})
            # The KIND, not merely "no envelope": `BridgeError::SshTimeout`
            # displays as "SSH command timeout after 2s" (src/error.rs:52). The
            # old assertion was `envelope(m) is None`, which a lost reply, a
            # dead server and any other failure satisfy just as well — it read
            # every one of them as "timed out as designed".
            err = error_text(m)
            check("H06b", "timeout" in err.lower(),
                  f"sleep 8 @ timeout 2 -> {err or json.dumps(m)[:300]}")

            m = s.tool("ssh_session_exec", {"session_id": sid2, "command": "echo vivant"})
            env = envelope(m)
            check("H06c", env is not None and env.get("output") == "vivant",
                  f"echo vivant in the SAME session -> "
                  f"{env if env is not None else json.dumps(m)[:300]}")

            lst = text_of(s.tool("ssh_session_list", {}))
            check("H06d", sid2 in lst, f"session still listed -> {lst[:200]}")

        # --- H02b / H02c: generate the audit FAILURE and DENIED trails ------
        # Asserted by the caller against the bridge host's own audit log, which
        # is why they are here and not in H-fixes.json. Together with the
        # success trail above they cover three of the four entry points Task 2
        # made the tool name mandatory on; the fourth, `process_success`, is
        # covered by every ssh_exec / ssh_user_info line H-fixes.json leaves.
        m = s.tool("ssh_session_exec",
                   {"session_id": "H-session-unknown-id", "command": "echo x"})
        # `BridgeError::SessionNotFound` displays as "Session not found: <id>"
        # (src/error.rs:79). Asserting the kind is what makes this a case: the
        # old form passed on ANY error, so a server that could not start, a
        # blacklist refusal or a lost reply all produced the same PASS.
        err = error_text(m)
        check("H02b", "Session not found" in err,
              f"unknown session_id -> {err or json.dumps(m)[:200]}")

        # Denied by the local validator BEFORE any SSH traffic: `>\\s*/dev/(sd|
        # mmcblk|nvme)` is a blacklist pattern, and ssh_session_exec is not
        # annotated destructive, so no confirmation gate stands in front of the
        # denial. Chosen to be harmless even if the pattern were missing from a
        # config: /dev/sdzz-bridge-probe is not a device node, and an
        # unprivileged user cannot create one under /dev, so the unguarded form
        # fails with EACCES instead of writing to a disk. A case must be safe on
        # its own terms — see the `about` block of H-fixes.json.
        #
        # `sid` is required, and its absence RAISES rather than falling back to
        # the unknown id H02b already uses. With a fallback this case could not
        # fail: a session that never opened would make it a second copy of H02b,
        # the blacklist would never be reached, and it would still print PASS —
        # the very defect caught in the brief's own H01 and fixed by adding H01b.
        if not sid:
            raise RuntimeError(
                "H02c needs the H04/H05 session and it never opened: without it this case "
                "would silently degrade into a second H02b and still report PASS. "
                "Fix the session, do not weaken the case."
            )
        m = s.tool("ssh_session_exec",
                   {"session_id": sid,
                    "command": "echo probe > /dev/sdzz-bridge-probe"})
        # The kind again: `BridgeError::CommandDenied` displays as "Command
        # denied: Command matches blacklist pattern: <pattern>"
        # (src/error.rs:59, src/security/validator.rs:167). An EACCES from the
        # host would also be an error, and would mean the pattern was missing
        # from the config and the command actually travelled — which is exactly
        # the outcome this case must not report as a pass.
        err = error_text(m)
        check("H02c", "blacklist" in err,
              f"blacklisted command -> {err or json.dumps(m)[:200]}")
    finally:
        for leftover in (sid, sid2):
            if leftover:
                s.tool("ssh_session_close", {"session_id": leftover})
        s.close()

    print(f"\n{FAILS} FAIL(s)")
    sys.exit(min(FAILS, 255))


if __name__ == "__main__":
    main()
