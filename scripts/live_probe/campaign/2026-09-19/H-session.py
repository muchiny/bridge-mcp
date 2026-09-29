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

H02b and H02c are TRAIL GENERATORS, not assertions. Their `check` passes on any
error at all, which is deliberate: the property under test is that the resulting
line in the bridge host's audit log carries `tool_name`, and that log is not
reachable from here. The proof is the audit line, asserted by the caller; a PASS
printed below means only that the trail was produced.

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
            timed_out = envelope(m) is None
            check("H06b", timed_out,
                  f"sleep 8 @ timeout 2 -> {json.dumps(m)[:300]}")

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
        check("H02b", "error" in m or m.get("result", {}).get("isError"),
              f"unknown session_id -> {json.dumps(m)[:200]}")

        # Denied by the local validator BEFORE any SSH traffic: `>\\s*/dev/(sd|
        # mmcblk|nvme)` is a blacklist pattern, and ssh_session_exec is not
        # annotated destructive, so no confirmation gate stands in front of the
        # denial. Chosen to be harmless even if the pattern were missing from a
        # config: /dev/sdzz-bridge-probe is not a device node, and an
        # unprivileged user cannot create one under /dev, so the unguarded form
        # fails with EACCES instead of writing to a disk. A case must be safe on
        # its own terms — see the `about` block of H-fixes.json.
        m = s.tool("ssh_session_exec",
                   {"session_id": sid or "H-session-unknown-id",
                    "command": "echo probe > /dev/sdzz-bridge-probe"})
        check("H02c", "error" in m or m.get("result", {}).get("isError"),
              f"blacklisted command -> {json.dumps(m)[:200]}")
    finally:
        for leftover in (sid, sid2):
            if leftover:
                s.tool("ssh_session_close", {"session_id": leftover})
        s.close()

    print(f"\n{FAILS} FAIL(s)")
    sys.exit(min(FAILS, 255))


if __name__ == "__main__":
    main()
