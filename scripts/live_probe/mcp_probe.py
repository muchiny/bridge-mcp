#!/usr/bin/env python3
"""MCP protocol probe against one long-lived `bridge-mcp serve` (stdio).

Sessions, tunnels and the output cache live inside ONE server process, so they
cannot be exercised by a harness that spawns a server per case. Checks E01-E16
(with sub-ids) print PASS/FAIL and the decisive fragment; the exit code is the
number of FAILs.

Read-only on the host except: E08 (`ssh_exec echo mrtr-ok`, executed only with
--confirm and only after the MRTR gate grants it), E14 (a session that runs
`cd /tmp` then `pwd`, closed afterwards), E15 (a local tunnel on port 18022,
closed afterwards) and E16 (`ssh_pty_exec echo pty-ok`). Nothing is written.

Usage: mcp_probe.py BIN [--host raspberry] [--confirm]
Without --confirm the gate is observed but never answered, so nothing runs
through it. See the CONFIRM comment at E08 for the wire shape and its source."""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "campaign-probe", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
}
FAILS = 0


class Server:
    def __init__(self, binary):
        env = dict(os.environ, RUST_LOG="error")
        self.p = subprocess.Popen([binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.n = 0
        # daemon=True: a non-daemon Timer is joined at interpreter shutdown, so
        # the probe could not exit before the full 600 s deadline elapsed.
        self.watchdog = threading.Timer(600, self.p.kill)
        self.watchdog.daemon = True
        self.watchdog.start()

    def call(self, method, params=None, meta=True):
        self.n += 1
        req = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": dict(params or {})}
        if meta:
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
        self.p.stdin.close()
        self.p.wait(timeout=10)


def text_of(msg):
    r = msg.get("result", {})
    return "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")


def check(cid, cond, detail):
    global FAILS
    print(f"{cid} {'PASS' if cond else 'FAIL'} — {detail[:200]!r}")
    if not cond:
        FAILS += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--confirm", action="store_true")
    a = ap.parse_args()
    H = a.host
    s = Server(a.binary)

    d = s.call("server/discover")
    r = d.get("result", {})
    # 2026-07-28 discovery carries `supportedVersions` (the client picks one)
    # and moved `serverInfo` out of the top level into `_meta` under the
    # reserved reverse-DNS key — `DiscoverResult` / `DiscoverMeta`,
    # src/mcp/protocol.rs. There is no top-level `protocolVersion`.
    sinfo = r.get("_meta", {}).get("io.modelcontextprotocol/serverInfo")
    check("E01", "2026-07-28" in r.get("supportedVersions", []) and sinfo is not None,
          f"discover: supportedVersions={r.get('supportedVersions')} serverInfo={sinfo} keys={sorted(r)[:8]}")
    ext = r.get("capabilities", {}).get("extensions", {})
    check("E02", "io.modelcontextprotocol/tasks" in ext, f"extensions={sorted(ext)}")

    tl = s.call("tools/list").get("result", {})
    names = sorted(t["name"] for t in tl.get("tools", []))
    check("E03", len(names) == 4 and {"mcp_search_tools", "mcp_describe_tool", "mcp_call_tool"} <= set(names),
          f"tools/list -> {names}")

    # `mcp_search_tools` is a case-insensitive SUBSTRING match on name and
    # description (its own schema says so, src/mcp/meta_tools.rs), not a
    # token/phrase search: "k3s status" matches no name and no description.
    t = text_of(s.tool("mcp_search_tools", {"query": "k3s_status"}))
    check("E04", "ssh_k3s_status" in t, t)
    t = text_of(s.tool("mcp_describe_tool", {"name": "ssh_k8s_get"}))
    check("E05", "resource" in t, t)
    t = text_of(s.tool("mcp_call_tool", {"name": "ssh_k8s_get", "arguments": {"host": H, "resource": "namespaces", "output": "name"}}))
    check("E06", "namespace/argocd" in t, t)
    m = s.tool("ssh_k3s_status", {"host": H})
    check("E07", "error" not in m and not m.get("result", {}).get("isError"), f"direct tools/call ssh_k3s_status -> {text_of(m) or m.get('error')}")

    # The signed state binds sha256 over {"name", "arguments"} and that digest
    # is NOT canonicalised (`params_digest`, src/mcp/request_state.rs), so the
    # retry must repeat this exact object, key order included.
    GATE_ARGS = {"host": H, "command": "echo mrtr-ok"}
    g = s.tool("ssh_exec", GATE_ARGS)
    gr = g.get("result", {})
    check("E08a", gr.get("resultType") == "input_required" and "requestState" in gr,
          f"gate: resultType={gr.get('resultType')} keys={sorted(gr)}")
    print("E08 input_required payload (for --confirm): " + json.dumps(gr)[:600])
    if a.confirm:
        # `requestState` and `inputResponses` are SIBLINGS of `name`/`arguments`
        # on `params`, not members of `_meta` (`ToolCallParams`,
        # src/mcp/protocol.rs). The answer is keyed by the id the server used in
        # `inputRequests` (`CONFIRM_KEY` = "confirm_destructive",
        # src/mcp/server.rs) and must satisfy BOTH halves of
        # `destructive_confirmation_granted` (src/mcp/elicitation.rs):
        # action == "accept" AND content.confirm == true. Anything else, the
        # unticked box included, is refused.
        CONFIRM = lambda gr, H: {  # noqa: E731
            "name": "ssh_exec",
            "arguments": GATE_ARGS,
            "requestState": gr.get("requestState"),
            "inputResponses": {
                "confirm_destructive": {"action": "accept", "content": {"confirm": True}}
            },
        }
        check("E08b", CONFIRM is not None,
              "CONFIRM filled: params carry name/arguments verbatim + requestState "
              "+ inputResponses.confirm_destructive{action:accept, content:{confirm:true}}")
        if CONFIRM is not None:
            m2 = s.call("tools/call", CONFIRM(gr, H))
            check("E08c", "mrtr-ok" in text_of(m2), text_of(m2) or json.dumps(m2)[:300])

    g2 = s.tool("mcp_call_tool", {"name": "ssh_exec", "arguments": {"host": H, "command": "true"}})
    check("E09", g2.get("result", {}).get("resultType") == "input_required", f"meta-dispatch gate -> {json.dumps(g2)[:200]}")

    e = s.call("tools/list", meta=False)
    check("E10", e.get("error", {}).get("code") == -32602, f"no _meta.protocolVersion -> {e.get('error')}")
    e = s.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "0"}}, meta=False)
    check("E11", e.get("error", {}).get("code") == -32022, f"initialize -> {e.get('error')}")
    e = s.call("bridge/nope")
    check("E12", e.get("error", {}).get("code") == -32601, f"unknown method -> {e.get('error')}")

    # `save_output` is a FILE PATH (`Option<String>`), not a boolean, and the
    # cache id is minted by TRUNCATION, not by `save_output`
    # (`truncate_output_with_cache`, src/domain/output_truncator.rs). So
    # `max_output` is the lever that reaches the cache. The id is HEX —
    # `format!("out-{n:04x}")`, src/domain/output_cache.rs — so `out-\d+` would
    # miss out-000a..out-000f.
    OUT_ID = r"out-[0-9a-f]+"
    m = s.tool("ssh_k8s_get", {"host": H, "resource": "pods", "all_namespaces": True, "max_output": 50})
    full = text_of(m)
    oid = re.search(OUT_ID, full + json.dumps(m.get("result", {}).get("_meta", {})))
    check("E13a", oid is not None,
          f"ssh_k8s_get max_output=50 -> {len(full)} chars, id={oid.group(0) if oid else None}")
    if oid:
        f = text_of(s.tool("ssh_output_fetch", {"output_id": oid.group(0)}))
        check("E13b", "argocd" in f, f"output_fetch -> {f[:120]}")
    # Control on a non-table tool. Without it, a bare E13a failure cannot say
    # whether the output cache is broken or only this tool's path is.
    m = s.tool("ssh_k3s_status", {"host": H, "max_output": 50})
    ctl = text_of(m)
    cid = re.search(OUT_ID, ctl)
    check("E13c", cid is not None,
          f"ssh_k3s_status max_output=50 -> {len(ctl)} chars, id={cid.group(0) if cid else None}")
    if cid:
        f = text_of(s.tool("ssh_output_fetch", {"output_id": cid.group(0)}))
        check("E13d", "== nodes ==" in f, f"output_fetch -> {f[:120]}")

    sess = text_of(s.tool("ssh_session_create", {"host": H}))
    try:
        sid = json.loads(sess)["id"]
    except (ValueError, KeyError):
        sid = None
    check("E14a", sid is not None, f"session_create -> {sess}")
    if sid:
        # No `host` here: the session already carries it, and the tool declares
        # only session_id/command/timeout_seconds/max_output/sudo/sudo_user/
        # save_output — an undeclared `host` is rejected.
        s.tool("ssh_session_exec", {"session_id": sid, "command": "cd /tmp"})
        pwd = text_of(s.tool("ssh_session_exec", {"session_id": sid, "command": "pwd"}))
        check("E14b", "/tmp" in pwd, f"session cwd retained -> {pwd}")
        lst = text_of(s.tool("ssh_session_list", {}))
        check("E14c", sid in lst, f"session_list -> {lst[:120]}")
        cl = s.tool("ssh_session_close", {"session_id": sid})
        check("E14d", not cl.get("result", {}).get("isError") and cl.get("result", {}).get("resultType") != "input_required", f"session_close -> {json.dumps(cl)[:120]}")

    tun = text_of(s.tool("ssh_tunnel_create", {"host": H, "local_port": 18022, "remote_port": 22}))
    tid = f"tunnel-{H}-18022-22"
    check("E15a", tid in tun, f"tunnel_create -> {tun[:160]}")
    if tid in tun:
        # Guarded: an unforwarded tunnel would otherwise raise here, killing the
        # probe with the tunnel still open on the host and E15d/E16 never run.
        try:
            ok = socket.create_connection(("127.0.0.1", 18022), timeout=5)
            banner = ok.recv(64).decode(errors="replace")
            ok.close()
        except OSError as exc:
            banner = f"<no data: {exc}>"
        check("E15b", banner.startswith("SSH-"), f"through tunnel -> {banner!r}")
        check("E15c", tid in text_of(s.tool("ssh_tunnel_list", {})), "tunnel_list")
        cl = s.tool("ssh_tunnel_close", {"tunnel_id": tid})
        check("E15d", not cl.get("result", {}).get("isError"), f"tunnel_close -> {json.dumps(cl)[:120]}")

    t = text_of(s.tool("ssh_pty_exec", {"host": H, "command": "echo pty-ok", "rows": 24, "cols": 80}))
    check("E16", "pty-ok" in t, t)

    s.close()
    print(f"\n{FAILS} FAIL(s)")
    sys.exit(min(FAILS, 255))


if __name__ == "__main__":
    main()
