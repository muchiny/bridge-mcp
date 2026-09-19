#!/usr/bin/env python3
"""MCP destructive-gate round-trip, parameterized by tool (lane C, sous-lane 1).

Derived from `mcp_probe.py` (copied, not modified — that file is Task 2's and
stays untouched). Reuses its `Server` class, its `META` with
`"io.modelcontextprotocol/clientCapabilities": {"elicitation": {}}`, and the
E08a/b/c mechanism it pioneered: `requestState` and `inputResponses` are
SIBLINGS of `name`/`arguments` on `params`, the answer key is
`confirm_destructive`, and the sha256 digest over `{"name","arguments"}` is
NOT canonicalised (`params_digest`, src/mcp/request_state.rs) — `arguments`
must be repeated identically, key order included, or the retry is refused.

Usage: mcp_gate.py BIN --host raspberry --confirm
Prints one `Cnnn OK|KO <detail>` line per case; KO details are truncated to
300 characters. Exit code is the number of KO.
"""
import argparse
import json
import os
import subprocess
import sys
import threading

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "campaign-c-gate", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
}
KOS = 0


class Server:
    def __init__(self, binary):
        env = dict(os.environ, RUST_LOG="error")
        self.p = subprocess.Popen([binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.n = 0
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
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def text_of(msg):
    r = msg.get("result", {})
    return "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")


def check(cid, cond, detail):
    global KOS
    print(f"{cid} {'OK' if cond else 'KO'} {detail[:300]!r}")
    if not cond:
        KOS += 1


def gate(s, tool, arguments):
    """Un aller (sans confirmation). Renvoie (msg, result)."""
    m = s.tool(tool, arguments)
    return m, m.get("result", {})


def confirm(s, tool, arguments, request_state, response):
    return s.call("tools/call", {
        "name": tool,
        "arguments": arguments,
        "requestState": request_state,
        "inputResponses": {"confirm_destructive": response},
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--confirm", action="store_true")
    a = ap.parse_args()
    H = a.host
    SBX = "/tmp/bridge-test-0909/lane-c"
    NS = "bridge-test"
    s = Server(a.binary)

    if not a.confirm:
        print("--confirm not passed: gate observed but never answered, C154-C159 skipped")
        s.close()
        sys.exit(0)

    # C150 — ssh_exec gate.
    args150 = {"host": H, "command": "echo campaign-c-mcp"}
    m150, r150 = gate(s, "ssh_exec", args150)
    check("C150", r150.get("resultType") == "input_required" and "requestState" in r150,
          f"resultType={r150.get('resultType')} keys={sorted(r150)}")

    # C151 — ssh_file_write gate.
    args151 = {"host": H, "path": f"{SBX}/c151.txt", "content": "mcp-gate\n"}
    _, r151 = gate(s, "ssh_file_write", args151)
    check("C151", r151.get("resultType") == "input_required",
          f"resultType={r151.get('resultType')} keys={sorted(r151)}")

    # C152 — ssh_k8s_delete gate.
    args152 = {"host": H, "resource": "configmap", "name": "bmcp-nonexistent-0909", "namespace": NS}
    _, r152 = gate(s, "ssh_k8s_delete", args152)
    check("C152", r152.get("resultType") == "input_required",
          f"resultType={r152.get('resultType')} keys={sorted(r152)}")

    # C153 — the gate does not bypass through the mcp_call_tool meta-dispatch.
    args153 = {"host": H, "command": "echo campaign-c-mcp-meta"}
    m153 = s.tool("mcp_call_tool", {"name": "ssh_exec", "arguments": args153})
    r153 = m153.get("result", {})
    check("C153", r153.get("resultType") == "input_required",
          f"meta-dispatch resultType={r153.get('resultType')} keys={sorted(r153)}")

    # C154 — replay C150, accept+confirm:true -> executes.
    _, r150b = gate(s, "ssh_exec", args150)
    m154 = confirm(s, "ssh_exec", args150, r150b.get("requestState"),
                   {"action": "accept", "content": {"confirm": True}})
    check("C154", "campaign-c-mcp" in text_of(m154), text_of(m154) or json.dumps(m154))

    # C155 — replay, decline -> no execution, error surfaced.
    _, r150c = gate(s, "ssh_exec", args150)
    m155 = confirm(s, "ssh_exec", args150, r150c.get("requestState"),
                   {"action": "decline"})
    r155 = m155.get("result", {})
    check("C155",
          ("error" in m155 or r155.get("isError"))
          and "campaign-c-mcp" not in text_of(m155),
          f"error={m155.get('error')} isError={r155.get('isError')} text={text_of(m155)!r}")

    # C156 — replay, accept but confirm:false -> refused (needs BOTH halves).
    _, r150d = gate(s, "ssh_exec", args150)
    m156 = confirm(s, "ssh_exec", args150, r150d.get("requestState"),
                   {"action": "accept", "content": {"confirm": False}})
    r156 = m156.get("result", {})
    check("C156",
          ("error" in m156 or r156.get("isError"))
          and "campaign-c-mcp" not in text_of(m156),
          f"error={m156.get('error')} isError={r156.get('isError')} text={text_of(m156)!r}")

    # C157 — replay with requestState altered by one character -> refused (digest invalid).
    _, r150e = gate(s, "ssh_exec", args150)
    rs = r150e.get("requestState")
    if isinstance(rs, str) and rs:
        bad_rs = rs[:-1] + ("0" if rs[-1] != "0" else "1")
    else:
        bad_rs = "tampered-" + json.dumps(rs)
    m157 = confirm(s, "ssh_exec", args150, bad_rs,
                   {"action": "accept", "content": {"confirm": True}})
    r157 = m157.get("result", {})
    check("C157",
          ("error" in m157 or r157.get("isError"))
          and "campaign-c-mcp" not in text_of(m157),
          f"error={m157.get('error')} isError={r157.get('isError')} text={text_of(m157)!r}")

    # C158 — replay with `arguments` reordered (command before host) -> the
    # digest is not canonicalised, so this SHOULD be refused. If it passes,
    # that is a DEFECT of contract, not a success (task-5-brief Step 5).
    _, r150f = gate(s, "ssh_exec", args150)
    reordered_args = {"command": args150["command"], "host": args150["host"]}
    m158 = confirm(s, "ssh_exec", reordered_args, r150f.get("requestState"),
                   {"action": "accept", "content": {"confirm": True}})
    r158 = m158.get("result", {})
    passed = "campaign-c-mcp" in text_of(m158)
    check("C158", not passed,
          ("DEFECT-if-passed: " if passed else "") +
          f"error={m158.get('error')} isError={r158.get('isError')} text={text_of(m158)!r}")

    # C159 — readOnly tool: the gate does not bite readOnlyHint tools.
    m159 = s.tool("ssh_ls", {"host": H, "path": "/tmp/bridge-test-0909"})
    r159 = m159.get("result", {})
    check("C159",
          r159.get("resultType") != "input_required" and not r159.get("isError"),
          f"resultType={r159.get('resultType')} isError={r159.get('isError')} text={text_of(m159)[:120]!r}")

    s.close()
    print(f"\n{KOS} KO")
    sys.exit(min(KOS, 255))


if __name__ == "__main__":
    main()
