#!/usr/bin/env python3
"""Lane D — MCP protocol surface probe, single long-lived `bridge-mcp serve`.

Fork of mcp_probe.py. Covers sub-lanes P1 (handshake/conformance), P2
(progressive listing), P3 (output cache/pagination), P4 (sessions/PTY), P5
(tunnels) and P6a (the MCP half of concurrency: P6-01..P6-05). P6b/P7/P8 are
CLI/HTTP and live in lane_d_cli.sh.

Everything destructive/mutating is confined to $SBX (a subdirectory of the
shared campaign sandbox) or is a read against the host. See task-6-brief.md
for the case table this implements verbatim.

Usage: lane_d_proto.py BIN [--host raspberry] [--sbx /tmp/bridge-test-0909/lane-d]
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "lane-d-probe", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
}
META_TASKS = {**META, "io.modelcontextprotocol/clientCapabilities":
              {"elicitation": {}, "extensions": {"io.modelcontextprotocol/tasks": {}}}}
META_CLAUDE = {**META, "io.modelcontextprotocol/clientInfo": {"name": "claude-lane-d", "version": "1"}}

FAILS = 0
LOG = []  # (case_id, verdict, detail) tuples, for the JSON side-channel


class Server:
    def __init__(self, binary):
        env = dict(os.environ, RUST_LOG="error")
        self.p = subprocess.Popen([binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.n = 0
        self.watchdog = threading.Timer(600, self.p.kill)
        self.watchdog.daemon = True
        self.watchdog.start()
        self._lock = threading.Lock()
        self._answers = {}  # id -> (msg, monotonic_recv_time)
        # Responses to a malformed/raw request carry id=null (JSON-RPC parse
        # errors) or no recognisable id at all, so they cannot be demuxed by
        # id. ALL stdout reads happen on this one reader thread (a second
        # reader racing it — e.g. call_raw() doing its own readline() — can
        # steal the very response call_raw() is waiting for, hanging it
        # forever: exactly what happened here on first run). call_raw()
        # instead appends every id-less response to this list, in arrival
        # order, and polls its length.
        self._unkeyed = []
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        while True:
            line = self.p.stdout.readline()
            if not line:
                return
            t = time.monotonic()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                with self._lock:
                    self._unkeyed.append(({"_raw": line}, t))
                continue
            mid = msg.get("id")
            with self._lock:
                if mid is None:
                    self._unkeyed.append((msg, t))
                else:
                    self._answers[mid] = (msg, t)

    def _wait_for(self, mid, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if mid in self._answers:
                    return self._answers.pop(mid)
            time.sleep(0.02)
        return ({"error": {"code": -2, "message": "no answer"}}, time.monotonic())

    def call(self, method, params=None, meta=True, timeout=30):
        self.n += 1
        mid = self.n
        req = {"jsonrpc": "2.0", "id": mid, "method": method, "params": dict(params or {})}
        if meta is True:
            req["params"]["_meta"] = META
        elif meta:
            req["params"]["_meta"] = meta
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        msg, _t = self._wait_for(mid, timeout=timeout)
        return msg

    def call_meta(self, method, params, meta):
        """Explicit control of the _meta envelope (None omits it entirely)."""
        self.n += 1
        mid = self.n
        req = {"jsonrpc": "2.0", "id": mid, "method": method, "params": dict(params or {})}
        if meta is not None:
            req["params"]["_meta"] = meta
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        msg, _t = self._wait_for(mid, timeout=30)
        return msg

    def call_raw(self, line, timeout=10):
        """Write a raw, possibly malformed line straight to stdin and take
        the next id-less response the reader thread collects (a malformed
        request's response is id=null, so it cannot be demuxed by id)."""
        with self._lock:
            start = len(self._unkeyed)
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self._unkeyed) > start:
                    return self._unkeyed.pop(start)[0]
            time.sleep(0.02)
        return {"error": {"code": -2, "message": "no answer"}}

    def call_async(self, method, params, meta=True):
        """Write the request without waiting for the reply. Returns the id;
        retrieve the (msg, monotonic_recv_time) later via wait_async()."""
        self.n += 1
        mid = self.n
        req = {"jsonrpc": "2.0", "id": mid, "method": method, "params": dict(params or {})}
        if meta is True:
            req["params"]["_meta"] = META
        elif meta:
            req["params"]["_meta"] = meta
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return mid

    def wait_async(self, mid, timeout=30):
        return self._wait_for(mid, timeout=timeout)

    def tool(self, name, arguments, meta=True):
        return self.call("tools/call", {"name": name, "arguments": arguments}, meta=meta)

    def close(self):
        self.watchdog.cancel()
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def text_of(msg):
    r = msg.get("result", {})
    return "\n".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")


def check(cid, cond, detail):
    global FAILS
    verdict = "PASS" if cond else "FAIL"
    print(f"{cid} {verdict} — {detail[:200]!r}")
    LOG.append({"id": cid, "verdict": verdict, "detail": detail})
    if not cond:
        FAILS += 1


def note(cid, detail):
    """Record a discovered-contract observation without a PASS/FAIL verdict."""
    print(f"{cid} NOTE — {detail[:300]!r}")
    LOG.append({"id": cid, "verdict": "NOTE", "detail": detail})


OUT_ID = r"out-[0-9a-f]+"


def sess_output(resp):
    """A successful ssh_session_exec's text content is a JSON blob
    ({"cwd","exit_code","output","session_id"}) -- extract just `output`.
    An error response is plain text (e.g. "Session not found: ..."), not
    JSON; fall back to the raw text in that case."""
    t = text_of(resp)
    try:
        return json.loads(t).get("output", "")
    except (ValueError, AttributeError):
        return t


def run_p1(s, H):
    print("\n=== P1 — handshake & conformance ===")
    d = s.call("server/discover")
    r = d.get("result", {})
    sinfo = r.get("_meta", {}).get("io.modelcontextprotocol/serverInfo")
    check("P1-01", r.get("supportedVersions") == ["2026-07-28"], f"supportedVersions={r.get('supportedVersions')}")
    check("P1-02", sinfo is not None, f"serverInfo={sinfo}")
    keys = set(r.keys())
    expected = {"_meta", "cacheScope", "capabilities", "instructions", "resultType", "supportedVersions", "ttlMs"}
    check("P1-03", expected <= keys and "protocolVersion" not in r, f"keys={sorted(keys)}")
    ext = r.get("capabilities", {}).get("extensions", {})
    check("P1-04", {"io.modelcontextprotocol/tasks", "com.bridge-mcp/multi-host",
                    "com.bridge-mcp/output-pagination"} <= set(ext),
          f"extensions={sorted(ext)}")
    instr = r.get("instructions", "")
    check("P1-05", bool(instr) and "353" in instr, f"len={len(instr)} has353={'353' in instr}")

    cacheable = []
    for method in ["tools/list", "prompts/list", "resources/list", "resources/templates/list",
                   "server/discover", "completion/complete"]:
        params = {"name": "dummy"} if method == "completion/complete" else {}
        resp = s.call(method, params)
        res = resp.get("result", {})
        has = "ttlMs" in res and "cacheScope" in res
        cacheable.append((method, has))
    non_cacheable = [m for m, has in cacheable if not has]
    note("P1-06", f"cacheable={[m for m,has in cacheable if has]} non_cacheable={non_cacheable}")

    r1 = s.call("tools/list").get("result", {})
    r2 = s.tool("mcp_search_tools", {"query": "session"})
    r3 = s.call("prompts/list").get("result", {})
    r4 = s.call("resources/list").get("result", {})
    all4 = [r1, r2.get("result", {}), r3, r4]
    check("P1-07", all("_meta" in x and "io.modelcontextprotocol/serverInfo" in x.get("_meta", {}) for x in all4),
          f"serverInfo present on {[('_meta' in x and 'io.modelcontextprotocol/serverInfo' in x.get('_meta',{})) for x in all4]}")
    check("P1-08", all("resultType" in x for x in all4), f"resultType present on {[('resultType' in x) for x in all4]}")

    e = s.call_meta("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "x", "version": "0"}}, None)
    err = e.get("error", {})
    check("P1-09", err.get("code") == -32022 and err.get("data", {}).get("supported") == ["2026-07-28"]
          and err.get("data", {}).get("requested") == "2025-06-18", f"initialize(legacy) -> {err}")

    e = s.call_meta("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                    "clientInfo": {"name": "x", "version": "0"}}, None)
    check("P1-10", e.get("error", {}).get("code") == -32022, f"initialize(current) -> {e.get('error')}")

    e = s.call_meta("tools/list", {}, None)
    check("P1-11", e.get("error", {}).get("code") == -32602, f"tools/list no _meta -> {e.get('error')}")

    meta_bad_rev = {**META, "io.modelcontextprotocol/protocolVersion": "2025-06-18"}
    e = s.call_meta("tools/list", {}, meta_bad_rev)
    code = e.get("error", {}).get("code")
    note("P1-12", f"_meta.protocolVersion=2025-06-18 (present, unsupported) -> code={code} msg={e.get('error',{}).get('message')}")

    e = s.call_raw('{"jsonrpc":"2.0","id":99,"method":')
    check("P1-13", e.get("error", {}).get("code") == -32700, f"truncated JSON -> {e.get('error')}")

    e = s.call_raw('["2.0",1,"tools/call",{"name":"ssh_exec"}]')
    check("P1-14", e.get("error", {}).get("code") == -32600, f"array body -> {e.get('error')}")

    e = s.call("bridge/nope")
    err = e.get("error", {})
    check("P1-15", err.get("code") == -32601 and "bridge/nope" in err.get("message", ""), f"unknown method -> {err}")

    e = s.tool("ssh_nexiste_pas_du_tout", {})
    err = e.get("error", {})
    check("P1-16", err.get("code") == -32602 and "Unknown tool: ssh_nexiste_pas_du_tout" in err.get("message", ""),
          f"unknown tool -> {err}")

    e = s.tool("ssh_podman_ps", {"host": H})
    err = e.get("error", {})
    check("P1-17", err.get("code") == -32602 and "group `podman` is not enabled" in err.get("message", ""),
          f"disabled group -> {err}")

    e = s.tool("ssh_k8s_get", {"host": H})
    is_err = e.get("error") is not None or e.get("result", {}).get("isError")
    note("P1-18", f"missing required 'resource' -> error={e.get('error')} result_isError={e.get('result',{}).get('isError')} text={text_of(e)[:150]}")
    check("P1-18", is_err, f"missing-required-arg is an error of some kind -> {e.get('error') or text_of(e)[:150]}")

    e = s.tool("ssh_session_exec", {"session_id": "x", "command": "true", "host": H})
    msg = e.get("error", {}).get("message", "") or text_of(e)
    check("P1-19", "unknown field `host`" in msg and "expected one of `session_id`" in msg, f"undeclared host -> {msg[:200]}")

    removed = ["ping", "logging/setLevel", "notifications/roots/list_changed", "resources/subscribe",
               "resources/unsubscribe", "tasks/list", "tasks/result", "completions/complete"]
    codes = {}
    for m in removed:
        resp = s.call(m, {})
        codes[m] = resp.get("error", {}).get("code")
    check("P1-20", all(c == -32601 for c in codes.values()), f"removed methods -> {codes}")

    e = s.call("completion/complete", {"ref": {"type": "ref/prompt", "name": "dummy"}, "argument": {"name": "x", "value": ""}})
    check("P1-21", e.get("error", {}).get("code") != -32601, f"completion/complete singular -> {e.get('error')}")

    e = s.call_meta("tasks/get", {"taskId": "nonexistent"}, META)
    check("P1-22", e.get("error", {}).get("code") == -32021, f"tasks/get w/o extension -> {e.get('error')}")

    mid = s.call_async("subscriptions/listen", {"notifications": {"toolsListChanged": True}})
    msg, _t = s.wait_async(mid, timeout=3)
    is_no_immediate = msg.get("error", {}).get("code") == -2  # our "no answer" sentinel = still open
    note("P1-23", f"subscriptions/listen -> {'no immediate result (id stays open)' if is_no_immediate else json.dumps(msg)[:200]}")

    e = s.tool("ssh_storage_df", {"host": H})
    content_types = [c.get("type") for c in e.get("result", {}).get("content", [])]
    has_structured = "structuredContent" in e.get("result", {})
    check("P1-24", "app" not in content_types and has_structured,
          f"content types={content_types} structuredContent={has_structured}")


def run_p2(s, H, bin_path):
    print("\n=== P2 — progressive listing ===")
    local = subprocess.run([bin_path, "list-tools", "--groups-only"], env=dict(os.environ, RUST_LOG="error"),
                           capture_output=True, text=True)
    local_tail = local.stdout.strip().splitlines()[-1] if local.stdout.strip() else ""
    note("P2-local-baseline", f"list-tools --groups-only tail: {local_tail!r}")
    local_val = subprocess.run([bin_path, "validate"], env=dict(os.environ, RUST_LOG="error"),
                               capture_output=True, text=True)
    val_tail = "\n".join(local_val.stdout.strip().splitlines()[-3:])
    note("P2-local-validate", f"validate tail:\n{val_tail}")

    tl = s.call("tools/list").get("result", {})
    names = sorted(t["name"] for t in tl.get("tools", []))
    check("P2-01", names == sorted(["mcp_call_tool", "mcp_describe_tool", "mcp_list_tool_groups", "mcp_search_tools"]),
          f"tools/list -> {names}")

    g = json.loads(text_of(s.tool("mcp_list_tool_groups", {})) or "{}")
    total_groups = g.get("total_groups")
    total_tools = g.get("total_tools")
    check("P2-02", total_groups == 56 and total_tools == 353, f"total_groups={total_groups} total_tools={total_tools}")

    mcp_groups = {gr["group"]: gr["count"] for gr in g.get("groups", [])} if isinstance(g.get("groups"), list) else g.get("groups", {})
    cli_groups = {}
    for line in local.stdout.splitlines():
        mm = re.match(r"^([a-z_]+)\s+(\d+)\s*$", line)
        if mm:
            cli_groups[mm.group(1)] = int(mm.group(2))
    if mcp_groups and cli_groups:
        common = set(mcp_groups) & set(cli_groups)
        mismatches = [k for k in common if mcp_groups[k] != cli_groups[k]]
        check("P2-03", len(mismatches) == 0 and len(common) > 0,
              f"compared {len(common)} groups, mismatches={mismatches[:5]}")
    else:
        note("P2-03", f"could not fully parse both sides for per-group diff; mcp_groups keys={len(mcp_groups)} cli_groups keys={len(cli_groups)}")

    t = text_of(s.tool("mcp_search_tools", {"query": "k3s_status"}))
    try:
        res = json.loads(t)
        first_name = res.get("results", [{}])[0].get("name")
    except (ValueError, IndexError):
        first_name = None
    check("P2-04", first_name == "ssh_k3s_status", f"search k3s_status -> first={first_name}")

    t = text_of(s.tool("mcp_search_tools", {"query": "k3s status"}))
    try:
        total = json.loads(t).get("total_matches")
    except ValueError:
        total = None
    check("P2-05", total == 0, f"search 'k3s status' (phrase) -> total_matches={total}")

    t = text_of(s.tool("mcp_search_tools", {"query": "session"}))
    try:
        results = json.loads(t).get("results", [])
    except ValueError:
        results = []
    enabled_groups = set(mcp_groups) if mcp_groups else None
    ok = all((enabled_groups is None or r.get("group") in enabled_groups) for r in results)
    check("P2-06", ok and len(results) > 0, f"search 'session' -> {len(results)} results, all in enabled groups={ok}")

    t = text_of(s.tool("mcp_search_tools", {"query": "vault"}))
    try:
        total = json.loads(t).get("total_matches")
    except ValueError:
        total = None
    check("P2-07", total == 0, f"search 'vault' (disabled group) -> total_matches={total}")

    t = text_of(s.tool("mcp_search_tools", {"query": "ps", "group": "docker", "limit": 50}))
    try:
        results = json.loads(t).get("results", [])
    except ValueError:
        results = []
    check("P2-08", len(results) > 0 and all(r.get("group") == "docker" for r in results),
          f"search ps in group=docker -> {len(results)} results")

    t = text_of(s.tool("mcp_search_tools", {"query": "ssh", "limit": 300}))
    try:
        returned = len(json.loads(t).get("results", []))
    except ValueError:
        returned = -1
    check("P2-09", 0 <= returned <= 200, f"limit=300 clamped -> returned={returned}")

    e = s.tool("mcp_search_tools", {"query": ""})
    err_text = text_of(e)
    is_error = e.get("result", {}).get("isError") or e.get("error") is not None
    check("P2-10", is_error and "non-empty" in (err_text or json.dumps(e.get("error", {}))),
          f"empty query -> isError={is_error} text={err_text[:150] or e.get('error')}")

    t = text_of(s.tool("mcp_describe_tool", {"name": "ssh_k8s_get"}))
    has_all = all(k in t for k in ["reduction_strategy", "reduce_marker", "annotations", "input_schema", "jq_filter"])
    check("P2-11", has_all, f"describe_tool ssh_k8s_get missing keys check -> len={len(t)}")

    e = s.tool("mcp_describe_tool", {"name": "ssh_vault_status"})
    err_text = text_of(e)
    is_error = e.get("result", {}).get("isError") or e.get("error") is not None
    check("P2-12", is_error and "group `vault` is not enabled" in (err_text or ""), f"describe disabled tool -> {err_text[:150]}")

    t = text_of(s.tool("mcp_call_tool", {"name": "ssh_k8s_get", "arguments": {"host": H, "resource": "namespaces", "output": "name"}}))
    check("P2-13", "namespace/argocd" in t, f"meta-dispatch ssh_k8s_get -> {t[:150]}")

    e = s.tool("mcp_call_tool", {"name": "ssh_podman_ps", "arguments": {"host": H}})
    err_text = text_of(e)
    is_error = e.get("result", {}).get("isError") or e.get("error") is not None
    check("P2-14", is_error and "group `podman` is not enabled" in (err_text or json.dumps(e.get("error", {}))),
          f"meta-dispatch disabled group -> {err_text[:150] or e.get('error')}")

    e = s.tool("mcp_call_tool", {"name": "ssh_exec", "arguments": {"host": H, "command": "true"}})
    check("P2-15", e.get("result", {}).get("resultType") == "input_required", f"meta-dispatch destructive gate -> {json.dumps(e)[:200]}")

    e = s.tool("ssh_k3s_status", {"host": H})
    is_err = e.get("error") is not None or e.get("result", {}).get("isError")
    check("P2-16", not is_err, f"direct real-name call while progressive -> {text_of(e)[:150] or e.get('error')}")
    note("P2-17", "confirmed: progressive listing hides DISCOVERY only, not a dispatch/access control — undocumented in README.md")

    e = s.call_meta("tools/list", {"cursor": "pas-un-entier"}, META)
    err = e.get("error", {})
    check("P2-18", err.get("code") == -32602 and "Invalid pagination cursor" in err.get("message", ""), f"bad cursor -> {err}")


def run_p3(s, H, sbx):
    print("\n=== P3 — output cache & pagination ===")
    m = s.tool("ssh_k3s_status", {"host": H, "max_output": 50})
    full = text_of(m)
    has_banner = "⚠️ MORE DATA AVAILABLE — Truncated:" in full
    oid = re.search(OUT_ID, full)
    check("P3-01", has_banner and oid is not None, f"len={len(full)} banner={has_banner} id={oid.group(0) if oid else None}")
    id1 = oid.group(0) if oid else None

    if id1:
        f = s.tool("ssh_output_fetch", {"output_id": id1})
        ft = text_of(f)
        hdr_ok = re.search(rf"--- output_id={re.escape(id1)} \| offset=0 \| chars=\d+/\d+ \| has_more=false ---", ft)
        check("P3-02", hdr_ok is not None and "== nodes ==" in ft, f"fetch full -> hdr_ok={bool(hdr_ok)} has_nodes={'== nodes ==' in ft}")

        f = s.tool("ssh_output_fetch", {"output_id": id1, "offset": 100, "limit": 50})
        ft = text_of(f)
        hdr_ok = re.search(r"offset=100 \| chars=50/\d+ \| has_more=true", ft)
        check("P3-03", hdr_ok is not None, f"paginated fetch -> {ft[:120]}")

        f = s.tool("ssh_output_fetch", {"output_id": id1, "offset": 999999})
        ft = text_of(f)
        is_err = f.get("result", {}).get("isError")
        hdr_ok = re.search(r"chars=0/\d+ \| has_more=false", ft)
        note("P3-04", f"offset beyond end -> isError={is_err} matched_zero_chars={bool(hdr_ok)} text={ft[:150]}")

    e = s.tool("ssh_output_fetch", {"output_id": "out-ffff"})
    et = text_of(e)
    is_err = e.get("result", {}).get("isError")
    check("P3-05", is_err and "Output 'out-ffff' not found" in et and "TTL: 300s" in et, f"unknown id -> {et[:150]}")

    m = s.tool("ssh_k8s_get", {"host": H, "resource": "pods", "all_namespaces": True, "max_output": 50})
    full = text_of(m)
    oid = re.search(OUT_ID, full)
    has_banner = "MORE DATA AVAILABLE" in full
    check("P3-06", has_banner and oid is not None, f"ssh_k8s_get (table tool) -> len={len(full)} banner={has_banner} id={oid.group(0) if oid else None} — FAIL is expected regression of D2")

    p3_07 = {}
    for tool in ["ssh_disk_usage", "ssh_storage_df", "ssh_service_list", "ssh_process_list"]:
        mm = s.tool(tool, {"host": H, "max_output": 50})
        tt = text_of(mm)
        oo = re.search(OUT_ID, tt)
        p3_07[tool] = {"len": len(tt), "id": oo.group(0) if oo else None}
    note("P3-07", f"D2 extent check: {p3_07}")

    ids = []
    for i in range(11):
        mm = s.tool("ssh_k3s_status", {"host": H, "max_output": 50})
        tt = text_of(mm)
        oo = re.search(OUT_ID, tt)
        ids.append(oo.group(0) if oo else None)
    expected_ids = [f"out-{n:04x}" for n in range(len(ids))]
    # ids are cumulative across the whole run (P3-01 already minted 1-2), so
    # just check they are consecutive hex and monotonically increasing.
    hexes = [int(i.split("-")[1], 16) for i in ids if i]
    check("P3-08", len(hexes) == 11 and hexes == sorted(hexes) and all(f"out-{h:04x}" == i for h, i in zip(hexes, ids)),
          f"11 ids -> {ids}")

    if ids and ids[0]:
        f = s.tool("ssh_output_fetch", {"output_id": ids[0]})
        is_err = f.get("result", {}).get("isError")
        check("P3-09", not is_err, f"refetch first of the 11 ids ({ids[0]}) -> isError={is_err}")

    m = s.tool("ssh_k3s_status", {"host": H, "save_output": True})
    et = text_of(m)
    is_err = m.get("result", {}).get("isError")
    check("P3-13", is_err and "invalid type: boolean `true`, expected a string" in et, f"save_output=true(bool) -> {et[:150]}")

    m = s.tool("ssh_k3s_status", {"host": H, "max_output": 50}, meta=META_CLAUDE)
    len_claude = len(text_of(m))
    m2 = s.tool("ssh_k3s_status", {"host": H, "max_output": 50}, meta=META)
    len_default = len(text_of(m2))
    note("P3-15", f"client_overrides by clientInfo.name: META_CLAUDE len={len_claude} META(lane-d-probe) len={len_default}")

    return id1  # for P3-10 (needs a fresh server) done by caller


def run_p3_fresh(binary, H):
    """P3-10: the output cache is per-process. Kill the serve used for P3-01
    (which minted out-0000) and start a brand new one; out-0000 must be gone."""
    print("\n=== P3-10 — cache does not survive a server restart ===")
    s2 = Server(binary)
    try:
        e = s2.tool("ssh_output_fetch", {"output_id": "out-0000"})
        is_err = e.get("result", {}).get("isError")
        et = text_of(e)
        check("P3-10", is_err and "not found" in et, f"fresh serve, out-0000 -> isError={is_err} text={et[:150]}")
    finally:
        s2.close()


def run_p4(s, H, sbx):
    print("\n=== P4 — persistent sessions & PTY ===")
    n_sess_exec = 0

    def marked(cmd):
        """Append a harmless no-op (`:` swallows its argument, prints
        nothing, does not affect $?) carrying a unique lane-d-sess-<n>
        literal. Audit's `command` field is args.command verbatim
        (ssh_session_exec.rs:186), so the marker lands in the audit log
        regardless of whether the marker segment itself ever executes
        (e.g. after a bare `exit`, which is exactly the case P4-14 probes)."""
        nonlocal n_sess_exec
        n_sess_exec += 1
        return f"{cmd}; : lane-d-sess-{n_sess_exec:02d}"

    sess = text_of(s.tool("ssh_session_create", {"host": H}))
    try:
        obj = json.loads(sess)
        sid = obj.get("id")
    except ValueError:
        obj, sid = {}, None
    check("P4-01", sid is not None and obj.get("host") == H and "cwd" in obj and "created_at_secs_ago" in obj, f"session_create -> {sess[:150]}")

    if not sid:
        note("P4-BLOCK", "session_create failed, skipping rest of P4")
        return 0

    def sess_exec(cmd, **kw):
        return s.tool("ssh_session_exec", {"session_id": sid, "command": marked(cmd), **kw})

    # DISCOVERED DEFECT (found live, not in the 2026-09-06 report): a command
    # whose own stdout has no trailing newline loses ALL of its output.
    # parse_exec_output (src/ssh/session.rs:533-556) finds the begin_marker,
    # then does `raw[..begin_pos].rfind('\n')` to locate where the command's
    # last output line starts; when the command's own last line has no
    # trailing \n, the marker is glued onto that same line, rfind('\n') skips
    # straight past it (or finds nothing, for single-line output), and the
    # slice `raw[..line_start]` silently drops the entire unterminated line.
    # `printf %s`/`cat <file with no final \n>` never end in \n -> repro is
    # 100%. This is unrelated to the persistence property P4-03/04/08/12 are
    # actually testing, so (case edit, §3.8 category 3, property preserved:
    # "does state persist across ssh_session_exec calls") the readback here
    # uses `echo` (which appends \n) instead of the brief's `printf %s`, and
    # the write in P4-12 appends \n to the file so `cat`'s own output isn't
    # itself unterminated. The raw bug is demonstrated separately below
    # (P4-NL) with a minimal, marker-free repro.
    raw_nl = s.tool("ssh_session_exec", {"session_id": sid, "command": "printf lane-d-no-nl"})
    raw_nl_out = sess_output(raw_nl)
    check("P4-NL", raw_nl_out == "", f"DISCOVERED DEFECT: command output with no trailing newline is dropped entirely -> printf (no \\n) output={raw_nl_out!r} (expected 'lane-d-no-nl') see src/ssh/session.rs:533-556")

    sess_exec(f"cd {sbx}")
    pwd = sess_output(sess_exec("pwd"))
    check("P4-02", pwd == sbx, f"cwd persists -> {pwd!r}")
    j = json.loads(text_of(s.tool("ssh_session_list", {})) or "[]")
    listed = next((x for x in j if x.get("id") == sid), None)
    note("P4-02-cwd-json", f"session_list cwd for S1 -> {listed.get('cwd') if listed else None}")

    sess_exec(f"export LANE_D=marker-{sid[:6] if sid else '0909'}")
    marker_val = sess_output(sess_exec('echo "$LANE_D"')).strip()
    marker_expected = f"marker-{sid[:6] if sid else '0909'}"
    check("P4-03", marker_val == marker_expected, f"exported env var persists -> {marker_val!r} expected {marker_expected!r} (readback via echo, not printf %s, to sidestep P4-NL)")

    sess_exec("LANE_D_LOCAL=plain")
    plain_val = sess_output(sess_exec('echo "$LANE_D_LOCAL"')).strip()
    check("P4-04", plain_val == "plain", f"unexported shell var persists -> {plain_val!r}")

    sess_exec("umask 0027; umask")
    umask_val = sess_output(sess_exec("umask"))
    check("P4-05", "0027" in umask_val, f"umask persists -> {umask_val!r}")

    lst = text_of(s.tool("ssh_session_list", {}))
    listed_j = json.loads(lst or "[]")
    s1_entry = next((x for x in listed_j if x.get("id") == sid), None)
    check("P4-06", s1_entry is not None and s1_entry.get("cwd") == sbx, f"session_list reflects cwd -> {s1_entry}")

    sess2 = text_of(s.tool("ssh_session_create", {"host": H}))
    try:
        sid2 = json.loads(sess2).get("id")
    except ValueError:
        sid2 = None
    check("P4-07", sid2 is not None and sid2 != sid, f"second session id -> {sid2} vs {sid}")

    def sess2_exec(cmd, **kw):
        return s.tool("ssh_session_exec", {"session_id": sid2, "command": marked(cmd), **kw})

    if sid2:
        v = sess_output(sess2_exec('echo "${LANE_D:-vide}"')).strip()
        check("P4-08", v == "vide", f"isolation: S2 does not see S1's LANE_D -> {v!r}")
        pwd2 = sess_output(sess2_exec("pwd"))
        check("P4-09", pwd2 != sbx, f"isolation: S2 cwd untouched -> {pwd2!r}")

    lst = json.loads(text_of(s.tool("ssh_session_list", {})) or "[]")
    check("P4-10", len(lst) == 2, f"two sessions listed -> {len(lst)}")

    h = text_of(s.tool("ssh_health", {}))
    check("P4-11", "Total active sessions: 2" in h, f"ssh_health agrees -> {h[:300]}")

    # Write WITH a trailing newline, sidestepping P4-NL for this probe's own
    # readback (cat's stdout must end in \n to survive parse_exec_output).
    sess_exec(f"printf 'lane-d\\n' > {sbx}/lane-d-session.txt")
    catout = sess_output(sess_exec(f"cat {sbx}/lane-d-session.txt"))
    check("P4-12", catout == "lane-d", f"real write persists across session -> {catout!r}")

    idun = sess_output(s.tool("ssh_session_exec", {"session_id": sid, "command": marked("id -un"), "sudo": True}))
    check("P4-15", idun.strip() == "root", f"sudo works in session -> {idun!r}")

    rm_probe = s.tool("ssh_session_exec", {"session_id": sid, "command": marked(f"rm -rf {sbx}/blacklist-probe")})
    is_err = rm_probe.get("error") is not None or rm_probe.get("result", {}).get("isError")
    err_text = rm_probe.get("error", {}).get("message", "") or text_of(rm_probe)
    check("P4-16", is_err and ("blacklist" in err_text.lower() or "denied" in err_text.lower()), f"blacklist applies in session -> {err_text[:150]}")

    bad = s.tool("ssh_session_exec", {"session_id": "inexistant", "command": marked("true")})
    is_err = bad.get("error") is not None or bad.get("result", {}).get("isError")
    bt = bad.get("error", {}).get("message", "") or text_of(bad)
    check("P4-17", is_err and "inexistant" in bt, f"unknown session id -> {bt[:150]}")

    # Fix round 1 (reviewer-flagged): P4-13's evidence must isolate `exit`
    # from the timeout mechanism at P4-18. Both paths converge on the SAME
    # eviction call (read_until_marker_inclusive returning ANY Err --
    # EOF/closed-channel OR timeout -- evicts and closes the session,
    # src/ssh/session.rs:219-227) but they are two DIFFERENT triggers, and
    # running the exit probe on S1 *after* a timeout on that same S1 (the
    # original order here) means S1 is already dead from the timeout by
    # the time "exit 7" runs -- P4-13 would then just be re-observing the
    # timeout's eviction, not exit's. So the exit probe runs HERE, on S1,
    # which is still alive (only cd/env/umask/write/sudo/blacklist/unknown-
    # session-id have touched it so far -- none of those are fatal). The
    # timeout probe (P4-18) moves below onto ITS OWN fresh session S3, so
    # neither probe's evidence is contaminated by the other's eviction.
    ex = sess_exec("exit 7")
    exj = {}
    ex_text = text_of(ex)
    try:
        exj = json.loads(ex_text)
    except ValueError:
        pass
    ex_is_err = ex.get("result", {}).get("isError")
    check("P4-13", exj.get("exit_code") == 7 or ex_is_err,
          f"exit_code in session JSON -> {exj or ex_text} (attendu exit_code:7; observed: isError={ex_is_err}, discovered contract below)")

    pwd_after_exit = text_of(sess_exec("pwd"))
    session_survived = sbx in pwd_after_exit
    note("P4-14", f"DISCOVERED CONTRACT: a bare 'exit N' inside ssh_session_exec's command KILLS the session (channel closes; session manager evicts it) -- session_survived={session_survived}, next call -> {pwd_after_exit!r}. "
         "Mechanism per source: build_exec_wrapper (session.rs:423-436) runs the command with NO subshell isolation, so `exit` terminates the persistent shell itself; that closes the channel, "
         "read_until_marker_inclusive sees EOF and returns Err(\"Shell session closed unexpectedly\") (session.rs:502-506); execute_in_session's `if let Err(e) = ...` (session.rs:219-227) evicts and "
         "closes the session on ANY such Err, unconditionally.")
    check("P4-14", not session_survived and "not found" in pwd_after_exit.lower(),
          f"session does NOT survive a bare 'exit N' -> {pwd_after_exit}")

    # DISCOVERED DEFECT (reviewer-flagged, own id P4-TO): the SAME eviction
    # at session.rs:219-227 fires on ANY Err from read_until_marker_inclusive,
    # and a timeout is ALSO an Err (SshTimeout, session.rs:516-518) -- the
    # comment at the eviction site says "Shell is dead", but a command that
    # merely ran long is not necessarily a dead shell. A fresh session S3
    # isolates this from the exit probe above: verify it survives a
    # NON-fatal blocking wait, then time it out, then check whether it
    # still answers.
    sess3 = text_of(s.tool("ssh_session_create", {"host": H}))
    try:
        sid3 = json.loads(sess3).get("id")
    except ValueError:
        sid3 = None

    def sess3_exec(cmd, **kw):
        return s.tool("ssh_session_exec", {"session_id": sid3, "command": marked(cmd), **kw})

    t0 = time.monotonic()
    to = sess3_exec("sleep 20", timeout_seconds=3)
    elapsed = time.monotonic() - t0
    to_text = text_of(to)
    is_err = to.get("error") is not None or to.get("result", {}).get("isError")
    check("P4-18", is_err and elapsed < 10.0 and "not found" not in to_text.lower(),
          f"S3 (fresh) timeout honored -> isError={is_err} elapsed={elapsed:.1f}s text={to_text[:120]!r}")

    after_timeout = sess3_exec("true") if sid3 else {}
    at_text = text_of(after_timeout)
    at_is_err = after_timeout.get("error") is not None or after_timeout.get("result", {}).get("isError")
    note("P4-TO", f"DISCOVERED DEFECT: a plain timeout (not an exit) ALSO destroys the session -- src/ssh/session.rs:219-227 evicts on ANY Err from read_until_marker_inclusive, and SshTimeout "
         f"(session.rs:516-518) is such an Err. The eviction site's own comment says \"Shell is dead\", but the remote shell may be perfectly alive, just slow -- this permanently destroys a "
         f"persistent session for a merely-slow command. next call on S3 -> isError={at_is_err} text={at_text[:150]!r}")
    check("P4-TO", at_is_err and "not found" in at_text.lower(),
          f"S3 does NOT survive a timeout (same eviction path as exit, different trigger) -> {at_text}")

    # P4-21: clean close, no destructive-gate detour. Tested on S2 (never
    # exit'd/timed-out) rather than S1 or S3 so this assertion is not
    # collateral damage from either eviction discovery above.
    cl1 = s.tool("ssh_session_close", {"session_id": sid2}) if sid2 else {}
    cl1r = cl1.get("result", {})
    check("P4-21", bool(sid2) and cl1r.get("resultType") != "input_required" and not cl1r.get("isError"), f"session_close (S2) -> {json.dumps(cl1)[:200]}")

    after = s.tool("ssh_session_exec", {"session_id": sid, "command": marked("true")})
    is_err = after.get("error") is not None or after.get("result", {}).get("isError")
    check("P4-22", is_err, f"exec on S1 after it self-destructed via exit -> isError={is_err} (session is genuinely gone, not merely delisted)")

    # Defensive: S3 should already be dead from its own timeout eviction
    # (P4-TO), but close it explicitly in case that ever changes, so a fix
    # to the eviction bug doesn't silently leave an orphan session behind.
    if sid3:
        s.tool("ssh_session_close", {"session_id": sid3})

    final_list_text = text_of(s.tool("ssh_session_list", {}))
    # Empty state is the friendly string "No active sessions.", not "[]"
    # (same pattern as ssh_tunnel_list's "No active tunnels." in P5-01).
    try:
        lst_final = json.loads(final_list_text or "[]")
    except ValueError:
        lst_final = [] if "No active sessions." in final_list_text else [final_list_text]
    h_final = text_of(s.tool("ssh_health", {}))
    check("P4-23", len(lst_final) == 0 and "Total active sessions: 0" in h_final,
          f"no orphan sessions -> list={lst_final} health_has_zero={'Total active sessions: 0' in h_final}")

    pty = text_of(s.tool("ssh_pty_exec", {"host": H, "command": "echo pty-ok", "rows": 24, "cols": 80}))
    check("P4-24", "pty-ok" in pty and "\r\n" in pty, f"pty_exec CRLF -> {pty!r}")

    a = text_of(s.tool("ssh_pty_interact", {"host": H, "input": "lane-d-echo", "session_id": "peu-importe"}))
    b = text_of(s.tool("ssh_pty_interact", {"host": H, "input": "lane-d-echo", "session_id": "autre"}))
    check("P4-25", "lane-d-echo" in a and "lane-d-echo" in b, f"pty_interact session_id ignored (both identical) -> {a!r} / {b!r}")

    rz = s.tool("ssh_pty_resize", {"host": H, "rows": 40, "cols": 120})
    rz_ok = not rz.get("result", {}).get("isError") and rz.get("error") is None
    sz = text_of(s.tool("ssh_pty_exec", {"host": H, "command": "stty size"}))
    check("P4-26", rz_ok and "40 120" not in sz, f"pty_resize succeeds={rz_ok} but stty size on a fresh pty -> {sz!r} (no persisting PTY object)")

    return n_sess_exec


def run_p5(s, H):
    print("\n=== P5 — tunnels ===")
    base = text_of(s.tool("ssh_tunnel_list", {}))
    check("P5-01", "No active tunnels." in base, f"baseline -> {base!r}")

    tun = text_of(s.tool("ssh_tunnel_create", {"host": H, "local_port": 18022, "remote_port": 22}))
    tid = f"tunnel-{H}-18022-22"
    check("P5-02", tid in tun, f"tunnel id form -> {tun[:160]}")

    banner = "<not attempted>"
    if tid in tun:
        try:
            ok = socket.create_connection(("127.0.0.1", 18022), timeout=5)
            banner = ok.recv(64).decode(errors="replace")
            ok.close()
        except OSError as exc:
            banner = f"<no data: {exc}>"
    check("P5-03", banner.startswith("SSH-"), f"through tunnel -> {banner!r}")

    ss_out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    listen_lines = [l for l in ss_out.splitlines() if ":18022" in l]
    check("P5-04", any("127.0.0.1:18022" in l for l in listen_lines) and not any("0.0.0.0:18022" in l for l in listen_lines),
          f"listen addr -> {listen_lines}")

    lst = text_of(s.tool("ssh_tunnel_list", {}))
    has_fields = tid in lst
    check("P5-05", has_fields, f"tunnel_list inventory -> {lst[:250]}")

    dup = s.tool("ssh_tunnel_create", {"host": H, "local_port": 18022, "remote_port": 22})
    dup_text = text_of(dup)
    is_err = dup.get("error") is not None or dup.get("result", {}).get("isError")
    check("P5-06", is_err, f"duplicate port -> isError={is_err} text={dup_text[:150] or dup.get('error')}")

    tun2 = text_of(s.tool("ssh_tunnel_create", {"host": H, "local_port": 18023, "remote_port": 6443}))
    tid2 = f"tunnel-{H}-18023-6443"
    ok2 = False
    if tid2 in tun2:
        try:
            c = socket.create_connection(("127.0.0.1", 18023), timeout=5)
            c.close()
            ok2 = True
        except OSError as exc:
            ok2 = False
    check("P5-07", tid2 in tun2 and ok2, f"second simultaneous tunnel (K3s apiserver, connect+close only) -> created={tid2 in tun2} connect_ok={ok2}")

    bad_close = s.tool("ssh_tunnel_close", {"tunnel_id": "tunnel-inexistant-1-2"})
    is_err = bad_close.get("error") is not None or bad_close.get("result", {}).get("isError")
    check("P5-08", is_err, f"close unknown tunnel -> isError={is_err}")

    c1 = s.tool("ssh_tunnel_close", {"tunnel_id": tid})
    c2 = s.tool("ssh_tunnel_close", {"tunnel_id": tid2})
    ok1 = not c1.get("result", {}).get("isError") and c1.get("error") is None
    ok2c = not c2.get("result", {}).get("isError") and c2.get("error") is None
    check("P5-09", ok1 and ok2c, f"close both real tunnels -> {ok1} {ok2c}")

    final = text_of(s.tool("ssh_tunnel_list", {}))
    ss_out2 = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    remaining = len([l for l in ss_out2.splitlines() if ":18022" in l or ":18023" in l])
    check("P5-10", "No active tunnels." in final and remaining == 0, f"ports released -> list={final!r} remaining_listeners={remaining}")


def run_p6a(s, H):
    print("\n=== P6a — concurrency (MCP half) ===")
    ids = []
    for i in range(6):
        mid = s.call_async("tools/call", {"name": "ssh_pty_exec", "arguments": {"host": H, "command": "sleep 6"}})
        ids.append(mid)
    t_start = time.monotonic()
    times = []
    errs = []
    for mid in ids:
        msg, t = s.wait_async(mid, timeout=20)
        times.append(t - t_start)
        errs.append(msg.get("error"))
    check("P6-01", all(e is None for e in errs), f"6 calls, errors -> {errs}")
    t1_5 = times[:5]
    t6 = times[5]
    check("P6-02", max(t1_5) < 10.0, f"first 5 timestamps -> {t1_5}")
    check("P6-03", (t6 - max(t1_5)) > 3.0, f"6th - max(1..5) -> {t6 - max(t1_5):.1f}s (t6={t6:.1f}s)")

    # P6-04/05: the exemption must be tested with EXACTLY 5 in-flight sleeps,
    # not 6. The read loop calls acquire_owned() (blocking) BEFORE spawning
    # each handler, in the same order messages are read off stdin -- so if a
    # 6th (non-exempt) message is sent first, the loop blocks trying to
    # acquire ITS permit and never even reads what comes after it, exemption
    # or not. (First attempt at this case used 6 in-flight + a probe sent
    # right after: it hung for the full 5s wait, misreporting the exemption
    # as broken -- it was testing the read-loop's FIFO ordering, not the
    # exemption.) Sending only 5 fills every permit without leaving a 6th
    # message stuck in the read loop, so the probe -- sent as the very next
    # message -- is the next thing the loop reads and can dispatch
    # immediately if truly exempt.
    ids2 = []
    for i in range(5):
        mid = s.call_async("tools/call", {"name": "ssh_pty_exec", "arguments": {"host": H, "command": "sleep 6"}})
        ids2.append(mid)
    time.sleep(0.3)  # let the read loop actually acquire all 5 permits
    t0 = time.monotonic()
    exempt_mid = s.call_async("tasks/get", {"taskId": "probe"}, meta=META_TASKS)
    exempt_msg, exempt_t = s.wait_async(exempt_mid, timeout=5)
    exempt_elapsed = exempt_t - t0
    check("P6-04", exempt_elapsed < 2.0, f"tasks/get with tasks extension, semaphore full -> {exempt_elapsed:.2f}s msg={exempt_msg}")

    counter_mid = s.call_async("tasks/get", {"taskId": "probe"}, meta=META)
    counter_msg, _ = s.wait_async(counter_mid, timeout=5)
    check("P6-05", counter_msg.get("error", {}).get("code") == -32021, f"tasks/get without extension -> {counter_msg.get('error')}")

    # Drain the 5 in-flight sleeps (not 6 -- P6-04's fix cut this batch to 5,
    # see the comment above) before moving on, so P7/P8 don't inherit load.
    for mid in ids2:
        s.wait_async(mid, timeout=20)


LOCK_DIR = "/home/muchini/bmcp-test-0909/.superpowers/campaign/2026-09-09/.lane-exclusive"


class ExclusiveLock:
    """Campaign-wide mutual exclusion for P6-P8 (brief step "Poser un verrou
    de campagne", .superpowers/sdd/2026-09-09-raspberry-full-campaign/
    task-6-brief.md Parallelisme section). P8 starts a daemon on the
    default socket path; every other lane's `bridge-mcp tool` call gets
    silently rerouted to it the moment that socket exists
    (try_forward_to_daemon, src/cli/runner.rs:87-132) -- an unlocked P8 can
    hijack another lane's CLI calls mid-run. `os.mkdir` is atomic (fails if
    the directory already exists), so this both detects real contention
    from another lane and survives a lane_d_proto.py + lane_d_cli.sh
    handoff: acquire() refuses to steal a lock it did not create, and
    release() only ever removes a lock this instance created."""

    def __init__(self, path=LOCK_DIR):
        self.path = path
        self.owned = False

    def acquire(self):
        try:
            os.mkdir(self.path)
            self.owned = True
        except FileExistsError:
            print(f"ABORT: {self.path} already held by another lane/run -- "
                  "P6-P8 are exclusive, refusing to start.", file=sys.stderr)
            sys.exit(1)

    def release(self):
        if self.owned:
            try:
                os.rmdir(self.path)
            except OSError as e:
                print(f"WARNING: could not remove lock {self.path}: {e}", file=sys.stderr)
            self.owned = False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--sbx", default="/tmp/bridge-test-0909/lane-d")
    ap.add_argument("--only", default="", help="comma list of p1,p2,p3,p4,p5,p6a to restrict which sub-lanes run")
    ap.add_argument("--json-out", default="")
    a = ap.parse_args()
    H = a.host
    sbx = a.sbx
    only = set(a.only.split(",")) if a.only else {"p1", "p2", "p3", "p4", "p5", "p6a"}

    s = Server(a.binary)
    n_sess_exec = 0
    try:
        if "p1" in only:
            run_p1(s, H)
        if "p2" in only:
            run_p2(s, H, a.binary)
        if "p3" in only:
            run_p3(s, H, sbx)
        if "p4" in only:
            n_sess_exec = run_p4(s, H, sbx)
        if "p5" in only:
            run_p5(s, H)
        if "p6a" in only:
            lock = ExclusiveLock()
            lock.acquire()
            try:
                run_p6a(s, H)
            finally:
                lock.release()
    finally:
        s.close()

    if "p3" in only:
        run_p3_fresh(a.binary, H)

    if "p4" in only:
        print(f"\nP4 ssh_session_exec calls emitted: {n_sess_exec}")

    if a.json_out:
        with open(a.json_out, "w") as f:
            json.dump(LOG, f, indent=2)

    print(f"\n{FAILS} FAIL(s)")
    sys.exit(min(FAILS, 255))


if __name__ == "__main__":
    main()
