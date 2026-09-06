#!/usr/bin/env python3
"""Live probe of the reduction params against a bridge host, through the CLI
and through a stdio MCP session, in parallel.

Usage:
  scripts/live_probe/run.py BIN [--host raspberry] [--jobs 4] [--path both|cli|mcp]
                            [--only J1,J4] [--baseline] [--report PATH]

Each case in cases.json runs through every path it lists. A verdict is
UNEXPECTED (and counted in the exit code) when a case fails without
--baseline, or when a case owned by "base" fails with --baseline. With
--baseline, a failing case owned by a lane is reported as "KO (expected)":
that is the defect the lane exists to fix.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "live-probe", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
NOISE = ("WinRM Basic auth",)


def env():
    e = dict(os.environ)
    e["RUST_LOG"] = "error"
    return e


def clean(text):
    return "\n".join(l for l in text.splitlines() if not any(n in l for n in NOISE))


def run_cli(binary, tool, args, yes):
    cmd = [binary, "tool", tool]
    if yes:
        cmd.append("--yes")
    cmd += ["--json-args", json.dumps(args)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env())
    return p.returncode, clean(p.stdout), clean(p.stderr)


def run_mcp(binary, tool, args):
    proc = subprocess.Popen(
        [binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env(),
    )
    try:
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": tool, "arguments": args, "_meta": META}}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        for _ in range(50):
            line = proc.stdout.readline()
            if not line:
                return 1, "", "mcp: server closed stdout without answering"
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != 1:
                continue
            if "error" in msg:
                return 1, "", f"Error: {msg['error'].get('message', msg['error'])}"
            result = msg.get("result", {})
            if result.get("resultType") == "input_required":
                return 1, "", "Error: input_required (destructive gate) — case must be cli-only"
            text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            if result.get("isError"):
                return 1, text, f"Error: {text}"
            return 0, text, ""
        return 1, "", "mcp: no response with id 1 in 50 lines"
    finally:
        proc.kill()


def check(expect, rc, out, err):
    kind, _, arg = expect.partition("=")
    s = out.rstrip("\n")
    lines = s.splitlines() if s else []
    both = out + "\n" + err
    if kind == "ok":
        return rc == 0 and "Error:" not in both
    if kind == "first":
        return rc == 0 and lines[:1] == [arg]
    if kind == "eq":
        return rc == 0 and s == arg.replace("\\n", "\n")
    if kind == "re":
        return rc == 0 and re.search(arg, s, re.M) is not None
    if kind == "lines":
        return rc == 0 and len(lines) == int(arg)
    if kind == "lines>":
        return rc == 0 and len(lines) >= int(arg)
    if kind == "count":
        needle, _, n = arg.rpartition(":")
        return rc == 0 and s.count(needle) == int(n)
    if kind == "json":
        try:
            json.loads(s)
            return rc == 0
        except json.JSONDecodeError:
            return False
    if kind == "error":
        return rc != 0 and arg in both
    raise SystemExit(f"unknown expectation kind {kind!r}")


def substitute(value, variables):
    if isinstance(value, str):
        for k, v in variables.items():
            value = value.replace("${" + k + "}", v)
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--path", choices=["both", "cli", "mcp"], default="both")
    ap.add_argument("--only", default="")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--report", default="")
    a = ap.parse_args()

    spec = json.loads((HERE / "cases.json").read_text())
    variables = spec.get("vars", {})
    only = {x for x in a.only.split(",") if x}
    cases = [c for c in spec["cases"] if not only or c["id"] in only]

    jobs = []
    for c in cases:
        args = {"host": a.host}
        args.update({k: substitute(v, variables) for k, v in c["args"].items()})
        for path in c.get("paths", ["cli", "mcp"]):
            if a.path != "both" and path != a.path:
                continue
            jobs.append((c, path, args))

    def work(job):
        c, path, args = job
        if path == "cli":
            rc, out, err = run_cli(a.binary, c["tool"], args, c.get("yes", False))
        else:
            rc, out, err = run_mcp(a.binary, c["tool"], args)
        return c["id"], path, check(c["expect"], rc, out, err), out[:400], err[:400]

    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        results = list(ex.map(work, jobs))

    by_case = {}
    for cid, path, passed, out, err in results:
        by_case.setdefault(cid, {})[path] = {"ok": passed, "out": out, "err": err}

    unexpected = 0
    rows = []
    for c in cases:
        verdicts = by_case.get(c["id"], {})
        cells = []
        for path in ("cli", "mcp"):
            v = verdicts.get(path)
            if v is None:
                cells.append("  -  ")
                continue
            if v["ok"]:
                cells.append(" OK  ")
            elif a.baseline and c.get("owner", "base") != "base":
                cells.append("KO(e)")
            else:
                cells.append(" KO  ")
                unexpected += 1
        rows.append(f"{c['id']:<6} {c.get('owner','base'):<7} cli:{cells[0]} mcp:{cells[1]}  {c['expect'][:60]}")
    print("\n".join(rows))
    print(f"\n{len(cases)} cases, {len(jobs)} runs, {unexpected} unexpected verdict(s)")
    for c in cases:
        for path, v in by_case.get(c["id"], {}).items():
            if not v["ok"] and not (a.baseline and c.get("owner", "base") != "base"):
                print(f"--- {c['id']} [{path}] out: {v['out']!r}\n    err: {v['err']!r}")

    report = a.report or str(HERE.parents[1] / ".superpowers" / "probes" /
                             f"{datetime.date.today()}-{Path(a.binary).stem}.json")
    Path(report).parent.mkdir(parents=True, exist_ok=True)
    Path(report).write_text(json.dumps({"binary": a.binary, "host": a.host, "baseline": a.baseline,
                                        "results": by_case}, indent=2))
    print(f"report: {report}")
    sys.exit(unexpected)


if __name__ == "__main__":
    main()
