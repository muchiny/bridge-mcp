#!/usr/bin/env python3
"""Before/after snapshot of the campaign host, through read-only bridge-mcp
tools only. `snapshot.py BIN --out FILE` writes it; `snapshot.py --diff
BEFORE AFTER` prints what moved and exits 1 when a guarded field differs
(node readiness, failed units, sandbox presence, k3s activity) or the
running-pod set changed by more than the CronJob churn (two pods)."""
import argparse
import json
import os
import subprocess
import sys


def call(binary, host, tool, **args):
    env = dict(os.environ, RUST_LOG="error")
    p = subprocess.run([binary, "tool", tool, "--json-args", json.dumps({"host": host, **args})],
                       capture_output=True, text=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout


def take(binary, host):
    rc, pods = call(binary, host, "ssh_k8s_get", resource="pods", all_namespaces=True, output="name")
    rc2, nodes = call(binary, host, "ssh_k8s_get", resource="nodes")
    rc3, failed = call(binary, host, "ssh_service_list", state="failed")
    rc4, tmp = call(binary, host, "ssh_ls", path="/tmp")
    rc5, alerts = call(binary, host, "ssh_alert_list")
    rc6, k3s = call(binary, host, "ssh_service_status", service="k3s")
    return {
        "pods": sorted(l for l in pods.splitlines() if l.startswith("pod/")),
        "node_ready": rc2 == 0 and any("Ready" in l.split() for l in nodes.splitlines()),
        "failed_units": sorted(t[0] for t in (l.split() for l in failed.splitlines()) if t and t[0].endswith(".service")),
        "sandbox_present": "bridge-campaign" in tmp,
        "k3s_active": rc6 == 0 and "active (running)" in k3s,
        "alerts_raw": alerts.strip(),
        "rc": [rc, rc2, rc3, rc4, rc5, rc6],
    }


def diff(before, after):
    bad = 0
    for key in ("node_ready", "failed_units", "sandbox_present", "k3s_active"):
        if before[key] != after[key]:
            print(f"CHANGED {key}: {before[key]!r} -> {after[key]!r}")
            bad += 1
    gone = sorted(set(before["pods"]) - set(after["pods"]))
    new = sorted(set(after["pods"]) - set(before["pods"]))
    for p in gone:
        print(f"pod gone: {p}")
    for p in new:
        print(f"pod new:  {p}")
    if len(gone) + len(new) > 2:
        print(f"CHANGED pods: {len(gone)} gone, {len(new)} new (> 2, more than CronJob churn)")
        bad += 1
    print("host unchanged" if bad == 0 else f"{bad} guarded field(s) changed")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--out", default="")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"))
    a = ap.parse_args()
    if a.diff:
        before, after = (json.load(open(p)) for p in a.diff)
        sys.exit(1 if diff(before, after) else 0)
    if not a.binary or not a.out:
        ap.error("BIN and --out are required to take a snapshot")
    snap = take(a.binary, a.host)
    with open(a.out, "w") as f:
        json.dump(snap, f, indent=2)
    print(f"{len(snap['pods'])} pods, node_ready={snap['node_ready']}, failed_units={snap['failed_units']}, "
          f"sandbox_present={snap['sandbox_present']}, k3s_active={snap['k3s_active']} -> {a.out}")
    sys.exit(0 if all(r == 0 for r in snap["rc"]) and snap["node_ready"] else 1)


if __name__ == "__main__":
    main()
