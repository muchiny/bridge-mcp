#!/usr/bin/env python3
"""Before/after snapshot of the campaign host, through read-only bridge-mcp
tools only (plus two `ssh_exec` line counts, both a `wc -l` over a read-only
pipeline). `snapshot.py BIN --out FILE` takes a live snapshot and writes it;
`snapshot.py --from-dir DIR --out FILE` builds one offline from captured
`DIR/<field>.txt` files (used by snapshot_selftest.py, never touches a host);
`snapshot.py --diff BEFORE AFTER` prints what moved and exits 1 when a
guarded field differs.

Guarded (hard) fields: node_ready, k3s_active, failed_units, namespaces,
users, groups, crons, listening_ports, packages_count, units_count,
k8s_workloads. sandbox_present/home_sandbox are compared against a declared
--expect-sandbox {absent,present} instead of an equality (the campaign's own
sandbox legitimately flips this True for a few hours). pods tolerates up to
two entries of churn (the media-backup CronJob). alerts_raw is informational
only, never guarded.

Every parse_<field>(text, rc) below is a pure function, proven independently
by scripts/live_probe/snapshot_selftest.py against a real capture and a
single-change doctored fixture under scripts/live_probe/snapshot_fixtures/.
"""
import argparse
import json
import os
import re
import subprocess
import sys

# --- capture specs: shared between live take() and offline load_from_dir() ---
# name -> (tool, kwargs). "yes" is not a tool arg; it is looked up from
# YES_REQUIRED so call() knows which of these need --yes (destructiveHint).
CAPTURE_SPECS = {
    "pods": ("ssh_k8s_get", dict(resource="pods", all_namespaces=True, output="name")),
    "nodes": ("ssh_k8s_get", dict(resource="nodes")),
    "failed_units": ("ssh_service_list", dict(state="failed", columns=["UNIT"], limit=200)),
    "sandbox_present": ("ssh_ls", dict(path="/tmp")),
    "home_sandbox": ("ssh_ls", dict(path="/home/muchini")),
    "alerts_raw": ("ssh_alert_list", dict()),
    "k3s_active": ("ssh_service_status", dict(service="k3s")),
    "namespaces": ("ssh_k8s_get", dict(resource="namespaces", output="name", limit=50)),
    "packages_count": ("ssh_exec", dict(command="dpkg-query -f '.\\n' -W | wc -l")),
    "units_count": ("ssh_exec", dict(command="systemctl list-units --all --type=service --no-legend --plain | wc -l")),
    "users": ("ssh_user_list", dict(columns=["USER"])),
    "groups": ("ssh_group_list", dict(columns=["GROUP"])),
    "crons": ("ssh_cron_list", dict(system=True)),
    "listening_ports": ("ssh_net_connections", dict(listening=True, protocol="tcp")),
    "k8s_workloads_deployments": ("ssh_k8s_get", dict(all_namespaces=True, output="name", resource="deployments")),
    "k8s_workloads_statefulsets": ("ssh_k8s_get", dict(all_namespaces=True, output="name", resource="statefulsets")),
    "k8s_workloads_daemonsets": ("ssh_k8s_get", dict(all_namespaces=True, output="name", resource="daemonsets")),
    "k8s_workloads_cronjobs": ("ssh_k8s_get", dict(all_namespaces=True, output="name", resource="cronjobs")),
}
# destructiveHint tools in the specs above are ssh_exec calls whose command is
# a read-only `... | wc -l` pipeline (no file touched); --yes is authorized
# for exactly these two per the campaign's task-1 brief.
YES_REQUIRED = {"packages_count", "units_count"}


def call(binary, host, tool, yes=False, timeout=120, **args):
    env = dict(os.environ, RUST_LOG="error")
    cmd = [binary, "tool"]
    if yes:
        cmd.append("--yes")
    cmd += [tool, "--json-args", json.dumps({"host": host, **args})]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       env=env, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout


# ------------------------------- pure parses -------------------------------
# Each takes the raw tool stdout and its return code, and returns a value.
# None of these touch the network, a file, or global state.

SANDBOX_RE = re.compile(r"^(bridge-|bmcp-)")


def parse_pods(text, rc):
    if rc != 0:
        return []
    return sorted(l for l in text.splitlines() if l.startswith("pod/"))


def parse_node_ready(text, rc):
    # "Ready" as a whole token on some line -- l.split() tokenizes on any
    # run of whitespace, tabs included, so this is correct against the
    # TAB-separated `ssh_k8s_get resource=nodes` output. Token equality
    # (not substring) means "NotReady" never matches "Ready".
    return rc == 0 and any("Ready" in l.split() for l in text.splitlines())


def parse_failed_units(text, rc):
    if rc != 0:
        return []
    out = []
    for l in text.splitlines():
        t = l.split()
        if t and t[0].endswith(".service"):
            out.append(t[0])
    return sorted(out)


def _ls_names(text, rc):
    """ssh_ls returns a JSON array of {name, path, is_dir, size, permissions}."""
    if rc != 0:
        return []
    try:
        entries = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(entries, list):
        return []
    return [e.get("name", "") for e in entries if isinstance(e, dict)]


def parse_sandbox_present(text, rc):
    return any(SANDBOX_RE.match(n) for n in _ls_names(text, rc))


# home_sandbox applies the exact same pattern to a different directory
# listing (ssh_ls path=/home/muchini) -- reuse the parse verbatim.
parse_home_sandbox = parse_sandbox_present


def parse_k3s_active(text, rc):
    return rc == 0 and "active (running)" in text


def parse_alerts_raw(text, rc):
    return text.strip() if rc == 0 else ""


def parse_namespaces(text, rc):
    if rc != 0:
        return []
    return sorted(l for l in text.splitlines() if l.strip())


def parse_count(text, rc):
    """A single integer from a `... | wc -l` ssh_exec call."""
    if rc != 0:
        return -1
    s = text.strip()
    return int(s) if s.isdigit() else -1


def _tab_header_column(text, rc, colname):
    """Extract one column by header name from TAB-separated tool output.

    Falls back to the first whitespace-split token as a last resort (covers
    a single-column header too: a one-element header list still satisfies
    `colname in header` above).
    """
    if rc != 0:
        return []
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    header = lines[0].split("\t")
    rows = lines[1:]
    if colname in header:
        idx = header.index(colname)
        return [(r.split("\t")[idx] if idx < len(r.split("\t")) else "") for r in rows]
    return [r.split()[0] for r in rows if r.split()]


def parse_users(text, rc):
    return sorted(v for v in _tab_header_column(text, rc, "USER") if v)


def parse_groups(text, rc):
    return sorted(v for v in _tab_header_column(text, rc, "GROUP") if v)


def parse_crons(text, rc):
    if rc != 0:
        return []
    return sorted(l for l in text.splitlines() if l.strip())


PORT_RE = re.compile(r":(\d+)$")


def parse_listening_ports(text, rc):
    # Column name confirmed against a real capture (Task 1 Step 3):
    # `ssh_net_connections listening=true protocol=tcp` header is
    # STATE\tRECV-Q\tSEND-Q\tLOCAL_ADDRESS\tPEER_ADDRESS\tPROCESS.
    addrs = _tab_header_column(text, rc, "LOCAL_ADDRESS")
    ports = set()
    for a in addrs:
        m = PORT_RE.search(a)
        if m:
            ports.add(int(m.group(1)))
    return sorted(ports)


def parse_workload_names(text, rc):
    if rc != 0:
        return []
    return sorted(l for l in text.splitlines() if l.strip())


def build_snapshot(calls, rc):
    dep = parse_workload_names(calls["k8s_workloads_deployments"], rc["k8s_workloads_deployments"])
    sts = parse_workload_names(calls["k8s_workloads_statefulsets"], rc["k8s_workloads_statefulsets"])
    ds = parse_workload_names(calls["k8s_workloads_daemonsets"], rc["k8s_workloads_daemonsets"])
    cj = parse_workload_names(calls["k8s_workloads_cronjobs"], rc["k8s_workloads_cronjobs"])
    return {
        "pods": parse_pods(calls["pods"], rc["pods"]),
        "node_ready": parse_node_ready(calls["nodes"], rc["nodes"]),
        "failed_units": parse_failed_units(calls["failed_units"], rc["failed_units"]),
        "sandbox_present": parse_sandbox_present(calls["sandbox_present"], rc["sandbox_present"]),
        "home_sandbox": parse_home_sandbox(calls["home_sandbox"], rc["home_sandbox"]),
        "k3s_active": parse_k3s_active(calls["k3s_active"], rc["k3s_active"]),
        "alerts_raw": parse_alerts_raw(calls["alerts_raw"], rc["alerts_raw"]),
        "namespaces": parse_namespaces(calls["namespaces"], rc["namespaces"]),
        "packages_count": parse_count(calls["packages_count"], rc["packages_count"]),
        "units_count": parse_count(calls["units_count"], rc["units_count"]),
        "users": parse_users(calls["users"], rc["users"]),
        "groups": parse_groups(calls["groups"], rc["groups"]),
        "crons": parse_crons(calls["crons"], rc["crons"]),
        "listening_ports": parse_listening_ports(calls["listening_ports"], rc["listening_ports"]),
        "k8s_workloads": {
            "deployments": len(dep),
            "statefulsets": len(sts),
            "daemonsets": len(ds),
            "cronjobs": len(cj),
        },
        "rc": dict(rc),
    }


def take(binary, host):
    calls, rc = {}, {}
    for name, (tool, kwargs) in CAPTURE_SPECS.items():
        rc[name], calls[name] = call(binary, host, tool, yes=name in YES_REQUIRED, **kwargs)
    return build_snapshot(calls, rc)


class MissingCaptureFiles(Exception):
    """Raised by load_from_dir() when the union of given directories still
    lacks a field's capture file -- carries every missing name so the caller
    can report all of them at once, not just the first."""

    def __init__(self, missing, directories):
        self.missing = missing
        self.directories = directories
        names = ", ".join(f"{m}.txt" for m in missing)
        dirs = ", ".join(directories)
        super().__init__(f"missing capture file(s) [{names}] -- looked in: {dirs}")


def load_from_dir(directories):
    """Build a snapshot from `DIR/<field>.txt` files instead of calling the
    host. `directories` is a path, or a list of paths searched in order --
    the first directory to hold a given field's file wins, so a later
    directory only fills the gaps an earlier one leaves (Ruling R10: this is
    what lets a partial doctored-fixtures directory be completed by the real
    captures directory, e.g. `--from-dir fixtures --from-dir captures`)."""
    if isinstance(directories, str):
        directories = [directories]
    calls, rc = {}, {}
    missing = []
    for name in CAPTURE_SPECS:
        found = None
        for d in directories:
            path = os.path.join(d, f"{name}.txt")
            if os.path.exists(path):
                found = path
                break
        if found is None:
            missing.append(name)
            continue
        with open(found) as f:
            calls[name] = f.read()
        rc_path = os.path.splitext(found)[0] + ".rc"
        rc[name] = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else 0
    if missing:
        raise MissingCaptureFiles(missing, directories)
    return build_snapshot(calls, rc)


# --------------------------------- diff() -----------------------------------

HARD_FIELDS = [
    "node_ready", "k3s_active", "failed_units", "namespaces", "users", "groups",
    "crons", "listening_ports", "packages_count", "units_count", "k8s_workloads",
]

# Closed set of sandbox object names/markers the campaign is allowed to create
# (Task 1bis / global-constraints §3.0). Matched against list *entries*, never
# against a bare count.
SANDBOX_NAME_RE = re.compile(r"^(btest0909|btestgrp0909|bridge-test|bridge-test-0909|bt-)")
SANDBOX_MARKER = "BRIDGE_TEST_0909"

# units_count has no underlying name list (it is a bare `wc -l`, deliberately,
# to dodge max_output truncation on packages/units -- see Task 1 Step 2). Of
# the sandbox's two transient systemd units, only bridge-test-0909.service
# counts under `--type=service` (the paired .timer is unit type "timer" and
# is excluded by that filter), so the tolerated delta is exactly 1.
SANDBOX_UNIT_COUNT_DELTA = 1


def _is_sandbox_named(value):
    return bool(SANDBOX_NAME_RE.match(value) or SANDBOX_MARKER in value)


def _strip_sandbox(values):
    return [v for v in values if not _is_sandbox_named(v)]


def diff(before, after, expect_sandbox="absent", expect_sandbox_objects=False):
    bad = 0

    def hard(key, b, a):
        nonlocal bad
        if b != a:
            print(f"CHANGED {key}: {b!r} -> {a!r}")
            bad += 1

    for key in HARD_FIELDS:
        b, a = before[key], after[key]
        if expect_sandbox_objects and key in ("namespaces", "users", "groups", "crons"):
            b, a = _strip_sandbox(b), _strip_sandbox(a)
        elif expect_sandbox_objects and key == "k8s_workloads":
            # Task 7/8 sandbox creates exactly one Deployment ('bt-pause') in
            # $NS. k8s_workloads is a cluster-wide count with no per-object
            # names to filter, so tolerate exactly a +1 on 'deployments'.
            b2, a2 = dict(b), dict(a)
            if a2.get("deployments", 0) - b2.get("deployments", 0) == 1:
                a2["deployments"] = b2.get("deployments", 0)
            b, a = b2, a2
        elif expect_sandbox_objects and key == "units_count":
            if abs(a - b) <= SANDBOX_UNIT_COUNT_DELTA:
                a = b
        hard(key, b, a)

    expected_present = expect_sandbox == "present"
    for key in ("sandbox_present", "home_sandbox"):
        if after[key] != expected_present:
            print(f"CHANGED {key}: expected {expected_present!r}, got {after[key]!r}")
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

    if before.get("alerts_raw") != after.get("alerts_raw"):
        print("INFO alerts_raw changed (not guarded)")

    print("host unchanged" if bad == 0 else f"{bad} guarded field(s) changed")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--out", default="")
    ap.add_argument("--from-dir", action="append", default=[],
                    help="Build a snapshot from DIR/<field>.txt files instead of the host. "
                         "Repeatable: later --from-dir directories fill the gaps left by "
                         "earlier ones (first directory given wins per field).")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--expect-sandbox", choices=["absent", "present"], default="absent")
    ap.add_argument("--expect-sandbox-objects", action="store_true")
    a = ap.parse_args()

    if a.diff:
        before, after = (json.load(open(p)) for p in a.diff)
        bad = diff(before, after, expect_sandbox=a.expect_sandbox,
                   expect_sandbox_objects=a.expect_sandbox_objects)
        sys.exit(1 if bad else 0)

    if a.from_dir:
        if not a.out:
            ap.error("--out is required with --from-dir")
        try:
            snap = load_from_dir(a.from_dir)
        except MissingCaptureFiles as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        if not a.binary or not a.out:
            ap.error("BIN and --out are required to take a snapshot")
        snap = take(a.binary, a.host)

    with open(a.out, "w") as f:
        json.dump(snap, f, indent=2)
    print(f"{len(snap['pods'])} pods, node_ready={snap['node_ready']}, "
          f"failed_units={snap['failed_units']}, sandbox_present={snap['sandbox_present']}, "
          f"home_sandbox={snap['home_sandbox']}, k3s_active={snap['k3s_active']} -> {a.out}")
    sys.exit(0 if all(r == 0 for r in snap["rc"].values()) and snap["node_ready"] else 1)


if __name__ == "__main__":
    main()
