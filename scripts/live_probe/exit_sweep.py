#!/usr/bin/env python3
"""Generate the D1 exit-code sweep (F-exit-sweep.json), Task 8 / Lane F, Step 3.

D1 is "the CLI exits 0 even when the remote command fails" (confirmed earlier in
the campaign). This script measures how many of the 180 Linux `readOnlyHint`
tools exhibit it, using a universal, side-effect-free probe: `sudo=true
sudo_user=bridgenouser`. `sudo -n -u bridgenouser ...` refuses BEFORE running
anything (unknown user) and exits non-zero on the host — so the probe can never
touch the sandbox, no matter which tool it rides on.

The generator invents nothing: for each of the 180 readOnlyHint tools it takes
the FIRST already-proven, successful argument set from lanes A-E's case files
(scripts/live_probe/campaign/2026-09-09/{A,A2,A3,A4,B,C,E}*.json — the DATED
directory only, never the 2026-09-06 baseline glob) and adds
`sudo`/`sudo_user` to it. Tools with no such case, or whose schema does not
declare `sudo_user`, are excluded and reported by name — never guessed.

Usage:
    scripts/live_probe/exit_sweep.py BIN [--out PATH] [--campaign-dir DIR]
"""
import argparse
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_CAMPAIGN_DIR = os.path.join(HERE, "campaign", "2026-09-09")
DEFAULT_REPORT_DIR = os.path.join(REPO_ROOT, ".superpowers", "campaign", "2026-09-09")
DEFAULT_OUT = os.path.join(DEFAULT_CAMPAIGN_DIR, "F-exit-sweep.json")

# Assertion prefixes that mean "the case ran the tool successfully and got
# real content back" (task-8-brief.md Step 3.2) — as opposed to error=/exit=N/
# nore=, which encode a failure path and would not give us a live, working
# argument set to reuse.
OK_PREFIXES = ("ok", "re=", "lines", "first=")

# task-8-brief.md Step 3's named list of 21 tools "sans sudo_user" — kept here
# ONLY for the cross-check against what Step 3.1's live measurement finds
# (see main()). The live measurement against list-tools --json is what
# actually drives exclusion, per "ne rien inventer".
BRIEF_NAMED_NO_SUDO_USER = {
    "ssh_disk_usage", "ssh_download", "ssh_find", "ssh_health", "ssh_history",
    "ssh_ls", "ssh_metrics", "ssh_metrics_multi", "ssh_output_fetch",
    "ssh_runbook_list", "ssh_runbook_validate", "ssh_session_close",
    "ssh_session_create", "ssh_session_list", "ssh_status", "ssh_sync",
    "ssh_tail", "ssh_tunnel_close", "ssh_tunnel_create", "ssh_tunnel_list",
    "ssh_upload",
}


def expect_is_ok(expect):
    e = expect[0] if isinstance(expect, list) else expect
    return isinstance(e, str) and e.startswith(OK_PREFIXES)


def load_readonly_linux_tools(inventory_path):
    """inventory.tsv (Task 0, authoritative): group / tool / class / reduce."""
    tools = set()
    with open(inventory_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            _group, tool, klass, _reduce = line.split("\t")
            if klass == "readonly":
                tools.add(tool)
    return tools


def load_lane_case_files(campaign_dir):
    """The dated glob {A,A2,A3,A4,B,C,E}*.json — never the undated 2026-09-06
    baseline (campaign/{A-host,...}.json lives one directory up)."""
    files = set()
    for prefix in ("A", "A2", "A3", "A4", "B", "C", "E"):
        files.update(glob.glob(os.path.join(campaign_dir, f"{prefix}*.json")))
    return sorted(files)


def first_proven_args_by_tool(case_files):
    """Returns {tool: (args, source_vars, source_path, case_id)} — the source
    file's own `vars` travel with the args, because ${VAR} placeholders in a
    reused arg value (e.g. "${SANDBOX}/a.txt") can only be resolved against
    the vars dict that ORIGINALLY defined them (run.py substitutes ${VAR}
    using the spec file's own `vars`, nothing global)."""
    first = {}
    for path in case_files:
        with open(path) as f:
            data = json.load(f)
        source_vars = data.get("vars", {})
        for case in data.get("cases", []):
            tool = case.get("tool")
            if not tool or tool in first:
                continue
            if expect_is_ok(case.get("expect")):
                first[tool] = (case.get("args", {}), source_vars, path, case.get("id"))
    return first


VAR_REF_RE = __import__("re").compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def resolve_vars_for(args, source_vars, tool, conflicts_out):
    """Which ${VAR} keys does this tool's reused args reference, and what do
    they resolve to in the source file that proved them? Returns {var: value}
    for just the vars this tool's args actually use."""
    needed = {}
    for v in args.values():
        if isinstance(v, str):
            for name in VAR_REF_RE.findall(v):
                if name in source_vars:
                    needed[name] = source_vars[name]
                else:
                    conflicts_out.append(
                        f"{tool}: references \\${{{name}}} but it is not in its "
                        f"source file's own vars block — cannot resolve")
    return needed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--campaign-dir", default=DEFAULT_CAMPAIGN_DIR,
                     help="scripts/live_probe/campaign/2026-09-09 — lane case files (versioned)")
    ap.add_argument("--report-dir", default=DEFAULT_REPORT_DIR,
                     help=".superpowers/campaign/2026-09-09 — inventory.tsv (gitignored)")
    a = ap.parse_args()

    listing = json.loads(subprocess.check_output([a.binary, "--json", "list-tools"]))
    by_name = {t["annotations"]["title"]: t for t in listing}

    inventory_path = os.path.join(a.report_dir, "inventory.tsv")
    readonly_linux = load_readonly_linux_tools(inventory_path)
    if len(readonly_linux) != 180:
        print(f"WARNING: inventory.tsv readonly count is {len(readonly_linux)}, "
              f"not the expected 180 — code may have moved since 2026-09-06",
              file=sys.stderr)

    # Live measurement (Step 3.1): which readOnlyHint Linux tools do NOT
    # declare `sudo_user` in their schema.
    no_sudo_user = sorted(
        t for t in readonly_linux
        if "sudo_user" not in by_name.get(t, {}).get("inputSchema", {}).get("properties", {})
    )

    case_files = load_lane_case_files(a.campaign_dir)
    first_args = first_proven_args_by_tool(case_files)

    candidates = sorted(readonly_linux - set(no_sudo_user))
    no_lane_case = sorted(t for t in candidates if t not in first_args)
    sweepable = sorted(t for t in candidates if t in first_args)

    cases = []
    merged_vars = {}
    var_conflicts = []
    var_resolve_errors = []
    provenance = []
    for tool in sweepable:
        src_args, source_vars, src_path, src_id = first_args[tool]
        args = dict(src_args)
        args["sudo"] = True
        args["sudo_user"] = "bridgenouser"
        cases.append({
            "id": f"FS-{tool}",
            "owner": "base",
            "tool": tool,
            "paths": ["cli"],
            "args": args,
            "expect": "re=sudo: unknown user",
            # Harnais (run.py Step 5 guard): obligatoire sur tout cas
            # ssh_exec-shaped portant sudo=true (ici : tout outil dont les args
            # reconduits par la lane source contiennent une clé de charge
            # shell — command/commands/health_check/input — p.ex.
            # ssh_fleet_diff). Ajouté inconditionnellement : inoffensif sur
            # les autres cas, où le garde ne le regarde jamais.
            "sudo_reason": "D1 exit-sweep probe (Step 2): sudo -n -u bridgenouser "
                           "refuses before running anything (unknown user) — the "
                           "read-only command underneath never executes.",
        })
        provenance.append((tool, os.path.basename(src_path), src_id))
        needed = resolve_vars_for(src_args, source_vars, tool, var_resolve_errors)
        for name, value in needed.items():
            if name in merged_vars and merged_vars[name] != value:
                var_conflicts.append(
                    f"{name}: {tool} needs {value!r} but another selected tool "
                    f"already pinned {merged_vars[name]!r}")
            else:
                merged_vars[name] = value

    if var_resolve_errors or var_conflicts:
        raise SystemExit("Unresolvable ${VAR} references — refusing to write a file "
                          "the harness would garble:\n  " +
                          "\n  ".join(var_resolve_errors + var_conflicts))

    out = {"vars": merged_vars, "cases": cases}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Verdict lines (Step 3), to stdout for the caller to paste into F.md.
    print(f"readonly_linux_total={len(readonly_linux)}")
    print(f"no_sudo_user_measured={len(no_sudo_user)} {no_sudo_user}")
    brief_extra = sorted(BRIEF_NAMED_NO_SUDO_USER - set(no_sudo_user))
    if brief_extra:
        print(f"brief_named_but_not_measured_as_missing_sudo_user={len(brief_extra)} "
              f"(not even readOnlyHint-Linux any more, per inventory.tsv) {brief_extra}")
    print(f"lane_case_files={[os.path.basename(p) for p in case_files]}")
    print(f"no_lane_case={len(no_lane_case)} {no_lane_case}")
    print(f"resolved_vars={merged_vars}")
    for tool, base, cid in provenance:
        print(f"  provenance: {tool} <- {base}:{cid}")
    print(f"cases_generated={len(cases)}")
    print(f"out={a.out}")


if __name__ == "__main__":
    main()
