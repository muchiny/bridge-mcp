#!/usr/bin/env python3
"""Proves every guard in snapshot.py actually fires, against a real capture
and a single-change doctored fixture -- no external dependency, no host
contact. Task 1 (2026-09-09 raspberry campaign) Step 5.

For each of the 13 guarded fields (the 12 rows of the Task 1 brief's Step 2
table plus k3s_active) this asserts three things:
  1. the parse works on the real capture, AND the result is non-degenerate
     (e.g. failed_units must contain 'exim4-base.service', not [] --
     the whole point: a guard that can never fire reports "host unchanged"
     no matter what actually happened on the host);
  2. the parse sees a difference on the doctored fixture;
  3. diff() surfaces that difference (exits non-zero, prints a CHANGED line).

It also proves the 'pods' tolerance directly: a delta of 2 does not trip
diff(), a delta of 3 does.

Captures/fixtures live under scripts/live_probe/snapshot_fixtures/{captures,
fixtures}/, found relative to this file's own location -- not the caller's
cwd (ruling R8 of the Task 1 dispatch).
"""
import copy
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import snapshot  # noqa: E402

CAPTURES = os.path.join(HERE, "snapshot_fixtures", "captures")
FIXTURES = os.path.join(HERE, "snapshot_fixtures", "fixtures")

# field -> list of underlying CAPTURE_SPECS keys whose fixture differs for it.
# (k8s_workloads is assembled from four sub-calls; only the deployments one
# has a doctored fixture -- the other three are left identical to their
# captures when overlaid.)
FIELD_FILES = {
    "node_ready": ["nodes"],
    "failed_units": ["failed_units"],
    "sandbox_present": ["sandbox_present"],
    "home_sandbox": ["home_sandbox"],
    "namespaces": ["namespaces"],
    "packages_count": ["packages_count"],
    "units_count": ["units_count"],
    "users": ["users"],
    "groups": ["groups"],
    "crons": ["crons"],
    "listening_ports": ["listening_ports"],
    "k8s_workloads": ["k8s_workloads_deployments"],
    "k3s_active": ["k3s_active"],
}

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def nondegenerate_ok(field, value):
    checks = {
        "node_ready": lambda v: v is True,
        "failed_units": lambda v: v != [] and "exim4-base.service" in v,
        "sandbox_present": lambda v: v is False,
        "home_sandbox": lambda v: v is False,
        "namespaces": lambda v: len(v) > 0,
        "packages_count": lambda v: v > 300,
        "units_count": lambda v: v > 50,
        "users": lambda v: len(v) > 0,
        "groups": lambda v: len(v) > 0,
        "crons": lambda v: len(v) > 0,
        "listening_ports": lambda v: len(v) > 0,
        "k8s_workloads": lambda v: v.get("deployments", 0) > 0,
        "k3s_active": lambda v: v is True,
    }
    return checks[field](value)


def overlay_dir(field):
    """A temp dir = captures/ with this field's fixture file(s) swapped in."""
    d = tempfile.mkdtemp(prefix=f"snapshot-selftest-{field}-")
    for name in snapshot.CAPTURE_SPECS:
        shutil.copy(os.path.join(CAPTURES, f"{name}.txt"), os.path.join(d, f"{name}.txt"))
    for name in FIELD_FILES[field]:
        shutil.copy(os.path.join(FIXTURES, f"{name}.txt"), os.path.join(d, f"{name}.txt"))
    return d


def run_field(field, baseline):
    real_value = baseline[field]

    ok = check(nondegenerate_ok(field, real_value),
               f"{field}: non-degenerate check failed on real capture, got {real_value!r}")

    d = overlay_dir(field)
    try:
        doctored = snapshot.load_from_dir(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    fixture_value = doctored[field]
    ok = check(fixture_value != real_value, f"{field}: parse did not see the doctored fixture "
               f"as different (both parsed to {real_value!r})") and ok

    buf = []
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()) as cap:
        bad = snapshot.diff(baseline, doctored)
    lines = cap.getvalue()
    ok = check(bad != 0, f"{field}: diff() returned 0 (no change reported) for a doctored fixture") and ok
    ok = check(f"CHANGED {field}" in lines,
               f"{field}: diff() did not print 'CHANGED {field}' -- got:\n{lines}") and ok

    print(f"{'PASS' if ok else 'FAIL'} {field}")
    return ok


def run_pods_tolerance(baseline):
    before = copy.deepcopy(baseline)
    pods = before["pods"]
    assert len(pods) >= 3, "not enough real pods to prove the tolerance"

    after_2 = copy.deepcopy(before)
    after_2["pods"] = pods[2:]  # 2 gone
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        bad2 = snapshot.diff(before, after_2)
    ok = check(bad2 == 0, f"pods_tolerance: a 2-pod delta tripped diff() (bad={bad2})")

    after_3 = copy.deepcopy(before)
    after_3["pods"] = pods[3:]  # 3 gone
    with contextlib.redirect_stdout(io.StringIO()):
        bad3 = snapshot.diff(before, after_3)
    ok = check(bad3 != 0, "pods_tolerance: a 3-pod delta did NOT trip diff()") and ok

    print(f"{'PASS' if ok else 'FAIL'} pods_tolerance")
    return ok


def main():
    baseline = snapshot.load_from_dir(CAPTURES)
    all_ok = True
    for field in FIELD_FILES:
        all_ok = run_field(field, baseline) and all_ok
    all_ok = run_pods_tolerance(baseline) and all_ok

    if not all_ok:
        print(f"\n{len(FAILS)} failure(s):", file=sys.stderr)
        for f in FAILS:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)
    print(f"\n{len(FIELD_FILES)}/{len(FIELD_FILES)} PASS + pods_tolerance PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
