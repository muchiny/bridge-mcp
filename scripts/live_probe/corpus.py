#!/usr/bin/env python3
"""Differential audit of the sanitizer on real host output.

Captures each command twice — raw over plain ssh, and through the bridge's
own pipeline (`ssh_exec`, which sanitizes stdout) — and classifies every
line that differs. The only legitimate difference is a redaction marker
standing where a secret-shaped value stood, with everything before the
value byte-identical. Raw captures can hold real secrets: the output
directory is gitignored.
"""
import argparse
import datetime
import difflib
import json
import os
import re
import subprocess
from pathlib import Path

COMMANDS = {
    "kubectl_pods_json": "kubectl get pods -A -o json",
    "kubectl_pods_yaml": "kubectl get pods -A -o yaml",
    "kubectl_all_yaml": "kubectl get all -A -o yaml",
    "kubectl_secrets_yaml": "kubectl get secrets -A -o yaml",
    "kubectl_configmaps_yaml": "kubectl get configmaps -A -o yaml",
    "kubectl_describe_pods": "kubectl describe pods -A",
    "kubectl_events": "kubectl get events -A",
    "helm_plex": "helm template t /home/muchini/media-stack-k8s/charts/plex",
    "helm_qbittorrent": "helm template t /home/muchini/media-stack-k8s/charts/qbittorrent",
    "helm_backup": "helm template t /home/muchini/media-stack-k8s/charts/backup",
    "journal": "journalctl -n 400 --no-pager",
    "systemctl": "systemctl list-units --no-pager --all",
    "df": "df -h",
    "ss": "ss -tulpn",
    "ps": "ps aux",
    "env": "env",
    "os_release": "cat /etc/os-release",
}
MARKER = re.compile(r"\[(?:[A-Z_]+_)?REDACTED\]")


def capture_raw(ssh_target, command):
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", ssh_target, command],
                       capture_output=True, text=True, timeout=120)
    return p.stdout


def capture_bridged(binary, host, command):
    env = dict(os.environ, RUST_LOG="error")
    p = subprocess.run([binary, "tool", "ssh_exec", "--yes", "--json-args",
                        json.dumps({"host": host, "command": command, "max_output": 0})],
                       capture_output=True, text=True, timeout=180, env=env)
    return "\n".join(l for l in p.stdout.splitlines() if "WinRM Basic auth" not in l) + "\n"


def secret_shaped(value):
    v = value.strip().strip("\"'")
    if len(v) < 8:
        return False
    letters_only = all(c.isalpha() or c in "_.-" for c in v)
    digits_only = v.isdigit()
    return not (letters_only or digits_only)


def classify_pair(before, after):
    if not MARKER.search(after):
        return "DEFECT", "changed without a redaction marker"
    i = 0
    while i < min(len(before), len(after)) and before[i] == after[i]:
        i += 1
    prefix = before[:i]
    if not re.search(r"""(?:[=:]\s*["']?|\s)$""", prefix) and prefix.strip() != "":
        return "DEFECT", f"prefix altered: {prefix!r}"
    j = 0
    while (j < min(len(before), len(after)) - i
           and before[len(before) - 1 - j] == after[len(after) - 1 - j]):
        j += 1
    value = before[i:len(before) - j]
    if secret_shaped(value):
        return "OK", ""
    return "REVIEW", f"redacted a value that does not look like a secret: {value!r}"


def classify(raw, bridged):
    raw_lines, br_lines = raw.splitlines(), bridged.splitlines()
    out, counts = [], {"OK": 0, "REVIEW": 0, "DEFECT": 0}
    sm = difflib.SequenceMatcher(a=raw_lines, b=br_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag != "replace" or (i2 - i1) != (j2 - j1):
            counts["DEFECT"] += 1
            out.append(f"DEFECT line-count changed ({tag}) raw[{i1}:{i2}] bridged[{j1}:{j2}]:\n"
                       + "".join(f"  - {l}\n" for l in raw_lines[i1:i2])
                       + "".join(f"  + {l}\n" for l in br_lines[j1:j2]))
            continue
        for b, a in zip(raw_lines[i1:i2], br_lines[j1:j2]):
            verdict, why = classify_pair(b, a)
            counts[verdict] += 1
            if verdict != "OK":
                out.append(f"{verdict} {why}\n  - {b}\n  + {a}\n")
    return counts, "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--ssh", default="muchini@192.168.1.51")
    ap.add_argument("--out", default="")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    out = Path(a.out or Path(__file__).resolve().parents[2] / ".superpowers" / "corpus" / str(datetime.date.today()))
    for sub in ("raw", "bridged", "classified"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    only = {x for x in a.only.split(",") if x}
    summary, defects = {}, 0
    for name, command in COMMANDS.items():
        if only and name not in only:
            continue
        raw = capture_raw(a.ssh, command)
        bridged = capture_bridged(a.binary, a.host, command)
        (out / "raw" / f"{name}.txt").write_text(raw)
        (out / "bridged" / f"{name}.txt").write_text(bridged)
        counts, report = classify(raw, bridged)
        (out / "classified" / f"{name}.txt").write_text(report)
        summary[name] = counts
        defects += counts["DEFECT"]
        print(f"{name:<26} raw={len(raw.splitlines()):>6} lines  OK={counts['OK']:<4} REVIEW={counts['REVIEW']:<4} DEFECT={counts['DEFECT']}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\n{defects} DEFECT line(s); details in {out}/classified/")
    raise SystemExit(min(defects, 255))


if __name__ == "__main__":
    main()
