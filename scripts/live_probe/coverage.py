#!/usr/bin/env python3
"""Contrat de couverture : chaque outil Linux-applicable est exercé au moins une
fois par la campagne.

  coverage.py BIN --cases F1.json F2.json … [--waivers W.json] [--report P]

N'ouvre AUCUNE connexion : tout vient de `list-tools`, qui ne lit que la config
locale. Code de sortie = nombre de manques non couverts par une dérogation
(capé à 255), 0 quand le contrat tient.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Exclusion Windows PAR GROUPE. Mesuré 2026-09-09 : ces 13 groupes = 74 outils,
# 353 - 74 = 279 outils Linux-applicables.
WINDOWS_GROUPS = frozenset({
    "active_directory", "hyperv", "iis", "scheduled_tasks", "windows_events",
    "windows_features", "windows_firewall", "windows_network", "windows_perf",
    "windows_process", "windows_registry", "windows_services", "windows_updates",
})
EXPECTED_TOTAL = 353
EXPECTED_LINUX = 279
# Un outil de test délibérément inexistant (cas « outil inconnu ») porte ce préfixe.
SENTINEL = "ssh_bridge_campaign_"
ROW = re.compile(r"^(ssh_\S+)\s+(\S+)\s+(\S+)\s")


def _run(binary, *args):
    e = dict(os.environ, RUST_LOG="error")
    p = subprocess.run([binary, *args], capture_output=True, text=True,
                       timeout=120, env=e, stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        raise SystemExit(f"coverage: `{' '.join(args)}` a échoué (rc={p.returncode})\n"
                         f"{p.stderr[:400]}")
    return p.stdout


def inventory(binary):
    """{nom: {group, reduce, readonly, destructive}} pour les outils activés.

    Deux sources croisées : `--json list-tools` porte les annotations et `reduce`
    mais PAS le groupe ; la sortie texte porte le groupe. Un désaccord entre les
    deux = parsing cassé, on refuse de mesurer plutôt que de mesurer faux.
    """
    tools = json.loads(_run(binary, "--json", "list-tools"))
    ann = {t["name"]: t for t in tools}
    groups = {}
    for line in _run(binary, "list-tools").splitlines():
        m = ROW.match(line)
        if m:
            groups[m.group(1)] = (m.group(2), m.group(3))
    if set(ann) != set(groups):
        raise SystemExit(
            f"coverage: `--json list-tools` ({len(ann)}) et `list-tools` ({len(groups)}) "
            "ne listent pas les mêmes outils — corrige le parsing avant toute mesure")
    return {
        name: {
            "group": groups[name][0],
            "reduce": t.get("reduce", groups[name][1]),
            "readonly": bool(t.get("annotations", {}).get("readOnlyHint")),
            "destructive": bool(t.get("annotations", {}).get("destructiveHint")),
        }
        for name, t in ann.items()
    }


def linux_tools(inv):
    missing = WINDOWS_GROUPS - {v["group"] for v in inv.values()}
    if missing:
        raise SystemExit(f"coverage: groupe(s) Windows introuvable(s) {sorted(missing)} — "
                         "un groupe a été renommé, mets WINDOWS_GROUPS à jour")
    if len(inv) != EXPECTED_TOTAL:
        raise SystemExit(f"coverage: {len(inv)} outils activés au lieu de {EXPECTED_TOTAL} — "
                         "la config a bougé depuis la Task 0, refais le décompte")
    lin = {n: v for n, v in inv.items() if v["group"] not in WINDOWS_GROUPS}
    if len(lin) != EXPECTED_LINUX:
        raise SystemExit(f"coverage: {len(lin)} outils Linux au lieu de {EXPECTED_LINUX}")
    return lin


def union_of_cases(paths):
    """{outil: [ids de cas]} sur l'union des fichiers de cas."""
    used = {}
    for p in paths:
        spec = json.loads(Path(p).read_text())
        for c in spec["cases"]:
            used.setdefault(c["tool"], []).append(f"{Path(p).stem}:{c['id']}")
    return used


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--cases", nargs="+", required=True)
    ap.add_argument("--waivers", default="",
                    help='JSON {"ssh_docker_ps": "ENV: pas de Docker sur le Pi"}')
    ap.add_argument("--report", default="")
    a = ap.parse_args()

    inv = inventory(a.binary)
    lin = linux_tools(inv)
    used = union_of_cases(a.cases)
    waivers = json.loads(Path(a.waivers).read_text()) if a.waivers else {}

    covered = {t for t in used if t in lin}
    missing = sorted(set(lin) - covered)
    windows_touched = sorted(t for t in used if t in inv and t not in lin)
    unknown = sorted(t for t in used if t not in inv and not t.startswith(SENTINEL))
    unwaived = [t for t in missing if t not in waivers]

    by_group = {}
    for t, v in lin.items():
        g = by_group.setdefault(v["group"], {"total": 0, "cov": 0, "miss": []})
        g["total"] += 1
        if t in covered:
            g["cov"] += 1
        else:
            g["miss"].append(t)
    for g in sorted(by_group):
        d = by_group[g]
        flag = "" if not d["miss"] else "  MANQUE: " + ", ".join(sorted(d["miss"]))
        print(f"{g:<24} {d['cov']:>3}/{d['total']:<3}{flag}")

    print("\n-- matrice `reduce` (Linux) --")
    for kind in ("—", "*", "cols", "jq+tsv", "yq+tsv"):
        tot = [t for t, v in lin.items() if v["reduce"] == kind]
        print(f"  {kind:<7} {sum(1 for t in tot if t in covered):>3}/{len(tot)}")

    print(f"\n{len(covered)}/{len(lin)} outils Linux couverts, "
          f"{len(missing)} manquant(s) dont {len(unwaived)} sans dérogation")
    if windows_touched:
        print(f"HORS PÉRIMÈTRE (Windows) : {windows_touched}")
    if unknown:
        print(f"OUTILS INEXISTANTS cités par un cas : {unknown}")
    for t in sorted(set(missing) & set(waivers)):
        print(f"  dérogation {t}: {waivers[t]}")

    if a.report:
        Path(a.report).parent.mkdir(parents=True, exist_ok=True)
        Path(a.report).write_text(json.dumps(
            {"covered": sorted(covered), "missing": missing, "unwaived": unwaived,
             "unknown": unknown, "windows_touched": windows_touched,
             "by_group": by_group, "used": used}, indent=2, ensure_ascii=False))
        print(f"report: {a.report}")

    sys.exit(min(len(unwaived) + len(unknown) + len(windows_touched), 255))


if __name__ == "__main__":
    main()
