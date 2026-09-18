#!/usr/bin/env python3
"""Contrat de couverture : chaque outil Linux-applicable est exercé au moins une
fois par la campagne.

  coverage.py BIN --cases F1.json F2.json … [--waivers W.json] [--report P]
                  [--reports RUN_REPORT.json ...]

N'ouvre AUCUNE connexion : tout vient de `list-tools`, qui ne lit que la config
locale (et, si fourni, de la LECTURE de fichiers de rapport `run.py` déjà sur
disque — toujours aucun sous-processus, aucune connexion). Code de sortie =
nombre de manques non couverts par une dérogation (capé à 255), 0 quand le
contrat tient.

Fix round 1 (review I-2) : SANS `--reports`, ce script mesure « nommé par au
moins un cas », pas « exécuté au moins une fois » — `union_of_cases` ne lit
que les fichiers de cas, jamais un rapport d'exécution, donc un outil avec
`paths: []` (zéro job construit), ou dont le seul cas est filtré par --only,
ou dont le fichier a été refusé par `guard()`, est compté couvert sans avoir
jamais tourné. Avec `--reports`, un outil n'est compté couvert que si l'un de
ses cas a produit une entrée non vide dans `results` d'au moins un rapport
`run.py` fourni — c'est-à-dire qu'il a réellement traversé `attempt()`.
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


def ran_case_ids(report_paths):
    """{"<stem du fichier de cas>:<id de cas>"} ayant réellement produit un
    RÉSULTAT (donc réellement passé par `attempt()`, au moins sur un chemin)
    dans l'un des rapports JSON de run.py fournis. Lecture de fichiers déjà
    sur disque — aucune connexion, aucun sous-processus.

    Fix round 4 (relecture, I-2) : la version précédente rendait l'id NU, et
    l'intersection dans `main()` comparait `i.rpartition(":")[2] in ran` —
    elle jetait donc le stem que `union_of_cases` avait justement calculé.
    Mesuré : un fichier de cas dont `X1` est `ssh_docker_ps` avec `paths: []`
    était crédité par le `X1` d'une AUTRE lane, portant un autre outil. Les
    ids de cas ne sont uniques que DANS un fichier ; la clé doit l'être
    aussi. Le rapport porte son propre `cases_file` (champ ajouté au Step 6),
    c'est lui qui donne le stem — un rapport qui ne le porte pas est refusé
    plutôt que rabattu silencieusement sur l'ancienne comparaison ambiguë.

    « Réellement produit un résultat » veut dire : l'entrée du chemin porte
    une liste `attempts` non vide. Une entrée vide (`paths: []` → aucun job
    construit) ne compte pas ; un dict de chemins présent mais sans tentative
    non plus."""
    ran = set()
    for p in report_paths:
        data = json.loads(Path(p).read_text())
        cases_file = data.get("cases_file")
        if not cases_file:
            raise SystemExit(f"coverage: le rapport {p} ne porte pas de champ "
                             "'cases_file' — il précède le harnais 2026-09-09 et "
                             "ses ids de cas ne sont pas rattachables à un fichier ; "
                             "rejoue-le avec le run.py courant")
        stem = Path(cases_file).stem
        for cid, paths in data.get("results", {}).items():
            if any(r.get("attempts") for r in (paths or {}).values()):
                ran.add(f"{stem}:{cid}")
    return ran


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--cases", nargs="+", required=True)
    ap.add_argument("--waivers", default="",
                    help='JSON {"ssh_docker_ps": "ENV: pas de Docker sur le Pi"}')
    ap.add_argument("--report", default="")
    ap.add_argument("--reports", nargs="*", default=[],
                    help="fix round 1 (I-2) : rapports JSON run.py ; si fournis, un "
                         "outil n'est compté « couvert » que si l'un de ses cas a "
                         "réellement produit un résultat dans l'un d'eux, pas "
                         "seulement nommé un tool dans un fichier de cas")
    a = ap.parse_args()

    inv = inventory(a.binary)
    lin = linux_tools(inv)
    used = union_of_cases(a.cases)
    if a.reports:
        ran = ran_case_ids(a.reports)
        # Fix round 4 (I-2) : intersection sur la clé COMPLÈTE `stem:id`, pas
        # sur l'id nu — deux lanes peuvent nommer `X1` deux outils différents.
        used = {t: [i for i in ids if i in ran] for t, ids in used.items()}
        used = {t: ids for t, ids in used.items() if ids}

    waivers = json.loads(Path(a.waivers).read_text()) if a.waivers else {}
    # Fix round 1 (Minor #2) : une dérogation qui vise un outil Windows ou un
    # nom qui n'existe pas du tout est une erreur dans le fichier de
    # dérogations lui-même — mesuré : elle passait avant silencieusement.
    bogus_waivers = sorted(t for t in waivers if t not in lin)
    if bogus_waivers:
        raise SystemExit(f"coverage: --waivers cite {bogus_waivers} — pas un outil "
                         "Linux actif (faute de frappe, outil Windows, ou outil "
                         "jamais activé) ; corrige le fichier de dérogations")

    covered = {t for t in used if t in lin}
    missing = sorted(set(lin) - covered)
    windows_touched = sorted(t for t in used if t in inv and t not in lin)
    unknown = sorted(t for t in used if t not in inv and not t.startswith(SENTINEL))
    unwaived = [t for t in missing if t not in waivers]
    # Une dérogation qui ne vise aucun manque actuel est PÉRIMÉE (l'outil est
    # déjà couvert) — pas fatal, mais imprimé pour que ça ne passe plus inaperçu.
    stale_waivers = sorted(t for t in waivers if t not in missing)

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
    REDUCE_KINDS = ("—", "*", "cols", "jq+tsv", "yq+tsv")
    reduce_total = 0
    for kind in REDUCE_KINDS:
        tot = [t for t, v in lin.items() if v["reduce"] == kind]
        reduce_total += len(tot)
        print(f"  {kind:<7} {sum(1 for t in tot if t in covered):>3}/{len(tot)}")
    # Fix round 1 (Minor #4) : la liste `REDUCE_KINDS` est câblée en dur ; sans
    # cette somme, un nouveau genre de `reduce` disparaîtrait silencieusement
    # de la matrice au lieu de faire échouer la mesure.
    if reduce_total != len(lin):
        unaccounted = sorted({v["reduce"] for v in lin.values()} - set(REDUCE_KINDS))
        raise SystemExit(f"coverage: la matrice `reduce` ne couvre que {reduce_total}/"
                         f"{len(lin)} outils Linux — genre(s) non listé(s) : "
                         f"{unaccounted} — mets REDUCE_KINDS à jour")

    print(f"\n{len(covered)}/{len(lin)} outils Linux couverts, "
          f"{len(missing)} manquant(s) dont {len(unwaived)} sans dérogation")
    if windows_touched:
        print(f"HORS PÉRIMÈTRE (Windows) : {windows_touched}")
    if unknown:
        print(f"OUTILS INEXISTANTS cités par un cas : {unknown}")
    for t in sorted(set(missing) & set(waivers)):
        print(f"  dérogation {t}: {waivers[t]}")
    if stale_waivers:
        print(f"  dérogation(s) PÉRIMÉE(S) (outil déjà couvert) : {stale_waivers}")

    if a.report:
        Path(a.report).parent.mkdir(parents=True, exist_ok=True)
        Path(a.report).write_text(json.dumps(
            # Fix round 1 (Minor #3) : les dérogations n'étaient imprimées
            # qu'à l'écran ; un lecteur du JSON seul voyait `unwaived: []` sans
            # aucun moyen de savoir que des outils avaient été excusés, ni
            # pourquoi. `waivers`/`stale_waivers` rendent ce fichier auto-suffisant.
            {"covered": sorted(covered), "missing": missing, "unwaived": unwaived,
             "unknown": unknown, "windows_touched": windows_touched,
             "by_group": by_group, "used": used, "waivers": waivers,
             "stale_waivers": stale_waivers, "reports": a.reports},
            indent=2, ensure_ascii=False))
        print(f"report: {a.report}")

    sys.exit(min(len(unwaived) + len(unknown) + len(windows_touched), 255))


if __name__ == "__main__":
    main()
