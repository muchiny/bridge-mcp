#!/usr/bin/env python3
"""Live probe of the reduction params against a bridge host, through the CLI
and through a stdio MCP session, in parallel.

Usage:
  scripts/live_probe/run.py BIN [--host raspberry] [--jobs 4] [--path both|cli|mcp]
                            [--only J1,J4] [--baseline] [--report PATH] [--cases PATH]
                            [--rerun-ko N]

Champs d'un cas : id, owner, tool, args, expect (chaîne OU liste — toutes doivent
passer), paths (["cli","mcp"]), yes (bool), flags (drapeaux globaux du CLI, insérés
AVANT le nom d'outil, chemin cli seulement), argstyle ("json-args" par défaut, ou
"kv" pour la branche key=value qui seule valide les arguments inconnus).

Champ `sudo_reason` (chaîne) : obligatoire sur tout cas `ssh_exec`/`ssh_session_exec`
portant `sudo: true` — le garde-fou refuse le fichier sans lui.

Champ `guard_probe` (bool) : réservé aux sondes qui doivent CONTENIR un motif de
blacklist pour le mesurer (lane C : C161, C201-C208, C220-C238 ; lane F : F16).
Il lève la seule interdiction COMMAND_DENY, et uniquement si la charge est
inerte par construction — préfixée d'un `echo`, ou ne nommant que des chemins
du bac à sable / suffixés `-nonexistent`. Sinon le cas est refusé quand même.

Espèces d'assertion : ok, first=, eq=, re=, lines=, lines>=, lines<=, count=, json,
error=, exit=N, nore=REGEX, bytes<=N, bytes>=N, stderr=SUBSTR, trunc[=N], notrunc,
saved=CHEMIN, dur<=S, dur>=S. Il n'y en a PAS d'autre : `maxbytes=`, `minbytes=`,
`maxlines=`, `outid`, `file=`, `filebytes=`, `and=` et `discover` n'existent pas — et,
depuis le fix round 1 (C-3), une espèce inconnue ou un `argstyle` inconnu sont détectés
par `guard()` **avant** toute exécution (auparavant `check()` ne levait SystemExit que
dans un worker, après coup — un fichier pouvait déjà avoir tiré sur l'hôte et aucun
rapport n'était écrit). `check()` garde le même SystemExit en second rideau.
`re=` ne voit que stdout ; `nore=`, `error=`, `trunc` et `notrunc` voient stdout+stderr ;
`stderr=` ne voit que stderr ; `bytes*`, `trunc`, `notrunc` et `dur*` n'imposent aucune
condition sur rc (D1 le rend inexploitable).

Un garde-fou refuse le fichier entier avant toute exécution : outil inexistant, espèce
d'assertion ou argstyle inconnu (C-3), les dix outils de classe (b) (§3.4(b)) refusés
par NOM sans aucune échappatoire — ni --dry-run (§3.10) ni guard_probe (ruling R20) —,
chemin ou objet hors bac à sable (y compris niché dans une liste/un dict, I-9), `pid`
autre que la sentinelle 2147483647 (I-9), `save_output` hors du répertoire local même
sur un outil readonly (I-8), `saved=` sans `paths=["cli"]` ou partagé entre deux cas
(course, I-11), écriture (ou `systemctl stop/disable/mask`, ou kill-family) hors bac à
sable n'importe où dans `command` — plus l'adjacence verbe/chemin n'est PAS requise
(C-2) —, sudo sans sudo_reason, ssh_k8s_delete avec all/label_selector/field_selector,
commande interdite (COMMAND_DENY), flags/argstyle sur le chemin mcp.
`--dry-run` ne vaut certificat d'inertie que pour `bridge-mcp tool` : pour
`upload`/`download`/`daemon` il est ignoré et la commande s'exécute (P8-11) — et ne
vaut de toute façon RIEN pour les dix outils de classe (b), refusés même sous
--dry-run.
`guard_probe` lève l'interdiction COMMAND_DENY seulement si la commande ENTIÈRE est
inerte — chaque segment scindé sur `&&`/`||`/`;`/`|`/retour-ligne doit l'être
indépendamment (C-1) ; toute substitution de commande (rétro-guillemets, `$(...)`)
refuse d'emblée.
"""

import argparse
import concurrent.futures
import datetime
import importlib.util  # fix round 1 (Minor #9) : remonté du milieu du fichier
import json
import os
import re
import subprocess
import sys
import threading
import time
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


def kv_pairs(args):
    """Rend les args en `clé=valeur` — la branche que --json-args court-circuite.

    Un champ de type `array`/`object` doit être un littéral JSON : `coerce_value`
    (src/cli/runner.rs:1761) ne fait `serde_json::from_str` que sur cette forme et
    retombe SILENCIEUSEMENT en String sinon.
    """
    out = []
    for k, v in args.items():
        if isinstance(v, bool):
            out.append(f"{k}={'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            out.append(f"{k}={v}")
        elif isinstance(v, str):
            out.append(f"{k}={v}")
        else:
            out.append(f"{k}={json.dumps(v, ensure_ascii=False)}")
    return out


def run_cli(binary, tool, args, yes, flags=(), argstyle="json-args"):
    # Tous les drapeaux visés sont `global = true` (src/cli/mod.rs:71-115), mais on
    # les place AVANT le nom d'outil : après, ils se mêlent aux positionnels
    # `[ARGS]...` de `bridge-mcp tool` et la commande cesse d'être copiable telle
    # quelle dans un rapport.
    cmd = [binary, "tool"]
    if yes:
        cmd.append("--yes")
    cmd += list(flags)
    cmd.append(tool)
    if argstyle == "kv":
        cmd += kv_pairs(args)
    elif argstyle == "json-args":
        cmd += ["--json-args", json.dumps(args)]
    else:
        raise SystemExit(f"argstyle inconnu {argstyle!r} (json-args|kv)")
    t0 = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env(),
                           stdin=subprocess.DEVNULL)
        rc, so, se = p.returncode, clean(p.stdout), clean(p.stderr)
    except subprocess.TimeoutExpired:
        rc, so, se = 1, "", "cli: timeout after 180s"
    return rc, so, se, time.monotonic() - t0, cmd


def run_mcp(binary, tool, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args, "_meta": META}}
    argv = [binary, "serve", "<<<", json.dumps(req)]
    t0 = time.monotonic()
    proc = subprocess.Popen(
        [binary, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env(),
    )
    timer = threading.Timer(180, proc.kill)
    timer.start()
    try:
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        for _ in range(50):
            line = proc.stdout.readline()
            if not line:
                return 1, "", "mcp: server closed stdout without answering", time.monotonic() - t0, argv
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != 1:
                continue
            if "error" in msg:
                return 1, "", f"Error: {msg['error'].get('message', msg['error'])}", time.monotonic() - t0, argv
            result = msg.get("result", {})
            if result.get("resultType") == "input_required":
                return 1, "", "Error: input_required (destructive gate) — case must be cli-only", time.monotonic() - t0, argv
            text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            if result.get("isError"):
                return 1, text, f"Error: {text}", time.monotonic() - t0, argv
            return 0, text, "", time.monotonic() - t0, argv
        return 1, "", "mcp: no response with id 1 in 50 lines", time.monotonic() - t0, argv
    finally:
        timer.cancel()
        proc.kill()


# Deux formes de bannière : CLI (cache absent) et MCP (cache présent),
# src/domain/output_truncator.rs:38-104.
TRUNC_RE = re.compile(
    r"\[truncated: (?P<t1>\d+) lines total, (?P<o1>\d+) lines omitted"
    r"|MORE DATA AVAILABLE — Truncated: (?P<t2>\d+) lines total, (?P<o2>\d+) lines omitted")


def omitted_lines(text):
    """Nombre de lignes omises annoncé par la bannière, ou None si pas de bannière."""
    m = TRUNC_RE.search(text)
    return None if m is None else int(m.group("o1") or m.group("o2"))


def check(expect, rc, out, err, ctx=None):
    kind, _, arg = expect.partition("=")
    s = out.rstrip("\n")
    lines = s.splitlines() if s else []
    both = out + "\n" + err
    ctx = ctx or {}
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
    if kind == "lines<":                       # "lines<=N" — borne haute de cardinalité
        return rc == 0 and len(lines) <= int(arg)
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
    if kind == "exit":
        return rc == int(arg)
    if kind == "nore":
        return rc == 0 and re.search(arg, both, re.M) is None
    # --- ajouts campagne 2026-09-09 -------------------------------------
    # Volontairement SANS condition sur rc : D1 fait que rc reste 0 même
    # quand la commande distante a échoué, donc l'exiger masquerait la
    # mesure au lieu de la valider.
    if kind == "bytes<":                       # "bytes<=N"
        return len(out.encode()) <= int(arg)
    if kind == "bytes>":                       # "bytes>=N"
        return len(out.encode()) >= int(arg)
    if kind == "stderr":
        return arg in err
    if kind == "notrunc":
        return omitted_lines(both) is None
    if kind == "trunc":                        # "trunc" ou "trunc=N" (omises >= N)
        n = omitted_lines(both)
        return n is not None and n >= (int(arg) if arg else 1)
    if kind == "saved":
        p = Path(arg)
        return p.is_file() and p.stat().st_size > 0 and p.stat().st_size >= len(out.encode())
    if kind == "dur<":                         # "dur<=N" secondes
        return float(ctx.get("duration", 1e9)) <= float(arg)
    if kind == "dur>":                         # "dur>=N" secondes
        return float(ctx.get("duration", -1.0)) >= float(arg)
    raise SystemExit(f"unknown expectation kind {kind!r}")


# --- §6 garde-fou --------------------------------------------------------
# Outils dont AUCUNE invocation réelle n'est admissible sur ce Pi : ils
# n'ont pas d'objet « bac à sable » possible (ils agissent sur le nœud, le
# gestionnaire de paquets, le pare-feu ou le cluster entier).
# EXACTEMENT la liste §3.4(b) des Contraintes globales, ni plus ni moins, PLUS
# ssh_pkg_install (décision B : ne rien installer). Un garde plus large que le
# contrat qu'il fait respecter refuse en bloc les fichiers des lanes A, C et E,
# et le réflexe d'un exécutant face à un garde qui refuse tout est de l'éditer —
# un garde édité par l'agent qu'il surveille ne protège plus rien.
NEVER_PROBE_LIVE = frozenset({
    "ssh_k3s_uninstall", "ssh_k3s_killall", "ssh_k3s_upgrade",
    "ssh_k3s_cert_rotate", "ssh_k3s_etcd_snapshot_restore",
    "ssh_k8s_drain", "ssh_k8s_localpath_gc",
    "ssh_pkg_remove", "ssh_pkg_update",
    "ssh_firewall_deny",
})
# `ssh_pkg_install` (MUTANT, pas destructif — donc `is_inert` ne le couvre pas)
# est admis dans UNE seule forme, celle de A409 : paquet inexistant ET aucun
# `sudo`, donc apt échoue sur le verrou dpkg avant toute résolution. Toute
# autre forme est refusée. Le mettre dans NEVER_PROBE_LIVE tout court faisait
# avorter A2-missing-heavy.json en entier (mesuré le 2026-09-12).
PKG_INSTALL_OK = re.compile(r"^bmcp-nonexistent[\w.-]*$")
# Objets que la campagne a le droit de créer et donc de modifier (Task 1bis, §3.0).
SANDBOX_PATH_RE = re.compile(r"^/tmp/bridge-test-0909(?:-local)?(?:/|$)")
# Deux familles de noms légitimes, et pas une seule : les objets que la
# campagne CRÉE (bridge-test…, btest0909, bt-…, et le marqueur cron littéral
# BRIDGE_TEST_0909 du §3.0, en MAJUSCULES — la version précédente de cette
# regex ne l'acceptait pas et faisait avorter E3-identity-cron-systemd.json
# sur E319), et les cibles VOLONTAIREMENT INEXISTANTES sur lesquelles tirent
# les lanes A, C et F (`bmcp-nope…`, `bmcp-nonexistent…`, `…-bmcp-nonexistent-0909`,
# `bridge-test-nonexistent…`). Sans la seconde famille, C135, C139, C140,
# C141, C142 refusaient C1-gate.json en entier — alors qu'une cible qui
# n'existe pas est, par construction, la forme la plus sûre du plan.
SANDBOX_NAME_RE = re.compile(
    r"^(bridge-test|btest0909|btestgrp0909|bridge-test-0909|bt-)[\w.-]*$"
    r"|^BRIDGE_TEST_0909$"
    r"|^bmcp-(nope|nonexistent|probe)[\w.-]*$"
    r"|[\w.-]*-bmcp-nonexistent-0909(\.[\w.-]+)?$")
# Cas dont le CONTRAT EST LE REFUS PAR LE PRODUIT : ils nomment délibérément
# un objet vital pour prouver qu'un garde applicatif tire. Ils sont exemptés
# de NAME_KEYS — et d'eux seuls : la liste est fermée, énumérée par id, et
# toute addition exige la même justification écrite que C162/C163 (Task 5
# Step 4, « Danger C162/C163 »).
GUARD_EXPECTED_REFUSAL = frozenset({"C161b", "C162", "C163", "C164"})
LOCAL_OUT_RE = re.compile(
    r"^(/home/muchini/bmcp-test-0909/\.superpowers/|/tmp/bridge-test-0909)")
PATH_KEYS = frozenset({"path", "paths", "source", "destination", "dest", "target",
                       "target_file", "file", "directory", "local_path", "remote_path",
                       "archive", "backup_path",
                       # clés réellement employées par les cas mutants des lanes C/E :
                       "output_file", "archive_file", "mount_point", "template_path",
                       "output_path", "chart_path", "project_dir"})
NAME_KEYS = frozenset({"name", "names", "username", "group", "service", "unit",
                       "namespace", "release", "pattern"})
# Fix round 1 (review C-3/R20): les espèces d'assertion et les valeurs d'argstyle
# valides, pour un refus AVANT exécution plutôt qu'un SystemExit dans un worker
# après que des cas ont déjà tourné (mesuré : 3 run_cli avant l'abort, aucun
# rapport écrit — run.py:227,107 anciennement).
OWNERS = frozenset({"campaign", "base", "env", "discover", "defect"})
EXPECT_KINDS = frozenset({
    "ok", "first", "eq", "re", "lines", "lines>", "lines<", "count", "json",
    "error", "exit", "nore", "bytes<", "bytes>", "stderr", "notrunc", "trunc",
    "saved", "dur<", "dur>",
})
ARGSTYLES = frozenset({"json-args", "kv"})
# Fix round 1 (review R20, ruling du contrôleur) : les dix outils de classe (b)
# des contraintes globales §3.4(b) ne sont JAMAIS invocables, sous AUCUNE forme
# — pas même --dry-run (§3.10) — et sans échappatoire `guard_probe`. Refusés par
# NOM, avant tout autre calcul (avant même `is_inert`), dans `guard()`.
# Défense en profondeur : la porte destructive s'exécute AVANT la blacklist
# (défaut connu), donc un `--yes` la franchit et seule la blacklist serveur
# arrête ensuite. On refuse ici, côté harness, sans dépendre d'elle.
COMMAND_DENY = re.compile(
    r"rm\s+-rf|\bmkfs(\.|\s)|\bdd\b.*\bof=/dev/|\b(shutdown|reboot|halt|poweroff)\b"
    r"|\binit\s+[06]\b|k3s-uninstall|k3s-killall|>\s*/dev/(sd|mmcblk|nvme)")
SENTINEL = "ssh_bridge_campaign_"

# --- sondes de garde-fou : l'exception, et sa condition d'inertie ----------
# La lane C existe pour PROUVER que la blacklist mord : ses charges utiles
# (C201-C208, C220-C238, C161) et F16 contiennent nécessairement les motifs de
# COMMAND_DENY. Un garde qui les refuse en bloc ne protège rien, il empêche de
# mesurer le garde du produit — mesuré le 2026-09-12 : C1-gate.json,
# C2-blacklist.json et F-regressions.json avortaient tous les trois.
# Le contournement est donc NOMMÉ (`"guard_probe": true` dans le cas) et
# CONDITIONNEL : la charge doit être inerte par construction, ce qui se
# vérifie mécaniquement — soit elle est préfixée d'un `echo` (éventuellement
# après une affectation `VAR=…;`), soit tout chemin absolu qu'elle nomme est
# sous le bac à sable ou porte un suffixe d'inexistence. Une sonde qui ne
# satisfait aucune des deux formes est refusée MALGRÉ son `guard_probe`.
# Fix round 1 (review C-1): l'ancienne version de `INERT_ECHO` était ancrée en
# DÉBUT de chaîne seulement — `echo probe && shutdown -h now` matchait le
# préfixe et `is_inert_probe` rendait la main avant d'avoir regardé le reste
# de la commande. Toute substitution de commande (rétro-guillemets, `$(...)`)
# exécute un contenu non analysable statiquement : elle refuse la sonde
# d'emblée, quoi qu'il arrive ensuite. Le reste de la commande — hors le
# préfixe `VAR=valeur;` documenté, qui n'est PAS un opérateur de séquencement
# mais une affectation locale au même segment — est scindé sur tout opérateur
# de séquencement (`&&`, `||`, `;`, `|`, retour à la ligne) et CHAQUE segment
# résultant doit, à lui seul, être inerte.
CHAIN_OPS = re.compile(r"&&|\|\||;|\||\n")
SHELL_SUBST = re.compile(r"`|\$\(")
VAR_ASSIGN_PREFIX = re.compile(r"^\s*[A-Za-z_]\w*=\S*\s*;\s*")
# Un segment est un `echo` pur seulement s'il ne porte plus, après le mot
# `echo`, aucun caractère qui lui donnerait un effet de bord (redirection,
# séquencement, substitution) : `echo shutdown` est pur, `echo x > /etc/motd`
# ne l'est pas (la redirection retombe sur le contrôle par chemin ci-dessous).
ECHO_ONLY = re.compile(r"^\s*echo\b[^>|;&`]*$")
NONEXISTENT_SUFFIX = re.compile(
    r"-(nonexistent|guard-probe|canary-does-not-exist|inexistant)[\w.-]*$")


def _segment_is_inert(seg):
    """Un seul segment (déjà scindé sur tout opérateur de séquencement) est
    inerte s'il s'agit d'un `echo` pur, ou si tout chemin absolu qu'il nomme
    est sous le bac à sable ou porte un suffixe d'inexistence."""
    if ECHO_ONLY.match(seg):
        return True
    paths = re.findall(r"(?<![\w-])(/[A-Za-z0-9._/-]+)", seg)
    return bool(paths) and all(
        SANDBOX_PATH_RE.match(p) or NONEXISTENT_SUFFIX.search(p) for p in paths)


def is_inert_probe(c):
    """Vrai si un cas `guard_probe` est démontrablement sans effet, sur la
    TOTALITÉ de la commande — pas seulement son préfixe (C-1)."""
    if not c.get("guard_probe"):
        return False
    cmd = c["args"].get("command", "")
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    if SHELL_SUBST.search(cmd):
        return False
    body = VAR_ASSIGN_PREFIX.sub("", cmd, count=1)
    segments = [s.strip() for s in CHAIN_OPS.split(body) if s.strip()]
    return bool(segments) and all(_segment_is_inert(s) for s in segments)


def _coverage():
    """Charge coverage.py par chemin, pour ne pas entrer en collision avec le
    paquet pip `coverage` qui porte le même nom de module."""
    spec = importlib.util.spec_from_file_location("live_probe_coverage", HERE / "coverage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def is_inert(c, inv):
    """Vrai quand ce cas ne peut RIEN exécuter sur l'hôte.

    Deux formes seulement : --dry-run SUR LE BRAS `tool` (main.rs:145-153 rend
    la main avant `confirm_destructive` et avant toute I/O), et un outil
    `destructiveHint` sans `yes` (la porte refuse : exit 4 en CLI sans tty,
    `elicitation` non déclarée côté MCP).

    `--dry-run` n'est PAS un certificat d'inertie universel : seuls les bras
    `Exec` et `Tool` testent le drapeau (main.rs:113-119, 145-153). `upload`,
    `download`, `status`, `history`, `validate`, `config-diff` et `daemon`
    l'ignorent et s'exécutent pour de vrai — c'est ce que prouve P8-11, où
    `--dry-run upload` dépose bien le fichier sur le Pi. `run.py` n'émet que
    `bridge-mcp tool …`, donc le raccourci ne vaut que là, et on l'écrit.
    """
    if "--dry-run" in c.get("flags", []) and c.get("subcommand", "tool") == "tool":
        return True
    return bool(inv.get(c["tool"], {}).get("destructive")) and not c.get("yes", False)


# Fix round 1 (C-2) : l'ancien contrôle exigeait le chemin immédiatement après
# le verbe (`rm |mv |cp |…` suivi tout de suite du chemin) — `rm -r -- /etc/motd`
# (la forme même que §3.3 impose pour tout démontage), `rm -fr /etc/motd` et
# `cp SRC /etc/x` (le chemin dangereux n'est pas le premier après le verbe)
# passaient tous. Le nouveau contrôle détecte le verbe n'importe où dans la
# commande, puis inspecte TOUS les chemins absolus, sans exiger l'adjacence.
WRITE_VERB = re.compile(r"\b(rm|mv|cp|chmod|chown|tee|mkdir|truncate|dd)\b")
FIND_DELETE = re.compile(r"\bfind\b.*(-delete\b|-exec\b)")
REDIRECT = re.compile(r">>?(?!=)")
# `systemctl stop k3s` ne porte AUCUN chemin absolu — c'est l'exemple cité par
# le commentaire original comme raison d'être du contrôle par chemin, et ce
# contrôle ne le voyait jamais puisqu'il n'y a pas de chemin à inspecter.
SERVICE_STOP_RE = re.compile(r"\bsystemctl\s+(?:stop|disable|mask)\s+(\S+)")
# Aucune forme sandboxée légitime n'existe pour kill/pkill/killall en `command`
# brut : un PID sandboxé passe par l'outil dédié `ssh_process_kill` (liste
# blanche §3.2), jamais par une commande `ssh_exec` à la main.
KILL_FAMILY_RE = re.compile(r"\b(?:kill|pkill|killall)\b")
ABS_PATH = re.compile(r"(?<![\w-])(/[A-Za-z0-9._/-]+)")
READ_ONLY_OK = re.compile(
    r"^/(etc/os-release|etc/hostname|proc|sys|usr|bin|sbin|lib|var/log|dev/null)")


def _walk_args(args):
    """Génère (clé, valeur-chaîne) pour toute chaîne trouvée dans les args,
    y compris nichée dans une liste ou un dict (fix round 1, I-9 :
    `files=[{"path": …}]` et `names=[...]` échappaient tout contrôle car
    seules les valeurs `str` de premier niveau étaient inspectées). Dans un
    dict, SES clés prennent le relais du contrôle ; dans une liste, chaque
    élément hérite de la clé de la liste, sauf s'il est lui-même un dict."""
    def walk(k, v):
        if isinstance(v, str):
            yield k, v
        elif isinstance(v, dict):
            for kk, vv in v.items():
                yield from walk(kk, vv)
        elif isinstance(v, list):
            for item in v:
                yield from walk(k, item)
    for k, v in args.items():
        yield from walk(k, v)


def guard(cases, inv):
    """Refuse le fichier entier avant la première exécution. Aucune option ne
    la désactive : un garde-fou débrayable n'en est pas un."""
    bad = []

    # Fix round 1 (ruling R20 du contrôleur) : chemin séparé, AVANT tout le
    # reste, pour les dix outils de classe (b) (§3.4(b)) — jamais invoqués,
    # sous AUCUNE forme, pas même --dry-run (§3.10). Aucune échappatoire :
    # ni `is_inert`, ni `guard_probe` ne s'appliquent à ce refus.
    never_probe_cids = set()
    for c in cases:
        if c["tool"] in NEVER_PROBE_LIVE:
            bad.append(f"{c['id']}: {c['tool']} est de classe (b) (§3.4(b)) — refus "
                       "par nom, sans exception --dry-run/guard_probe (§3.10)")
            never_probe_cids.add(c["id"])

    # Fix round 1 (I-11) : deux cas qui partagent le même `saved=` chemin
    # entrent en course dès qu'ils tournent en parallèle — inspection au
    # niveau du fichier entier, indépendante de --jobs.
    saved_targets = {}
    for c in cases:
        for e in c.get("expect", []):
            if isinstance(e, str) and e.startswith("saved="):
                saved_targets.setdefault(e.partition("=")[2], []).append(c["id"])
    for target, ids in saved_targets.items():
        if len(ids) > 1:
            bad.append(f"cas {ids} partagent le même chemin saved={target!r} — "
                       "collision garantie (I-11)")

    for c in cases:
        cid, tool = c["id"], c["tool"]
        if cid in never_probe_cids:
            continue                                       # déjà refusé ci-dessus
        if tool not in inv and not tool.startswith(SENTINEL):
            bad.append(f"{cid}: outil inexistant {tool!r} "
                       f"(préfixe {SENTINEL!r} réservé aux cas « outil inconnu »)")
            continue
        # Fix round 1 (C-3) : espèce d'assertion et argstyle vérifiés ICI,
        # avant tout subprocess — pas dans un worker après coup, où l'ancien
        # SystemExit surgissait après que d'autres cas avaient déjà tourné
        # (mesuré par la relecture : 3 run_cli exécutés avant l'abort, aucun
        # rapport écrit, contrairement à ce que promettait la docstring).
        for e in c.get("expect", []):
            kind = e.partition("=")[0] if isinstance(e, str) else None
            if kind not in EXPECT_KINDS:
                bad.append(f"{cid}: espèce d'assertion inconnue {e!r} dans expect")
        argstyle = c.get("argstyle", "json-args")
        if argstyle not in ARGSTYLES:
            bad.append(f"{cid}: argstyle inconnu {argstyle!r} (json-args|kv)")
        # Fix round 1 (Minor #8) : une faute de frappe sur `owner` se lisait
        # silencieusement comme "non-base" (tout ce qui n'est pas exactement
        # "base" prend la branche KO(e) sous --baseline).
        owner = c.get("owner", "base")
        if owner not in OWNERS:
            bad.append(f"{cid}: owner={owner!r} hors du vocabulaire fermé {sorted(OWNERS)}")
        if (c.get("flags") or c.get("argstyle")) and "mcp" in c.get("paths", ["cli", "mcp"]):
            bad.append(f"{cid}: flags/argstyle n'existent pas côté MCP — mets paths=['cli']")
        if (any(isinstance(e, str) and e.startswith("saved=") for e in c.get("expect", []))
                and c.get("paths", ["cli", "mcp"]) != ["cli"]):
            bad.append(f"{cid}: saved= exige paths=['cli'] (sinon course cli/mcp — I-11)")
        inert = is_inert(c, inv)
        if tool == "ssh_pkg_install" and not inert:
            pkg = str(c["args"].get("package", ""))
            if c["args"].get("sudo") or not PKG_INSTALL_OK.match(pkg):
                bad.append(f"{cid}: ssh_pkg_install n'est admis que sans sudo et sur un "
                           f"paquet `bmcp-nonexistent*` (décision B) — vu package={pkg!r}")
        if c.get("guard_probe") and not is_inert_probe(c):
            bad.append(f"{cid}: guard_probe déclaré mais la charge n'est pas inerte "
                       "(ni un `echo` intégral sans effet de bord, ni confinée au bac à "
                       "sable / aux cibles suffixées -nonexistent, sur CHAQUE segment)")
        if tool == "ssh_k8s_delete" and ({"all", "label_selector", "field_selector"}
                                         & set(c["args"])):
            # validate_delete (kubernetes.rs:920-936) ne protège les namespaces
            # que sur le couple (resource, name) : par `all`/`label_selector`/
            # `field_selector`, `name` vaut "" et le garde applicatif ne mord pas.
            bad.append(f"{cid}: ssh_k8s_delete avec all/label_selector/field_selector "
                       "— forme interdite dans toute la campagne")
        # Fix round 1 (I-8) : `save_output` écrit sur la machine bridge (WSL),
        # pas sur le Pi — orthogonal à `readonly`/`inert`, donc vérifié
        # inconditionnellement plutôt que dans la boucle d'arguments plus bas,
        # que `readonly` court-circuitait entièrement (la majorité des outils
        # qui utilisent réellement `save_output` sont readonly).
        sv = c["args"].get("save_output")
        if isinstance(sv, str) and not LOCAL_OUT_RE.match(sv):
            bad.append(f"{cid}: save_output={sv!r} hors du répertoire de sortie local")
        # Fix round 1 (I-9) : `pid` est un entier, dans aucun PATH_KEYS/NAME_KEYS,
        # donc invisible à la boucle par clé ci-dessous. Seule la valeur
        # sentinelle est mécaniquement vérifiable sans état inter-tâches — un
        # pid réel exige la garde d'identité E505a/E505b (§3.2), hors du
        # périmètre de ce garde-fou statique.
        pid = c["args"].get("pid")
        if pid is not None and not isinstance(pid, bool):
            try:
                pid_ok = int(pid) == 2147483647
            except (TypeError, ValueError):
                pid_ok = False
            if not pid_ok:
                bad.append(f"{cid}: pid={pid!r} — seule la sentinelle 2147483647 est "
                           "vérifiable ici (§3.2) ; un pid réel exige la garde d'identité "
                           "E505a/E505b dans le même sous-lot")
        if inert:
            continue
        if inv.get(tool, {}).get("readonly"):
            continue                                   # lecture seule : hors périmètre du garde-fou
        if tool in ("ssh_exec", "ssh_session_exec", "ssh_exec_multi"):
            cmdtext = c["args"].get("command", "")
            if not isinstance(cmdtext, str):
                bad.append(f"{cid}: command doit être une chaîne, pas {type(cmdtext).__name__}")
            else:
                if (c.get("sudo") or c["args"].get("sudo")) and not c.get("sudo_reason"):
                    bad.append(f"{cid}: sudo=true sans champ 'sudo_reason' justifiant l'élévation")
                has_write_verb = bool(WRITE_VERB.search(cmdtext) or FIND_DELETE.search(cmdtext)
                                       or REDIRECT.search(cmdtext))
                if has_write_verb:
                    for p in ABS_PATH.findall(cmdtext):
                        if (SANDBOX_PATH_RE.match(p) or READ_ONLY_OK.match(p)
                                or p.startswith("/run/systemd/system/bridge-test-0909")):
                            continue
                        bad.append(f"{cid}: écriture hors bac à sable dans command: {p}")
                m = SERVICE_STOP_RE.search(cmdtext)
                if m and not m.group(1).startswith("bridge-test-0909"):
                    bad.append(f"{cid}: systemctl stop/disable/mask hors bac à sable "
                               f"dans command: {m.group(1)}")
                if KILL_FAMILY_RE.search(cmdtext):
                    bad.append(f"{cid}: kill/pkill/killall dans command — utiliser "
                               "ssh_process_kill (liste blanche §3.2), pas une commande brute")
        for k, v in _walk_args(c["args"]):
            if k in PATH_KEYS and not SANDBOX_PATH_RE.match(v):
                bad.append(f"{cid}: {k}={v!r} hors du bac à sable {SANDBOX_PATH_RE.pattern}")
            elif (k in NAME_KEYS and not SANDBOX_NAME_RE.match(v)
                  and cid not in GUARD_EXPECTED_REFUSAL):
                bad.append(f"{cid}: {k}={v!r} n'est pas un objet créé par la campagne")
            elif k == "command" and COMMAND_DENY.search(v) and not is_inert_probe(c):
                bad.append(f"{cid}: command={v!r} touche un motif interdit "
                           "(ajouter `\"guard_probe\": true` SI et seulement si la charge "
                           "est inerte par construction, sur CHAQUE segment)")
    if bad:
        raise SystemExit("GARDE-FOU — aucun cas n'a été exécuté :\n  " + "\n  ".join(bad))


def substitute(value, variables):
    if isinstance(value, str):
        for k, v in variables.items():
            value = value.replace("${" + k + "}", v)
    return value


def expectations(c):
    """`expect` accepte une chaîne ou une liste ; TOUTES doivent passer."""
    e = c["expect"]
    return e if isinstance(e, list) else [e]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--path", choices=["both", "cli", "mcp"], default="both")
    ap.add_argument("--only", default="")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--report", default="")
    ap.add_argument("--cases", default=str(HERE / "cases.json"))
    ap.add_argument("--rerun-ko", type=int, default=0,
                    help="rejoue en série (jobs=1) les (cas, chemin) en échec, N fois")
    a = ap.parse_args()

    spec = json.loads(Path(a.cases).read_text())
    variables = spec.get("vars", {})
    allcases = []
    for c in spec["cases"]:
        c = dict(c)
        c["args"] = {k: substitute(v, variables) for k, v in c["args"].items()}
        c["expect"] = [substitute(e, variables) for e in expectations(c)]
        allcases.append(c)
    inv = _coverage().inventory(a.binary)      # cf. Step 5
    guard(allcases, inv)                       # cf. Step 5 — AVANT toute exécution ; fix
                                                # round 1 (I-10) : `path_filter` était mort
    only = {x for x in a.only.split(",") if x}
    cases = [c for c in allcases if not only or c["id"] in only]

    jobs = []
    for c in cases:
        args = {"host": a.host, **c["args"]}
        for path in c.get("paths", ["cli", "mcp"]):
            if a.path != "both" and path != a.path:
                continue
            jobs.append((c, path, args))

    ATTEMPT_KEYS = ("ok", "rc", "duration", "out", "err", "failed", "out_bytes", "omitted_lines")

    def attempt(c, path, args):
        # `saved=` mentirait sur un fichier laissé par un run précédent.
        for e in c["expect"]:
            if e.startswith("saved="):
                p = Path(e.partition("=")[2])
                p.unlink(missing_ok=True)
        if path == "cli":
            rc, out, err, dt, argv = run_cli(a.binary, c["tool"], args, c.get("yes", False),
                                             c.get("flags", []), c.get("argstyle", "json-args"))
        else:
            rc, out, err, dt, argv = run_mcp(a.binary, c["tool"], args)
        ctx = {"duration": dt, "argv": argv}
        # Fix round 1 (I-4) : quelle assertion précise a échoué, pas un seul
        # booléen global — `all()` court-circuite, donc sans ceci un échec
        # sur la première assertion d'une liste rend le verdict des suivantes
        # à jamais inconnu du rapport (mesuré sur un cas `["exit=0", "re=…"]`).
        checks = [{"expect": e, "ok": check(e, rc, out, err, ctx)} for e in c["expect"]]
        ok = all(x["ok"] for x in checks)
        failed = [x["expect"] for x in checks if not x["ok"]]
        # Fix round 1 (I-7) : le nombre d'octets et de lignes omises sont déjà
        # calculés par check() puis jetés ; sans eux un échec bytes<=/trunc ne
        # dit jamais "401 octets" ou "bannière absente", et l'extrait [:400]
        # place la preuve décisive hors champ pour tout payload assez gros
        # pour que D2 soit intéressant.
        both = out + "\n" + err
        return {"ok": ok, "rc": rc, "duration": round(dt, 3), "argv": argv,
                "out": out[:400], "err": err[:400], "failed": failed,
                "out_bytes": len(out.encode()), "omitted_lines": omitted_lines(both)}

    def work(job):
        c, path, args = job
        r = attempt(c, path, args)
        r["expect"] = c["expect"]
        return c["id"], path, r

    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        results = list(ex.map(work, jobs))

    by_case = {}
    for cid, path, r in results:
        r["attempts"] = [{k: r[k] for k in ATTEMPT_KEYS}]
        by_case.setdefault(cid, {})[path] = r

    if a.rerun_ko:
        by_id = {c["id"]: c for c in cases}
        ko = [(cid, path) for cid, paths in by_case.items()
              for path, r in paths.items() if not r["ok"]]
        for cid, path in ko:                        # série stricte : jamais de parallélisme ici
            c = by_id[cid]
            args = {"host": a.host, **c["args"]}
            # Fix round 1 (I-6) : la boucle ne rompt PLUS au premier succès —
            # global-constraints §4 exige trois verdicts consignés avant de
            # conclure ("obligation de trois relances… le cas déclaré FLAKY
            # seulement si les trois ne concordent pas"), pas "le premier qui
            # bascule gagne" (mesuré : l'ancien code ne consignait que 2
            # tentatives sur les 3 requises par --rerun-ko 2).
            for _ in range(a.rerun_ko):
                r = attempt(c, path, args)
                by_case[cid][path]["attempts"].append({k: r[k] for k in ATTEMPT_KEYS})
            verdicts = {att["ok"] for att in by_case[cid][path]["attempts"]}
            if len(verdicts) > 1:
                # Fix round 1 (I-5) : le sommaire de tête reflète la DERNIÈRE
                # tentative — pas la première (celle qui a échoué), laissée en
                # place avec seulement `ok` forcé à True par l'ancien code, ce
                # qui faisait cohabiter `ok=true` avec le `rc`/`duration` d'un
                # échec. L'historique complet reste, honnête, dans `attempts`.
                by_case[cid][path].update({k: r[k] for k in ATTEMPT_KEYS + ("argv",)})
                by_case[cid][path]["flaky"] = True
        n_flaky = sum(1 for p in by_case.values() for r in p.values() if r.get("flaky"))
        print(f"rerun-ko: {len(ko)} échec(s) rejoué(s) en série, {n_flaky} FLAKY")

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
            if v.get("flaky"):
                cells.append("FLAKY")
            elif v["ok"]:
                cells.append(" OK  ")
            elif a.baseline and c.get("owner", "base") != "base":
                cells.append("KO(e)")
            else:
                cells.append(" KO  ")
                unexpected += 1
        rows.append(f"{c['id']:<6} {c.get('owner','base'):<7} cli:{cells[0]} mcp:{cells[1]}  {' '.join(c['expect'])[:60]}")
    print("\n".join(rows))
    print(f"\n{len(cases)} cases, {len(jobs)} runs, {unexpected} unexpected verdict(s)")
    for c in cases:
        for path, v in by_case.get(c["id"], {}).items():
            if not v["ok"] and not (a.baseline and c.get("owner", "base") != "base"):
                # Fix round 1 (I-4) : nommer l'assertion en cause, pas
                # seulement les extraits stdout/stderr.
                print(f"--- {c['id']} [{path}] failed: {v.get('failed')}\n"
                      f"    out: {v['out']!r}\n    err: {v['err']!r}")

    report = a.report or str(HERE.parents[1] / ".superpowers" / "probes" /
                             f"{datetime.date.today()}-{Path(a.binary).stem}-{Path(a.cases).stem}.json")
    Path(report).parent.mkdir(parents=True, exist_ok=True)
    Path(report).write_text(json.dumps({"binary": a.binary, "host": a.host, "baseline": a.baseline,
                                        "rerun_ko": a.rerun_ko, "cases_file": a.cases,
                                        "results": by_case}, indent=2))
    print(f"report: {report}")
    sys.exit(unexpected)


if __name__ == "__main__":
    main()
