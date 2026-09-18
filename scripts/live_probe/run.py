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
chemin ou objet hors bac à sable (y compris niché dans une liste/un dict, I-9),
`save_output` hors du répertoire local même sur un outil readonly (I-8), `saved=` sans
`paths=["cli"]` ou partagé entre deux cas (course, I-11), sudo sans sudo_reason,
ssh_k8s_delete avec all/label_selector/field_selector, commande interdite
(COMMAND_DENY), flags/argstyle sur le chemin mcp, et — fix round 4 — un ARGUMENT
d'assertion malformé (`bytes<=abc`, `count=x`, `re=(`), qui mourait auparavant dans un
worker APRÈS que des cas avaient tiré, sans rapport écrit.

`command` (ssh_exec/ssh_session_exec/ssh_exec_multi) est analysée par `scan_command()`,
qui tokenise comme un shell et distingue CIBLE et SOURCE. Sont refusés : toute CIBLE
d'écriture hors bac à sable — cible de redirection (`> /proc/sysrq-trigger`, y compris
la forme bash `>& fichier`) ou opérande d'un verbe d'écriture (rm, mv, cp, chmod,
chown, tee, mkdir, truncate, dd, find -delete/-exec) — ; un verbe d'écriture sans cible
absolue (répertoire courant inconnu) ; un `cd` hors bac à sable dans une commande qui
écrit ; `systemctl <verbe disruptif>` ou `service … stop` sur une unité qui ne commence
pas par `bridge-test-0909` (TOUTES les unités de la liste, sur CHAQUE segment) ;
`kill`/`pkill`/`killall` en position de commande. Les SOURCES lues ne sont pas
contraintes : c'est ce qui rend `cat /etc/passwd > /tmp/bridge-test-0909/copie` licite
et `echo c > /proc/sysrq-trigger` interdit — l'ancienne exemption en bloc de /proc,
/sys, /usr et /var/log (`READ_ONLY_OK`) excusait les DEUX.

Champ `pid_identity` (chaîne) : un `pid` réel sur un outil non-readonly n'est admis
que si le cas nomme ici la garde d'identité qui l'a confirmé dans le MÊME sous-lot
(§3.2, E505a/E505b). Sans lui, seuls la sentinelle 2147483647 et les pid 0/1 (refusés
inconditionnellement par `process.rs:73`, donc inertes — et 0 est le gabarit que
`E-patch-pid.sh` réécrit) passent. Un outil `readonly` qui prend un pid
(`ssh_perf_trace`) n'est pas concerné : lire un pid n'agit sur rien.
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
import posixpath
import re
import shlex
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


# Fix round 4 (relecture : « READ_ONLY_OK est le trou le plus large du garde »).
# L'ancien contrôle cherchait un verbe d'écriture N'IMPORTE OÙ dans le TEXTE de
# la commande, puis passait TOUT chemin absolu par SANDBOX_PATH_RE **ou**
# READ_ONLY_OK. Deux défauts opposés, tous deux mesurés :
#   - trop permissif — READ_ONLY_OK exemptait /proc, /sys, /usr, /var/log en
#     BLOC, y compris comme CIBLE d'écriture : `echo c > /proc/sysrq-trigger`
#     (redémarrage matériel immédiat du Pi), `rm -r -- /usr/local/bin/foo`,
#     `tee /var/log/evil.log`, `truncate -s 0 /var/log/syslog`,
#     `find /usr -name foo -delete` et `cd /var/log && rm -r -- syslog`
#     PASSAIENT le garde ;
#   - trop strict — la SOURCE lue par une écriture confinée au bac à sable
#     (`cat /etc/passwd > /tmp/bridge-test-0909/copy.txt`) était refusée, et
#     `\brm\b` matchait « rm-notes », `\bcp\b` « cp.txt », `\bdd\b` « /x/dd ».
# Le nouveau contrôle sépare CIBLE et SOURCE. Il tokenise la commande comme le
# ferait un shell (`shlex`, `punctuation_chars=True` : `>` `>>` `>&` `|` `&&`
# `;` deviennent des jetons distincts, et tout ce qui est entre guillemets
# reste UN jeton — le `>` de `awk '$3 > 50 {print}'` n'est donc plus lu comme
# une redirection), puis n'exige le bac à sable que des CIBLES d'écriture :
# cible de redirection et opérandes du verbe. Les SOURCES ne sont plus
# contraintes du tout — c'est pourquoi `READ_ONLY_OK` a disparu : sa seule
# raison d'être était d'excuser les chemins que la règle « tout chemin absolu
# d'une commande écrivante » ramassait au passage, et il n'y a plus rien à
# excuser. Le garde surveille ce qui est ÉCRIT sur le Pi ; la protection
# contre les fuites en lecture est ailleurs (`nore=`, §3.7, et la blacklist
# du produit), pas ici, et elle ne l'a jamais été (`cat /etc/shadow` n'était
# pas plus refusé avant qu'après).
WRITE_VERBS = frozenset({"rm", "mv", "cp", "chmod", "chown", "tee", "mkdir",
                         "truncate", "dd"})
# `cp`/`mv` LISENT leur(s) premier(s) opérande(s) et n'ÉCRIVENT que le dernier.
COPY_VERBS = frozenset({"cp", "mv"})
KILL_VERBS = frozenset({"kill", "pkill", "killall"})
# Préfixes transparents : ils n'exécutent pas, ils enveloppent.
WRAPPERS = frozenset({"sudo", "env", "nice", "nohup", "time", "ionice",
                      "command", "exec", "stdbuf", "doas"})
SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh", "ash", "busybox", "su"})
CTRL_TOKENS = frozenset({"&&", "||", ";", ";;", "|", "&", "|&"})
VAR_ASSIGN_TOKEN = re.compile(r"^[A-Za-z_]\w*=")
# Seules cibles d'écriture admissibles. `/dev/null` remplace ici l'entrée
# `dev/null` de feu READ_ONLY_OK : jeter dans le trou noir n'est pas écrire.
def _write_target_ok(p):
    return (SANDBOX_PATH_RE.match(p) or p == "/dev/null"
            or p.startswith("/run/systemd/system/bridge-test-0909"))
# `systemctl stop k3s` ne porte AUCUN chemin absolu — c'est l'exemple cité par
# le commentaire original comme raison d'être du contrôle par chemin, et ce
# contrôle ne le voyait jamais puisqu'il n'y a pas de chemin à inspecter.
# Fix round 4 : l'ancien `SERVICE_STOP_RE.search(...)` ne voyait QUE la
# première occurrence et QU'UNE seule unité (`\S+`), donc
# `systemctl stop bridge-test-0909.service k3s` (systemctl prend une LISTE) et
# `systemctl stop bridge-test-0909.service; systemctl stop k3s` passaient tous
# les deux, comme `systemctl --now disable k3s`, `systemctl restart k3s` et
# `service k3s stop` (hors de la forme reconnue). Remplacé par un contrôle par
# jetons, segment par segment, sur toutes les unités de la ligne.
SYSTEMCTL_DISRUPTIVE = frozenset({
    "stop", "disable", "mask", "restart", "try-restart", "reload",
    "reload-or-restart", "force-reload", "kill", "isolate", "revert",
    "set-default", "edit", "switch-root", "halt", "poweroff", "reboot",
    "emergency", "rescue", "suspend", "hibernate", "hybrid-sleep"})
SERVICE_DISRUPTIVE = frozenset({"stop", "restart", "reload", "force-reload"})


def _op_class(tok):
    """`ctrl` = séparateur de commandes, `redir` = redirection en sortie,
    `redin` = redirection en entrée, None = un mot ordinaire."""
    if tok in CTRL_TOKENS:
        return "ctrl"
    if tok and set(tok) <= set("<>&|"):
        return "redir" if ">" in tok else "redin"
    return None


class CommandUnparsable(Exception):
    """Guillemet non fermé : le garde refuse plutôt que de deviner."""


def _tokenize(cmd):
    """Jetons façon shell. Chaque ligne est tokenisée séparément et les lignes
    sont recollées par un `;` explicite : `shlex` traite le retour à la ligne
    comme une espace banale, ce qui fondrait `ls /etc\\nrm /usr/x` en UN seul
    segment dont le mot de commande serait `ls` — le `rm` devenait invisible."""
    out = []
    for n, line in enumerate(cmd.split("\n")):
        if n:
            out.append(";")
        lx = shlex.shlex(line, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        lx.commenters = ""          # `#` ne doit rien tronquer silencieusement
        try:
            out.extend(lx)
        except ValueError as e:
            raise CommandUnparsable(str(e))
    return out


def _segments(tokens):
    seg, segs = [], []
    for t in tokens:
        if _op_class(t) == "ctrl":
            if seg:
                segs.append(seg)
            seg = []
        else:
            seg.append(t)
    if seg:
        segs.append(seg)
    return segs


def _split_redirs(seg):
    """(mots, cibles de redirection). Un `2` collé devant `>` est un
    descripteur, pas un mot ; `2>&1` et `>&2` dupliquent un descripteur et ne
    visent aucun fichier."""
    words, targets, i = [], [], 0
    while i < len(seg):
        cls = _op_class(seg[i])
        if cls == "redir":
            if words and words[-1].isdigit():
                words.pop()
            if i + 1 < len(seg):
                nxt = seg[i + 1]
                if not (nxt.isdigit() or nxt == "-"):
                    targets.append(nxt)
                i += 2
                continue
            i += 1
            continue
        if cls == "redin":
            i += 2 if i + 1 < len(seg) else 1
            continue
        words.append(seg[i])
        i += 1
    return words, targets


def _command_word(words):
    """(mot de commande, opérandes) après avoir traversé les affectations
    `VAR=val` et les préfixes transparents (`sudo`, `env`, `timeout 5`…)."""
    i = 0
    while i < len(words):
        w = words[i]
        if VAR_ASSIGN_TOKEN.match(w):
            i += 1
            continue
        if w in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                # `sudo -u btest0909 …` : le drapeau emporte sa valeur
                if words[i] in ("-u", "-g", "-U", "-C", "-p", "-S", "-i"):
                    i += 1
                i += 1
            continue
        if w == "timeout":
            i += 1
            while i < len(words) and (words[i].startswith("-")
                                      or re.fullmatch(r"[\d.]+[smhd]?", words[i])):
                i += 1
            continue
        return w, words[i + 1:]
    return None, []


def _abs_targets(verb, operands):
    """Les opérandes ÉCRITS par `verb`, chemins absolus uniquement."""
    absolute = [o for o in operands if o.startswith("/")]
    if verb == "dd":
        return [o.partition("=")[2] for o in operands if o.startswith("of=")
                and o.partition("=")[2].startswith("/")]
    if verb in COPY_VERBS:
        return absolute[-1:]                       # seul le dernier est écrit
    return absolute


def _norm(p):
    """`/dev/null/../../etc/motd` visait bien `/etc/motd` : la version
    précédente comparait la chaîne brute et l'exemption `/dev/null` mordait
    sur le préfixe."""
    return posixpath.normpath(p.split("*")[0]) if "*" in p else posixpath.normpath(p)


def scan_command(cmd, depth=0):
    """Analyse statique d'une `command` d'`ssh_exec`. Rend la liste des motifs
    de refus (vide = la commande n'écrit rien hors du bac à sable, ne coupe
    aucun service hors bac à sable, ne tue aucun processus).

    Limite documentée : une commande construite dynamiquement (`$(...)`,
    `eval "$x"`) n'est pas analysable statiquement — `SHELL_SUBST` la refuse
    déjà pour les sondes `guard_probe`, et pour une commande ordinaire le
    garde ne voit que le texte littéral. Les formes `sh -c '<cmd>'` et
    `eval <mots>` SONT descendues récursivement (profondeur 3), sinon
    `bash -c 'rm -r -- /etc/x'` deviendrait un simple jeton entre guillemets."""
    if depth > 3:
        return ["commande imbriquée trop profondément pour être analysée"]
    try:
        tokens = _tokenize(cmd)
    except CommandUnparsable as e:
        return [f"commande non analysable ({e}) — le garde refuse plutôt que de deviner"]

    bad = []
    segs = _segments(tokens)
    cd_targets, redir_targets = [], []
    # Pré-passe : où la commande se place-t-elle ? Un `cd` DANS le bac à sable
    # (et aucun `cd` ailleurs) rend un chemin relatif sûr — sans quoi
    # `cd /tmp/bridge-test-0909 && rm -r -- stale`, forme parfaitement
    # légitime d'un démontage de lane, serait refusé.
    for seg in segs:
        w, _ = _split_redirs(seg)
        v, ops = _command_word(w)
        if v in ("cd", "pushd") and ops:
            cd_targets.append(ops[0])
    cwd_sandboxed = (bool(cd_targets)
                     and all(t.startswith("/") and SANDBOX_PATH_RE.match(_norm(t))
                             for t in cd_targets))
    for seg in segs:
        words, rtargets = _split_redirs(seg)
        redir_targets.extend(rtargets)
        verb, operands = _command_word(words)
        if verb is None:
            continue
        if verb in SHELLS and "-c" in operands:
            j = operands.index("-c")
            if j + 1 < len(operands):
                bad.extend(scan_command(operands[j + 1], depth + 1))
        if verb == "eval" and operands:
            bad.extend(scan_command(" ".join(operands), depth + 1))
        if verb == "xargs":
            inner = [o for o in operands if not o.startswith("-")]
            if inner:
                bad.extend(scan_command(" ".join(inner), depth + 1))
        # --- cibles d'écriture -------------------------------------------
        cmd_is_write = verb in WRITE_VERBS
        find_deletes = verb == "find" and any(o in ("-delete", "-exec") for o in operands)
        targets = []
        # Un verbe d'écriture ailleurs qu'en tête compte aussi (`sudo -u x rm /etc/y`,
        # `find … -exec rm -- /etc/y +`) — mais par ÉGALITÉ DE JETON, jamais par
        # sous-chaîne : c'est ce qui rendait `ls -l /home/muchini/rm-notes` suspect.
        for idx, w in enumerate(words):
            if w in WRITE_VERBS:
                targets.extend(_abs_targets(w, words[idx + 1:]))
        if find_deletes:
            targets.extend(o for o in operands if o.startswith("/"))
        if cmd_is_write or find_deletes:
            # Cible RELATIVE : elle dépend du répertoire courant, que seul un
            # `cd` DANS le bac à sable rend connu (`cd /var/log && rm -r -- syslog`
            # détruit /var/log/syslog sans qu'aucun chemin absolu dangereux
            # n'apparaisse). Les opérandes relatifs ne sont pas classés un par un
            # — `chmod 644 …`, `truncate -s 0 …` en portent qui ne sont pas des
            # chemins ; c'est l'ABSENCE de toute cible absolue qui déclenche.
            if (not targets and not cwd_sandboxed
                    and not any(o.startswith("/") for o in operands)):
                bad.append(f"`{verb}` sans cible absolue et sans `cd` dans le bac à "
                           "sable — cible relative, donc dépendante d'un répertoire "
                           "courant inconnu")
        for t in targets:
            if not _write_target_ok(_norm(t)):
                bad.append(f"écriture hors bac à sable dans command: {t}")
        # --- systemctl / service -----------------------------------------
        if verb == "systemctl":
            rest = [o for o in operands if not o.startswith("-")]
            if rest and rest[0] in SYSTEMCTL_DISRUPTIVE:
                for unit in rest[1:]:
                    if not unit.startswith("bridge-test-0909"):
                        bad.append(f"systemctl {rest[0]} hors bac à sable "
                                   f"dans command: {unit}")
                if len(rest) == 1:
                    bad.append(f"systemctl {rest[0]} sans unité nommée — "
                               "portée non bornée")
        if verb == "service":
            rest = [o for o in operands if not o.startswith("-")]
            if len(rest) >= 2 and rest[1] in SERVICE_DISRUPTIVE:
                if not rest[0].startswith("bridge-test-0909"):
                    bad.append(f"service {rest[1]} hors bac à sable "
                               f"dans command: {rest[0]}")
        # --- kill/pkill/killall ------------------------------------------
        if verb in KILL_VERBS:
            bad.append("kill/pkill/killall dans command — utiliser "
                       "ssh_process_kill (liste blanche §3.2), pas une commande brute")
    for t in redir_targets:
        if t.startswith("/"):
            if not _write_target_ok(_norm(t)):
                bad.append(f"redirection hors bac à sable dans command: {t}")
        elif not cwd_sandboxed:
            # `cd /var/log && echo x > syslog` écrase /var/log/syslog sans
            # qu'aucun chemin absolu dangereux n'apparaisse dans la ligne.
            bad.append(f"redirection vers un chemin relatif ({t}) sans `cd` dans le "
                       "bac à sable — cible dépendante d'un répertoire courant inconnu")
    return bad


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


# Fix round 4 (relecture, Minor #11 : « factuellement faux »). Le fix round 1
# (C-3) ne validait que l'ESPÈCE de l'assertion, pas son ARGUMENT : mesuré, un
# fichier dont le troisième cas portait `bytes<=abc` tirait les TROIS cas puis
# mourait sur un `ValueError` levé dans un worker, SANS écrire de rapport —
# C-3 mot pour mot, dans la ronde même qui corrigeait l'autre moitié de C-3.
# Les mêmes conversions que `check()`, faites ici, avant le premier sous-processus.
EXPECT_INT_KINDS = frozenset({"lines", "lines>", "lines<", "exit",
                              "bytes<", "bytes>"})
EXPECT_FLOAT_KINDS = frozenset({"dur<", "dur>"})


def expect_arg_error(e):
    """Message d'erreur si l'ARGUMENT de l'assertion `e` est malformé, sinon
    None. Reproduit exactement les conversions de `check()` — `int(arg)` pour
    les cardinalités et les codes de sortie, `float(arg)` pour les durées,
    `int(n)` après `rpartition(':')` pour `count=`, `int(arg)` optionnel pour
    `trunc=N` — et refuse aussi un argument VIDE là où `check()` en exige un."""
    kind, sep, arg = e.partition("=")
    if kind in EXPECT_INT_KINDS or kind in EXPECT_FLOAT_KINDS:
        conv, label = ((int, "entier") if kind in EXPECT_INT_KINDS
                       else (float, "nombre"))
        if not sep:
            return f"{e!r} : {kind} exige un argument {label} ({kind}=N)"
        try:
            conv(arg)
        except (TypeError, ValueError):
            return f"{e!r} : argument {arg!r} n'est pas un {label}"
        return None
    if kind == "count":
        needle, csep, n = arg.rpartition(":")
        if not sep or not csep or not needle:
            return f"{e!r} : count exige la forme count=AIGUILLE:N"
        try:
            int(n)
        except (TypeError, ValueError):
            return f"{e!r} : cardinalité {n!r} n'est pas un entier"
        return None
    if kind == "trunc" and sep:
        try:
            int(arg)
        except (TypeError, ValueError):
            return f"{e!r} : argument {arg!r} n'est pas un entier (trunc ou trunc=N)"
        return None
    if kind in ("re", "nore"):
        # Un motif VIDE est toujours vrai (`re=` passe quoi qu'il arrive) ou
        # toujours faux (`nore=`) : une assertion qui n'assertit rien.
        if not arg:
            return f"{e!r} : {kind} exige une expression régulière non vide"
        try:
            re.compile(arg)
        except re.error as err:
            return f"{e!r} : expression régulière invalide ({err})"
        return None
    if kind == "saved" and not arg:
        return f"{e!r} : saved exige un chemin"
    # `error=`, `eq=`, `first=`, `stderr=` avec un argument VIDE sont des
    # idiomes LÉGITIMES et massivement employés par le corpus committé :
    # `error=` seul veut dire « rc != 0, peu importe le message » (31 cas dans
    # A-host.json et B-k8s.json), `eq=` « sortie vide », `first=` « première
    # ligne vide ». Les refuser était une sur-détection de ce fix round,
    # attrapée en mesurant le corpus et non en relisant le code.
    return None


def _expect_list(c):
    """Fix round 2 : `guard()` doit rester correct qu'on l'appelle sur des cas
    déjà normalisés par `main()` (où `c["expect"]` est toujours une liste,
    `expectations()` + substitution déjà appliquées) OU directement sur le
    JSON brut d'un fichier de cas — où `expect` est le plus souvent une
    CHAÎNE nue. `for e in c.get("expect", [])` sur une chaîne itère ses
    CARACTÈRES ('o', 'k' pour "ok"...) : c'est exactement ce qui faisait
    refuser les 357 cas du corpus (tous en forme scalaire) avant ce fix.
    Réutilise `expectations()` (chaîne OU liste -> liste), tolérant en plus
    une clé `expect` absente."""
    if "expect" not in c:
        return []
    return expectations(c)


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
        for e in _expect_list(c):
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
        for e in _expect_list(c):
            kind = e.partition("=")[0] if isinstance(e, str) else None
            if kind not in EXPECT_KINDS:
                bad.append(f"{cid}: espèce d'assertion inconnue {e!r} dans expect")
            else:
                why = expect_arg_error(e)
                if why:
                    bad.append(f"{cid}: {why}")
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
        if (any(isinstance(e, str) and e.startswith("saved=") for e in _expect_list(c))
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
        # donc invisible à la boucle par clé ci-dessous.
        # Fix round 4 (relecture, « breakage 2 ») : n'accepter QUE la sentinelle
        # interdisait tout le flux §3.2 que la campagne s'est donné — le
        # `E-patch-pid.sh` commité réécrit `"pid": 0` en PID réel (après avoir
        # lui-même prouvé, contre l'hôte, que ce PID est vivant ET que son argv
        # est exactement celui du `sleep` de la campagne) ; le fichier de lane E
        # devenait donc irrecevable APRÈS patch, et le fichier non patché
        # (`"pid": 0`, le gabarit que le script cherche) l'était AVANT. Et
        # `ssh_perf_trace`, un outil EN LECTURE SEULE qui prend un pid, était
        # refusé sur n'importe quel pid — alors que le contrat 279/279 exige
        # de l'exercer. Trois portes, toutes vérifiables sans état inter-tâches :
        #   - outil `readonly` : lire un pid n'agit sur rien ;
        #   - pid 0 ou 1 : `process.rs:73` les refuse inconditionnellement,
        #     inertes par construction (et 0 est le gabarit d'E-patch-pid.sh) ;
        #   - sentinelle 2147483647, ou un pid réel SI le cas nomme sa garde
        #     d'identité dans le champ `pid_identity` (§3.2 : « le PID rendu par
        #     E505a ET re-confirmé par la garde d'identité E505b dans le MÊME
        #     sous-lot »). Le champ est la trace écrite de cette garde : un pid
        #     réel sans elle reste refusé (c'est ce qui refuse C18/C19).
        pid = c["args"].get("pid")
        if (pid is not None and not isinstance(pid, bool)
                and not inv.get(tool, {}).get("readonly")):
            try:
                pid_i = int(pid)
            except (TypeError, ValueError):
                pid_i = None
            if pid_i is None:
                bad.append(f"{cid}: pid={pid!r} n'est pas un entier")
            elif pid_i in (0, 1, 2147483647):
                pass                               # inerte par construction
            elif not str(c.get("pid_identity", "")).strip():
                bad.append(f"{cid}: pid={pid!r} réel sans champ 'pid_identity' — §3.2 "
                           "exige un PID créé par la campagne ET re-confirmé par la "
                           "garde d'identité E505a/E505b dans le MÊME sous-lot ; "
                           "nomme-la dans `pid_identity`, ou utilise la sentinelle "
                           "2147483647")
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
                for line in scan_command(cmdtext):
                    bad.append(f"{cid}: {line}")
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


def verdict_cell(v, baseline, is_base):
    """(cellule d'affichage, 1 si ce verdict compte dans `unexpected`).

    Fix round 4 (relecture, « breakage 3 » — vert-alors-que-cassé). Depuis
    I-6, `flaky` ne veut plus dire « a fini par passer » : il veut dire « les
    trois verdicts ne concordent pas ». La cellule FLAKY était testée AVANT
    `ok`, donc un cas dont la DERNIÈRE tentative échoue (verdicts
    [True, False, False]) s'affichait FLAKY et sortait de `unexpected` — une
    lane pouvait sortir en 0 en laissant un cas réellement KO. C'est le pire
    défaut possible pour cette campagne : vert alors que cassé. Désormais `ok`
    décide seul du compte et du code de sortie, et `flaky` n'est qu'une
    ÉTIQUETTE (`KO*` = a échoué ET a varié ; la preuve complète est dans
    `attempts`). Cela tranche du même coup le Minor #6 laissé ouvert
    (précédence FLAKY / KO(e) sous `--baseline`) : la précédence est `ok`
    d'abord, toujours. Extrait de `main()` pour être testable — la règle qui
    décide du code de sortie ne doit pas vivre uniquement dans une boucle
    d'affichage qu'aucun test ne peut atteindre."""
    if v is None:
        return "  -  ", 0
    if v["ok"]:
        return ("FLAKY" if v.get("flaky") else " OK  "), 0
    if baseline and not is_base:
        return "KO(e)", 0
    return ("KO*  " if v.get("flaky") else " KO  "), 1


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
            cell, counted = verdict_cell(v, a.baseline,
                                         c.get("owner", "base") == "base")
            cells.append(cell)
            unexpected += counted
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
