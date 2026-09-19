#!/usr/bin/env python3
"""Test unitaire local de check() et de guard() — aucune connexion, aucun
sous-processus RÉSEAU. La section « régression corpus » plus bas invoque le
binaire LOCAL (`list-tools`, comme `coverage.py` et Step 1 : lecture de la
config locale uniquement) pour obtenir l'inventaire réel — c'est la même
garantie « local, pas de connexion » que le reste de la campagne, pas une
exception à elle.

Lancer : scripts/live_probe/selftest_check.py
Sortie 0 = toutes les espèces d'assertion, et tout ce que `guard()` doit
refuser ou accepter, se comportent comme documenté.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("live_probe_run", HERE / "run.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

# Bannières réelles, recopiées de src/domain/output_truncator.rs:38-104.
CLI_BANNER = ("head\n\n--- [truncated: 200000 lines total, 199990 lines omitted, "
              "1288896 → 998 chars] ---\n\ntail")
MCP_BANNER = ("head\n\n⚠️ MORE DATA AVAILABLE — Truncated: 200000 lines total, "
              "199990 lines omitted (1288896 → 998 chars).\n"
              'To get the complete output, call: ssh_output_fetch(output_id="out-000a", '
              "offset=0, limit=50000)\n\ntail")
ZERO_BANNER = "head\n\n--- [truncated: 3 lines total, 0 lines omitted, 40 → 30 chars] ---\n\ntail"

FAILS = []


def want(label, expect, rc, out, err, ctx, expected):
    got = R.check(expect, rc, out, err, ctx)
    if got is not expected:
        FAILS.append(f"{label}: check({expect!r}) = {got}, attendu {expected}")


tmp = Path(tempfile.mkdtemp(prefix="bmcp-selftest-"))
full = tmp / "full.txt"
full.write_text("x" * 5000)
empty = tmp / "empty.txt"
empty.write_text("")

# --- régressions sur les espèces existantes (elles doivent survivre au ctx) ---
want("ok",        "ok",              0, "hello\n", "", None, True)
want("ok-err",    "ok",              0, "Error: nope", "", None, False)
want("first",     "first=NAME",      0, "NAME\nfoo\n", "", None, True)
want("eq-nl",     "eq=a\\nb",        0, "a\nb\n", "", None, True)
want("lines>=",   "lines>=2",        0, "a\nb\nc\n", "", None, True)
want("count",     "count=pod:2",     0, "pod pod", "", None, True)
want("exit",      "exit=4",          4, "", "refused", None, True)
want("error",     "error=Unknown host", 1, "", "Error: Unknown host", None, True)
want("nore",      "nore=AKIA",       0, "redacted", "", None, True)
want("nore-err",  "nore=AKIA",       0, "ok", "AKIAIOSFODNN7EXAMPLE", None, False)

# --- bytes<= / bytes>= : la mesure qui prouve D2 -----------------------------
want("bytes<=-ok",  "bytes<=400",  0, "x" * 400, "", None, True)
want("bytes<=-ko",  "bytes<=400",  0, "x" * 401, "", None, False)
want("bytes>=-ok",  "bytes>=400",  0, "x" * 400, "", None, True)
# Fix round 1 (review I-1) : sans un cas False, un stub `return True` pour
# `bytes>=` passait toute la suite — "green-only", mesuré par la relecture.
want("bytes>=-ko",  "bytes>=400",  0, "x" * 399, "", None, False)
# et sans un cas où le seuil est ignoré, `bytes>= (arg quelconque)` -> True
# passait aussi (mutant "ignorer l'argument").
want("bytes>=-ko2", "bytes>=1000000", 0, "x" * 10, "", None, False)
want("bytes-utf8",  "bytes<=3",    0, "é",       "", None, True)   # 2 octets
# Fix round 1 (I-1) : `bytes<=3` sur "é" (1 caractère, 2 octets) ne
# discrimine RIEN — <=3 passe qu'on compte des caractères ou des octets.
# `bytes<=1` sépare les deux : 2 octets > 1 (False), 1 caractère <= 1 (True) —
# un mutant qui compterait des caractères au lieu d'octets serait ici attrapé.
want("bytes-utf8-discriminates", "bytes<=1", 0, "é", "", None, False)
want("bytes-rc",    "bytes<=10",   0, "[exit:3]\n", "", None, True)  # rc ignoré (D1)

# --- trunc / notrunc : les deux formes de bannière ---------------------------
want("trunc-cli",   "trunc",       0, CLI_BANNER, "", None, True)
want("trunc-mcp",   "trunc",       0, MCP_BANNER, "", None, True)
want("trunc-min",   "trunc=199990", 0, CLI_BANNER, "", None, True)
want("trunc-min-ko", "trunc=199991", 0, CLI_BANNER, "", None, False)
want("trunc-zero",  "trunc",       0, ZERO_BANNER, "", None, False)  # 0 omise = pas une preuve
want("trunc-none",  "trunc",       0, "sortie entière", "", None, False)
want("notrunc-ok",  "notrunc",     0, "sortie entière", "", None, True)
want("notrunc-ko",  "notrunc",     0, CLI_BANNER, "", None, False)
want("notrunc-err", "notrunc",     0, "ok", MCP_BANNER, None, False)  # bannière côté stderr
# Fix round 1 (I-1) : `trunc` doit lire stdout+stderr — seul `notrunc-err`
# ci-dessus le prouvait ; sans un cas positif équivalent pour `trunc`, un
# mutant qui lirait `out` seul (au lieu de `both`) passait toute la suite.
want("trunc-stderr", "trunc",      0, "head", CLI_BANNER, None, True)  # bannière côté stderr

# --- stderr= : la seule qui distingue les deux flux (D4) ---------------------
want("stderr-ok",   "stderr=Did you mean", 1, "", "Unknown argument. Did you mean 'path'?", None, True)
want("stderr-not-stdout", "stderr=Did you mean", 1, "Did you mean", "", None, False)
want("stderr-serde", "stderr=unknown field", 1, "", "Invalid --json-args: unknown field `pathh`", None, True)

# --- saved= ------------------------------------------------------------------
want("saved-ok",    f"saved={full}",  0, "x" * 100, "", None, True)
want("saved-small", f"saved={full}",  0, "x" * 6000, "", None, False)  # fichier < stdout
want("saved-empty", f"saved={empty}", 0, "", "", None, False)
want("saved-none",  f"saved={tmp}/absent.txt", 0, "x", "", None, False)

# --- dur<= / dur>= : la mesure qui prouve D10 --------------------------------
want("dur<=-ok", "dur<=8",  0, "", "", {"duration": 5.2},  True)
want("dur<=-ko", "dur<=8",  0, "", "", {"duration": 15.7}, False)
want("dur>=-ok", "dur>=1",  0, "", "", {"duration": 15.7}, True)
want("dur-nocx", "dur<=8",  0, "", "", None,               False)  # sans ctx : jamais vrai
# Fix round 1 (I-1) : `dur>=` était "green-only" (aucun cas False dans la
# suite d'origine) — un stub `return True` la traversait. Ajouts : la borne
# manquée (False), le seuil ignoré (False), et le défaut sans ctx (False, pas
# 1e9 — sinon un `dur>=1` sans contexte de durée passerait à tort).
want("dur>=-ko",   "dur>=8",   0, "", "", {"duration": 5.2},  False)
want("dur>=-ko2",  "dur>=100", 0, "", "", {"duration": 15.7}, False)
want("dur>=-nocx", "dur>=1",   0, "", "", None,               False)
# Boundary >= vs > : durée == seuil doit passer avec >=.
want("dur>=-boundary", "dur>=15.7", 0, "", "", {"duration": 15.7}, True)

# --- error= : la clause `rc != 0` (D1), et re= : stdout SEULEMENT (§3.7) -----
# Fix round 4 : le rapport du fix round 1 AFFIRMAIT ces deux tests ; ils
# n'existaient pas, et les deux mutants correspondants survivaient — mesuré
# par la relecture. Les voici, écrits pour de bon.
# `error=` exige rc != 0 : un message d'erreur imprimé avec rc 0 (exactement
# ce que fait D1) ne doit PAS satisfaire `error=`, sinon l'assertion
# confondrait « la commande a échoué » et « le mot Error apparaît ».
want("error-needs-rc",  "error=Unknown host", 0, "", "Error: Unknown host", None, False)
want("error-rc-ok",     "error=Unknown host", 1, "", "Error: Unknown host", None, True)
# `error=` cherche dans stdout+stderr (les deux), contrairement à `re=`.
want("error-in-stdout", "error=Unknown host", 1, "Error: Unknown host", "", None, True)
# `re=` ne voit QUE stdout : un secret qui ne fuit que sur stderr est invisible
# pour `re=` — c'est le piège que §3.7 nomme, et un mutant qui lirait
# stdout+stderr passerait sans ce cas.
want("re-stdout-only",  "re=AKIA[A-Z0-9]+", 0, "rien ici", "AKIAIOSFODNN7EXAMPLE", None, False)
want("re-stdout-hit",   "re=AKIA[A-Z0-9]+", 0, "AKIAIOSFODNN7EXAMPLE", "", None, True)
# `nore=`, lui, voit les deux — la contre-épreuve du couple.
want("nore-sees-stderr", "nore=AKIA[A-Z0-9]+", 0, "rien ici", "AKIAIOSFODNN7EXAMPLE", None, False)

# --- lines<= : la borne haute de cardinalité ---------------------------------
want("lines<=-ok", "lines<=3", 0, "a\nb\n", "", None, True)
want("lines<=-ko", "lines<=3", 0, "a\nb\nc\nd\n", "", None, False)

# --- l'espèce inconnue reste une erreur dure ---------------------------------
try:
    R.check("wat=1", 0, "", "", None)
    FAILS.append("une espèce inconnue n'a pas levé SystemExit")
except SystemExit:
    pass

# --- il n'existe QU'UN vocabulaire : l'ancien doit rester une erreur dure ----
# (fige le fait que la Task 4 ne patche plus check() de son côté)
for dead in ("maxbytes=400", "minbytes=10", "maxlines=5", "outid",
             "file=/tmp/x", "filebytes=/tmp/x:1", "and=ok&&ok", "discover",
             "lines>4"):
    try:
        R.check(dead, 0, "", "", None)
        FAILS.append(f"l'espèce morte {dead!r} n'a pas levé SystemExit")
    except SystemExit:
        pass

# --- kv_pairs : la sérialisation que coerce_value attend ---------------------
got = R.kv_pairs({"path": "/tmp", "recursive": True, "limit": 3, "columns": ["NAME", "STATUS"]})
expected = ['path=/tmp', 'recursive=true', 'limit=3', 'columns=["NAME", "STATUS"]']
if got != expected:
    FAILS.append(f"kv_pairs = {got}, attendu {expected}")

# --- expectations() : chaîne et liste ---------------------------------------
if R.expectations({"expect": "ok"}) != ["ok"] or R.expectations({"expect": ["a", "b"]}) != ["a", "b"]:
    FAILS.append("expectations() ne normalise pas chaîne/liste")

# =============================================================================
# Fix round 1 — preuves both-ways de guard() (C-1, C-2, C-3, R20, I-9, I-11).
# Un garde qui n'a jamais tiré n'est pas un garde : chaque cas ci-dessous
# prouve à la fois qu'une charge dangereuse est refusée ET qu'une charge
# légitime équivalente passe. `guard()` reçoit `expect` déjà normalisé en
# LISTE (c'est ce que fait `main()` avant de l'appeler) — jamais une chaîne
# nue, qu'un `for e in c["expect"]` itérerait caractère par caractère.
# =============================================================================

# Inventaire synthétique minimal — aucune connexion, aucun binaire. `readonly`
# et `destructive` reflètent la réalité mesurée (list-tools --json) pour les
# seuls outils que ces preuves exercent.
INV = {
    "ssh_exec":            {"group": "core",       "reduce": "-", "readonly": False, "destructive": True},
    "ssh_ls":              {"group": "file_ops",    "reduce": "-", "readonly": True,  "destructive": False},
    "ssh_file_write":      {"group": "file_ops",    "reduce": "-", "readonly": False, "destructive": True},
    "ssh_file_patch":      {"group": "file_ops",    "reduce": "-", "readonly": False, "destructive": True},
    "ssh_files_write":     {"group": "file_ops",    "reduce": "-", "readonly": False, "destructive": True},
    "ssh_service_stop":    {"group": "systemd",     "reduce": "-", "readonly": False, "destructive": True},
    "ssh_pkg_install":     {"group": "package",     "reduce": "-", "readonly": False, "destructive": False},
    "ssh_helm_repo_remove": {"group": "kubernetes",  "reduce": "-", "readonly": False, "destructive": True},
    "ssh_process_kill":    {"group": "process",     "reduce": "-", "readonly": False, "destructive": True},
    "ssh_k8s_delete":      {"group": "kubernetes",  "reduce": "-", "readonly": False, "destructive": True},
    "ssh_cron_remove":     {"group": "cron",        "reduce": "-", "readonly": False, "destructive": True},
    "ssh_user_delete":     {"group": "user_management", "reduce": "-", "readonly": False, "destructive": True},
    # readonly ET preneur de `pid` : la combinaison que le contrôle `pid` du
    # fix round 1 refusait, alors que le contrat 279/279 exige de l'exercer.
    "ssh_perf_trace":      {"group": "performance", "reduce": "-", "readonly": True,  "destructive": False},
}


def _bad_of(mod, cases_list, inv):
    """Rend le message de refus de guard(), ou None si guard() ne refuse pas —
    pour COMPARER deux verdicts (fix round 2 : forme scalaire vs liste), pas
    seulement en affirmer un."""
    try:
        mod.guard(cases_list, inv)
        return None
    except SystemExit as e:
        return str(e)


def guard_refuses(label, cases_list, must_contain):
    try:
        R.guard(cases_list, INV)
        FAILS.append(f"{label}: guard() n'a PAS refusé (attendu un message "
                     f"contenant {must_contain!r})")
    except SystemExit as e:
        if must_contain not in str(e):
            FAILS.append(f"{label}: guard() a refusé, mais sans {must_contain!r} "
                         f"— message: {e}")


def guard_passes(label, cases_list):
    try:
        R.guard(cases_list, INV)
    except SystemExit as e:
        FAILS.append(f"{label}: guard() a refusé à tort — {e}")


# --- C-1 : INERT_ECHO ne devait plus être ancré sur le seul préfixe ----------
guard_refuses("guard-C1-chain-and-shutdown",
    [{"id": "H18", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "echo probe && shutdown -h now"}, "expect": ["exit=4"]}],
    "H18:")
guard_refuses("guard-C1-chain-semicolon-rm",
    [{"id": "H17", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "echo go; rm -r -- /etc/motd"}, "expect": ["exit=4"]}],
    "H17:")
guard_refuses("guard-C1-command-substitution",
    [{"id": "H19", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "echo $(cat /etc/shadow)"}, "expect": ["exit=4"]}],
    "H19:")
guard_passes("guard-C1-pure-echo-still-passes",
    [{"id": "G3", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "echo shutdown"}, "expect": ["exit=4"]}])
guard_passes("guard-C1-var-prefix-echo-still-passes",
    [{"id": "G3b", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "PID=1; echo shutdown"}, "expect": ["exit=4"]}])

# --- C-2 : le verbe n'a plus besoin d'être adjacent au chemin ----------------
guard_refuses("guard-C2-rm-r-dashdash",       # la forme même que §3.3 impose pour tout démontage
    [{"id": "H17b", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "rm -r -- /etc/motd"}, "expect": ["ok"]}],
    "H17b:")
guard_refuses("guard-C2-cp-not-first-path",
    [{"id": "H20", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "cp /tmp/bridge-test-0909/x /etc/motd"}, "expect": ["ok"]}],
    "H20:")
guard_refuses("guard-C2-systemctl-stop-k3s",   # aucun chemin absolu dans cette commande
    [{"id": "H-sysctl", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "systemctl stop k3s"}, "expect": ["ok"]}],
    "H-sysctl:")
guard_refuses("guard-C2-kill-family",
    [{"id": "H-kill", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "pkill -f media-plex"}, "expect": ["ok"]}],
    "H-kill:")
guard_passes("guard-C2-sandboxed-mv-still-passes",
    [{"id": "H21", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "mv /tmp/bridge-test-0909/a /tmp/bridge-test-0909/b"},
      "expect": ["ok"]}])
guard_passes("guard-C2-systemctl-stop-sandbox-unit-passes",
    [{"id": "H-sysctl-ok", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "systemctl stop bridge-test-0909.service"}, "expect": ["ok"]}])

# --- C-3 : espèce d'assertion / argstyle inconnus, refusés AVANT exécution ---
guard_refuses("guard-C3-unknown-kind",
    [{"id": "H22", "tool": "ssh_ls", "paths": ["cli"], "args": {"path": "/tmp"},
      "expect": ["maxbytes=400"]}],
    "H22:")
guard_refuses("guard-C3-unknown-argstyle",
    [{"id": "H23", "tool": "ssh_ls", "paths": ["cli"], "argstyle": "json",
      "args": {"path": "/tmp"}, "expect": ["ok"]}],
    "H23:")
guard_passes("guard-C3-known-kind-and-argstyle-pass",
    [{"id": "H24", "tool": "ssh_ls", "paths": ["cli"], "argstyle": "kv",
      "args": {"path": "/tmp"}, "expect": ["ok", "lines>=1"]}])

# --- R20 (ruling du contrôleur) : les dix outils de classe (b), aucune échappatoire
# Fix round 4 (relecture : « la preuve de R20 est vacue »). La version
# précédente tournait contre `INV`, l'inventaire SYNTHÉTIQUE, où aucun des dix
# outils n'existe : la branche `outil inexistant` refusait donc les 30 cas
# MÊME SANS R20, et l'assertion — qui ne cherchait que l'id du cas dans le
# message — était satisfaite dans les deux mondes. Mesuré : vider
# `NEVER_PROBE_LIVE` laissait la suite à `0 échec(s)`. Deux corrections, il
# fallait les DEUX : (a) un inventaire où les dix outils EXISTENT, sinon la
# branche `outil inexistant` couvre tout ; (b) une assertion sur le MOTIF du
# refus (« est de classe (b) »), jamais sur le seul id du cas.
NEVER_PROBE_LIVE_TOOLS = (
    "ssh_k3s_uninstall", "ssh_k3s_killall", "ssh_k3s_upgrade", "ssh_k3s_cert_rotate",
    "ssh_k3s_etcd_snapshot_restore", "ssh_pkg_update", "ssh_pkg_remove",
    "ssh_k8s_drain", "ssh_firewall_deny", "ssh_k8s_localpath_gc",
)
if len(R.NEVER_PROBE_LIVE) != 10:
    FAILS.append(f"R20 : NEVER_PROBE_LIVE porte {len(R.NEVER_PROBE_LIVE)} outils, "
                 "attendu exactement les dix de §3.4(b)")
if set(NEVER_PROBE_LIVE_TOOLS) != set(R.NEVER_PROBE_LIVE):
    FAILS.append("R20 : NEVER_PROBE_LIVE ne coïncide plus avec la liste §3.4(b) "
                 f"— écart {set(NEVER_PROBE_LIVE_TOOLS) ^ set(R.NEVER_PROBE_LIVE)}")
# Inventaire où les dix EXISTENT : sans lui, la preuve ci-dessous ne prouve
# que « guard() refuse un outil inconnu », ce qui est une autre règle.
INV_R20 = dict(INV)
for _t in NEVER_PROBE_LIVE_TOOLS:
    INV_R20[_t] = {"group": "k3s", "reduce": "-", "readonly": False, "destructive": True}


def guard_refuses_in(label, cases_list, inv, must_contain):
    try:
        R.guard(cases_list, inv)
        FAILS.append(f"{label}: guard() n'a PAS refusé (attendu un message "
                     f"contenant {must_contain!r})")
    except SystemExit as e:
        if must_contain not in str(e):
            FAILS.append(f"{label}: guard() a refusé, mais sans {must_contain!r} "
                         f"— message: {e}")


for _t in NEVER_PROBE_LIVE_TOOLS:
    guard_refuses_in(f"guard-R20-{_t}-dry-run",  # --dry-run n'est PAS une échappatoire (§3.10)
        [{"id": f"R20d-{_t}", "tool": _t, "paths": ["cli"], "flags": ["--dry-run"],
          "args": {}, "expect": ["ok"]}], INV_R20,
        f"R20d-{_t}: {_t} est de classe (b)")
    guard_refuses_in(f"guard-R20-{_t}-no-yes",   # ni l'absence de `yes` (via is_inert)
        [{"id": f"R20n-{_t}", "tool": _t, "paths": ["cli"], "args": {}, "expect": ["ok"]}],
        INV_R20, f"R20n-{_t}: {_t} est de classe (b)")
    guard_refuses_in(f"guard-R20-{_t}-guard-probe",  # ni guard_probe
        [{"id": f"R20g-{_t}", "tool": _t, "paths": ["cli"], "guard_probe": True,
          "args": {}, "expect": ["ok"]}], INV_R20,
        f"R20g-{_t}: {_t} est de classe (b)")
    guard_refuses_in(f"guard-R20-{_t}-yes",      # ni --yes
        [{"id": f"R20y-{_t}", "tool": _t, "paths": ["cli"], "yes": True,
          "args": {}, "expect": ["ok"]}], INV_R20,
        f"R20y-{_t}: {_t} est de classe (b)")

# --- I-9 : les valeurs non-chaîne (int, listes, dicts nichés) n'échappaient pas
guard_refuses("guard-I9-pid-real-without-identity",
    [{"id": "H-pid", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 31337}, "expect": ["ok"]}],
    "H-pid: pid=31337 réel sans champ 'pid_identity'")
guard_passes("guard-I9-pid-sentinel-passes",
    [{"id": "H-pid-ok", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 2147483647}, "expect": ["ok"]}])
guard_refuses("guard-I9-nested-path-in-list-of-dicts",
    [{"id": "H-files", "tool": "ssh_files_write", "yes": True, "paths": ["cli"],
      "args": {"files": [{"path": "/etc/motd", "content": "pwned"}]}, "expect": ["ok"]}],
    "H-files:")
guard_refuses("guard-I9-plural-names-key",
    [{"id": "H-names", "tool": "ssh_helm_repo_remove", "yes": True, "paths": ["cli"],
      "args": {"names": ["stable"]}, "expect": ["ok"]}],
    "H-names:")
guard_passes("guard-I9-nested-sandbox-path-passes",
    [{"id": "H-files-ok", "tool": "ssh_files_write", "yes": True, "paths": ["cli"],
      "args": {"files": [{"path": "/tmp/bridge-test-0909/x", "content": "ok"}]},
      "expect": ["ok"]}])

# --- I-11 : saved= sur les deux chemins par défaut, et partagé entre 2 cas --
guard_refuses("guard-I11-saved-default-both-paths",
    [{"id": "H-saved", "tool": "ssh_ls", "args": {"path": "/tmp/bridge-test-0909/x"},
      "expect": ["saved=/tmp/bridge-test-0909/out.txt"]}],
    "H-saved:")
guard_passes("guard-I11-saved-cli-only-passes",
    [{"id": "H-saved-ok", "tool": "ssh_ls", "paths": ["cli"],
      "args": {"path": "/tmp/bridge-test-0909/x"},
      "expect": ["saved=/tmp/bridge-test-0909/out.txt"]}])
guard_refuses("guard-I11-saved-shared-target-two-cases",
    [{"id": "H-shareA", "tool": "ssh_ls", "paths": ["cli"],
      "args": {"path": "/tmp/bridge-test-0909/x"},
      "expect": ["saved=/tmp/bridge-test-0909/shared.txt"]},
     {"id": "H-shareB", "tool": "ssh_ls", "paths": ["cli"],
      "args": {"path": "/tmp/bridge-test-0909/y"},
      "expect": ["saved=/tmp/bridge-test-0909/shared.txt"]}],
    "shared.txt")

# --- régression : le jeu G1-G5 original (safety review) tient toujours -----
guard_refuses("guard-regression-G1-service-name",
    [{"id": "G1", "tool": "ssh_service_stop", "yes": True, "paths": ["cli"],
      "args": {"service": "k3s"}, "expect": ["ok"]}],
    "G1:")
guard_refuses("guard-regression-G1b-etc-motd-redirect",
    [{"id": "G1b", "tool": "ssh_exec", "yes": True, "paths": ["cli"],
      "args": {"command": "echo x > /etc/motd"}, "expect": ["ok"]}],
    "G1b:")
guard_refuses("guard-regression-G4-guard-probe-not-inert",
    [{"id": "G4", "tool": "ssh_exec", "yes": True, "guard_probe": True, "paths": ["cli"],
      "args": {"command": "rm -rf /var/log"}, "expect": ["exit=4"]}],
    "G4:")
guard_refuses("guard-regression-G5-pkg-install-wrong-form",
    [{"id": "G5", "tool": "ssh_pkg_install", "paths": ["cli"],
      "args": {"package": "htop", "sudo": True}, "expect": ["ok"]}],
    "G5:")
guard_passes("guard-regression-G2-sandbox-write-passes",
    [{"id": "G2", "tool": "ssh_file_write", "yes": True, "paths": ["cli"],
      "args": {"path": "/tmp/bridge-test-0909/g2.txt", "content": "x\n"},
      "expect": ["ok"]}])

# =============================================================================
# Fix round 4 — les trous confirmés par le contrôleur, et les sur-détections
# que la correction ne doit PAS créer. Chaque bloc prouve les DEUX sens :
# la charge dangereuse refusée, la charge légitime équivalente acceptée.
# =============================================================================

def _X(cid, cmd, **kw):
    """Un cas `ssh_exec` avec `yes` — donc NON inerte, donc soumis à
    `scan_command()`. Sans `yes`, `is_inert()` court-circuite tout et la
    preuve ne prouverait rien (c'est la divergence exacte qui a fait croire à
    la relecture que `KILL_FAMILY_RE` bloquait les sondes de la lane C)."""
    c = {"id": cid, "tool": "ssh_exec", "yes": True, "paths": ["cli"],
         "args": {"command": cmd}, "expect": ["ok"]}
    c.update(kw)
    return c


# --- R4-a : READ_ONLY_OK exemptait /proc, /sys, /usr, /var/log EN CIBLE -----
# `echo c > /proc/sysrq-trigger` est un redémarrage matériel immédiat du Pi.
for _cid, _cmd in (
        ("W1", "echo c > /proc/sysrq-trigger"),
        ("W2", "echo 1 > /proc/sys/vm/drop_caches"),
        ("W3", "rm -r -- /usr/local/bin/foo"),
        ("W4", "tee /var/log/evil.log"),
        ("W5", 'tee "/var/log/evil.log"'),
        ("W6", "truncate -s 0 /var/log/syslog"),
        ("W7", "find /usr -name foo -delete"),
        ("W8", "cd /var/log && rm -r -- syslog"),
        ("W9", "rm -r -- syslog"),
        ("W10", "echo pwned >& /etc/motd"),          # forme bash exclue par (?!&)
        ("W11", "echo pwned &> /etc/motd"),
        ("W12", "echo pwned >| /etc/motd"),
        ("W13", "echo x > /dev/null/../../etc/motd"),  # exemption /dev/null par préfixe
        ("W14", "echo x > /tmp/bridge-test-0909/../../etc/motd"),
        ("W15", "ls /etc\nrm -r -- /usr/local/bin/foo"),   # 2e ligne invisible
        ("W16", "bash -c 'rm -r -- /etc/motd'"),
        ("W17", "sh -c 'echo x > /proc/sysrq-trigger'"),
        ("W18", "eval rm -r -- /etc/motd"),
        ("W19", "find /etc -name x | xargs rm"),
        ("W20", "cp /tmp/bridge-test-0909/x /etc/motd"),
        ("W21", "rm -r -- '/etc/motd"),               # guillemet non fermé
        # W22-W25 isolent chacun un mécanisme qui, sans eux, est couvert par un
        # autre contrôle : la mutation le laisserait alors survivre (mesuré).
        ("W22", "eval 'rm -r -- /etc/motd'"),         # entre guillemets : SEULE la récursion eval voit le rm
        ("W23", "ls /etc\nsystemctl stop k3s"),       # SEULE la coupure par ligne voit le 2e segment
        ("W24", "cd /var/log && echo x > syslog"),    # SEULE cwd_sandboxed voit la cible relative
        ("W25", "echo x > out.txt"),                  # redirection relative, aucun `cd`
):
    guard_refuses(f"guard-R4-write-{_cid}", [_X(_cid, _cmd)], f"{_cid}:")
for _cid, _cmd in (
        ("P1", "cat /etc/passwd > /tmp/bridge-test-0909/copy.txt"),   # SOURCE hors bac
        ("P2", "head -5 /boot/firmware/config.txt > /tmp/bridge-test-0909/cfg"),
        ("P3", "cp /etc/os-release /tmp/bridge-test-0909/os"),
        ("P4", "ls -l /home/muchini/rm-notes"),       # `\brm\b` matchait « rm-notes »
        ("P5", "cat /home/muchini/cp.txt"),
        ("P6", "stat /home/muchini/dd"),
        ("P7", "awk '$3 > 50 {print}' /home/muchini/x.log"),  # `>` entre guillemets
        ("P8", "cd /tmp/bridge-test-0909 && rm -r -- stale"),
        ("P9", "find /tmp/bridge-test-0909 -name '*.tmp' -exec rm -- {} +"),
        ("P10", "echo x >> /tmp/bridge-test-0909/log"),
        ("P11", "chmod 755 /tmp/bridge-test-0909/x"),
        ("P12", "echo x > /run/systemd/system/bridge-test-0909.service"),
        ("P13", "ls /etc/systemd/system/*.wants/ 2>/dev/null | grep -c bridge-test || true"),
        ("P14", "ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l"),
        ("P15", "journalctl -u k3s > /dev/null 2>&1"),
        ("P16", "ls /etc 2>&1 | head"),
        ("P17", "cd /tmp/bridge-test-0909 && echo x > out.txt"),   # relatif MAIS cwd dans le bac
        ("P18", "cd /tmp/bridge-test-0909 && tee log.txt"),
):
    guard_passes(f"guard-R4-read-{_cid}", [_X(_cid, _cmd)])

# --- R4-b : `systemctl stop` prend une LISTE, et `.search` ne voyait que la
# première occurrence ; `--now disable`, `restart` et `service` échappaient ---
for _cid, _cmd in (
        ("S1", "systemctl stop bridge-test-0909.service k3s"),
        ("S2", "systemctl stop bridge-test-0909.service; systemctl stop k3s"),
        ("S3", "systemctl --now disable k3s"),
        ("S4", "systemctl restart k3s"),
        ("S5", "systemctl mask k3s"),
        ("S6", "service k3s stop"),
        ("S7", "systemctl stop"),                     # portée non bornée
):
    guard_refuses(f"guard-R4-systemctl-{_cid}", [_X(_cid, _cmd)], f"{_cid}:")
for _cid, _cmd in (
        ("SP1", "systemctl stop bridge-test-0909.service"),
        ("SP2", "systemctl stop bridge-test-0909.service bridge-test-0909.timer"),
        ("SP3", "systemctl daemon-reload"),           # ne doit PAS matcher `reload`
        ("SP4", "systemctl status k3s"),
        ("SP5", "systemctl is-active k3s"),
        ("SP6", "systemctl list-units --failed"),
):
    guard_passes(f"guard-R4-systemctl-{_cid}", [_X(_cid, _cmd)])

# --- R4-c : kill-family — en POSITION DE COMMANDE seulement ------------------
for _cid, _cmd in (("K1", "pkill -f media-plex"), ("K2", "sudo kill -9 4242"),
                   ("K3", "killall sshd")):
    kw = {"sudo_reason": "sonde"} if _cid == "K2" else {}
    guard_refuses(f"guard-R4-kill-{_cid}", [_X(_cid, _cmd, **kw)],
                  "kill/pkill/killall dans command")
# ... et les sondes légitimes de la lane C, qui DOIVENT contenir le littéral :
# `k3s-killall` est une entrée de la blacklist vivante, une sonde qui la
# mesure ne peut pas éviter le mot. Un garde qui les refuse n'empêche pas une
# destruction, il empêche de mesurer le garde du produit.
guard_passes("guard-R4-kill-probe-k3s-killall",
    [_X("KP1", "echo k3s-killall guard probe", guard_probe=True)])
guard_passes("guard-R4-kill-probe-quoted-pkill",
    [_X("KP2", "echo 'pkill -9 -f k3s'", guard_probe=True)])
guard_passes("guard-R4-kill-word-in-readonly-diag",
    [_X("KP3", "grep -c kill /var/log/syslog")])
guard_passes("guard-R4-dd-probe-stays-inert",
    [_X("KP4", "echo dd if=/dev/zero of=/dev/null", guard_probe=True)])

# --- R4-d : `pid` — la sentinelle N'EST PLUS la seule valeur admissible ------
# §3.2 autorise un PID réel créé et confirmé dans le MÊME sous-lot ; le
# `E-patch-pid.sh` commité réécrit `"pid": 0` en PID réel. N'accepter que la
# sentinelle rendait ce flux — et le `ssh_perf_trace` READONLY — irrecevables.
guard_refuses("guard-R4-pid-real-without-identity",
    [{"id": "PID1", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 31337}, "expect": ["ok"]}],
    "PID1: pid=31337 réel sans champ 'pid_identity'")
guard_refuses("guard-R4-pid-not-an-integer",
    [{"id": "PID2", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": "abc"}, "expect": ["ok"]}],
    "PID2: pid='abc' n'est pas un entier")
guard_passes("guard-R4-pid-real-with-identity",
    [{"id": "PID3", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "pid_identity": "E505b — ps -p <pid> -o args= == 'sleep 86400'",
      "args": {"pid": 31337}, "expect": ["ok"]}])
guard_passes("guard-R4-pid-zero-is-the-patch-template",
    [{"id": "PID4", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 0}, "expect": ["exit=4"]}])
guard_passes("guard-R4-pid-sentinel-still-passes",
    [{"id": "PID5", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 2147483647}, "expect": ["ok"]}])
guard_passes("guard-R4-pid-on-readonly-tool",
    [{"id": "PID6", "tool": "ssh_perf_trace", "paths": ["cli"],
      "args": {"pid": 31337}, "expect": ["ok"]}])

# --- R4-e : Minor #11 — l'ARGUMENT d'assertion, validé AVANT exécution ------
# Mesuré par la relecture : `bytes<=abc` tirait les TROIS cas du fichier puis
# mourait dans un worker sur un ValueError, SANS rapport écrit — C-3 mot pour
# mot, dans la ronde même qui corrigeait l'autre moitié de C-3.
for _cid, _exp in (("M1", "bytes<=abc"), ("M2", "count=x"), ("M3", "re=(unclosed"),
                   ("M4", "dur<=x"), ("M5", "exit"), ("M6", "lines>=deux"),
                   ("M7", "trunc=beaucoup"), ("M8", "nore="), ("M9", "saved=")):
    guard_refuses(f"guard-R4-expect-arg-{_cid}",
        [{"id": _cid, "tool": "ssh_ls", "paths": ["cli"],
          "args": {"path": "/tmp/bridge-test-0909"}, "expect": [_exp]}],
        f"{_cid}:")
# ... et les formes LÉGITIMES, massivement employées par le corpus committé :
# `error=` nu veut dire « rc != 0, peu importe le message » (31 cas dans
# A-host.json et B-k8s.json), `trunc` nu veut dire « au moins une ligne omise ».
guard_passes("guard-R4-expect-arg-legit",
    [{"id": "MOK", "tool": "ssh_ls", "paths": ["cli"],
      "args": {"path": "/tmp/bridge-test-0909"},
      "expect": ["error=", "eq=", "first=", "stderr=", "trunc", "notrunc",
                 "bytes<=400", "dur<=5", "count=pod:2", "lines>=1", "exit=4",
                 "re=^NAME", "nore=AKIA", "json", "ok"]}])

# --- R4-f : `flaky` n'implique plus `ok` — un cas fini KO DOIT compter -------
# Le défaut le plus grave possible ici : une lane sortant en 0 alors qu'un cas
# a réellement échoué. `verdict_cell` est extrait de `main()` exactement pour
# que cette règle soit testable.
for _label, _v, _base, _isbase, _cell, _cnt in (
        ("ok",             {"ok": True},                     False, True, " OK  ", 0),
        ("flaky-ended-ok", {"ok": True, "flaky": True},       False, True, "FLAKY", 0),
        ("flaky-ended-ko", {"ok": False, "flaky": True},      False, True, "KO*  ", 1),
        ("ko",             {"ok": False},                     False, True, " KO  ", 1),
        ("baseline-expected-ko", {"ok": False},               True, False, "KO(e)", 0),
        ("baseline-flaky-ko",    {"ok": False, "flaky": True}, True, False, "KO(e)", 0),
        ("baseline-base-ko",     {"ok": False},               True, True,  " KO  ", 1),
        ("absent",         None,                              False, True, "  -  ", 0),
):
    _got = R.verdict_cell(_v, _base, _isbase)
    if _got != (_cell, _cnt):
        FAILS.append(f"verdict_cell {_label}: {_got} au lieu de {(_cell, _cnt)} — "
                     "un cas fini KO doit compter dans `unexpected` quel que soit "
                     "son étiquetage FLAKY")

# =============================================================================
# Fix round 5 (ruling R22) — les HUIT charges de sonde que global-constraints
# §3.3 impose doivent toutes passer `guard()`. C'est le test d'acceptation
# réel de la lane C : une sonde de blacklist DOIT contenir le motif qu'elle
# mesure, sinon elle ne mesure rien ; un garde qui la refuse n'empêche aucune
# destruction, il empêche de mesurer le garde du produit.
# =============================================================================

# (motif de la blacklist vivante, charge utile §3.3). Chaque charge est
# vérifiée DEUX fois : elle doit passer `guard()`, ET elle doit réellement
# matcher son motif — sans quoi « corriger » une sonde en lui retirant le
# motif la ferait passer tout en la rendant inutile.
GUARD_PROBE_PAYLOADS = (
    (r"rm\s+-rf",
     "rm -rf /tmp/bridge-test-0909/nonexistent-guard-probe"),
    (r"cat\s+/etc/shadow",
     "cat /etc/shadow-nonexistent-guard-probe"),
    (r"\b(shutdown|reboot|halt|poweroff)\b",
     "echo shutdown guard probe"),
    (r"\binit\s+[06]\b",
     "echo init 0 guard probe"),
    (r"\bmkfs(\.|\s)",
     "echo mkfs.ext4 guard probe"),
    (r"\bdd\b.*\bof=/dev/",
     "echo dd if=/dev/zero of=/dev/null"),
    # R22 : forme QUOTÉE. Le `>` est à l'intérieur d'un jeton, le shell ne le
    # lit jamais comme un opérateur et ne redirige rien — mais la blacklist du
    # produit, elle, matche sur le texte brut, donc la sonde mord quand même.
    (r">\s*/dev/(sd|mmcblk|nvme)",
     'echo "probe > /dev/sdz9999"'),
    (r"k3s-uninstall|k3s-killall",
     "echo k3s-uninstall.sh guard probe"),
)
if len(GUARD_PROBE_PAYLOADS) != 8:
    FAILS.append("§3.3 tabule HUIT charges de sonde ; la liste en porte "
                 f"{len(GUARD_PROBE_PAYLOADS)}")
for _i, (_pat, _payload) in enumerate(GUARD_PROBE_PAYLOADS):
    if not re.search(_pat, _payload):
        FAILS.append(f"sonde §3.3 #{_i}: la charge {_payload!r} ne matche PLUS son "
                     f"motif de blacklist {_pat!r} — elle ne mesure donc rien ; "
                     "une sonde ne se « corrige » pas en lui retirant le motif")
    guard_passes(f"guard-R22-probe-{_i}-{_pat[:18]}",
        [{"id": f"GP{_i}", "tool": "ssh_exec", "yes": True, "guard_probe": True,
          "paths": ["cli"], "args": {"command": _payload}, "expect": ["exit=4"]}])

# --- R22, l'autre sens : ce que l'exemption ne doit PAS admettre ------------
# Une exemption par SUFFIXE sur une cible d'écriture créerait un vrai fichier
# dans /etc ; c'est refusé par `scan_command()`, pas par l'inertie.
for _cid, _cmd in (
        ("Q1", 'echo "x" > /etc/motd'),      # argument quoté MAIS redirection réelle
        ("Q2", "echo probe > /dev/sdz9999"),  # forme NON quotée : `>` est un opérateur
        ("Q3", "echo x > /etc/motd-nonexistent-guard-probe"),
        ("Q4", "rm -rf /etc/motd-nonexistent-guard-probe"),
        ("Q5", "echo x >> /etc/motd"),
        ("Q6", "echo x >& /etc/motd"),
        ("Q7", "echo x | tee /etc/motd"),
        ("Q8", "echo x; rm -r -- /etc/motd"),
        ("Q9", "rm -rf /etc/motd"),
        ("Q10", "sudo rm -rf /etc/x"),
        ("Q11", "bash -c 'rm -rf /etc/motd'"),
        ("Q12", "cat /etc/shadow"),           # §3.3 : aucune sonde ne nomme un vrai fichier d'/etc
        ("Q13", "echo 'unbalanced"),          # guillemet non fermé : refus, pas devinette
        ("Q14", "echo x > out.txt"),          # cible relative, cwd inconnu
):
    guard_refuses(f"guard-R22-not-inert-{_cid}",
        [{"id": _cid, "tool": "ssh_exec", "yes": True, "guard_probe": True,
          "paths": ["cli"], "args": {"command": _cmd}, "expect": ["exit=4"]}],
        f"{_cid}:")
# Les mêmes, SANS `yes`. Un cas destructif sans `yes` est `inert` : `guard()`
# fait `continue` AVANT `scan_command()` et avant la boucle COMMAND_DENY, donc
# `is_inert_probe()` est alors le SEUL décideur. Sans ces variantes, les
# contrôles de redirection de `_segment_is_inert` sont masqués par
# `scan_command()` et leur mutation survit — mesuré.
for _cid, _cmd in (
        ("QN1", 'echo "x" > /etc/motd'),
        ("QN2", "echo probe > /dev/sdz9999"),
        ("QN3", "echo x > /etc/motd-nonexistent-guard-probe"),
        ("QN4", "echo x >> /etc/motd"),
        ("QN5", "echo x >& /etc/motd"),
        ("QN6", "echo 'unbalanced"),
        ("QN7", "echo x > out.txt"),
        ("QN8", "echo x; rm -r -- /etc/motd"),
):
    guard_refuses(f"guard-R22-not-inert-noyes-{_cid}",
        [{"id": _cid, "tool": "ssh_exec", "guard_probe": True, "paths": ["cli"],
          "args": {"command": _cmd}, "expect": ["exit=4"]}],
        f"{_cid}: guard_probe déclaré mais la charge n'est pas inerte")
# Et les huit charges §3.3 doivent passer dans les DEUX formes — la lane C peut
# écrire une sonde avec ou sans `yes` selon la porte qu'elle mesure.
for _i, (_pat, _payload) in enumerate(GUARD_PROBE_PAYLOADS):
    guard_passes(f"guard-R22-probe-noyes-{_i}",
        [{"id": f"GN{_i}", "tool": "ssh_exec", "guard_probe": True, "paths": ["cli"],
          "args": {"command": _payload}, "expect": ["exit=4"]}])

# ... et les formes inertes que la tokenisation doit continuer d'accepter :
for _cid, _cmd in (
        ("QP1", "PID=1; echo shutdown"),      # segment d'affectation seule
        ("QP2", "echo a && echo b"),
        ("QP3", "echo -e 'a\\tb'"),
        ("QP4", "echo x 2>/dev/null"),        # redirection vers /dev/null
        ("QP5", 'echo "rm -rf /"'),           # charge entièrement quotée
        ("QP6", "echo x > /tmp/bridge-test-0909/probe.txt"),
):
    guard_passes(f"guard-R22-inert-{_cid}",
        [{"id": _cid, "tool": "ssh_exec", "yes": True, "guard_probe": True,
          "paths": ["cli"], "args": {"command": _cmd}, "expect": ["exit=4"]}])

# =============================================================================
# Fix round 6 (ruling R23) — le verdict du garde ne doit PAS dépendre de `yes`.
# Mesuré au round 5 : les cinq charges dangereuses ne refusaient qu'avec
# `yes: true`, parce que les contrôles de `command` vivaient derrière le
# court-circuit `inert`. Le raisonnement (« sans --yes la porte destructive du
# produit refuse, exit 4 ») est exact mais inapplicable ICI : §3.3 exige que
# toute sonde soit inoffensive *si le garde tombe*, et la lane C existe pour
# chercher les trous de cette porte-là (D1, D5). Le garde du harnais ne peut
# pas faire reposer la sûreté du Pi sur le mécanisme que la campagne teste.
# Cette matrice est l'assertion permanente : aucune évolution future ne peut
# réintroduire un garde dépendant de `yes`.
# =============================================================================

R23_SHAPES = (
    ("yes=F/gp=F", {}),
    ("yes=T/gp=F", {"yes": True}),
    ("yes=T/gp=T", {"yes": True, "guard_probe": True}),
    # `--dry-run` rend aussi le cas `inert` : même court-circuit, même risque.
    ("dry-run",    {"flags": ["--dry-run"], "paths": ["cli"]}),
)


def _shape_case(cid, cmd, extra):
    c = {"id": cid, "tool": "ssh_exec", "paths": ["cli"],
         "args": {"command": cmd}, "expect": ["ok"]}
    c.update(extra)
    return c


# Doivent refuser dans les QUATRE formes. Les cinq premières sont les charges
# que le contrôleur a mesurées comme ne refusant qu'avec `yes`. `shutdown -h now`
# est le cas qui a obligé à remonter AUSSI `COMMAND_DENY` : il ne porte aucun
# chemin, aucun verbe d'écriture, aucun systemctl, aucun kill — `scan_command`
# ne le voit pas, seule la blacklist par nom l'attrape.
for _cid, _cmd in (
        ("R23a", "echo c > /proc/sysrq-trigger"),
        ("R23b", "rm -r -- /usr/local/bin/foo"),
        ("R23c", "tee /var/log/evil.log"),
        ("R23d", "echo pwned >& /etc/motd"),
        ("R23e", "systemctl stop bridge-test-0909.service k3s"),
        ("R23f", "shutdown -h now"),
        ("R23g", "rm -rf /etc/motd"),
        ("R23h", "pkill -f media-plex"),
        ("R23i", "find /usr -name foo -delete"),
        ("R23j", "bash -c 'rm -r -- /etc/motd'"),
):
    for _shape, _extra in R23_SHAPES:
        guard_refuses(f"guard-R23-{_cid}-{_shape}",
                      [_shape_case(_cid, _cmd, _extra)], f"{_cid}:")

# Doivent passer dans toutes les formes SAUF `gp=T` — `guard_probe` impose en
# plus l'inertie §3.3, qui est une contrainte d'écriture de sonde, pas de
# sûreté (cf. la section « item parké » du rapport).
for _cid, _cmd in (
        ("R23p", "cat /etc/passwd > /tmp/bridge-test-0909/copy.txt"),
        ("R23q", "mv /tmp/bridge-test-0909/a /tmp/bridge-test-0909/b"),
        ("R23r", "systemctl stop bridge-test-0909.service"),
        # les quatre commandes RÉELLES d'E9-teardown-proof.json
        ("R23s", "ls /etc/systemd/system/*.wants/ 2>/dev/null | grep -c bridge-test || true"),
        ("R23t", "findmnt -n /tmp/bridge-test-0909/mnt || echo unmounted"),
        ("R23u", "ls /tmp/snapshot_bridge-test-0909_*.tar.gz 2>/dev/null | wc -l"),
):
    for _shape, _extra in R23_SHAPES:
        if _shape == "yes=T/gp=T":
            continue
        guard_passes(f"guard-R23-{_cid}-{_shape}", [_shape_case(_cid, _cmd, _extra)])

# =============================================================================
# Fix round 7 (ruling R24) — R23 étendu aux ARGUMENTS. Un outil
# `destructiveHint` visant un chemin ou un objet hors bac à sable doit être
# refusé MÊME SANS `yes` : sinon la sûreté du Pi repose encore sur la porte
# destructive du produit, celle-là même dont la lane C cherche les trous.
# Le court-circuit `readonly` reste, lui : lire n'agit sur rien.
# =============================================================================

# `guard_probe` est exclu de cette matrice : sur un outil sans clé `command`,
# `is_inert_probe()` est faux par construction et le cas est refusé pour CETTE
# raison-là — l'assertion ne prouverait alors pas ce qu'elle prétend (c'est le
# piège de la preuve vacue de R20). Restent les trois formes utiles.
R24_SHAPES = tuple((n, e) for n, e in R23_SHAPES if "guard_probe" not in e)

# (id, outil, args hors bac à sable, fragment de message ATTENDU). Le fragment
# est ce qui rend la preuve non vacue : le refus doit venir de PATH_KEYS /
# NAME_KEYS, pas d'une autre règle qui passerait par là.
for _cid, _tool, _args, _why in (
        ("R24a", "ssh_file_write",      {"path": "/etc/motd", "content": "x"},
         "path='/etc/motd' hors du bac à sable"),
        ("R24b", "ssh_file_patch",      {"path": "/etc/hosts", "content": "x"},
         "path='/etc/hosts' hors du bac à sable"),
        ("R24c", "ssh_service_stop",    {"service": "k3s"},
         "service='k3s' n'est pas un objet créé par la campagne"),
        ("R24d", "ssh_user_delete",     {"username": "root"},
         "username='root' n'est pas un objet créé par la campagne"),
        ("R24e", "ssh_cron_remove",     {"pattern": ".*"},
         "pattern='.*' n'est pas un objet créé par la campagne"),
        ("R24f", "ssh_k8s_delete",      {"namespace": "kube-system", "name": "coredns",
                                         "resource": "deployment"},
         "namespace='kube-system' n'est pas un objet créé par la campagne"),
        ("R24g", "ssh_helm_repo_remove", {"names": ["stable"]},
         "names='stable' n'est pas un objet créé par la campagne"),
        ("R24h", "ssh_files_write",     {"files": [{"path": "/etc/motd", "content": "x"}]},
         "path='/etc/motd' hors du bac à sable"),
):
    if _tool not in INV:
        FAILS.append(f"guard-R24-{_cid}: {_tool} absent de l'inventaire synthétique "
                     "— la preuve serait couverte par la branche « outil inexistant » "
                     "et ne prouverait rien (cf. R20)")
        continue
    if not INV[_tool]["destructive"] or INV[_tool]["readonly"]:
        FAILS.append(f"guard-R24-{_cid}: {_tool} n'est plus destructif/non-readonly "
                     "dans l'inventaire synthétique — la matrice ne teste plus R24")
        continue
    for _shape, _extra in R24_SHAPES:
        _c = {"id": _cid, "tool": _tool, "paths": ["cli"], "args": dict(_args),
              "expect": ["ok"]}
        _c.update(_extra)
        guard_refuses(f"guard-R24-{_cid}-{_shape}", [_c], f"{_cid}: {_why}")
# ... et l'équivalent confiné au bac à sable doit passer dans les trois formes.
for _cid, _tool, _args in (
        ("R24p", "ssh_file_write",   {"path": "/tmp/bridge-test-0909/x", "content": "x"}),
        ("R24q", "ssh_service_stop", {"service": "bridge-test-0909-nonexistent.service"}),
        ("R24r", "ssh_user_delete",  {"username": "btest0909"}),
        ("R24s", "ssh_cron_remove",  {"pattern": "BRIDGE_TEST_0909"}),
        ("R24t", "ssh_k8s_delete",   {"namespace": "bridge-test", "name": "bridge-test-pod",
                                      "resource": "pod"}),
        ("R24u", "ssh_files_write",  {"files": [{"path": "/tmp/bridge-test-0909/y",
                                                 "content": "x"}]}),
):
    for _shape, _extra in R24_SHAPES:
        _c = {"id": _cid, "tool": _tool, "paths": ["cli"], "args": dict(_args),
              "expect": ["ok"]}
        _c.update(_extra)
        guard_passes(f"guard-R24-{_cid}-{_shape}", [_c])
# Un outil READONLY n'est pas concerné : lire /etc n'agit sur rien, et remonter
# le court-circuit `readonly` refuserait la majorité des cas des lanes A et B.
for _shape, _extra in R24_SHAPES:
    _c = {"id": "R24ro", "tool": "ssh_ls", "paths": ["cli"],
          "args": {"path": "/etc"}, "expect": ["ok"]}
    _c.update(_extra)
    guard_passes(f"guard-R24-readonly-{_shape}", [_c])

# =============================================================================
# Fix round 2 — le bug qui aurait dû rendre TOUT le round 1 inutile : la
# validation d'espèce/argstyle du C-3 itérait `c.get("expect", [])` sans
# passer par `expectations()`. Sur un `expect` SCALAIRE (la forme des 357
# cas du corpus — "ok" n'est pas une liste), `for e in "ok"` itère les
# CARACTÈRES 'o' et 'k', pas la chaîne entière : `guard()` refusait alors
# TOUT fichier de cas existant, y compris les cinq fichiers baseline
# 2026-09-06 et les preuves déjà relues de la Task 1bis. Rule 1 appliquée à
# la lettre : le vieux bug ne se voyait qu'en GREEN (`selftest_check: 0
# échec(s)`) parce que rien ne testait jamais `guard()` sur du JSON de cas
# BRUT — seulement sur des dicts déjà construits à la main avec `expect` en
# liste. Les preuves ci-dessous testent `guard()` sur le contenu RÉEL des
# fichiers de cas, chargé depuis le disque, exactement comme un futur appel
# de `guard()` en dehors de `main()` le ferait.
# =============================================================================

# --- équivalence scalaire / liste-à-un-élément, à la fois pour guard() et pour
# le sens que `check()` (via `expectations()`) leur donne -------------------
_scalar_case = {"id": "SCALAR", "tool": "ssh_ls", "paths": ["cli"],
                "args": {"path": "/tmp/bridge-test-0909/x"}, "expect": "ok"}
_list_case = {"id": "LIST", "tool": "ssh_ls", "paths": ["cli"],
              "args": {"path": "/tmp/bridge-test-0909/x"}, "expect": ["ok"]}
if R.expectations(_scalar_case) != R.expectations(_list_case):
    FAILS.append("expectations() ne rend pas la même liste pour un expect "
                 "scalaire et son équivalent à un élément")
_scalar_verdict = _bad_of(R, [_scalar_case], INV)
_list_verdict = _bad_of(R, [_list_case], INV)
if _scalar_verdict != _list_verdict:
    FAILS.append(f"guard() diverge entre expect scalaire ({_scalar_verdict!r}) "
                 f"et liste équivalente ({_list_verdict!r})")
# Un expect scalaire MULTI-CARACTÈRES qui ressemblerait à une espèce connue
# lettre par lettre serait le pire cas — "ok" contient 'o' et 'k', ni l'un ni
# l'autre une espèce valide, donc l'ancien bug aurait aussi dû se voir ici.
guard_passes("guard-fix2-scalar-expect-passes", [_scalar_case])
guard_passes("guard-fix2-list-expect-passes", [_list_case])

# --- régression corpus : le contenu RÉEL des fichiers commités, avec le
# VRAI inventaire (nécessite le binaire local — voir docstring du module) --
_BIN = os.environ.get("BMCP_SELFTEST_BIN", str(HERE.parents[1] / "target" / "release" / "bridge-mcp"))
if not Path(_BIN).is_file():
    FAILS.append(f"régression corpus : binaire introuvable à {_BIN!r} — "
                 "impossible de charger l'inventaire réel, ce fichier ne "
                 "prouve alors RIEN sur guard() vis-à-vis du corpus (le "
                 "définir via BMCP_SELFTEST_BIN si le worktree diffère)")
else:
    _inv = R._coverage().inventory(_BIN)

    def _corpus_cases(relpath):
        return json.loads((HERE / relpath).read_text())["cases"]

    # Ces quatre fichiers sont des cas RÉELLEMENT en jeu dans la campagne
    # 2026-09-09 (les trois premiers sont la baseline 2026-09-06 la plus
    # ancienne et la plus simple, la moins susceptible d'avoir jamais visé
    # les conventions nées avec CETTE campagne ; E9 est du Task 1bis déjà
    # relu). Ils DOIVENT passer `guard()` intégralement, sans modification —
    # si l'un d'eux échoue, c'est `guard()` qui a régressé, jamais le fichier.
    for _rel in ("campaign/A-host.json", "campaign/A2-host-heavy.json",
                 "campaign/B-k8s.json", "campaign/2026-09-09/E9-teardown-proof.json"):
        try:
            R.guard(_corpus_cases(_rel), _inv)
        except SystemExit as e:
            FAILS.append(f"régression corpus : guard() refuse {_rel} (devrait "
                         f"passer intégralement) — {e}")

    # Ruling R21 (fix round 3) : C-security.json et D-sandbox.json sont DEUX
    # des cinq fichiers baseline 2026-09-06 — gelés par global constraints
    # §3.0bis ("servent uniquement de baseline"), consommés STATIQUEMENT par
    # `coverage.py` (simple appariement de noms d'outil) et JAMAIS exécutés
    # par `run.py` dans cette campagne. `guard()` ne doit donc JAMAIS les
    # accepter : les admettre voudrait dire admettre `ssh_k8s_drain` et
    # `ssh_pkg_remove`, que R20 interdit sans exception. Leur refus n'est pas
    # un bug à corriger ni le bug scalaire (déjà réglé plus haut) — c'est le
    # garde-fou qui applique fidèlement, à la lettre, des règles nées APRÈS
    # l'écriture de ces deux fichiers. Le test ci-dessous n'exige donc PAS
    # qu'ils passent : il exige (a) qu'ils soient refusés et (b) que CHAQUE
    # ligne de refus relève d'une des six CLASSES ci-dessous — jamais un
    # compte exact de lignes, pour survivre à une reformulation du message
    # tout en continuant à échouer si le garde-fou était un jour relâché pour
    # les admettre.
    REFUSAL_CLASSES = {
        "R20 : outil de classe (b) (ssh_k8s_drain / ssh_pkg_remove)": "est de classe (b)",
        "orthographe morte du bac à sable (/tmp/bridge-campaign)": "bac à sable",
        "namespace/nom non créé par CETTE campagne (default/argocd, 2026-09-06)":
            "n'est pas un objet créé par la campagne",
        "sudo sans sudo_reason (champ né avec cette campagne)":
            "sudo=true sans champ 'sudo_reason'",
        "pid réel sans la garde d'identité §3.2": "réel sans champ 'pid_identity'",
        "sonde de blacklist sans guard_probe (champ né avec cette tâche)":
            "touche un motif interdit",
        "redirection hors bac à sable (sonde 2026-09-06 vers /dev/mmcblk…)":
            "redirection hors bac à sable",
    }
    # Fix round 4 (relecture : « la preuve R21 n'a pas de dents non plus »).
    # L'appartenance à une classe ne pinne RIEN de quantitatif : mesuré,
    # élargir `SANDBOX_PATH_RE` à l'orthographe morte faisait tomber
    # D-sandbox.json de 38 lignes à 11 et la suite restait verte. On fige donc
    # l'ENSEMBLE EXACT des ids refusés de chaque fichier (insensible à une
    # reformulation de message, mais pas à un relâchement du garde), et on
    # exige explicitement qu'au moins une ligne de C-security porte le motif
    # R20 — la propriété que R21 nomme, et que rien ne pinnait.
    REFUSED_IDS = {
        # Fix round 7 (ruling R24) : l'ensemble passe de 14 à 38 ids, 17 à 47
        # lignes. Le delta est les 24 cas destructifs SANS `yes` portant une
        # clé de chemin/nom hors bac à sable (C12-C17, C20-C31, C34-C37,
        # C42-C43) — ils ne refusaient jusqu'ici que parce que `is_inert()`
        # court-circuitait le contrôle avant de l'atteindre. C'est un
        # RENFORCEMENT attendu, pas une régression : R21 garde de toute façon
        # ce fichier refusé en bloc, et il n'est jamais exécuté.
        "campaign/C-security.json": {
            "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19",
            "C20", "C21", "C22", "C23", "C24", "C25", "C26", "C27",
            "C28", "C29", "C30", "C31", "C32", "C33", "C34", "C35",
            "C36", "C37", "C42", "C43", "C44", "C45", "C52", "C53",
            "C54", "C55", "C56", "C58", "C59", "C72"},
        "campaign/D-sandbox.json": {
            "D01", "D02", "D04", "D06", "D07", "D09", "D10", "D12", "D15",
            "D17", "D18", "D19", "D20", "D22", "D23", "D26", "D27", "D29",
            "D32", "D33", "D34", "D35", "D36", "D37", "D38", "D39", "D40",
            "D90"},
    }
    REQUIRED_TAGS = {
        # R21 en toutes lettres : C-security est refusé PARCE QUE R20 interdit
        # ssh_k8s_drain et ssh_pkg_remove — pas seulement « pour une raison ».
        "campaign/C-security.json": ("ssh_k8s_drain est de classe (b)",
                                     "ssh_pkg_remove est de classe (b)"),
        "campaign/D-sandbox.json": ("hors du bac à sable",),
    }
    for _rel in ("campaign/C-security.json", "campaign/D-sandbox.json"):
        try:
            R.guard(_corpus_cases(_rel), _inv)
            FAILS.append(f"régression corpus : {_rel} passe désormais guard() — "
                         "R21 : ceci n'est PAS voulu (admettre ce fichier admet "
                         "ssh_k8s_drain/ssh_pkg_remove, que R20 interdit) ; ne "
                         "PAS relâcher le garde-fou pour ce résultat")
        except SystemExit as e:
            reasons = str(e).splitlines()[1:]
            if not reasons:
                FAILS.append(f"régression corpus : {_rel} refusé sans aucune "
                             "ligne de raison — message vide ?")
            unclassed = [ln for ln in reasons
                        if not any(tag in ln for tag in REFUSAL_CLASSES.values())]
            if unclassed:
                FAILS.append(f"régression corpus : {_rel} refusé pour une "
                             f"raison HORS des classes attendues (R21) — "
                             f"nouvelle règle, ou vraie régression ? {unclassed}")
            got_ids = {ln.strip().split(":")[0] for ln in reasons}
            if got_ids != REFUSED_IDS[_rel]:
                FAILS.append(
                    f"régression corpus (R21) : {_rel} ne refuse plus exactement "
                    f"les mêmes cas — en moins {sorted(REFUSED_IDS[_rel] - got_ids)}, "
                    f"en plus {sorted(got_ids - REFUSED_IDS[_rel])}. Un cas qui CESSE "
                    "d'être refusé veut dire que le garde-fou a été relâché ; ne pas "
                    "réaligner cette liste sans une décision écrite du contrôleur")
            for tag in REQUIRED_TAGS[_rel]:
                if not any(tag in ln for ln in reasons):
                    FAILS.append(f"régression corpus (R21) : {_rel} est refusé, mais "
                                 f"AUCUNE ligne ne porte {tag!r} — le refus ne tient "
                                 "donc plus à la règle que R21 nomme")

for f in FAILS:
    print("FAIL " + f)
print(f"\nselftest_check: {len(FAILS)} échec(s)")
sys.exit(min(len(FAILS), 255))
