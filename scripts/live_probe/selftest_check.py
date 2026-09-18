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
    "ssh_files_write":     {"group": "file_ops",    "reduce": "-", "readonly": False, "destructive": True},
    "ssh_service_stop":    {"group": "systemd",     "reduce": "-", "readonly": False, "destructive": True},
    "ssh_pkg_install":     {"group": "package",     "reduce": "-", "readonly": False, "destructive": False},
    "ssh_helm_repo_remove": {"group": "kubernetes",  "reduce": "-", "readonly": False, "destructive": True},
    "ssh_process_kill":    {"group": "process",     "reduce": "-", "readonly": False, "destructive": True},
    "ssh_k8s_delete":      {"group": "kubernetes",  "reduce": "-", "readonly": False, "destructive": True},
    "ssh_cron_remove":     {"group": "cron",        "reduce": "-", "readonly": False, "destructive": True},
    "ssh_user_delete":     {"group": "user_management", "reduce": "-", "readonly": False, "destructive": True},
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
NEVER_PROBE_LIVE_TOOLS = (
    "ssh_k3s_uninstall", "ssh_k3s_killall", "ssh_k3s_upgrade", "ssh_k3s_cert_rotate",
    "ssh_k3s_etcd_snapshot_restore", "ssh_pkg_update", "ssh_pkg_remove",
    "ssh_k8s_drain", "ssh_firewall_deny", "ssh_k8s_localpath_gc",
)
for _t in NEVER_PROBE_LIVE_TOOLS:
    guard_refuses(f"guard-R20-{_t}-dry-run",     # --dry-run n'est PAS une échappatoire (§3.10)
        [{"id": f"R20d-{_t}", "tool": _t, "paths": ["cli"], "flags": ["--dry-run"],
          "args": {}, "expect": ["ok"]}],
        f"R20d-{_t}:")
    guard_refuses(f"guard-R20-{_t}-no-yes",      # ni l'absence de `yes` (via is_inert)
        [{"id": f"R20n-{_t}", "tool": _t, "paths": ["cli"], "args": {}, "expect": ["ok"]}],
        f"R20n-{_t}:")
    guard_refuses(f"guard-R20-{_t}-guard-probe", # ni guard_probe
        [{"id": f"R20g-{_t}", "tool": _t, "paths": ["cli"], "guard_probe": True,
          "args": {}, "expect": ["ok"]}],
        f"R20g-{_t}:")

# --- I-9 : les valeurs non-chaîne (int, listes, dicts nichés) n'échappaient pas
guard_refuses("guard-I9-pid-not-sentinel",
    [{"id": "H-pid", "tool": "ssh_process_kill", "yes": True, "paths": ["cli"],
      "args": {"pid": 1}, "expect": ["ok"]}],
    "H-pid:")
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
        "pid réel au lieu de la sentinelle 2147483647": "seule la sentinelle 2147483647",
        "sonde de blacklist sans guard_probe (champ né avec cette tâche)":
            "touche un motif interdit",
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
                             f"raison HORS des six classes attendues (R21) — "
                             f"nouvelle règle, ou vraie régression ? {unclassed}")

for f in FAILS:
    print("FAIL " + f)
print(f"\nselftest_check: {len(FAILS)} échec(s)")
sys.exit(min(len(FAILS), 255))
