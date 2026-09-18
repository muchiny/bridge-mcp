#!/usr/bin/env python3
"""Test unitaire local de check() — aucune connexion, aucun sous-processus.

Lancer : scripts/live_probe/selftest_check.py
Sortie 0 = toutes les espèces d'assertion se comportent comme documenté.
"""
import importlib.util
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
want("bytes-utf8",  "bytes<=3",    0, "é",       "", None, True)   # 2 octets
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

for f in FAILS:
    print("FAIL " + f)
print(f"\nselftest_check: {len(FAILS)} échec(s)")
sys.exit(min(len(FAILS), 255))
