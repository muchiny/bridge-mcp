#!/usr/bin/env bash
# Lane B — Step 11 : 4 assertions de CONTENU sur les fichiers locaux ecrits
# par save_output. Ce ne sont PAS des cas run.py (aucun tool/args/expect du
# vocabulaire de check() ; coverage.py leverait KeyError sur c["tool"]).
# A executer APRES BO01 (produit ${OUT}/df.txt) et BO07 (produit
# ${OUT}/mid.txt), donc apres le run de BR-core... non, apres BO-saveoutput.
set -uo pipefail
OUT="/home/muchini/bmcp-test-0909/.superpowers/campaign/2026-09-09/out"
fail=0

check() {
  local desc="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $desc (got=$got)"
  else
    echo "FAIL: $desc (got=$got want=$want)"
    fail=1
  fi
}

n=$(grep -c '^Host: raspberry' "$OUT/df.txt" 2>/dev/null || echo 0)
check "df.txt commence par l'enveloppe (Host: raspberry)" "$n" "1"

n=$(grep -c -- '--- STDOUT ---' "$OUT/df.txt" 2>/dev/null || echo 0)
check "df.txt porte le separateur --- STDOUT ---" "$n" "1"

n=$(grep -c 'export LC_ALL=C' "$OUT/df.txt" 2>/dev/null || echo 0)
check "df.txt fuit la commande executee (export LC_ALL=C)" "$n" "1"

n=$(stat -c %a "$OUT/mid.txt" 2>/dev/null || echo "MISSING")
check "mid.txt est en mode 0600" "$n" "600"

echo "save_output_asserts: fail=$fail"
exit "$fail"
