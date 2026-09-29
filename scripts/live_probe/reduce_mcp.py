#!/usr/bin/env python3
"""Lane B — bloc BM (12 cas), MCP uniquement, session persistante.

Le cache de sortie (`output_id`) et `ssh_output_fetch` n'existent que dans un
`McpServer` qui vit plus d'un appel — donc hors de portée de `run.py`, qui
lance un `bridge-mcp serve` par cas. Ce script réutilise la classe `Server`
de `mcp_probe.py` : UN SEUL `bridge-mcp serve`, appels séquentiels, `call()`
numérote les ids JSON-RPC. L'ORDRE des 12 cas est significatif : le compteur
`output_id` (`out-0000`, `out-0001`, ...) n'avance que quand un appel alimente
réellement le cache, ce qui est la mesure même de D2 (BM06).

Usage: reduce_mcp.py BIN [--host raspberry]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mcp_probe as mp  # noqa: E402

FAILS = 0
RESULTS = []


def check(cid, cond, evidence):
    global FAILS
    ok = bool(cond)
    if not ok:
        FAILS += 1
    RESULTS.append((cid, ok, evidence))
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {evidence}")
    return ok


def fetch_content(text):
    """Retire l'en-tête `--- output_id=... ---` d'une réponse ssh_output_fetch."""
    _, _, rest = text.partition("\n")
    return rest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--host", default="raspberry")
    a = ap.parse_args()

    MID = "/tmp/bridge-test-0909/lane-b/mid.txt"
    s = mp.Server(a.binary)
    try:
        # BM01 — ssh_file_read max_output=200 : frappe out-0000.
        r = s.tool("ssh_file_read", {"host": a.host, "path": MID, "max_output": 200})
        t = mp.text_of(r)
        check("BM01", "⚠️ MORE DATA AVAILABLE" in t and 'output_id="out-0000"' in t,
              t[:200])

        # BM02 — pagination, offset=0.
        r = s.tool("ssh_output_fetch", {"output_id": "out-0000", "offset": 0, "limit": 100})
        t = mp.text_of(r)
        check("BM02", t.startswith("--- output_id=out-0000 | offset=0 | chars=100/588895 | has_more=true ---"),
              t[:120])

        # BM03 — fin de flux.
        r = s.tool("ssh_output_fetch", {"output_id": "out-0000", "offset": 588800, "limit": 100})
        t = mp.text_of(r)
        check("BM03", "has_more=false" in t.splitlines()[0], t.splitlines()[0])

        # BM04 — intégrité : somme des pages de 100000 caractères == mid.txt.
        expected = "\n".join(str(i) for i in range(1, 100001)) + "\n"
        assembled = []
        off = 0
        has_more = True
        pages = 0
        while has_more and pages < 10:
            r = s.tool("ssh_output_fetch", {"output_id": "out-0000", "offset": off, "limit": 100000})
            t = mp.text_of(r)
            header, _, body = t.partition("\n")
            assembled.append(body)
            has_more = "has_more=true" in header
            off += 100000
            pages += 1
        got = "".join(assembled)
        check("BM04", got == expected, f"len(got)={len(got)} len(expected)={len(expected)} pages={pages}")

        # BM05 — id inconnu.
        r = s.tool("ssh_output_fetch", {"output_id": "out-ffff"})
        t = mp.text_of(r)
        check("BM05", r.get("result", {}).get("isError") is True and "not found" in t, t[:150])

        # BM06 — D2 sur MCP : ssh_service_list ne frappe jamais out-0001.
        r = s.tool("ssh_service_list", {"host": a.host, "state": "running", "max_output": 200})
        t6a = mp.text_of(r)
        no_banner = "MORE DATA AVAILABLE" not in t6a
        r2 = s.tool("ssh_output_fetch", {"output_id": "out-0001"})
        t6b = mp.text_of(r2)
        not_found = r2.get("result", {}).get("isError") is True and "not found" in t6b
        check("BM06", no_banner and not_found,
              f"no_banner={no_banner} bytes={len(t6a.encode())} fetch_out-0001={t6b[:80]!r}")

        # BM07 — filtre jq ⇒ post_process sauté ⇒ cache alimenté (devient out-0001).
        r = s.tool("ssh_k8s_get", {
            "host": a.host, "resource": "pods", "all_namespaces": True, "output": "json",
            "jq_filter": ".items[].metadata.name", "max_output": 200})
        t7 = mp.text_of(r)
        check("BM07", "MORE DATA AVAILABLE" in t7, t7[:200])

        # BM08 — max_output=0 désactive tout.
        r = s.tool("ssh_k3s_status", {"host": a.host, "max_output": 0})
        t8 = mp.text_of(r)
        check("BM08", "MORE DATA AVAILABLE" not in t8 and "output_id=" not in t8, t8[:120])

        # BM09 — structuredContent d'un post_process nominal.
        r = s.tool("ssh_service_list", {"host": a.host, "state": "running"})
        has_sc9 = "structuredContent" in r.get("result", {})
        check("BM09", has_sc9, f"structuredContent present={has_sc9}")

        # BM10 — structuredContent survit-il à jq_was_applied ? (contrat à découvrir)
        r = s.tool("ssh_k8s_get", {
            "host": a.host, "resource": "pods", "all_namespaces": True, "output": "json",
            "jq_filter": ".items[].metadata.name"})
        has_sc10 = "structuredContent" in r.get("result", {})
        check("BM10", True, f"structuredContent present={has_sc10} (owner=discover, consigner tel quel)")

        # BM11 — chemin filtré + fichier absent : isError doit être positionné ; D1 si absent.
        r = s.tool("ssh_file_read", {
            "host": a.host, "path": "/tmp/bridge-test-0909/lane-b/absent.txt", "max_output": 200})
        is_err11 = r.get("result", {}).get("isError")
        t11 = mp.text_of(r)
        check("BM11", is_err11 is not True, f"isError={is_err11!r} text={t11[:150]!r} (D1 si isError non positionné)")

        # BM12 — pas d'état résiduel entre deux appels identiques d'une même session.
        r1 = s.tool("ssh_storage_df", {"host": a.host, "limit": 1})
        r2 = s.tool("ssh_storage_df", {"host": a.host, "limit": 1})
        t12a, t12b = mp.text_of(r1), mp.text_of(r2)
        check("BM12", t12a == t12b, f"identical={t12a == t12b} len={len(t12a)}/{len(t12b)}")
    finally:
        s.close()

    print(f"\nBM: {len(RESULTS)} cas, {FAILS} échec(s)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
