#!/usr/bin/env python3
"""Sync discovery-manifest versions to the crate version in Cargo.toml.

Reads `version` from the [package] table of Cargo.toml and rewrites the
`version` field (and server.json packages[].version) in every shippable
manifest, preserving JSON structure and 2-space indentation. Idempotent:
running twice produces no diff. CI runs `make sync-server-json` then
`git diff --exit-code` to fail on drift.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def crate_version() -> str:
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    in_package = False
    for line in cargo.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if in_package:
            m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    sys.exit("could not find [package] version in Cargo.toml")


def sync_json(rel: str, version: str, *, sync_packages: bool) -> None:
    path = ROOT / rel
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    if sync_packages and isinstance(data.get("packages"), list):
        for pkg in data["packages"]:
            if isinstance(pkg, dict) and "version" in pkg:
                pkg["version"] = version
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"synced {rel} -> {version}")


def main() -> None:
    version = crate_version()
    sync_json("server.json", version, sync_packages=True)
    sync_json(".well-known/mcp/server-card.json", version, sync_packages=False)
    sync_json("dxt/manifest.json", version, sync_packages=False)


if __name__ == "__main__":
    main()
