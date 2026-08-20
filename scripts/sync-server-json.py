#!/usr/bin/env python3
"""Sync discovery-manifest versions to the crate version in Cargo.toml.

Reads `version` from the [package] table of Cargo.toml and rewrites the
`version` field (and server.json packages[].version) in every shippable
manifest, preserving JSON structure and 2-space indentation. Idempotent:
running twice produces no diff. CI runs `make sync-server-json` then
`git diff --exit-code` to fail on drift.

Two syncers, because the files are not all the same shape: `sync_json` reparses
and reserializes (server.json, server-card.json, dxt/manifest.json), while
`sync_regex` rewrites the version in place for files that reserialization would
damage (see REGEX_SYNCED). Every file touched here is also asserted by
`tests/discovery_metadata.rs`, so drift fails the test suite even when nobody
runs this script.
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


# Files whose version cannot go through sync_json(): marketplace.json keeps its
# version at plugins[0].version (a top-level assignment would inject a bogus
# key), plugin.json would get its single-line "keywords" array reflowed by
# json.dumps, and dxt/README.md is Markdown, not JSON. Each of these carries
# exactly one `"version": "..."` field — asserted below, so a second one can
# never be silently skipped. `"dxt_version"` does not match: the pattern
# requires a quote immediately before `version`.
VERSION_FIELD = re.compile(r'("version"\s*:\s*")[^"]+(")')

REGEX_SYNCED = (
    ".claude-plugin/marketplace.json",
    "plugin/.claude-plugin/plugin.json",
    "dxt/README.md",
)


def sync_regex(rel: str, version: str) -> None:
    # Bytes, not read_text/write_text: text mode normalises newlines on read and
    # re-expands them to os.linesep on write, so a text-mode round-trip is only
    # byte-preserving by accident of running on Linux. These files must come out
    # byte-identical when the version already matches — that is what makes the
    # `git diff --exit-code` drift check meaningful rather than noisy.
    path = ROOT / rel
    text = path.read_bytes().decode("utf-8")
    new, n = VERSION_FIELD.subn(lambda m: m.group(1) + version + m.group(2), text)
    if n != 1:
        sys.exit(f"{rel}: expected exactly 1 version field, found {n}")
    path.write_bytes(new.encode("utf-8"))
    print(f"synced {rel} -> {version}")


def main() -> None:
    version = crate_version()
    sync_json("server.json", version, sync_packages=True)
    sync_json(".well-known/mcp/server-card.json", version, sync_packages=False)
    sync_json("dxt/manifest.json", version, sync_packages=False)
    for rel in REGEX_SYNCED:
        sync_regex(rel, version)


if __name__ == "__main__":
    main()
