# Release checklist

Run this immediately before pushing a version tag. Every line is a command with
an expected result — do not tick a box you did not run. Substitute the version
being released for `X.Y.Z` (`2.2.0` for the first use of this file).

## 1. The version is the same everywhere

- [ ] `grep -n '^version' Cargo.toml` — the single source of truth says `X.Y.Z`.
- [ ] `cargo test --test discovery_metadata` — 7 passed. This covers
  `server.json` (top level and every `packages[]` entry),
  `.well-known/mcp/server-card.json`, `dxt/manifest.json`,
  `.claude-plugin/marketplace.json`, `plugin/.claude-plugin/plugin.json` and
  `dxt/README.md`. The README example is asserted by a line-level scan rather
  than a JSON parse, and the test also pins that the file carries exactly one
  `"version"` field, so a second example can never be silently skipped.
- [ ] `make sync-server-json && git diff --exit-code` — no output. The syncer
  covers six files and must be a byte-level no-op when nothing has drifted.
  This is the same drift gate `.github/workflows/release.yml` runs after the
  binaries are built; failing it there wastes a whole release run.
- [ ] `grep -n -A1 '^name = "bridge-mcp"$' Cargo.lock fuzz/Cargo.lock` — both
  say `X.Y.Z`. Two separate workspaces, two lockfiles; the fuzz one drifted
  once already because only the root workspace gets re-resolved by a bump.
  Regenerate it with `cargo metadata --manifest-path fuzz/Cargo.toml
  --format-version 1 --offline` — **without** `--no-deps`, which skips
  resolution and rewrites nothing.
- [ ] `git grep -n '<previous version>'` — matches only `CHANGELOG.md` history,
  `CLAUDE.md` history, `docs/superpowers/plans/`, `scripts/probe_installed_binary.sh`
  (which deliberately records the previously-installed version as a historical
  fact), and the unrelated `uuid` crate in the two lockfiles.

## 2. The registry did not move

- [ ] `python3 scripts/validate_baseline.py` — `OK: baseline invariants hold.`
  with `baseline total: 476` and `current total: 476`.
- [ ] If, and only if, this release intentionally adds or removes a tool group:
  `.migration-baseline.json`, the conformance count test and the
  `tool_filtering` `known_groups` list were all updated in the same commit.
  These two test lists are hardcoded despite the "dynamic counts" claim.

## 3. The changelog is publishable

- [ ] `CHANGELOG.md` has exactly one `## [X.Y.Z] - <today>` heading and exactly
  one `[X.Y.Z]:` link reference definition. Duplicates resolve to whichever
  definition comes first in the file, silently. Note the never-tagged legacy
  `2.0.0` / `2.0.1` / `2.1.0` headings and their two link refs further down:
  they are history, they are why this line exists, and they must not be
  reused as a version number.
- [ ] `[Unreleased]:` compares against the tag you are about to push, and the
  `## [Unreleased]` section itself is empty.
- [ ] `git log --oneline <previous tag>..HEAD` — every commit is represented by
  a bullet, and every bullet has a commit.
- [ ] Every `BREAKING` bullet carries a migration sentence telling a client
  author, an operator, or a downstream crate what to change.
- [ ] **The breaking-change count in the preamble is re-derivable.** Count
  *distinct enumerated breaking changes*, never occurrences of the string
  `BREAKING`: take the union of every `BREAKING`-marked bullet and every row of
  the library-API table, deduplicated, and split lib-API from wire/behaviour.
  A `grep -c` counts lines, not changes, and the two lists have disagreed in
  both directions before — items marked in the bullets but missing from the
  table, and items in the table with no marker above. The preamble must also
  state the bar it used, so a reader can check the number instead of trusting
  it. This release shipped "seven, four in the lib API" for months against its
  own list of far more.
- [ ] The library-API table's column header names the version being released.
  It said `2.0.0` through the entire 2.2.0 cycle.
- [ ] `markdownlint --config .markdownlint.yaml CHANGELOG.md` — clean.

## 4. The gates are green

- [ ] `cargo fmt --all` first, then `CARGO_BUILD_JOBS=2 make ci` — exit 0.
  Formatting before linting, not after: `make ci` starts with `fmt-check`,
  which fails rather than fixes. Keep `CARGO_BUILD_JOBS=2`: `make lint` uses
  `--all-features`, and this box has OOM-crashed twice without the cap.
- [ ] `git status --porcelain` after the gate — empty. A gate that rewrites
  tracked files is a finding.
- [ ] RUSTSEC ignore lists still match and still hold the same 7 entries:
  `diff <(grep -v '^[[:space:]]*#' deny.toml | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]+' | sort -u) <(grep -v '^[[:space:]]*#' .cargo/audit.toml | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]+' | sort -u)`
  — no output. Changing one file without the other turns one CI gate red while
  the other stays green.

## 5. The tag will not be rejected

- [ ] `git tag | grep -Fx "vX.Y.Z"` — no output. The tag does not already exist.
- [ ] The tag name is `v` plus the exact `Cargo.toml` version.
  `.github/workflows/release.yml` fails the whole release on a mismatch; that
  has happened before (v1.19.0 was pushed on a commit titled v1.18.0).
- [ ] The number has never been used before, in a tag **or** in the changelog.
  `2.0.0`, `2.0.1` and `2.1.0` are burnt: they sit in `CHANGELOG.md` from a
  2.x line that was never tagged, which is why this release is `2.2.0`.
- [ ] You are not on the default branch, or you intend to be.

## 6. The shipped binary is built from the tag

- [ ] The tag exists locally **before** the release build starts.
- [ ] The binary installed to `~/.local/bin/bridge-mcp` was produced by a build
  whose source tree was checked out at the tag — not the build you happened to
  have in `target/` while committing. A stale install is invisible: the last
  one sat there for 23 commits, missing five command-injection fixes.
- [ ] `bridge-mcp --version` prints the version you are tagging, and the git
  revision it stamps resolves to the tagged commit (`make verify-install`).
- [ ] `scripts/probe_installed_binary.sh` passes against the reinstalled
  binary, not against a source checkout.

## 7. Only then

- [ ] `git push origin <branch>` **before** `git push origin vX.Y.Z`. Pushing
  the tag is what triggers the release workflow; if the branch is not there
  first, the tag points at a commit GitHub cannot see on any branch.
- [ ] Pushing publishes to a public surface. It is the owner's decision, not
  the implementer's, and it is the last line of this checklist for a reason.
