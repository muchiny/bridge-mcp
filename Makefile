# MCP SSH Bridge - Development Makefile

.PHONY: all build release check test test-otel test-daemon daemon-start daemon-stop daemon-status lint fmt fmt-check doc-check audit deny clean install setup help typos machete outdated quality mutants mutants-db mutants-file mutants-full security-audit zeroize-check geiger sbom security-tests semver-checks hack release-all release-target docker-build docker-scan deps-check deps-update ci-full release-pipeline careful bench bench-save bench-compare coverage coverage-check e2e-mock e2e-docker e2e-docker-up e2e-docker-down dxt sync-server-json registry-publish probe-install verify-install lint-stable markdownlint

# ---------------------------------------------------------------------------
# Guards around optional tooling.
#
# The idiom this replaces — `command -v X && X || echo "not installed"` —
# swallowed the tool's FAILURE, not just its absence. Reproduced on a witness:
# a `cargo deny` reporting a critical advisory and exiting 1 came out as
# "neither cargo-deny nor cargo-audit installed, skipping", recipe exit 0. And
# `audit` is in `ci`, the documented proof-of-completion before every commit —
# so `make ci` could go green on an open vulnerability. `coverage-check` had
# the same shape, which meant the coverage gate could not fail at all.
#
#   $(call need,TOOL,HINT)  absent -> FAIL. For gates that would otherwise
#                           claim success without having checked anything.
#                           Its `exit 1` fails the line, which aborts the recipe.
#
# There is deliberately no `want` macro. Make runs each recipe line in its OWN
# shell, so a guard line ending in `exit 0` only ends THAT line — make then runs
# the next line, tool absent or not. The guard and the command must share one
# shell, so genuinely optional tooling uses an explicit `if/else` block (see
# `outdated`). Nothing in `ci` is optional: `typos` used to be, and `make ci`
# went green on a machine without it having checked nothing.
#
# Neither form masks a failure: once the tool runs, its exit code is the recipe's.
need = command -v $(1) >/dev/null 2>&1 || { echo "$(1) not installed. $(2)"; exit 1; }

# Minimum line coverage enforced by `coverage-check`.
#
# Measured 2026-09-01: 96,41% (all targets), 96,14% (--lib). The gate was at
# 70, which would have let 26 points rot unnoticed — and it could not fail
# anyway, see the `need`/`want` note above. 93 leaves three points of slack for
# noise without being decorative. Keep in step with ci.yml's coverage job.
COVERAGE_MIN ?= 93

# Default target
all: check lint test

# Build debug version
build:
	cargo build

# Features the deployed binary needs on this machine: `full` brings jq/http/
# otel, `winrm`+`psrp` are required to LOAD a config that declares Windows
# hosts (`protocol: winrm|psrp` is a `#[cfg(feature = "winrm")]` enum variant,
# so a build without it refuses the whole file).
RELEASE_FEATURES ?= full,winrm,psrp

# Build release version
release:
	CARGO_BUILD_JOBS=2 cargo build --release --features $(RELEASE_FEATURES)

# Check compilation without building
check:
	cargo check --all-targets

# Run tests.
# The second line is not redundant: nextest cannot run doctests, so on any
# machine where the nextest path succeeds the compiled examples in src/ would
# otherwise never be built or executed (they weren't, anywhere, until 2026-08).
# Same command as the CI `Tests` job (--all-targets --all-features), so a green
# local run covers the same code. The fallback fires ONLY when nextest is not
# installed (`command -v`); a failing test fails the recipe, with nextest's
# report visible. The old `nextest 2>/dev/null || cargo test` replayed the whole
# suite under the slow harness on any test failure and threw the report away.
test:
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --all-targets --all-features; \
	else \
		echo "cargo-nextest not installed, falling back to cargo test"; \
		cargo test --all-targets --all-features; \
	fi
	cargo test --doc --all-features

# Run tests with OpenTelemetry feature enabled
# Validates the feature-gated telemetry module and OTLP plumbing compiles
# and that the in-process span capture test still passes when `otel` is on.
test-otel:
	cargo test --features "cli,otel"

# Run only the daemon integration suite (fast smoke test)
test-daemon:
	cargo test --test daemon_integration

# Start a local daemon for interactive development.
# Use `make daemon-stop` or Ctrl+C to terminate.
daemon-start:
	./target/release/bridge-mcp daemon start

# Gracefully stop the local daemon.
daemon-stop:
	./target/release/bridge-mcp daemon stop

# Report daemon status.
daemon-status:
	./target/release/bridge-mcp daemon status

# Run clippy linter (MSRV toolchain — rust-toolchain.toml pins 1.98.0)
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Run clippy on real stable, which is what the CI Clippy gate uses.
# rust-toolchain.toml outranks `rustup default`, so `make lint` alone can stay
# green while CI goes red on a lint that only exists in a newer clippy — that
# gap hid 48 lints until 2026-08. RUSTUP_TOOLCHAIN is the only way past the
# toolchain file short of `cargo +stable`.
# Its own CARGO_TARGET_DIR on purpose: sharing target/ with `make lint` makes
# the two targets evict each other's artifacts and rebuild the world on every
# alternation. Not under /tmp — that is a RAM-backed tmpfs on this box.
#
# The recipe also checks that the LOCAL stable is the UPSTREAM stable. The
# installed toolchain is whatever `rustup update` last fetched, and nothing keeps
# it current: it sat at 1.98.0 for six weeks while 1.99.0 shipped
# `assert_is_empty`, so this target read green on a stale compiler while CI's
# Clippy put 618 violations on every PR (#221, then #223). Do not delete the
# check as noise; it is the only thing that makes this target's green mean
# "what CI will say".
#   - always prints the compiler that linted;
#   - stable toolchain not installed -> FAIL, saying so (`rustup toolchain
#     install stable`), not a bogus "version mismatch";
#   - network reachable, versions differ -> FAIL (run `rustup update stable`);
#   - fetch failed (no network, or an HTTP status >= 400), OR it answered but the response has no `[pkg.rust]
#     version` line (upstream reformatted; the parser needs updating) -> loud
#     WARNING saying which, then lint anyway. A local gate must work offline;
#     this is about the dev machine, not the air-gapped hosts. On a networked
#     machine a warning is a SIGNAL (the parser broke), not background noise.
# Cost: `curl -m 10` can add up to 10 s to an offline `make ci`.
# Test hooks, all echoed when in use because they disarm the check. They are
# honoured ONLY when passed on the make command line (`make TEST_X=... lint-stable`);
# an exported environment variable is ignored, so a stray one cannot silently
# disarm the check:
#   TEST_STABLE_CHANNEL_URL       where to fetch (unroutable / file:// fixture)
#   TEST_UPSTREAM_STABLE_VERSION  skip the fetch: "1.99.0 (b940084d7 2026-09-28)"
#   TEST_STABLE_RUSTC             command replacing `rustc` (e.g. `false`)
# `rustup update stable` is deliberately NOT run here: a lint target must not
# mutate the developer's toolchain.
cmdline = $(if $(filter command line,$(origin $(1))),$($(1)))
STABLE_CHANNEL_URL := $(or $(call cmdline,TEST_STABLE_CHANNEL_URL),https://static.rust-lang.org/dist/channel-rust-stable.toml)
UP_OVERRIDE := $(call cmdline,TEST_UPSTREAM_STABLE_VERSION)
RUSTC_CMD := $(or $(call cmdline,TEST_STABLE_RUSTC),rustc)
lint-stable:
	@if [ -n '$(UP_OVERRIDE)' ]; then echo "NOTICE: lint-stable: TEST_UPSTREAM_STABLE_VERSION='$(UP_OVERRIDE)' is set; the upstream check is replaced by this constant"; fi; \
	if [ '$(STABLE_CHANNEL_URL)' != 'https://static.rust-lang.org/dist/channel-rust-stable.toml' ]; then echo "NOTICE: lint-stable: TEST_STABLE_CHANNEL_URL='$(STABLE_CHANNEL_URL)' is set; not fetching the real channel file"; fi; \
	if [ '$(RUSTC_CMD)' != rustc ]; then echo "NOTICE: lint-stable: TEST_STABLE_RUSTC='$(RUSTC_CMD)' is set; not asking the real rustc"; fi; \
	raw=$$(RUSTUP_TOOLCHAIN=stable $(RUSTC_CMD) --version 2>&1); \
	local=$$(printf '%s\n' "$$raw" | sed -n 's/^rustc //p'); \
	if [ -z "$$local" ]; then \
		echo "ERROR: lint-stable: could not get a version from the stable toolchain; it is probably not installed. Run 'rustup toolchain install stable'. Its output was:"; \
		printf '%s\n' "$$raw"; \
		exit 1; \
	fi; \
	echo "lint-stable: local stable compiler = $$local"; \
	up='$(UP_OVERRIDE)'; fetched=ok; \
	if [ -z "$$up" ]; then \
		toml=$$(curl -fsS -m 10 '$(STABLE_CHANNEL_URL)' 2>/dev/null) || fetched=failed; \
		up=$$(printf '%s\n' "$$toml" | awk '/^\[pkg\.rust\]/{f=1;next} f&&/^version/{gsub(/^version = "|"$$/,"");print;exit}'); \
	fi; \
	if [ "$$fetched" = failed ]; then \
		echo "WARNING: lint-stable: could not fetch $(STABLE_CHANNEL_URL) (no network, or the server answered with an HTTP error, status >= 400); cannot tell whether $$local is current. A newer clippy may still fail CI."; \
	elif [ -z "$$up" ]; then \
		echo "WARNING: lint-stable: $(STABLE_CHANNEL_URL) answered but its response has no [pkg.rust] version line (upstream reformatted the file, in which case the parser in this recipe needs updating, or something else answered, such as a captive portal). Cannot tell whether $$local is current."; \
	elif [ "$$up" != "$$local" ]; then \
		echo "ERROR: lint-stable: local stable is $$local but upstream stable is $$up. CI lints upstream stable; run 'rustup update stable'."; \
		exit 1; \
	else \
		echo "lint-stable: local stable matches upstream stable"; \
	fi
	RUSTUP_TOOLCHAIN=stable CARGO_TARGET_DIR=target-stable \
		cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Rustdoc as a lint: broken intra-doc links, bare URLs, invalid HTML
doc-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Security audit (requires cargo-audit: cargo install cargo-audit)
audit:
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo deny check advisories; \
	elif command -v cargo-audit >/dev/null 2>&1; then \
		cargo-audit audit; \
	else \
		echo "neither cargo-deny nor cargo-audit installed. cargo install cargo-deny"; \
		exit 1; \
	fi

# License and dependency check
deny:
	cargo deny check

# Clean build artifacts
clean:
	cargo clean

# Install to ~/.local/bin (in PATH ahead of ~/.cargo/bin on most setups).
# Uses the release target above which builds with --features $(RELEASE_FEATURES)
# so server-side jq filtering is available and configs declaring Windows hosts
# (winrm/psrp) can load.
#
# `install -m 0755` rather than `cp`: cp preserves the destination inode and
# leaves whatever mode was already there, so a previously-installed binary with
# a wrong mode silently keeps it. install(1) replaces the file atomically and
# sets the mode explicitly.
#
# The two checks run against target/release/bridge-mcp BEFORE the copy, not
# against the installed one after it. Checking afterwards still overwrote a
# working deployment with the broken build and only then failed the recipe, so
# the "FAIL" left the user worse off than not running the target at all.
install: release
	@mkdir -p ~/.local/bin
	@target/release/bridge-mcp validate >/dev/null 2>&1 \
		|| { echo "install: FAIL - fresh binary cannot load the local config (missing winrm/psrp feature?); nothing installed"; exit 1; }
	@target/release/bridge-mcp describe-tool ssh_k8s_get 2>/dev/null | grep -q jq_filter \
		|| { echo "install: FAIL - fresh binary does not advertise jq_filter (missing jq feature?); nothing installed"; exit 1; }
	install -m 0755 target/release/bridge-mcp ~/.local/bin/bridge-mcp
	@echo "install: OK - $$(~/.local/bin/bridge-mcp --version)"

# Behavioural fingerprint probes: does the INSTALLED binary actually contain
# the current behaviour? `--version` cannot answer this (CARGO_PKG_VERSION is
# identical across every build of a release). Override the binary with BIN=...
probe-install:
	@scripts/probe_installed_binary.sh $(BIN)

# Which binary `verify-install` inspects. Defaults to the deployed one; CI
# overrides it with the freshly built debug binary.
BIN ?= $(HOME)/.local/bin/bridge-mcp

# Fail loudly when the binary was not built from the current working tree.
# This is the identity check; `probe-install` is the behaviour check. Neither
# subsumes the other: a binary can carry the right SHA and have been built
# with the wrong feature set, and vice versa.
verify-install:
	@test -x "$(BIN)" || { echo "verify-install: no executable at $(BIN)"; exit 1; }
	@head_sha=$$(git rev-parse --short=12 HEAD 2>/dev/null); \
	if [ -z "$$head_sha" ]; then \
		echo "verify-install: FAIL - could not determine the working tree's git revision."; \
		echo "  Is git installed, and is $(CURDIR) a git checkout?"; \
		exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain --untracked-files=no)" ]; then \
		expected="$$head_sha-dirty"; \
	else \
		expected="$$head_sha"; \
	fi; \
	actual=$$("$(BIN)" --version | sed -n 's/.*(rev \(.*\))$$/\1/p'); \
	if [ -z "$$actual" ]; then \
		echo "verify-install: FAIL - $(BIN) prints no build revision at all."; \
		echo "  It predates build.rs. Rebuild: CARGO_BUILD_JOBS=2 make install"; \
		exit 1; \
	fi; \
	if [ "$$actual" != "$$expected" ]; then \
		echo "verify-install: FAIL - $(BIN) was built from $$actual, tree is $$expected."; \
		echo "  Rebuild and reinstall: CARGO_BUILD_JOBS=2 make install"; \
		exit 1; \
	fi; \
	echo "verify-install: OK - $(BIN) built from $$expected"

# Development mode with auto-reload
dev:
	cargo watch -x 'check --all-targets'

# Check for typos in code
typos:
	@$(call need,typos,cargo install typos-cli)
	typos

# Markdown lint with the same tool CI runs: markdownlint-cli2, which reads the
# repo's .markdownlint.yaml itself and prints its own version line (and the
# markdownlint rule set under it), so the log says which rulebook was applied.
# Tracked files only, on purpose: CI checks out nothing else, whereas a
# `**/*.md` glob here would also lint target/doc vendored font licences and
# gitignored plans, failing for reasons CI never sees. A Node tool in a Rust
# gate is a real cost; leaving it out let a duplicate `### Added` reach a red PR
# check after three green `make ci` runs. Not `npx --yes`: that would put a
# download inside a gate that has no honest way to degrade.
markdownlint:
	@$(call need,markdownlint-cli2,npm install -g markdownlint-cli2)
	git ls-files -z '*.md' | xargs -0 markdownlint-cli2

# Check for unused dependencies
machete:
	@$(call need,cargo-machete,cargo install cargo-machete)
	cargo machete

# Check for outdated dependencies
outdated:
	@if command -v cargo-outdated >/dev/null 2>&1; then \
		cargo outdated; \
	else \
		echo "cargo-outdated not installed, skipping. cargo install cargo-outdated"; \
	fi

# Full quality check (all linters)
quality: fmt-check lint typos machete

# Full CI check (quick). Mirrors the REQUIRED branch-protection contexts
# (Format, Clippy, Tests, Deny (advisories + licenses), Typos) and also runs
# Docs, `audit` and `markdownlint`, which are not required. CI additionally runs
# coverage (COVERAGE_MIN, 93%) and feature-powerset.
#
# `lint-stable` is in this list because CI's Clippy runs real stable
# (RUSTUP_TOOLCHAIN: stable at workflow level) while `lint` runs the 1.98.0
# pinned by rust-toolchain.toml. `lint` alone went green three times on a PR
# whose Clippy was red, and clippy 1.99's `assert_is_empty` put 618 violations
# on every PR. `lint` stays: it is the MSRV check. `test` uses --all-features
# for the same reason: CI's Tests job does.
#
# `doc-check` is in this list although Docs is NOT a required check: `make ci`
# passed on a doc comment that linked a public item to a private one, and the
# red arrived on the PR instead. Docs still fails the PR's CI run; it just
# does not block the merge button.
#
# Not covered: CI's Tests job also runs `make verify-install
# BIN=target/debug/bridge-mcp`. It is not here because it is noisy against a
# stale local target/debug, so a `build.rs` regression that makes
# BRIDGE_MCP_BUILD_REV fall back to `unknown` passes `make ci` and fails the
# required Tests context on the PR. `make ci` is not the whole of CI.
ci: fmt-check lint lint-stable test doc-check audit deny typos markdownlint

# Full CI check (comprehensive - replaces GitHub Actions)
ci-full: fmt-check lint lint-stable test audit typos markdownlint hack geiger doc-check
	@echo "Full CI complete."

# Setup development environment
setup:
	@echo "Installing Rust dev tools..."
	rustup component add rustfmt clippy
	@echo "Installing cargo tools..."
	cargo install cargo-nextest cargo-deny cargo-audit cargo-watch cargo-machete cargo-outdated typos-cli cargo-semver-checks cargo-hack cargo-insta cargo-geiger cargo-cyclonedx cargo-llvm-cov cross --locked
	@echo "Installing pre-commit (requires Python)..."
	@if command -v pip >/dev/null 2>&1; then \
		pip install --user pre-commit && pre-commit install; \
	else \
		echo "pip not found, skipping pre-commit"; \
	fi
	@echo "Installing markdownlint (requires Node.js)..."
	@if command -v npm >/dev/null 2>&1; then \
		npm install -g markdownlint-cli2; \
	else \
		echo "npm not found, skipping markdownlint"; \
	fi
	@echo ""
	@echo "Setup complete! Run 'make check' to verify."

# Code coverage report (requires cargo-llvm-cov: cargo install cargo-llvm-cov)
# WSL NOTE: full-crate coverage is heavy; locally we scope to --lib.
coverage:
	@if command -v cargo-llvm-cov >/dev/null 2>&1; then \
		cargo llvm-cov --lib --html --output-dir coverage && echo "Coverage report: coverage/html/index.html"; \
	else \
		echo "cargo-llvm-cov not installed, skipping. cargo install cargo-llvm-cov"; \
	fi

# Code coverage with minimum threshold (fail if below).
# Threshold must match ci.yml's coverage job (--fail-under-lines).
coverage-check:
	@$(call need,cargo-llvm-cov,cargo install cargo-llvm-cov)
	cargo llvm-cov --lib --summary-only --fail-under-lines $(COVERAGE_MIN)

# WSL-safe mutation settings (crash post-mortem 2026-07-04):
# - TMPDIR=/var/tmp — WSL /tmp is a RAM-backed tmpfs; cargo-mutants builds its
#   scratch trees under $TMPDIR, so building there doubles memory pressure.
# - -j 1 — a single job is the only proven-safe parallelism on this 24GB VM.
# - NEXTEST_TEST_THREADS=2 — caps per-mutant test parallelism.
MUTANTS_SAFE = TMPDIR=/var/tmp NEXTEST_TEST_THREADS=2 cargo mutants -j 1

# Mutation testing (security module only - fast)
mutants:
	@if command -v cargo-mutants >/dev/null 2>&1; then \
		$(MUTANTS_SAFE) --re '^src/security/'; \
	else \
		echo "cargo-mutants not installed, skipping. cargo install --locked cargo-mutants"; \
	fi

# Mutation testing (database + domain modules)
mutants-db:
	@if command -v cargo-mutants >/dev/null 2>&1; then \
		$(MUTANTS_SAFE) --re '^src/domain/'; \
	else \
		echo "cargo-mutants not installed, skipping. cargo install --locked cargo-mutants"; \
	fi

# Mutation testing of a single file: make mutants-file FILE=src/domain/output_cache.rs
mutants-file:
	@test -n "$(FILE)" || (echo "Usage: make mutants-file FILE=src/path/to/file.rs" && exit 1)
	@if command -v cargo-mutants >/dev/null 2>&1; then \
		$(MUTANTS_SAFE) --file "$(FILE)"; \
	else \
		echo "cargo-mutants not installed, skipping. cargo install --locked cargo-mutants"; \
	fi

# Full-project mutation is CI-only (weekly 8-shard job in security.yml +
# per-PR --in-diff job in ci.yml). Running it locally OOMs the WSL VM.
mutants-full:
	@echo "Refusing: full-crate mutation OOMs this WSL VM."
	@echo "Use the weekly sharded CI job (security.yml), the PR in-diff job (ci.yml),"
	@echo "or scope locally: make mutants-file FILE=src/path/to/file.rs"

# Extra runtime checks on dependencies (requires cargo-careful + nightly)
careful:
	@if command -v cargo-careful >/dev/null 2>&1; then \
		cargo +nightly careful test; \
	else \
		echo "cargo-careful not installed, skipping. cargo install cargo-careful"; \
	fi

# Run benchmarks
bench:
	cargo bench

# Save benchmark baseline for comparison
bench-save:
	cargo bench -- --save-baseline main

# Compare benchmarks against saved baseline
bench-compare:
	cargo bench -- --baseline main

# Run adversarial security test suite
security-tests:
	cargo test --test security_audit -- --nocapture

# Full security audit (dependency audit + security tests + unsafe scan)
security-audit: audit deny security-tests geiger

# Zeroization check — detect compiler-elided secret wipes by diffing MIR
# between opt-level=0 and opt-level=2. The compiler may delete a non-volatile
# memset it proves unobservable, silently leaving SSH credentials in memory.
# Tooling salvaged from the trailofbits/zeroize-audit plugin (removed 2026-08-02).
# CARGO_TARGET_DIR points at /var/tmp, never /tmp: /tmp is a 13GB RAM tmpfs here.
ZEROIZE_DIFF ?= $(HOME)/.claude/salvage/diff_rust_mir.sh
ZEROIZE_OUT ?= /var/tmp/bridge-mcp-mir

zeroize-check:
	@test -x "$(ZEROIZE_DIFF)" || { echo "missing $(ZEROIZE_DIFF) — see ~/.claude/salvage"; exit 2; }
	@free -m | awk 'NR==2 { if ($$7 < 6*1024) { print "BLOCK: only " $$7 " MB free, need >=6GB for two MIR builds"; exit 1 } }'
	@mkdir -p "$(ZEROIZE_OUT)"
	@echo "==> MIR at opt-level=0"
	@CARGO_TARGET_DIR="$(ZEROIZE_OUT)/O0" cargo rustc --lib -- --emit=mir -C opt-level=0 2>&1 | tail -3
	@echo "==> MIR at opt-level=2"
	@CARGO_TARGET_DIR="$(ZEROIZE_OUT)/O2" cargo rustc --lib -- --emit=mir -C opt-level=2 2>&1 | tail -3
	@o0=$$(find "$(ZEROIZE_OUT)/O0" -name '*.mir' | head -1); \
	o2=$$(find "$(ZEROIZE_OUT)/O2" -name '*.mir' | head -1); \
	test -n "$$o0" && test -n "$$o2" || { echo "no .mir emitted — check the cargo rustc output above"; exit 2; }; \
	"$(ZEROIZE_DIFF)" "$$o0" "$$o2"

# Scan for unsafe code in dependencies (requires cargo-geiger)
geiger:
	@command -v cargo-geiger >/dev/null 2>&1 || { echo "cargo-geiger not installed, run: cargo install cargo-geiger --locked"; exit 0; }
	@# FIND-021 (audit 2026-05-09): cloud features (aws-sdk, azure, gcp)
	@# pull nkeys-0.4.5 which cargo-geiger fails to extract on a cold
	@# graph. Pre-fetch first; if extraction still fails on --all-features,
	@# fall back to --forbid-only (acceptable since the workspace already
	@# enforces `#![forbid(unsafe_code)]`).
	@cargo fetch >/dev/null 2>&1 || true
	@cargo geiger --all-features --output-format Ascii 2>/dev/null \
	    || cargo geiger --forbid-only --output-format Ascii

# Check for semver-breaking API changes (requires cargo-semver-checks)
semver-checks:
	@if command -v cargo-semver-checks >/dev/null 2>&1; then \
		cargo semver-checks; \
	else \
		echo "cargo-semver-checks not installed, skipping. cargo install cargo-semver-checks"; \
	fi

# Check all feature combinations compile (requires cargo-hack)
hack:
	@$(call need,cargo-hack,cargo install cargo-hack)
	cargo hack check --feature-powerset --no-dev-deps

# Generate Software Bill of Materials (requires cargo-cyclonedx)
sbom:
	@if command -v cargo-cyclonedx >/dev/null 2>&1; then \
		cargo cyclonedx --format json --output-cdx; \
	else \
		echo "cargo-cyclonedx not installed, skipping. cargo install cargo-cyclonedx"; \
	fi

# Cross-compile for a specific target (requires cross: cargo install cross)
release-target:
	@test -n "$(TARGET)" || (echo "Usage: make release-target TARGET=x86_64-unknown-linux-gnu" && exit 1)
	@# Falling back to plain cargo when cross is ABSENT is deliberate. The old
	@# form also fell back when cross FAILED (docker down, image missing),
	@# turning a toolchain outage into a silently different build.
	@if command -v cross >/dev/null 2>&1; then \
		cross build --release --target $(TARGET); \
	else \
		echo "cross not installed, falling back to cargo build --target $(TARGET)"; \
		cargo build --release --target $(TARGET); \
	fi

# Cross-compile all release targets
release-all:
	@echo "Building release binaries..."
	@mkdir -p releases
	cargo build --release --target x86_64-unknown-linux-gnu
	@if command -v cross >/dev/null 2>&1; then \
		cross build --release --target aarch64-unknown-linux-gnu; \
		cross build --release --target x86_64-apple-darwin; \
		cross build --release --target aarch64-apple-darwin; \
		cross build --release --target x86_64-pc-windows-gnu; \
	else \
		echo "cross not installed, skipping. cargo install cross"; \
	fi

# Build Docker image locally
docker-build:
	docker build -t bridge-mcp:local .

# Build and scan Docker image with Trivy
docker-scan: docker-build
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image --severity CRITICAL,HIGH bridge-mcp:local; \
	else \
		echo "trivy not installed, skipping. https://aquasecurity.github.io/trivy"; \
	fi

# Check for outdated and unused dependencies (report-only complement to
# Dependabot, which opens the actual update PRs — see .github/dependabot.yml)
deps-check: outdated machete
	@echo "Dependency check complete. Run 'cargo update' to apply compatible updates."

# Update all compatible dependencies (minor/patch)
deps-update:
	cargo update
	@echo "Updated Cargo.lock with compatible versions."
	@echo "Run 'make outdated' to see remaining major updates."

# Mock-based E2E tests (no SSH required, fast)
e2e-mock:
	cargo test --test e2e_mock -- --nocapture

# Docker-based E2E tests (real SSH, requires docker)
# Not `e2e-docker: e2e-docker-up`: a failing prerequisite aborts before the
# recipe body, so a timed-out `up --wait` would skip teardown and leave port
# 2222 held. Up, test and down are one shell so down ALWAYS runs, and a failed
# teardown turns a passing run red instead of leaking the container silently.
e2e-docker:
	@status=0; \
	$(MAKE) e2e-docker-up || status=$$?; \
	if [ $$status -eq 0 ]; then \
		cargo test --test e2e_docker -- --ignored --test-threads=1 --nocapture || status=$$?; \
	fi; \
	$(MAKE) e2e-docker-down || { \
		echo "ERROR: e2e-docker-down failed; the container may still hold port 2222"; \
		[ $$status -ne 0 ] || status=1; \
	}; \
	exit $$status

# Start Docker SSH test server
e2e-docker-up:
	docker compose -f docker-compose.test.yml up -d --wait
	@echo "Docker SSH test server ready on port 2222."

# Stop Docker SSH test server
e2e-docker-down:
	docker compose -f docker-compose.test.yml down -v

# Full release pipeline (CI + cross-compile + Docker)
release-pipeline: ci-full release-all docker-scan
	@echo "Release pipeline complete."

# Build DXT package (Desktop Extension for Claude Desktop)
dxt: release
	@mkdir -p dist/dxt
	cp target/release/bridge-mcp dist/dxt/
	cp dxt/manifest.json dxt/icon.svg dist/dxt/
	cd dist && zip -r bridge-mcp.dxt dxt/
	@echo "DXT package: dist/bridge-mcp.dxt"

# Sync all discovery-manifest versions to Cargo.toml (single source of truth)
sync-server-json:
	python3 scripts/sync-server-json.py
	@echo "Discovery manifests synced to crate version."

# Build MCPB package (MCP Bundle for official registry)
mcpb: release
	@mkdir -p dist/mcpb
	cp target/release/bridge-mcp dist/mcpb/
	cp dxt/manifest.json dxt/icon.svg server.json dist/mcpb/
	cd dist && zip -r bridge-mcp.mcpb mcpb/
	@cd dist && sha256sum bridge-mcp.mcpb > bridge-mcp.mcpb.sha256
	@echo "MCPB package: dist/bridge-mcp.mcpb"
	@echo "SHA256: $$(cat dist/bridge-mcp.mcpb.sha256)"

# Publish server.json to the official MCP registry (registry.modelcontextprotocol.io).
# OPT-IN / MANUAL: not part of release-pipeline. Requires `mcp-publisher` on PATH
# and a prior `mcp-publisher login` (github-oidc or token). Fails fast on version
# drift so a stale manifest is never published.
registry-publish: sync-server-json
	@git diff --exit-code server.json \
		|| { echo "ERROR: server.json drifted — commit the sync first"; exit 1; }
	@command -v mcp-publisher >/dev/null 2>&1 \
		|| { echo "ERROR: mcp-publisher not found. Install from github.com/modelcontextprotocol/registry"; exit 1; }
	mcp-publisher publish
	@echo "Published server.json to registry.modelcontextprotocol.io"

# Show help
help:
	@echo "MCP SSH Bridge - Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  build            - Build debug version"
	@echo "  release          - Build release version (native)"
	@echo "  release-all      - Cross-compile all 5 platforms"
	@echo "  release-target   - Build specific target (TARGET=...)"
	@echo "  check            - Check compilation"
	@echo "  clean            - Clean build artifacts"
	@echo "  install          - Build (--features $(RELEASE_FEATURES)) + install to ~/.local/bin"
	@echo "  probe-install    - Fingerprint-probe the installed binary for staleness"
	@echo "  verify-install   - Fail unless the installed binary was built from HEAD"
	@echo ""
	@echo "Quality:"
	@echo "  test             - Run tests"
	@echo "  lint             - Run clippy (MSRV toolchain)"
	@echo "  lint-stable      - Run clippy on real stable (what CI gates on)"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check formatting"
	@echo "  typos            - Check for typos"
	@echo "  markdownlint     - Lint tracked markdown (as CI does)"
	@echo "  doc-check        - Rustdoc lint (broken links, -D warnings)"
	@echo "  hack             - Check all feature combinations"
	@echo "  quality          - Full quality check (lint+typos+machete)"
	@echo ""
	@echo "Security:"
	@echo "  audit            - Security audit (cargo-audit)"
	@echo "  deny             - License/dependency check"
	@echo "  geiger           - Scan for unsafe code in dependencies"
	@echo "  security-tests   - Run adversarial security tests"
	@echo "  security-audit   - Full security audit (audit+deny+tests+geiger)"
	@echo ""
	@echo "Dependencies:"
	@echo "  deps-check       - Check outdated + unused (report; Dependabot opens PRs)"
	@echo "  deps-update      - Update compatible dependencies"
	@echo "  machete          - Check for unused dependencies"
	@echo "  outdated         - Check for outdated dependencies"
	@echo "  sbom             - Generate SBOM (CycloneDX)"
	@echo ""
	@echo "Testing:"
	@echo "  coverage         - Generate HTML coverage report (cargo-llvm-cov, --lib)"
	@echo "  coverage-check   - Coverage with minimum threshold (COVERAGE_MIN=$(COVERAGE_MIN))"
	@echo "  mutants          - Mutation testing (security module, WSL-safe)"
	@echo "  mutants-db       - Mutation testing (domain modules, WSL-safe)"
	@echo "  mutants-file     - Mutation testing of one file (FILE=src/...)"
	@echo "  mutants-full     - [CI-ONLY] refuses locally, points to CI jobs"
	@echo "  semver-checks    - Check for semver-breaking changes"
	@echo "  careful          - Extra runtime checks (cargo-careful + nightly)"
	@echo "  bench            - Run benchmarks"
	@echo "  bench-save       - Save benchmark baseline"
	@echo "  bench-compare    - Compare against saved baseline"
	@echo "  e2e-mock         - Mock-based E2E pipeline tests (fast, no SSH)"
	@echo "  e2e-docker       - Docker-based E2E tests (real SSH, requires docker)"
	@echo "  e2e-docker-up    - Start Docker SSH test server"
	@echo "  e2e-docker-down  - Stop Docker SSH test server"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build     - Build Docker image locally"
	@echo "  docker-scan      - Build + Trivy security scan"
	@echo ""
	@echo "Packaging:"
	@echo "  dxt              - Build DXT package for Claude Desktop"
	@echo "  mcpb             - Build MCPB package for MCP Registry"
	@echo "  sync-server-json - Sync all 6 version-carrying manifests to Cargo.toml"
	@echo "  registry-publish - [MANUAL] Publish server.json to the official MCP registry"
	@echo ""
	@echo "Pipelines:"
	@echo "  ci               - Quick CI (fmt+lint+test+audit+typos)"
	@echo "  ci-full          - Full CI (ci+hack+geiger)"
	@echo "  release-pipeline - Full release (ci-full+release-all+docker-scan)"
	@echo ""
	@echo "Development:"
	@echo "  dev              - Watch mode with auto-check"
	@echo "  setup            - Install all dev dependencies"
	@echo ""
