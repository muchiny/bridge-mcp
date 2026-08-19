# MCP SSH Bridge - Development Makefile

.PHONY: all build release check test test-otel test-daemon daemon-start daemon-stop daemon-status lint fmt fmt-check doc-check audit deny clean install setup help typos machete outdated quality mutants mutants-db mutants-file mutants-full security-audit zeroize-check geiger sbom security-tests semver-checks hack release-all release-target docker-build docker-scan deps-check deps-update ci-full release-pipeline careful bench bench-save bench-compare coverage coverage-check e2e-mock e2e-docker e2e-docker-up e2e-docker-down dxt sync-server-json registry-publish probe-install verify-install

# Default target
all: check lint test

# Build debug version
build:
	cargo build

# Build release version (full features: cli + mimalloc + http + jq + otel)
release:
	cargo build --release --features full

# Check compilation without building
check:
	cargo check --all-targets

# Run tests.
# The second line is not redundant: nextest cannot run doctests, so on any
# machine where the nextest path succeeds the compiled examples in src/ would
# otherwise never be built or executed (they weren't, anywhere, until 2026-08).
test:
	cargo nextest run 2>/dev/null || cargo test
	cargo test --doc

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

# Run clippy linter (MSRV toolchain — rust-toolchain.toml pins 1.94.0)
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
lint-stable:
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
	@command -v cargo-deny >/dev/null 2>&1 && cargo deny check advisories || (command -v cargo-audit >/dev/null 2>&1 && cargo-audit audit || echo "neither cargo-deny nor cargo-audit installed, skipping")

# License and dependency check
deny:
	cargo deny check

# Clean build artifacts
clean:
	cargo clean

# Install to ~/.local/bin (in PATH ahead of ~/.cargo/bin on most setups).
# Uses the release target above which builds with --features full so server-side
# jq filtering is available.
#
# `install -m 0755` rather than `cp`: cp preserves the destination inode and
# leaves whatever mode was already there, so a previously-installed binary with
# a wrong mode silently keeps it. install(1) replaces the file atomically and
# sets the mode explicitly.
install: release
	@mkdir -p ~/.local/bin
	install -m 0755 target/release/bridge-mcp ~/.local/bin/bridge-mcp

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
	@head_sha=$$(git rev-parse --short=12 HEAD); \
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
	@command -v typos >/dev/null 2>&1 && typos || echo "typos not installed, skipping"

# Check for unused dependencies
machete:
	@command -v cargo-machete >/dev/null 2>&1 && cargo machete || echo "cargo-machete not installed, skipping"

# Check for outdated dependencies
outdated:
	@command -v cargo-outdated >/dev/null 2>&1 && cargo outdated || echo "cargo-outdated not installed, skipping"

# Full quality check (all linters)
quality: fmt-check lint typos machete

# Full CI check (quick). Mirrors the required ci.yml checks
# (Format/Clippy/Tests/Deny/Typos); CI additionally runs coverage (70%),
# feature-powerset and markdownlint.
ci: fmt-check lint test audit deny typos

# Full CI check (comprehensive - replaces GitHub Actions)
ci-full: fmt-check lint lint-stable test audit typos hack geiger doc-check
	@echo "Full CI complete."

# Setup development environment
setup:
	@echo "Installing Rust dev tools..."
	rustup component add rustfmt clippy
	@echo "Installing cargo tools..."
	cargo install cargo-nextest cargo-deny cargo-audit cargo-watch cargo-machete cargo-outdated typos-cli cargo-semver-checks cargo-hack cargo-insta cargo-geiger cargo-cyclonedx cargo-llvm-cov cross --locked
	@echo "Installing pre-commit (requires Python)..."
	@command -v pip >/dev/null 2>&1 && pip install --user pre-commit && pre-commit install || echo "pip not found, skipping pre-commit"
	@echo "Installing markdownlint (requires Node.js)..."
	@command -v npm >/dev/null 2>&1 && npm install -g markdownlint-cli || echo "npm not found, skipping markdownlint"
	@echo ""
	@echo "Setup complete! Run 'make check' to verify."

# Code coverage report (requires cargo-llvm-cov: cargo install cargo-llvm-cov)
# WSL NOTE: full-crate coverage is heavy; locally we scope to --lib.
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 && cargo llvm-cov --lib --html --output-dir coverage && echo "Coverage report: coverage/html/index.html" || echo "cargo-llvm-cov not installed, run: cargo install cargo-llvm-cov"

# Code coverage with minimum threshold (fail if below).
# Threshold must match ci.yml's coverage job (--fail-under-lines 70).
coverage-check:
	@command -v cargo-llvm-cov >/dev/null 2>&1 && cargo llvm-cov --lib --summary-only --fail-under-lines 70 || echo "cargo-llvm-cov not installed, run: cargo install cargo-llvm-cov"

# WSL-safe mutation settings (crash post-mortem 2026-07-04):
# - TMPDIR=/var/tmp — WSL /tmp is a RAM-backed tmpfs; cargo-mutants builds its
#   scratch trees under $TMPDIR, so building there doubles memory pressure.
# - -j 1 — a single job is the only proven-safe parallelism on this 24GB VM.
# - NEXTEST_TEST_THREADS=2 — caps per-mutant test parallelism.
MUTANTS_SAFE = TMPDIR=/var/tmp NEXTEST_TEST_THREADS=2 cargo mutants -j 1

# Mutation testing (security module only - fast)
mutants:
	@command -v cargo-mutants >/dev/null 2>&1 && $(MUTANTS_SAFE) --re '^src/security/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing (database + domain modules)
mutants-db:
	@command -v cargo-mutants >/dev/null 2>&1 && $(MUTANTS_SAFE) --re '^src/domain/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing of a single file: make mutants-file FILE=src/domain/output_cache.rs
mutants-file:
	@test -n "$(FILE)" || (echo "Usage: make mutants-file FILE=src/path/to/file.rs" && exit 1)
	@command -v cargo-mutants >/dev/null 2>&1 && $(MUTANTS_SAFE) --file "$(FILE)" || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Full-project mutation is CI-only (weekly 8-shard job in security.yml +
# per-PR --in-diff job in ci.yml). Running it locally OOMs the WSL VM.
mutants-full:
	@echo "Refusing: full-crate mutation OOMs this WSL VM."
	@echo "Use the weekly sharded CI job (security.yml), the PR in-diff job (ci.yml),"
	@echo "or scope locally: make mutants-file FILE=src/path/to/file.rs"

# Extra runtime checks on dependencies (requires cargo-careful + nightly)
careful:
	@command -v cargo-careful >/dev/null 2>&1 && cargo +nightly careful test || echo "cargo-careful not installed, run: cargo install cargo-careful"

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
	@command -v cargo-semver-checks >/dev/null 2>&1 && cargo semver-checks || echo "cargo-semver-checks not installed, run: cargo install cargo-semver-checks --locked"

# Check all feature combinations compile (requires cargo-hack)
hack:
	@command -v cargo-hack >/dev/null 2>&1 && cargo hack check --feature-powerset --no-dev-deps || echo "cargo-hack not installed, run: cargo install cargo-hack --locked"

# Generate Software Bill of Materials (requires cargo-cyclonedx)
sbom:
	@command -v cargo-cyclonedx >/dev/null 2>&1 && cargo cyclonedx --format json --output-cdx || echo "cargo-cyclonedx not installed, run: cargo install cargo-cyclonedx --locked"

# Cross-compile for a specific target (requires cross: cargo install cross)
release-target:
	@test -n "$(TARGET)" || (echo "Usage: make release-target TARGET=x86_64-unknown-linux-gnu" && exit 1)
	@command -v cross >/dev/null 2>&1 && cross build --release --target $(TARGET) || cargo build --release --target $(TARGET)

# Cross-compile all release targets
release-all:
	@echo "Building release binaries..."
	@mkdir -p releases
	cargo build --release --target x86_64-unknown-linux-gnu
	@command -v cross >/dev/null 2>&1 && cross build --release --target aarch64-unknown-linux-gnu || echo "cross not installed, skipping arm64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target x86_64-apple-darwin || echo "cross not installed, skipping macos-x86_64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target aarch64-apple-darwin || echo "cross not installed, skipping macos-arm64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target x86_64-pc-windows-gnu || echo "cross not installed, skipping windows"
	@echo "Packaging..."
	@test -f target/x86_64-unknown-linux-gnu/release/bridge-mcp && cd target/x86_64-unknown-linux-gnu/release && tar czf ../../../releases/bridge-mcp-linux-x86_64.tar.gz bridge-mcp && cd ../../../releases && sha256sum bridge-mcp-linux-x86_64.tar.gz > bridge-mcp-linux-x86_64.tar.gz.sha256 || true
	@test -f target/aarch64-unknown-linux-gnu/release/bridge-mcp && cd target/aarch64-unknown-linux-gnu/release && tar czf ../../../releases/bridge-mcp-linux-arm64.tar.gz bridge-mcp && cd ../../../releases && sha256sum bridge-mcp-linux-arm64.tar.gz > bridge-mcp-linux-arm64.tar.gz.sha256 || true
	@test -f target/x86_64-apple-darwin/release/bridge-mcp && cd target/x86_64-apple-darwin/release && tar czf ../../../releases/bridge-mcp-macos-x86_64.tar.gz bridge-mcp && cd ../../../releases && sha256sum bridge-mcp-macos-x86_64.tar.gz > bridge-mcp-macos-x86_64.tar.gz.sha256 || true
	@test -f target/aarch64-apple-darwin/release/bridge-mcp && cd target/aarch64-apple-darwin/release && tar czf ../../../releases/bridge-mcp-macos-arm64.tar.gz bridge-mcp && cd ../../../releases && sha256sum bridge-mcp-macos-arm64.tar.gz > bridge-mcp-macos-arm64.tar.gz.sha256 || true
	@test -f target/x86_64-pc-windows-gnu/release/bridge-mcp.exe && cd target/x86_64-pc-windows-gnu/release && zip -j ../../../releases/bridge-mcp-windows-x86_64.zip bridge-mcp.exe && cd ../../../releases && sha256sum bridge-mcp-windows-x86_64.zip > bridge-mcp-windows-x86_64.zip.sha256 || true
	@echo "Release artifacts in releases/"

# Build Docker image locally
docker-build:
	docker build -t bridge-mcp:local .

# Build and scan Docker image with Trivy
docker-scan: docker-build
	@command -v trivy >/dev/null 2>&1 && trivy image --severity CRITICAL,HIGH bridge-mcp:local || echo "trivy not installed, skipping scan"

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
e2e-docker: e2e-docker-up
	cargo test --test e2e_docker -- --ignored --test-threads=1 --nocapture
	$(MAKE) e2e-docker-down

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
	@echo "  install          - Build (--features full) + install to ~/.local/bin"
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
	@echo "  coverage-check   - Coverage with minimum threshold (--fail-under-lines 70)"
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
	@echo "  sync-server-json - Sync server.json / server-card / dxt manifest versions to Cargo.toml"
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
