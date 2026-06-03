# MCP SSH Bridge - Development Makefile

.PHONY: all build release check test test-otel test-daemon daemon-start daemon-stop daemon-status lint fmt fmt-check audit deny clean install setup help typos machete outdated quality mutants mutants-db mutants-full security-audit geiger sbom security-tests semver-checks hack release-all release-target docker-build docker-scan deps-check deps-update ci-full release-pipeline careful bench bench-save bench-compare coverage coverage-check e2e-mock e2e-docker e2e-docker-up e2e-docker-down dxt sync-server-json

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

# Run tests
test:
	cargo nextest run 2>/dev/null || cargo test

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

# Run clippy linter
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

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
install: release
	@mkdir -p ~/.local/bin
	cp target/release/bridge-mcp ~/.local/bin/

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

# Full CI check (quick)
ci: fmt-check lint test audit typos

# Full CI check (comprehensive - replaces GitHub Actions)
ci-full: fmt-check lint test audit typos hack geiger
	@echo "Full CI complete."

# Setup development environment
setup:
	@echo "Installing Rust dev tools..."
	rustup component add rustfmt clippy
	@echo "Installing cargo tools..."
	cargo install cargo-nextest cargo-deny cargo-audit cargo-watch cargo-machete cargo-outdated typos-cli cargo-semver-checks cargo-hack cargo-insta cargo-geiger cargo-cyclonedx cross --locked
	@echo "Installing pre-commit (requires Python)..."
	@command -v pip >/dev/null 2>&1 && pip install --user pre-commit && pre-commit install || echo "pip not found, skipping pre-commit"
	@echo "Installing markdownlint (requires Node.js)..."
	@command -v npm >/dev/null 2>&1 && npm install -g markdownlint-cli || echo "npm not found, skipping markdownlint"
	@echo ""
	@echo "Setup complete! Run 'make check' to verify."

# Code coverage report (requires cargo-tarpaulin: cargo install cargo-tarpaulin)
coverage:
	@command -v cargo-tarpaulin >/dev/null 2>&1 && cargo tarpaulin --engine llvm --out Html --output-dir coverage && echo "Coverage report: coverage/tarpaulin-report.html" || echo "cargo-tarpaulin not installed, run: cargo install cargo-tarpaulin"

# Code coverage with minimum threshold (fail if below)
coverage-check:
	@command -v cargo-tarpaulin >/dev/null 2>&1 && cargo tarpaulin --engine llvm --out xml --output-dir coverage --fail-under 60 || echo "cargo-tarpaulin not installed, run: cargo install cargo-tarpaulin"

# Mutation testing (security module only - fast)
mutants:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants --re '^src/security/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing (database + domain modules)
mutants-db:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants --re '^src/domain/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing (full project - slow)
mutants-full:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

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

# Check for outdated and unused dependencies (replaces Dependabot)
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
	@echo "  install          - Install to ~/.cargo/bin"
	@echo ""
	@echo "Quality:"
	@echo "  test             - Run tests"
	@echo "  lint             - Run clippy"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check formatting"
	@echo "  typos            - Check for typos"
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
	@echo "  deps-check       - Check outdated + unused (replaces Dependabot)"
	@echo "  deps-update      - Update compatible dependencies"
	@echo "  machete          - Check for unused dependencies"
	@echo "  outdated         - Check for outdated dependencies"
	@echo "  sbom             - Generate SBOM (CycloneDX)"
	@echo ""
	@echo "Testing:"
	@echo "  coverage         - Generate HTML coverage report (cargo-tarpaulin)"
	@echo "  coverage-check   - Coverage with minimum threshold (--fail-under 60)"
	@echo "  mutants          - Mutation testing (security module)"
	@echo "  mutants-db       - Mutation testing (domain/database)"
	@echo "  mutants-full     - Mutation testing (full project)"
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
