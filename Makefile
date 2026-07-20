BINARY      := defenseclaw
GATEWAY     := defenseclaw-gateway
HOOK_LAUNCHER := defenseclaw-hook
VERSION     := 0.8.6
.DEFAULT_GOAL := help
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
VENV        := .venv
GOBIN       := $(shell go env GOPATH)/bin
PLUGIN_DIR  := extensions/defenseclaw
RUFF        := $(shell if [ -x "$(VENV)/bin/ruff" ]; then printf '%s' "$(VENV)/bin/ruff"; elif command -v ruff >/dev/null 2>&1; then command -v ruff; else printf '%s' "$(VENV)/bin/ruff"; fi)
SOURCE_PLUGIN_INSTALL_TARGET = $(if $(filter openclaw,$(CONNECTOR)),plugin-install,maybe-openclaw-plugin-install)
# The race-enabled gateway package can exceed the default test deadline on
# supported arm64 developer/CI hosts without any individual test hanging.
GO_TEST_TIMEOUT ?= 60m

DIST_DIR    := dist
UPGRADE_SMOKE_FROM ?=

# Cross-platform virtualenv / executable layout. Windows Python venvs expose
# console entry points under Scripts/ (not bin/) and binaries carry a .exe
# suffix, which Go also appends to its build output. Detect the host once and
# parameterize the handful of install paths that differ so `make install` works
# on hosted Windows runners (the connector contract matrix) as well as
# Linux/macOS. $(OS) is set to "Windows_NT" by Windows itself and inherited by
# the MSYS/Git-Bash shell make runs there; it is unset elsewhere.
ifeq ($(OS),Windows_NT)
PYTHON ?= python
# PowerShell's inherited PATH places System32 before MSYS. Make recipes rely on
# POSIX utilities such as find, cp, ln, and rm, so prefer the MSYS toolchain;
# otherwise Windows find.exe interprets GNU find arguments and prints
# "FIND: Parameter format not correct" while silently skipping work.
export PATH := /usr/bin:$(PATH)
# GNU Make runs these recipes through MSYS, whose HOME defaults to
# /home/<user>. Native PowerShell and the installed DefenseClaw CLI use
# USERPROFILE instead, so deriving install paths from HOME silently places a
# second copy under C:\msys64\home that PowerShell never executes. Convert the
# native profile path to an MSYS path for recipe compatibility while keeping
# every installed artifact in the real Windows user profile.
USER_HOME := $(shell if [ -n "$$USERPROFILE" ]; then cygpath -u "$$USERPROFILE" 2>/dev/null || printf '%s' "$$USERPROFILE"; else printf '%s' "$$HOME"; fi)
VENV_BIN := $(VENV)/Scripts
EXE      := .exe
else
PYTHON ?= python3
USER_HOME := $(HOME)
VENV_BIN := $(VENV)/bin
EXE      :=
endif

INSTALL_DIR := $(USER_HOME)/.local/bin
DC_EXT_DIR  := $(USER_HOME)/.defenseclaw/extensions/defenseclaw
OC_EXT_DIR  := $(USER_HOME)/.openclaw/extensions/defenseclaw

# _bundle-data is a prerequisite of the target that creates $(VENV), so a
# fresh checkout cannot use the project interpreter while staging its first
# wheel/editable install. The runtime-asset expander is deliberately
# standard-library-only; select the venv interpreter when it already exists
# and otherwise use the host Python available on every supported installer/CI
# platform. Dependency-bearing scripts continue to use $(VENV_BIN)/python.
BOOTSTRAP_PYTHON := $(shell if [ -x "$(VENV_BIN)/python$(EXE)" ]; then printf '%s' "$(VENV_BIN)/python$(EXE)"; elif command -v python3 >/dev/null 2>&1; then command -v python3; elif command -v python >/dev/null 2>&1; then command -v python; else printf '%s' python; fi)

# Resolve newly published stable baselines at execution time. Explicit
# UPGRADE_SMOKE_FROM values still provide a deterministic developer override.
# Dynamic resolution requires the exact candidate in ARGS so only older
# releases can become upgrade baselines; the checked-in development VERSION is
# intentionally not a release-selection fallback.
define run_upgrade_matrix
	@set -eu; \
	from_versions='$(strip $(UPGRADE_SMOKE_FROM))'; \
	target_version=''; \
	set -- $(ARGS); \
	while [ "$$#" -gt 0 ]; do \
		case "$$1" in \
			--target-version) shift; [ "$$#" -gt 0 ] || { echo 'missing value for --target-version' >&2; exit 2; }; target_version="$$1" ;; \
			--target-version=*) target_version="$${1#--target-version=}" ;; \
		esac; \
		shift; \
	done; \
	resolution_dir=''; \
	cleanup() { if [ -n "$$resolution_dir" ]; then rm -rf "$$resolution_dir"; fi; }; \
	trap cleanup EXIT HUP INT TERM; \
	if [ -z "$$from_versions" ]; then \
		[ -n "$$target_version" ] || { echo 'dynamic upgrade matrix requires ARGS="--target-version X.Y.Z ..." (or explicit UPGRADE_SMOKE_FROM)' >&2; exit 2; }; \
		resolution_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/defenseclaw-baselines.XXXXXX")"; \
		$(BOOTSTRAP_PYTHON) scripts/resolve_upgrade_baselines.py \
			--target-version "$$target_version" \
			--output "$$resolution_dir/effective.json"; \
		from_versions="$$( $(BOOTSTRAP_PYTHON) -c \
			'import json, sys; print(" ".join(json.load(open(sys.argv[1], encoding="utf-8"))["published_baselines"]))' \
			"$$resolution_dir/effective.json" )"; \
	fi; \
	$(1) --from-versions "$$from_versions" $(2) $(ARGS)
endef

.PHONY: help all path doctor uninstall quickstart llm-setup \
        build install cli-install dev-install pycli dev-pycli gateway gateway-cross gateway-run start gateway-install \
        plugin plugin-install maybe-openclaw-plugin-install extensions test cli-test cli-test-cov cli-test-snap tui-test gateway-test go-test-cov \
        packaging-macos-test packaging-macos-bundle macos-app-license-check macos-app-upstream-check macos-app-build macos-app-test macos-app-release macos-app-release-verify \
        security-suite-test security-suite-eval \
        connector-matrix-test go-connector-matrix-test py-connector-matrix-test \
        test-verbose test-file lint py-lint go-lint ts-test rego-test clean \
        check check-audit-actions check-error-codes check-schemas telemetry-generate telemetry-check check-grafana-dashboards check-observability-v8-hard-cut check-observability-v8-spec check-v7 check-provider-coverage check-llm-catalog check-version-sync check-upgrade-manifest \
        upgrade-smoke upgrade-smoke-matrix upgrade-refusal-contract-matrix upgrade-developer-activation \
        upgrade-legacy-smoke upgrade-legacy-smoke-matrix upgrade-signed-protocol upgrade-signed-protocol-matrix \
        set-version \
        _bundle-data _source-install-preflight _source-install-dev-preflight _source-dev-install \
        proto proto-tools \
        dist dist-cli dist-gateway dist-plugin dist-sandbox dist-test dist-upgrade-manifest dist-checksums dist-clean

# ---------------------------------------------------------------------------
# Developer workflow help
# ---------------------------------------------------------------------------

help:
	@echo "DefenseClaw source-development workflow"
	@echo ""
	@echo "  make all      Build and activate this exact checkout using your existing"
	@echo "                developer state. This is the normal local development path."
	@echo "  make build    Build artifacts only. Does not install or change managed state."
	@echo "  make check    Run the standard validation suite."
	@echo "  make clean    Remove local build artifacts."
	@echo ""
	@echo "Common developer options:"
	@echo "  make all NO_QUICKSTART=1   rebuild/install without first-run setup"
	@echo "  make all CONNECTOR=none    rebuild/install without connector setup"
	@echo ""
	@echo "Release installation detected? Use: defenseclaw upgrade"
	@echo "Direct 'make install' and scripts/install-dev.sh are strict plumbing targets;"
	@echo "they intentionally do not reclaim an existing managed installation."

# ---------------------------------------------------------------------------
# Version stamping
# ---------------------------------------------------------------------------
# The manually dispatched release workflow owns the candidate version, stamps
# it into an isolated build checkout, and creates the remote tag only after
# every native gate and the protected release approval succeed. A version-only
# PR is not required. Local devs who want to stage a version for a manual smoke
# test of `make dist` can use this target as a friendly wrapper.
#
#   make set-version VERSION=0.4.1
#
# Refuses to run without an explicit VERSION= override — the implicit
# default of $(VERSION) would silently re-stamp the current pinned value.
set-version:
	@if [ -z "$(filter-out $(file < /dev/null),$(MAKEOVERRIDES))" ] || ! echo "$(MAKEOVERRIDES)" | grep -q 'VERSION='; then \
		echo "usage: make set-version VERSION=X.Y.Z" >&2; \
		exit 64; \
	fi
	@scripts/stamp-version.sh "$(VERSION)"

# CI gate that fails when any checked-in version source, lockfile, gateway
# runtime schema, or reviewed source-install identity disagrees. Mirrors the
# contract enforced by scripts/stamp-version.sh and the protected release job.
check-version-sync:
	@python3 scripts/source_release_identity.py check

# ---------------------------------------------------------------------------
# `make all` — one-shot build → install → PATH → quickstart
# ---------------------------------------------------------------------------
# Designed so a fresh clone only needs:
#
#   make all
#
# to reach a working guardrail. Everything downstream (install.sh,
# install-dev.sh, `defenseclaw quickstart`) is wired to behave the
# same way non-interactively, so CI and local dev share one codepath.
#
# Order matters:
#   1. install — produces every binary and links into $(INSTALL_DIR)
#   2. path    — ensures $(INSTALL_DIR) is on the user's shell PATH so
#                `defenseclaw` resolves in *new* shells; current shell
#                gets a reminder to source the rc file.
#   3. quickstart — runs the CLI binary we just built, so even a stale
#                shell PATH does not block the handoff.
#
# We also honour NO_QUICKSTART=1 and NO_PATH=1 as escape hatches for
# CI jobs that only want the binaries.
all: _source-install-dev-preflight
	@$(MAKE) --no-print-directory _source-dev-install
	@$(MAKE) --no-print-directory path
	@$(MAKE) --no-print-directory quickstart
	@$(MAKE) --no-print-directory llm-setup
	@echo ""
	@echo "╭────────────────────────────────────────────────────────────╮"
	@echo "│  DefenseClaw is installed and ready.                       │"
	@echo "╰────────────────────────────────────────────────────────────╯"
	@echo ""
	@echo "Try it out:"
	@echo "  defenseclaw            # launch the TUI"
	@echo "  defenseclaw doctor     # health check"
	@echo "  defenseclaw version    # CLI / gateway / plugin versions"
	@echo ""

path: _source-install-preflight
	@if [ "$${NO_PATH:-0}" = "1" ]; then \
		echo "NO_PATH=1 set — skipping PATH update"; \
	else \
		./scripts/add-to-path.sh "$(INSTALL_DIR)" $${YES:+--yes} || { \
			echo "  PATH update skipped. Add manually:"; \
			echo "    export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
		}; \
	fi

# Run the freshly-installed CLI binary directly so a stale shell PATH
# doesn't invoke an older `defenseclaw` still sitting earlier in PATH.
# The CLI handles its own idempotence, so repeated `make all` is safe.
quickstart: _source-install-preflight
	@profile="$${PROFILE:-observe}"; \
	if [ "$${NO_QUICKSTART:-0}" = "1" ]; then \
		echo "NO_QUICKSTART=1 set — skipping quickstart"; \
	elif [ "$${CONNECTOR:-}" = "none" ]; then \
		echo "CONNECTOR=none set — skipping first-run setup"; \
		echo "  Run later: defenseclaw init"; \
	else \
		if [ -x "$(INSTALL_DIR)/defenseclaw" ]; then \
			dc_bin="$(INSTALL_DIR)/defenseclaw"; \
		elif [ -x "$(VENV)/bin/defenseclaw" ]; then \
			dc_bin="$(VENV)/bin/defenseclaw"; \
		else \
			echo "  Could not locate the defenseclaw binary."; \
			echo "  Developers: run 'make all'. Release installs: run 'defenseclaw upgrade'."; \
			exit 1; \
		fi; \
		if [ -n "$${CONNECTOR:-}" ]; then \
			if ! "$$dc_bin" init --non-interactive --yes \
				--connector "$${CONNECTOR}" \
				--profile "$$profile" \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
				exit 1; \
			fi; \
		elif [ -t 0 ] && [ -t 1 ] && [ "$${CI:-}" != "true" ]; then \
			if ! "$$dc_bin" init \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
				exit 1; \
			fi; \
		else \
			if ! "$$dc_bin" init --non-interactive --yes \
				--profile "$$profile" \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
				exit 1; \
			fi; \
		fi; \
	fi

# Post-install interactive prompt for DEFENSECLAW_LLM_KEY + llm.model.
# Quickstart sets up the config skeleton non-interactively; this target
# fills in the two values that actually require a human (API key, model
# choice). Silently skipped when:
#   - stdin is not a TTY (CI, pipes, `make all < /dev/null`)
#   - NO_LLM_SETUP=1 or YES=1 is set (explicit opt-out)
#   - CI=true (GitHub Actions / GitLab / most CI runners)
# The script itself is idempotent: if both values are already present
# it exits without prompting, so rerunning `make all` is a no-op.
llm-setup: _source-install-preflight
	@if [ "$${NO_LLM_SETUP:-0}" = "1" ] || [ "$${YES:-0}" = "1" ] \
	    || [ "$${CI:-}" = "true" ] || [ ! -t 0 ] || [ ! -t 1 ]; then \
		echo "  Skipping interactive LLM setup (non-TTY or NO_LLM_SETUP=1)."; \
		echo "  Configure later with:"; \
		echo "    defenseclaw setup llm          # unified LLM (key + model, shared by judge + scanners)"; \
		echo "    defenseclaw setup llm --show   # inspect the currently configured LLM"; \
	else \
		./scripts/setup-llm.sh || { \
			echo "  LLM setup exited with errors — rerun with: defenseclaw setup llm"; \
			true; \
		}; \
	fi

# Thin wrappers over the CLI so operators never need to remember whether
# the binary is on PATH yet. Both fall through to the venv binary when
# the installed symlink is missing (e.g. after `make clean`).
doctor:
	@if [ -x "$(INSTALL_DIR)/defenseclaw" ]; then \
		"$(INSTALL_DIR)/defenseclaw" doctor $(ARGS); \
	elif [ -x "$(VENV)/bin/defenseclaw" ]; then \
		"$(VENV)/bin/defenseclaw" doctor $(ARGS); \
	else \
		echo "defenseclaw not installed — run 'make all' first"; exit 1; \
	fi

uninstall:
	@if [ -x "$(INSTALL_DIR)/defenseclaw" ]; then \
		"$(INSTALL_DIR)/defenseclaw" uninstall $(ARGS); \
	elif [ -x "$(VENV)/bin/defenseclaw" ]; then \
		"$(VENV)/bin/defenseclaw" uninstall $(ARGS); \
	else \
		echo "defenseclaw not installed — nothing to uninstall"; \
	fi

# ---------------------------------------------------------------------------
# Aggregate targets
# ---------------------------------------------------------------------------

build: pycli gateway plugin
	@echo ""
	@echo "All components built:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw"
	@echo "  • Go gateway   → ./$(GATEWAY)"
	@echo "  • OpenClaw plugin → $(PLUGIN_DIR)/dist/"
	@echo ""
	@echo "Build only: no installed files or managed state were changed."
	@echo "To activate this exact checkout for development, run 'make all'."
	@echo "For a release-managed installation, run 'defenseclaw upgrade'."

install: _source-install-preflight cli-install gateway-install $(SOURCE_PLUGIN_INSTALL_TARGET)
	@./scripts/source-install-preflight.sh claim \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@echo ""
	@echo "All components installed:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw  (activate with: source $(VENV)/bin/activate)"
	@echo "  • Go gateway   → $(INSTALL_DIR)/$(GATEWAY)"
	@if [ "$${CONNECTOR:-codex}" = "openclaw" ]; then \
		echo "  • OpenClaw plugin → ~/.defenseclaw/extensions/defenseclaw/"; \
	else \
		echo "  • OpenClaw plugin skipped (set CONNECTOR=openclaw to install it)"; \
	fi
	@echo ""
	@echo "Next steps:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw              # launch the interactive TUI (first run starts setup wizard)"
	@echo "  defenseclaw init         # or initialize via CLI (scripting / CI)"
	@echo "  defenseclaw --help       # see all CLI commands"
	@echo ""
	@if [ "$$(uname -s)" = "Linux" ]; then \
		echo "Sandbox mode (Linux):"; \
		echo "  defenseclaw init --sandbox          # create sandbox user + directories"; \
		echo "  defenseclaw setup sandbox            # configure networking + systemd"; \
		echo "  scripts/install-openshell-sandbox.sh  # install openshell-sandbox binary"; \
	else \
		echo "Sandbox mode (Linux only):"; \
		echo "  On a Linux host, use 'defenseclaw init --sandbox' to set up"; \
		echo "  openshell-sandbox standalone mode with network isolation."; \
	fi

maybe-openclaw-plugin-install: _source-install-preflight
	@if [ "$${CONNECTOR:-codex}" = "openclaw" ]; then \
		$(MAKE) plugin-install; \
	else \
		echo "Skipping OpenClaw plugin install (CONNECTOR=$${CONNECTOR:-codex})."; \
	fi

# ---------------------------------------------------------------------------
# Individual build targets
# ---------------------------------------------------------------------------

dev-install: _source-install-preflight
	@./scripts/install-dev.sh

# pycli depends on _bundle-data so every editable install (and the
# downstream `make all` / `make build`) sees the latest bundled
# assets — Grafana dashboards, splunk_local_bridge, guardrail
# policy bundles, codeguard skills. The runtime resolves these via
# importlib.resources.files("defenseclaw") / "_data", which in
# editable mode points straight at cli/defenseclaw/_data/. Without
# the dependency, edits under bundles/local_observability_stack/ or
# policies/guardrail/ silently lag behind every wheel-install
# until someone remembers to run `make dist-cli` (the only other
# call site for _bundle-data). That stale-mirror failure mode bit
# us with the v7 connector-detail dashboard — fixed at the source
# but invisible until a manual cp -r. Keeping the sync attached
# here makes that class of bug structurally impossible.
pycli: _bundle-data
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — install from https://docs.astral.sh/uv/"; exit 1; }
	@find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	uv sync --frozen --no-dev --python 3.12

dev-pycli: pycli
	uv sync --frozen --python 3.12
	@echo ""
	@echo "Done. Activate the environment and run:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw --help"

# ---------------------------------------------------------------------------
# Protobuf regeneration
# ---------------------------------------------------------------------------
# `proto` regenerates the Go stubs for the DefenseClaw ↔ AVC (Secure
# Client) contract at proto/defenseclaw/secureclient/v1/*.proto.
# Tool binaries are installed under .tools/bin so contributors do not
# need protoc-gen-go in their global $GOPATH/bin, and the versions
# are pinned to what the generated files were produced against.
# The generated .pb.go files are committed, so `make gateway` /
# `make build` never invoke `proto` — you only run it when the .proto
# changes.
PROTO_TOOLS_DIR := $(CURDIR)/.tools
PROTO_TOOLS_BIN := $(PROTO_TOOLS_DIR)/bin
PROTOC_GEN_GO_VERSION      := v1.36.5
PROTOC_GEN_GO_GRPC_VERSION := v1.5.1

proto-tools:
	@mkdir -p $(PROTO_TOOLS_BIN)
	@GOBIN=$(PROTO_TOOLS_BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@GOBIN=$(PROTO_TOOLS_BIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto: proto-tools
	@command -v protoc >/dev/null 2>&1 || { echo "protoc not found — brew install protobuf (or apt install protobuf-compiler)"; exit 1; }
	@cd proto/defenseclaw/secureclient/v1 && PATH="$(PROTO_TOOLS_BIN):$$PATH" protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		secureclient.proto
	@echo "Regenerated proto/defenseclaw/secureclient/v1/*.pb.go"

gateway: sync-openclaw-extension
	go build $(GOFLAGS) -o $(GATEWAY)$(EXE) ./cmd/defenseclaw
	$(if $(filter Windows_NT,$(OS)),go run ./internal/tools/windowsresources -target windows_amd64 -executable $(GATEWAY)$(EXE) -component gateway -version $(VERSION) -icon "$(CURDIR)/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png",)
	@echo "Built $(GATEWAY)$(EXE)"
	@echo "  Run with: ./$(GATEWAY)$(EXE)"
	@echo "  Check status: ./$(GATEWAY)$(EXE) status"
ifeq ($(OS),Windows_NT)
	go build -ldflags "-H=windowsgui -X main.version=$(VERSION)" -o $(HOOK_LAUNCHER).exe ./cmd/defenseclaw-hook
	go run ./internal/tools/windowsresources -target windows_amd64 -executable $(HOOK_LAUNCHER).exe -component hook -version $(VERSION) -icon "$(CURDIR)/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"
	@echo "Built $(HOOK_LAUNCHER).exe (Windows GUI subsystem)"
endif

# sync-openclaw-extension copies the runtime files of the DefenseClaw
# OpenClaw plugin into internal/gateway/connector/openclaw_extension so
# //go:embed picks them up at build time. Running it each build keeps the
# embedded tree in lockstep with extensions/defenseclaw/ — no separate
# install step required to enable inspection.
#
# The copy preserves the directory layout under dist/ (policy/,
# scanners/plugin_scanner/, etc.) because dist/index.js imports siblings
# by relative path. Flattening the tree silently breaks plugin load.
#
# Best-effort: a fresh clone has no extensions/defenseclaw/dist/ until
# `make plugin` runs. Forcing every gateway build to first run npm
# would block non-OpenClaw operators (zeptoclaw, codex, claude code)
# who don't need the plugin at all. Instead we drop a placeholder file
# so //go:embed has at least one entry, and the OpenClaw connector
# detects the placeholder at runtime and returns a clear error when
# `Setup` is called for OpenClaw without a built plugin. Operators who
# actually want OpenClaw run `make extensions` (or `make plugin`) first.
sync-openclaw-extension:
	@set -e; \
	embed_dir=internal/gateway/connector/openclaw_extension; \
	plugin_dist=$(PLUGIN_DIR)/dist; \
	if [ ! -d "$$plugin_dist" ] || [ -z "$$(ls -A "$$plugin_dist" 2>/dev/null)" ]; then \
	  if [ -f "$$embed_dir/.placeholder" ] || [ ! -d "$$embed_dir" ] \
	      || [ -z "$$(ls -A "$$embed_dir" 2>/dev/null | grep -v '^\.placeholder$$' || true)" ]; then \
	    mkdir -p "$$embed_dir"; \
	    printf '%s\n' "OpenClaw extension not built." \
	      "Run 'make extensions' (or 'make plugin') to populate the embedded tree." \
	      > "$$embed_dir/.placeholder"; \
	    echo "  • OpenClaw extension dist/ missing — embedded a placeholder (run 'make extensions' to enable OpenClaw)"; \
	  else \
	    echo "  • OpenClaw extension dist/ missing — keeping the previously synced tree under $$embed_dir/"; \
	  fi; \
	  exit 0; \
	fi; \
	rm -rf "$$embed_dir"; \
	mkdir -p "$$embed_dir/node_modules"; \
	cp $(PLUGIN_DIR)/package.json "$$embed_dir/"; \
	cp $(PLUGIN_DIR)/openclaw.plugin.json "$$embed_dir/"; \
	if command -v rsync >/dev/null 2>&1; then \
	  rsync -a \
	    --exclude='__tests__' --exclude='*.d.ts' --exclude='*.d.ts.map' --exclude='*.js.map' \
	    $(PLUGIN_DIR)/dist/ "$$embed_dir/dist/"; \
	else \
	  mkdir -p "$$embed_dir/dist"; \
	  (cd $(PLUGIN_DIR)/dist && find . -name "*.js" -not -path "*/__tests__/*" -print0 \
	    | while IFS= read -r -d '' f; do \
	        mkdir -p "../../../$$embed_dir/dist/$$(dirname "$$f")"; \
	        cp "$$f" "../../../$$embed_dir/dist/$$f"; \
	      done); \
	fi; \
	for dep in js-yaml argparse; do \
	  if [ -d "$(PLUGIN_DIR)/node_modules/$$dep" ]; then \
	    cp -R "$(PLUGIN_DIR)/node_modules/$$dep" "$$embed_dir/node_modules/"; \
	  fi; \
	done; \
	echo "  • Synced OpenClaw extension → $$embed_dir/"

# extensions — explicit, opt-in build of the OpenClaw TypeScript plugin
# followed by an embed sync. Only OpenClaw operators need this; the
# gateway itself builds without it (sync-openclaw-extension drops a
# placeholder that the OpenClaw connector detects at runtime). Use this
# target whenever you change anything under extensions/defenseclaw/ and
# want the change baked into the next gateway binary.
extensions: plugin sync-openclaw-extension
	@echo "  • OpenClaw extension is built and embedded — rebuild the gateway with 'make gateway'"

gateway-cross: sync-openclaw-extension
	@test -n "$(GOOS)" -a -n "$(GOARCH)" || { echo "Usage: make gateway-cross GOOS=linux GOARCH=amd64"; exit 1; }
	@if [ "$(GOOS)" = "windows" ] && [ "$(GOARCH)" != "amd64" ]; then \
		echo "native Windows release resources currently certify only GOARCH=amd64" >&2; exit 1; \
	fi
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(BINARY)-$(GOOS)-$(GOARCH) ./cmd/defenseclaw
	@if [ "$(GOOS)" = "windows" ]; then \
		go run ./internal/tools/windowsresources -target windows_$(GOARCH) \
			-executable $(BINARY)-$(GOOS)-$(GOARCH) -component gateway -version $(VERSION) \
			-icon "$(CURDIR)/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"; \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
			-ldflags "-H=windowsgui -X main.version=$(VERSION)" \
			-o $(HOOK_LAUNCHER)-$(GOOS)-$(GOARCH).exe ./cmd/defenseclaw-hook; \
		go run ./internal/tools/windowsresources -target windows_$(GOARCH) \
			-executable $(HOOK_LAUNCHER)-$(GOOS)-$(GOARCH).exe -component hook -version $(VERSION) \
			-icon "$(CURDIR)/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"; \
	fi
	@echo "Built $(BINARY)-$(GOOS)-$(GOARCH)"

gateway-run: gateway
	./$(GATEWAY)$(EXE)

start: gateway
	@./scripts/start.sh $(ARGS)

plugin:
	@command -v npm >/dev/null 2>&1 || { echo "npm not found — install Node.js from https://nodejs.org/"; exit 1; }
	cp internal/configs/providers.json $(PLUGIN_DIR)/src/providers.json
	cd $(PLUGIN_DIR) && NODE_ENV=development npm ci --include=dev && npm run build
	@echo ""
	@echo "Built OpenClaw plugin → $(PLUGIN_DIR)/dist/"
	@echo "  Install with: make plugin-install"

# ---------------------------------------------------------------------------
# Individual install targets
# ---------------------------------------------------------------------------

# Source installs are developer tooling, not an alternate release upgrader.
# Refuse any release-managed or different-checkout installation before an
# installed entry point or gateway can be replaced.  A marker makes subsequent
# rebuilds from this exact checkout idempotent; the legacy exact CLI symlink
# check admits same-checkout installs made before the marker existed.
_source-install-preflight:
	@./scripts/source-install-preflight.sh check \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"

# `make all` is the explicit developer-machine reinstall workflow.  It may
# reclaim markerless managed state only when the installed CLI is already the
# exact symlink/copy owned by this checkout.  Direct install targets remain
# fail-closed so they cannot become an alternate release upgrader.
_source-install-dev-preflight:
	@./scripts/source-install-preflight.sh dev-check \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"

# Developer-only publication used by `make all`.  Keep the dev modes literal
# here so ordinary install targets cannot inherit or opt into the reclaim path.
_source-dev-install: _source-install-dev-preflight
	@$(MAKE) --no-print-directory pycli
	@./scripts/source-install-preflight.sh dev-ensure-dir \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@./scripts/source-install-preflight.sh dev-publish-cli \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@if [ -x "$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" ]; then \
		python3 ./scripts/source-install-publish.py symlink \
			"$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" "$(INSTALL_DIR)/litellm$(EXE)" || true; \
	fi
	@for tool in skill-scanner skill-scanner-api skill-scanner-pre-commit \
	             mcp-scanner mcp-scanner-api; do \
		src="$(CURDIR)/$(VENV_BIN)/$$tool$(EXE)"; \
		if [ -x "$$src" ]; then \
			python3 ./scripts/source-install-publish.py symlink \
				"$$src" "$(INSTALL_DIR)/$$tool$(EXE)" || true; \
		fi; \
	done
	@$(MAKE) --no-print-directory gateway
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		/usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway $(GATEWAY)$(EXE) || exit 1; \
	fi
	@./scripts/source-install-preflight.sh dev-publish-gateway \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@./scripts/source-install-preflight.sh dev-claim \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@$(MAKE) --no-print-directory $(SOURCE_PLUGIN_INSTALL_TARGET)
	@echo ""
	@echo "All components installed:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw  (activate with: source $(VENV)/bin/activate)"
	@echo "  • Go gateway   → $(INSTALL_DIR)/$(GATEWAY)"
	@if [ "$${CONNECTOR:-codex}" = "openclaw" ]; then \
		echo "  • OpenClaw plugin → ~/.defenseclaw/extensions/defenseclaw/"; \
	else \
		echo "  • OpenClaw plugin skipped (set CONNECTOR=openclaw to install it)"; \
	fi

cli-install: _source-install-preflight
	@$(MAKE) --no-print-directory pycli
	@./scripts/source-install-preflight.sh ensure-dir \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@./scripts/source-install-preflight.sh publish-cli \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@if [ -x "$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" ]; then \
		python3 ./scripts/source-install-publish.py symlink \
			"$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" "$(INSTALL_DIR)/litellm$(EXE)" || true; \
	fi
	@# Expose the scanner entry points (skill-scanner, mcp-scanner,
	@# plus the -api / -pre-commit siblings) on PATH via the same
	@# ~/.local/bin symlink pattern we already use for the main CLI.
	@# Without these, a fresh `make all` leaves `defenseclaw doctor`
	@# reporting '[FAIL] Scanner: skill-scanner — not on PATH' because
	@# the binaries live in $(VENV)/bin but $(VENV)/bin is never on the
	@# operator's shell PATH by design. `|| true` keeps this optional
	@# so old venvs that somehow lack one of the entry points don't
	@# break install; the doctor check surfaces any real misses.
	@for tool in skill-scanner skill-scanner-api skill-scanner-pre-commit \
	             mcp-scanner mcp-scanner-api; do \
		src="$(CURDIR)/$(VENV_BIN)/$$tool$(EXE)"; \
		if [ -x "$$src" ]; then \
			python3 ./scripts/source-install-publish.py symlink \
				"$$src" "$(INSTALL_DIR)/$$tool$(EXE)" || true; \
		fi; \
	done
	@echo "Installed defenseclaw CLI to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

gateway-install: _source-install-preflight cli-install
	@$(MAKE) --no-print-directory gateway
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		/usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway $(GATEWAY)$(EXE) || exit 1; \
	fi
	@./scripts/source-install-preflight.sh publish-gateway \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@./scripts/source-install-preflight.sh claim \
		"$(CURDIR)" "$(INSTALL_DIR)" "$(VENV_BIN)" \
		"defenseclaw$(EXE)" "$(GATEWAY)$(EXE)"
	@echo "Installed $(GATEWAY)$(EXE) to $(INSTALL_DIR)"
	@# On Unix, a running sidecar kept the old inode; tell the operator so
	@# they know a restart is needed to pick up the new build.
	@# Use pgrep -x against the *basename* only — `pgrep -f "$(GATEWAY)"`
	@# matches this very make invocation ("make gateway-install") and
	@# any editor/tail window with the binary path on its cmdline, so
	@# it would fire a false "sidecar is running" hint on every build.
	@if [ "$(OS)" != "Windows_NT" ] && pgrep -x "$(GATEWAY)" >/dev/null 2>&1; then \
		echo "  Gateway sidecar is running an older build — restart with:"; \
		echo "    $(INSTALL_DIR)/$(GATEWAY)$(EXE) restart"; \
	fi
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

plugin-install: _source-install-preflight gateway-install
	@$(MAKE) --no-print-directory plugin
	@if [ ! -f $(PLUGIN_DIR)/dist/index.js ]; then \
		echo "Plugin not built — run 'make plugin' first"; \
		exit 1; \
	fi
	@rm -rf $(DC_EXT_DIR)
	@mkdir -p $(DC_EXT_DIR)
	@cp $(PLUGIN_DIR)/package.json $(DC_EXT_DIR)/
	@test -f $(PLUGIN_DIR)/openclaw.plugin.json && cp $(PLUGIN_DIR)/openclaw.plugin.json $(DC_EXT_DIR)/ || true
	@cp -r $(PLUGIN_DIR)/dist $(DC_EXT_DIR)/
	@if [ -d $(PLUGIN_DIR)/node_modules ]; then \
		mkdir -p $(DC_EXT_DIR)/node_modules; \
		for dep in js-yaml argparse; do \
			if [ -d $(PLUGIN_DIR)/node_modules/$$dep ]; then \
				cp -r $(PLUGIN_DIR)/node_modules/$$dep $(DC_EXT_DIR)/node_modules/; \
			fi; \
		done; \
	fi
	@if [ -d $(OC_EXT_DIR) ]; then \
		rm -rf $(OC_EXT_DIR)/dist; \
		cp $(PLUGIN_DIR)/package.json $(OC_EXT_DIR)/; \
		test -f $(PLUGIN_DIR)/openclaw.plugin.json && cp $(PLUGIN_DIR)/openclaw.plugin.json $(OC_EXT_DIR)/ || true; \
		cp -r $(PLUGIN_DIR)/dist $(OC_EXT_DIR)/; \
		echo "Synced OpenClaw plugin to $(OC_EXT_DIR)"; \
	fi
	@echo "Installed OpenClaw plugin to $(DC_EXT_DIR)"
	@echo "  Run 'defenseclaw setup guardrail' to register with OpenClaw (first time only)"

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

test: cli-test gateway-test

cli-test: _bundle-data
	$(VENV)/bin/python -m pytest cli/tests -q

cli-test-cov: _bundle-data
	$(VENV)/bin/python -m pytest cli/tests/ -v --tb=short --cov=defenseclaw --cov-report=xml:coverage-py.xml

cli-test-snap:
	$(VENV)/bin/python -m pytest cli/tests/tui -q $(if $(UPDATE),--snapshot-update,)

gateway-test: sync-openclaw-extension
	go test -race -timeout $(GO_TEST_TIMEOUT) ./internal/gateway/ ./test/... -v

# packaging-macos-test runs the pure-bash unit tests for the macOS installer
# scripts under packaging/macos/. They don't touch /Library, sudo, or
# launchctl and are safe to run on any macOS or Linux dev host.
packaging-macos-test:
	packaging/macos/tests/run_tests.sh

# packaging-macos-bundle assembles a shippable folder + tarball containing
# the prebuilt gateway binary alongside the install / uninstall scripts.
# The bundle is fully self-contained — no repo tree required at install
# time. Layout:
#
#   defenseclaw-macos-$(VERSION)-$(GOOS)-$(GOARCH)/
#     defenseclaw                      (binary; installed as .../bin/defenseclaw-gateway)
#     install.sh                       (calls the binary next to it)
#     uninstall.sh
#     com.defenseclaw.gateway.plist    (installed to /Library/LaunchDaemons)
#     lib/installer_lib.sh
#     lib/scrub_agent_configs.py
#     README.md                        (short usage)
#
# Ships as dist/defenseclaw-macos-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz.
#
# Overrides: GOOS/GOARCH cross-compile the gateway.
BUNDLE_GOOS  ?= darwin
# Universal (x86_64 + arm64 via lipo) is the default for macOS drops so the
# packaging team ships one artifact for both Intel and Apple Silicon. Override
# with BUNDLE_GOARCH=amd64 or =arm64 for a single-arch bundle.
BUNDLE_GOARCH ?= universal
BUNDLE_NAME  := defenseclaw-macos-$(VERSION)-$(BUNDLE_GOOS)-$(BUNDLE_GOARCH)
BUNDLE_DIR   := $(DIST_DIR)/$(BUNDLE_NAME)
# BUNDLE_LDFLAGS is passed to `go build -ldflags <value>` as a single
# argument (no shell re-parsing / eval).
BUNDLE_LDFLAGS := -X main.version=$(VERSION)
# BUNDLE_TAGS is the comma-separated `go build -tags` value applied to
# the packaged gateway binary. The macOS bundle ships as the managed
# distribution and pulls the managed cloud auth provider via
# internal/managed/cloudreg/provider_cisco.go. Override to "" only for
# local packaging tests where the private overlay isn't available; the
# resulting binary will fail-closed under managed_enterprise mode.
BUNDLE_TAGS  ?= cmid
# CMID_OVERLAY is the absolute (or repo-relative) path to the real
# cloudreg provider_cisco.go file — the one that imports the managed
# cloud auth module. The OSS working tree only ships a stub at that
# location so `go build`/`go test`/`go mod tidy` succeed in a clean
# environment with no private-registry access. Release builds pass
# CMID_OVERLAY=<path> plus CMID_VERSION=<pseudo-version>; the bundle
# script swaps the overlay in, `go get`s the pinned version, builds,
# then restores the stub from a snapshot whether the build succeeded or
# failed.
#
# Example (release):
#   make packaging-macos-bundle \
#     CMID_OVERLAY=/path/to/private/provider_cisco.go \
#     CMID_VERSION=v0.0.0-20260708144546-897b54f9678e
CMID_OVERLAY ?=
CMID_VERSION ?=

packaging-macos-bundle:
	@scripts/build-macos-bundle.sh \
	    "$(BUNDLE_GOOS)" \
	    "$(BUNDLE_GOARCH)" \
	    "$(BUNDLE_NAME)" \
	    "$(BUNDLE_DIR)" \
	    "$(DIST_DIR)" \
	    "$(VERSION)" \
	    "$(BUNDLE_LDFLAGS)" \
	    "$(BUNDLE_TAGS)" \
	    "$(CMID_OVERLAY)" \
	    "$(CMID_VERSION)"

# Native SwiftUI companion-app checks and release packaging. The release target
# builds a runtime-bearing drag-to-Applications DMG plus an app-only self-update
# zip. Both are ad-hoc signed by default; scripts/build-macos-app-release.sh
# switches to Developer ID signing/notarization when credentials are present.
macos-app-license-check:
	python3 scripts/macos_license_headers.py

macos-app-upstream-check:
	python3 scripts/check-macos-upstream.py

macos-app-build: macos-app-license-check
	xcodebuild \
	    -project macos/DefenseClawMac/DefenseClawMac.xcodeproj \
	    -scheme DefenseClawMac \
	    -configuration Release \
	    -destination 'generic/platform=macOS' \
	    -derivedDataPath build/macos-app/DerivedData \
	    ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
	    MARKETING_VERSION="$(VERSION)" \
	    CODE_SIGNING_ALLOWED=NO \
	    build

macos-app-test:
	macos/DefenseClawMac/script/test_connector_onboarding.sh
	macos/DefenseClawMac/script/test_first_run_connector_selection.sh
	macos/DefenseClawMac/script/test_numeric_safety.sh
	macos/DefenseClawMac/script/test_output_safety.sh
	macos/DefenseClawMac/script/test_secret_file_safety.sh
	macos/DefenseClawMac/script/test_runtime_install_filesystem.sh
	macos/DefenseClawMac/script/test_app_state_signal_safety.sh
	macos/DefenseClawMac/script/test_update_checker_verification.sh
	macos/DefenseClawMac/script/test_update_checker_safety.sh
	macos/DefenseClawMac/script/test_installation_context.sh
	macos/DefenseClawMac/script/test_local_model_discovery.sh
	macos/DefenseClawMac/script/test_setup_definitions_parity.sh
	$(MAKE) macos-app-build

macos-app-release: macos-app-license-check extensions dist-cli
	scripts/build-macos-app-release.sh "$(VERSION)" "$(DIST_DIR)"

macos-app-release-verify:
	scripts/verify-macos-app-release.sh "$(VERSION)" "$(DIST_DIR)"

# security-suite-test runs the deterministic security + PII coverage suite
# (regex layer + stubbed LLM-judge layer) plus the regex severity benchmark.
# No LLM key or running gateway required; this is the CI-safe tier and is
# also covered by `make gateway-test`.
security-suite-test:
	go test ./internal/gateway/ -run 'TestSecuritySuiteRegex|TestSecuritySuiteJudge|TestSeverityBenchmark' -count=1 -v

# security-suite-eval scores the judge corpus against a live model and runs
# the full eval corpus. Requires DEFENSECLAW_LLM_KEY. Not run in CI.
security-suite-eval:
	GUARDRAIL_BENCHMARK_LLM=1 go test ./internal/gateway/ -run '^(TestSecuritySuiteJudge|TestEvalInjectionJudge|TestEvalPIIJudge|TestEvalExfilJudge|TestEvalToolInjectionJudge)$$' -count=1 -timeout 120m -v

go-test-cov: sync-openclaw-extension
	go test -race -count=1 -timeout $(GO_TEST_TIMEOUT) -coverprofile=coverage.out ./...

connector-matrix-test: go-connector-matrix-test py-connector-matrix-test

go-connector-matrix-test: sync-openclaw-extension
	go test -count=1 \
		./internal/cli \
		./internal/config \
		./internal/gateway \
		./internal/gateway/connector \
		./test/e2e \
		-run 'Connector|Hook|CodeGuard|Telemetry|OTLP|AgentHook|Mode|Setup|Teardown|Capability|Matrix'

py-connector-matrix-test:
	$(VENV)/bin/python -m pytest -q \
		cli/tests/test_agent_discovery.py \
		cli/tests/test_cmd_guardrail_matrix.py \
		cli/tests/test_cmd_init.py \
		cli/tests/test_codeguard_opt_in.py \
		cli/tests/test_connector_mcp_writers.py \
		cli/tests/test_connector_paths.py \
		cli/tests/test_install_smoke.py \
		cli/tests/test_scan_ux_connector_matrix.py

ts-test:
	cp internal/configs/providers.json $(PLUGIN_DIR)/src/providers.json
	cd $(PLUGIN_DIR) && \
		if [ ! -x node_modules/.bin/vitest ]; then \
			NODE_ENV=development npm ci --include=dev; \
		fi && \
		npx --no-install vitest run

rego-test:
	PATH="$(GOBIN):$(PATH)" opa test policies/rego/ -v

test-verbose:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v --failfast

test-file:
	@test -n "$(FILE)" || { echo "Usage: make test-file FILE=test_config"; exit 1; }
	$(VENV)/bin/python -m unittest cli.tests.$(FILE) -v

# ---------------------------------------------------------------------------
# v7 parity gates — prevent drift between Go (source of truth),
# Python, and JSON schemas. Adding a new audit action / error code
# / schema? Run `make check` locally before pushing; CI runs this
# too and will fail the build on drift.
# ---------------------------------------------------------------------------

check: check-v7 check-observability-v8-hard-cut check-observability-v8-spec check-grafana-dashboards check-provider-coverage check-llm-catalog check-upgrade-manifest

check-v7: check-audit-actions check-audit-no-raw-literals check-error-codes check-schemas
	@echo "check-v7: all parity gates passed."

check-audit-actions:
	@$(VENV)/bin/python scripts/check_audit_actions.py

check-audit-no-raw-literals:
	@$(VENV)/bin/python scripts/check_audit_no_raw_literals.py

check-error-codes:
	@$(VENV)/bin/python scripts/check_error_codes.py

check-schemas:
	@$(VENV)/bin/python scripts/check_schemas.py

telemetry-generate:
	@$(VENV)/bin/python scripts/generate_telemetry_registry.py --write

telemetry-check:
	@$(VENV)/bin/python scripts/generate_telemetry_registry.py --check

# Semantic hard-cut gate: v7 may remain only inside the explicit
# upgrade/recovery boundaries. It checks forbidden ownership paths and
# patterns, not fragile repository-wide inventory totals.
check-observability-v8-hard-cut:
	@$(VENV)/bin/python scripts/check_observability_v8_hard_cut.py

check-observability-v8-spec:
	@$(VENV)/bin/python scripts/check_observability_v8_spec.py \
		--package docs/design/observability-v8

check-grafana-dashboards: _bundle-data
	@$(VENV)/bin/python scripts/check_grafana_dashboards.py --require-packaged

# check-provider-coverage runs the shared test/testdata/llm-endpoints.json
# corpus through both the Go shape detector (provider_coverage_test.go)
# and the TS interceptor (provider-coverage.test.ts). A drift between
# the two sides — e.g. a new provider added to providers.json but
# never exercised — would be the exact "silent bypass" failure mode
# Layer 4 of the robust-guardrail plan is designed to surface.
check-provider-coverage: sync-openclaw-extension
	@echo "==> provider coverage (Go)"
	@go test ./internal/gateway -run TestProviderCoverageCorpus -count=1
	@echo "==> provider coverage (TS)"
	cp internal/configs/providers.json $(PLUGIN_DIR)/src/providers.json
	cd $(PLUGIN_DIR) && \
		if [ ! -x node_modules/.bin/vitest ]; then \
			NODE_ENV=development npm ci --include=dev; \
		fi && \
		npx --prefer-offline --no-install vitest run src/__tests__/provider-coverage.test.ts
	@echo "check-provider-coverage: corpus is in sync across Go + TS."

# check-llm-catalog cross-references the suggested model ids in
# bundles/llm/model_catalog.json against LiteLLM's bundled registry,
# failing on ids LiteLLM no longer knows or has marked deprecated. The
# curated catalog carries provider/auth/region metadata LiteLLM does not
# model (so it stays hand-maintained), but the model list still rots as
# providers ship and retire models — this gate catches that drift.
check-llm-catalog:
	@$(VENV)/bin/python scripts/check_llm_catalog.py

check-upgrade-manifest:
	@python3 scripts/generate-upgrade-manifest.py --check

upgrade-smoke:
	@scripts/test-upgrade-protocol-release.sh --refusal-contract-only $(ARGS)

upgrade-smoke-matrix:
	$(call run_upgrade_matrix,scripts/test-upgrade-protocol-release.sh,--refusal-contract-only)

upgrade-refusal-contract-matrix: upgrade-smoke-matrix

upgrade-developer-activation:
	@scripts/test-developer-target-activation.sh $(ARGS)

upgrade-legacy-smoke:
	@scripts/test-upgrade-release.sh $(ARGS)

upgrade-legacy-smoke-matrix:
	$(call run_upgrade_matrix,scripts/test-upgrade-release.sh,)

upgrade-signed-protocol:
	@scripts/test-upgrade-protocol-release.sh $(ARGS)

upgrade-signed-protocol-matrix:
	$(call run_upgrade_matrix,scripts/test-upgrade-protocol-release.sh,)

# ---------------------------------------------------------------------------
# Lint targets
# ---------------------------------------------------------------------------

lint: py-lint go-lint
	$(VENV)/bin/python -m py_compile cli/defenseclaw/main.py

py-lint:
	$(RUFF) check cli/defenseclaw/

go-lint: sync-openclaw-extension
	@# gofmt drift is the #1 review comment on every PR, so fail fast
	@# on it before running the heavier analyzers.
	@unformatted=$$(gofmt -l $$(git ls-files '*.go') 2>/dev/null); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$unformatted" | sed 's/^/  /'; \
		echo "Run 'gofmt -w \$$(git ls-files '*.go')' to fix."; \
		exit 1; \
	fi
	@tmp=$$(mktemp); \
	status=0; \
	if PATH="$(GOBIN):$(PATH)" golangci-lint run >"$$tmp" 2>&1; then \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		exit 0; \
	else \
		status=$$?; \
	fi; \
	if [ $$status -eq 127 ] || grep -qE "used to build golangci-lint is lower than the targeted Go version|package requires newer Go version" "$$tmp"; then \
		cat "$$tmp"; \
		echo "golangci-lint is unavailable or does not yet support this repo's Go toolchain; falling back to 'go vet ./...'"; \
		rm -f "$$tmp"; \
		go vet ./...; \
		exit $$?; \
	fi; \
	cat "$$tmp"; \
	rm -f "$$tmp"; \
	exit $$status

# ---------------------------------------------------------------------------
# Distribution targets — build release artifacts into dist/
# ---------------------------------------------------------------------------

dist: dist-cli dist-gateway dist-plugin dist-sandbox dist-upgrade-manifest dist-checksums
	@echo ""
	@echo "Unsigned release-build inputs:"
	@ls -lh $(DIST_DIR)/
	@echo ""
	@echo "Local source install:"
	@echo "  make install"
	@echo "  NOTE: $(DIST_DIR)/ is not authenticated installer input for 0.8.4+."
	@echo "  The protected release workflow wraps, signs, seals, and tests these inputs."
	@echo ""
	@echo "Cut a release (the protected workflow creates the tag + assets atomically):"
	@echo "  Actions UI -> 'Release' workflow -> Run workflow -> enter X.Y.Z"
	@echo "  Or from the CLI: gh workflow run release.yaml --ref main -f version=X.Y.Z"
	@echo ""
	@echo "  NOTE: version must be bare X.Y.Z, no 'v' prefix — the release"
	@echo "  workflow + scripts/install.sh + 'defenseclaw upgrade' all"
	@echo "  resolve artifacts under https://github.com/.../releases/tag/X.Y.Z"

dist-cli: _bundle-data
	@mkdir -p $(DIST_DIR)
	@rm -rf build cli/*.egg-info
	@find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	uv build --wheel --out-dir $(DIST_DIR)

_bundle-data:
	@mkdir -p cli/defenseclaw/_data/policies/rego
	@mkdir -p cli/defenseclaw/_data/policies/openshell
	@mkdir -p cli/defenseclaw/_data/policies/guardrail
	@mkdir -p cli/defenseclaw/_data/scripts
	@mkdir -p cli/defenseclaw/_data/envvars
	@mkdir -p cli/defenseclaw/_data/skills
	@mkdir -p cli/defenseclaw/_data/splunk_local_bridge
	@mkdir -p cli/defenseclaw/_data/local_observability_stack
	@mkdir -p cli/defenseclaw/_data/llm
	@mkdir -p cli/defenseclaw/_data/config/v8
	@rm -rf cli/defenseclaw/_data/telemetry/v8
	@mkdir -p cli/defenseclaw/_data/telemetry/v8
	@rm -rf cli/defenseclaw/_data/policies/guardrail/default
	@rm -rf cli/defenseclaw/_data/policies/guardrail/strict
	@rm -rf cli/defenseclaw/_data/policies/guardrail/permissive
	@rm -rf cli/defenseclaw/_data/splunk_o11y_dashboards
	cp policies/rego/*.rego cli/defenseclaw/_data/policies/rego/
	rm -f cli/defenseclaw/_data/policies/rego/*_test.rego
	cp policies/rego/data.json cli/defenseclaw/_data/policies/rego/
	cp policies/*.yaml cli/defenseclaw/_data/policies/
	cp policies/openshell/*.rego cli/defenseclaw/_data/policies/openshell/
	cp policies/openshell/*.yaml cli/defenseclaw/_data/policies/openshell/
	cp -r policies/guardrail/default cli/defenseclaw/_data/policies/guardrail/
	cp -r policies/guardrail/strict cli/defenseclaw/_data/policies/guardrail/
	cp -r policies/guardrail/permissive cli/defenseclaw/_data/policies/guardrail/
	@# Use the canonical generator without repairing tracked docs before CI checks.
	$(PYTHON) scripts/gen_envvars_docs.py --bundle-only
	cp scripts/install-openshell-sandbox.sh cli/defenseclaw/_data/scripts/
	cp -r skills/codeguard cli/defenseclaw/_data/skills/
	@# Curated LLM model catalog consumed by `defenseclaw setup llm` and the
	@# Textual TUI model picker via importlib.resources. Tracked source lives
	@# at bundles/llm/; _data/llm/ is the gitignored build-staging copy.
	cp bundles/llm/model_catalog.json cli/defenseclaw/_data/llm/
	@# v8 config contracts are canonical under schemas/. The wheel receives
	@# exact build-staging copies so importlib.resources works after install.
	cp schemas/config/v8/defenseclaw-config.schema.json cli/defenseclaw/_data/config/v8/
	cp schemas/config/v8/reference/observability.yaml cli/defenseclaw/_data/config/v8/
	cp schemas/config/v8/reference/observability.md cli/defenseclaw/_data/config/v8/
	@# Git stores the reproducible telemetry runtime artifacts as deterministic
	@# gzip members. Wheels keep the stable public contract: exact raw JSON under
	@# the same six resource names used by installed CLI code.
	"$(BOOTSTRAP_PYTHON)" scripts/telemetry_runtime_assets.py \
		--root . --stage cli/defenseclaw/_data/telemetry/v8
	@# splunk_local_bridge and local_observability_stack are bind-mounted by Docker
	@# (Grafana, Loki, Splunk, etc.) when `defenseclaw obs up` is running. Prefer
	@# rsync-with-delete over `rm -rf && cp -r` because Docker Desktop on macOS
	@# captures the directory inode at container start time; replacing the inode
	@# silently empties the in-container view of the bind-mounted volume until the
	@# container is recreated. rsync --inplace --delete keeps the inode stable,
	@# mutates files in place, and prunes anything no longer in bundles/ so
	@# dashboard / dashcfg edits propagate without restarting the obs stack.
	@#
	@# Hosted Windows runners ship no rsync (`make install` for the connector
	@# contract matrix died here with CreateProcess failed). Fall back to a plain
	@# mirror there. That fallback loses inode stability during package staging;
	@# the runtime controller refreshes the user's seeded stack with atomic file
	@# replacement on every supported OS. Mirrors the rsync-or-cp guard in
	@# sync-openclaw-extension above.
	@for d in splunk_local_bridge local_observability_stack; do \
	  if command -v rsync >/dev/null 2>&1; then \
	    rsync -a --delete --inplace "bundles/$$d/" "cli/defenseclaw/_data/$$d/"; \
	  else \
	    rm -rf "cli/defenseclaw/_data/$$d"; \
	    mkdir -p "cli/defenseclaw/_data/$$d"; \
	    cp -R "bundles/$$d/." "cli/defenseclaw/_data/$$d/"; \
	  fi; \
	done
	cp -r bundles/splunk_o11y_dashboards cli/defenseclaw/_data/
	cp -r policies/openshell cli/defenseclaw/_data/policies/openshell

dist-gateway:
	@mkdir -p $(DIST_DIR)
	@for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		goos=$${pair%%/*}; goarch=$${pair##*/}; \
		echo "Building gateway $${goos}/$${goarch}..."; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(DIST_DIR)/$(GATEWAY)-$${goos}-$${goarch} \
			./cmd/defenseclaw; \
	done
	@echo "Gateway binaries built for all platforms"

dist-plugin: plugin
	@mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/defenseclaw-plugin-$(VERSION).tar.gz \
		-C $(PLUGIN_DIR) \
		package.json openclaw.plugin.json dist/ \
		$$(cd $(PLUGIN_DIR) && for dep in js-yaml argparse; do \
			[ -d "node_modules/$$dep" ] && echo "node_modules/$$dep"; \
		done)
	@echo "Plugin tarball built"

dist-sandbox:
	@mkdir -p $(DIST_DIR)/sandbox/policies $(DIST_DIR)/sandbox/scripts
	cp policies/openshell/*.rego $(DIST_DIR)/sandbox/policies/
	cp policies/openshell/*.yaml $(DIST_DIR)/sandbox/policies/
	cp scripts/install-openshell-sandbox.sh $(DIST_DIR)/sandbox/scripts/
	chmod +x $(DIST_DIR)/sandbox/scripts/install-openshell-sandbox.sh
	@echo "Sandbox artifacts copied to $(DIST_DIR)/sandbox/"

dist-test:
	@mkdir -p $(DIST_DIR)/test
	cp scripts/test-proxy-sandbox.py $(DIST_DIR)/test/
	cp scripts/test-e2e-tool-block.sh $(DIST_DIR)/test/
	cp scripts/test-e2e-sandbox-policy-diff.sh $(DIST_DIR)/test/ 2>/dev/null || true
	cp scripts/test-e2e-cli.py $(DIST_DIR)/test/ 2>/dev/null || true
	cp scripts/test-e2e-spark.sh $(DIST_DIR)/test/ 2>/dev/null || true
	cp scripts/test-e2e-mac.sh $(DIST_DIR)/test/ 2>/dev/null || true
	cp scripts/bundle-sandbox-test.sh $(DIST_DIR)/test/ 2>/dev/null || true
	chmod +x $(DIST_DIR)/test/*.sh 2>/dev/null || true
	@echo "Test scripts copied to $(DIST_DIR)/test/"

dist-upgrade-manifest:
	@mkdir -p $(DIST_DIR)
	python3 scripts/generate-upgrade-manifest.py --out $(DIST_DIR)/upgrade-manifest.json

dist-checksums:
	@test -d $(DIST_DIR) || { echo "Run 'make dist' first"; exit 1; }
	cd $(DIST_DIR) && find . -type f ! -name checksums.txt ! -name checksums.txt.sig ! -name checksums.txt.pem | sed 's#^\./##' | sort | xargs shasum -a 256 > checksums.txt
	@echo "Checksums written to $(DIST_DIR)/checksums.txt"

dist-clean:
	rm -rf $(DIST_DIR)
	rm -rf cli/defenseclaw/_data
	rm -rf sandbox-test-*

clean:
	rm -f $(GATEWAY) $(GATEWAY)$(EXE) $(HOOK_LAUNCHER).exe $(BINARY)-linux-* $(BINARY)-darwin-* $(HOOK_LAUNCHER)-windows-*.exe
	rm -rf $(VENV) cli/*.egg-info
	rm -rf $(PLUGIN_DIR)/dist $(PLUGIN_DIR)/node_modules
	rm -f coverage.out coverage-py.xml
	rm -rf cli/defenseclaw/_data
	rm -rf build/macos-app
	find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
