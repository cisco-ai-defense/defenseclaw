BINARY      := defenseclaw
GATEWAY     := defenseclaw-gateway
VERSION     := 0.8.0
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
VENV        := .venv
GOBIN       := $(shell go env GOPATH)/bin
INSTALL_DIR := $(HOME)/.local/bin
PLUGIN_DIR  := extensions/defenseclaw
DC_EXT_DIR  := $(HOME)/.defenseclaw/extensions/defenseclaw
OC_EXT_DIR  := $(HOME)/.openclaw/extensions/defenseclaw
RUFF        := $(shell if [ -x "$(VENV)/bin/ruff" ]; then printf '%s' "$(VENV)/bin/ruff"; elif command -v ruff >/dev/null 2>&1; then command -v ruff; else printf '%s' "$(VENV)/bin/ruff"; fi)

DIST_DIR    := dist
UPGRADE_SMOKE_FROM ?= 0.8.1 0.8.0 0.7.2 0.7.1 0.6.6 0.6.5 0.6.4 0.6.3 0.6.2 0.6.1 0.6.0 0.5.0 0.4.0

# Cross-platform virtualenv / executable layout. Windows Python venvs expose
# console entry points under Scripts/ (not bin/) and binaries carry a .exe
# suffix, which Go also appends to its build output. Detect the host once and
# parameterize the handful of install paths that differ so `make install` works
# on hosted Windows runners (the connector contract matrix) as well as
# Linux/macOS. $(OS) is set to "Windows_NT" by Windows itself and inherited by
# the MSYS/Git-Bash shell make runs there; it is unset elsewhere.
ifeq ($(OS),Windows_NT)
VENV_BIN := $(VENV)/Scripts
EXE      := .exe
else
VENV_BIN := $(VENV)/bin
EXE      :=
endif

.PHONY: all path doctor uninstall quickstart llm-setup \
        build install cli-install dev-install pycli dev-pycli gateway gateway-cross gateway-run start gateway-install \
        plugin plugin-install maybe-openclaw-plugin-install extensions test cli-test cli-test-cov cli-test-snap tui-test gateway-test go-test-cov \
        packaging-macos-test packaging-macos-bundle \
        security-suite-test security-suite-eval \
        connector-matrix-test go-connector-matrix-test py-connector-matrix-test \
        test-verbose test-file lint py-lint go-lint ts-test rego-test clean \
        check check-audit-actions check-error-codes check-schemas check-grafana-dashboards check-v7 check-provider-coverage check-llm-catalog check-version-sync check-upgrade-manifest \
        upgrade-smoke upgrade-smoke-matrix \
        set-version \
        _bundle-data \
        dist dist-cli dist-gateway dist-plugin dist-sandbox dist-test dist-upgrade-manifest dist-checksums dist-clean

# ---------------------------------------------------------------------------
# Version stamping
# ---------------------------------------------------------------------------
# The git tag is the canonical source of truth on a release; the workflow
# invokes `scripts/stamp-version.sh "$TAG"` directly. Local devs who want
# to pre-stage a version (e.g. for a manual smoke test of `make dist`)
# can use this target as a friendly wrapper.
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

# CI gate that fails when the four version sources disagree, catching
# drift before it reaches a release artifact. Mirrors the contract
# enforced by scripts/stamp-version.sh.
check-version-sync:
	@mk_ver=$$(grep -E '^VERSION[[:space:]]*:=' Makefile | head -1 | awk -F'=' '{gsub(/[[:space:]]/,"",$$2); print $$2}'); \
	py_ver=$$(grep -E '^version[[:space:]]*=' pyproject.toml | head -1 | awk -F'"' '{print $$2}'); \
	init_ver=$$(grep -E '^__version__[[:space:]]*=' cli/defenseclaw/__init__.py | head -1 | awk -F'"' '{print $$2}'); \
	pkg_ver=$$(grep -E '^  "version":' extensions/defenseclaw/package.json | head -1 | awk -F'"' '{print $$4}'); \
	if [ "$${mk_ver}" = "$${py_ver}" ] && [ "$${py_ver}" = "$${init_ver}" ] && [ "$${init_ver}" = "$${pkg_ver}" ]; then \
		echo "version sync OK: $${mk_ver}"; \
	else \
		echo "version drift detected:" >&2; \
		echo "  Makefile                         : $${mk_ver}" >&2; \
		echo "  pyproject.toml                   : $${py_ver}" >&2; \
		echo "  cli/defenseclaw/__init__.py      : $${init_ver}" >&2; \
		echo "  extensions/defenseclaw/package.json: $${pkg_ver}" >&2; \
		echo "" >&2; \
		echo "fix with: make set-version VERSION=X.Y.Z" >&2; \
		exit 1; \
	fi

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
all: install path quickstart llm-setup
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

path:
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
quickstart:
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
			echo "  Could not locate the defenseclaw binary — run 'make install' first."; \
			exit 1; \
		fi; \
		if [ -n "$${CONNECTOR:-}" ]; then \
			if ! "$$dc_bin" init --non-interactive --yes \
				--connector "$${CONNECTOR}" \
				--profile "$$profile" \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
			fi; \
		elif [ -t 0 ] && [ -t 1 ] && [ "$${CI:-}" != "true" ]; then \
			if ! "$$dc_bin" init \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
			fi; \
		else \
			if ! "$$dc_bin" init --non-interactive --yes \
				--profile "$$profile" \
				--scanner-mode "$${SCANNER_MODE:-local}" \
				--no-start-gateway --verify; then \
				echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
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
llm-setup:
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
	@echo "Run 'make install' to install all components."

install: cli-install gateway-install maybe-openclaw-plugin-install
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

maybe-openclaw-plugin-install:
	@if [ "$${CONNECTOR:-codex}" = "openclaw" ]; then \
		$(MAKE) plugin-install; \
	else \
		echo "Skipping OpenClaw plugin install (CONNECTOR=$${CONNECTOR:-codex})."; \
	fi

# ---------------------------------------------------------------------------
# Individual build targets
# ---------------------------------------------------------------------------

dev-install:
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

gateway: sync-openclaw-extension
	go build $(GOFLAGS) -o $(GATEWAY)$(EXE) ./cmd/defenseclaw
	@echo "Built $(GATEWAY)$(EXE)"
	@echo "  Run with: ./$(GATEWAY)$(EXE)"
	@echo "  Check status: ./$(GATEWAY)$(EXE) status"

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
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(BINARY)-$(GOOS)-$(GOARCH) ./cmd/defenseclaw
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

cli-install: pycli
	@mkdir -p $(INSTALL_DIR)
	@ln -sf "$(CURDIR)/$(VENV_BIN)/defenseclaw$(EXE)" "$(INSTALL_DIR)/defenseclaw$(EXE)"
	@ln -sf "$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" "$(INSTALL_DIR)/litellm$(EXE)" 2>/dev/null || true
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
			ln -sf "$$src" "$(INSTALL_DIR)/$$tool$(EXE)"; \
		fi; \
	done
	@echo "Installed defenseclaw CLI to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

gateway-install: cli-install gateway
	@mkdir -p $(INSTALL_DIR)
	@# Atomic replace: Linux returns ETXTBSY when overwriting an executable
	@# that is currently running (e.g. the sidecar started via `defenseclaw-
	@# gateway start`). cp(1) opens the destination for writing, which
	@# trips that check. rename(2) (invoked by mv) only swaps the directory
	@# entry, so the running process keeps the old inode and upgrades work
	@# live. We copy to a sibling temp file first so a partial write can
	@# never clobber a working binary.
	@gwt="$(INSTALL_DIR)/$(GATEWAY)$(EXE)"; \
	tmp="$$gwt.new.$$$$"; \
	trap 'rm -f "$$tmp"' EXIT INT TERM; \
	cp $(GATEWAY)$(EXE) "$$tmp"; \
	chmod +x "$$tmp"; \
	mv -f "$$tmp" "$$gwt"
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(GATEWAY)$(EXE) 2>/dev/null || true; \
	fi
	@echo "Installed $(GATEWAY)$(EXE) to $(INSTALL_DIR)"
	@# If a sidecar is already running it kept the old inode; tell the
	@# operator so they know a restart is needed to pick up the new build.
	@# Use pgrep -x against the *basename* only — `pgrep -f "$(GATEWAY)"`
	@# matches this very make invocation ("make gateway-install") and
	@# any editor/tail window with the binary path on its cmdline, so
	@# it would fire a false "sidecar is running" hint on every build.
	@if pgrep -x "$(GATEWAY)" >/dev/null 2>&1; then \
		echo "  Gateway sidecar is running an older build — restart with:"; \
		echo "    $(INSTALL_DIR)/$(GATEWAY)$(EXE) restart"; \
	fi
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

plugin-install: cli-install plugin
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
	go test -race ./internal/gateway/ ./test/... -v

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
#     defenseclaw-gateway              (binary)
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

packaging-macos-bundle:
	@scripts/build-macos-bundle.sh \
	    "$(BUNDLE_GOOS)" \
	    "$(BUNDLE_GOARCH)" \
	    "$(BUNDLE_NAME)" \
	    "$(BUNDLE_DIR)" \
	    "$(DIST_DIR)" \
	    "$(VERSION)" \
	    '$(GOFLAGS)'

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
	go test -race -count=1 -coverprofile=coverage.out ./...

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

check: check-v7 check-grafana-dashboards check-provider-coverage check-llm-catalog check-upgrade-manifest

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
	@scripts/test-upgrade-release.sh $(ARGS)

upgrade-smoke-matrix:
	@scripts/test-upgrade-release.sh --from-versions "$(UPGRADE_SMOKE_FROM)" $(ARGS)

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
	fi; \
	status=$$?; \
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
	@echo "Release artifacts:"
	@ls -lh $(DIST_DIR)/
	@echo ""
	@echo "Test locally:"
	@echo "  ./scripts/install.sh --local $(DIST_DIR)"
	@echo ""
	@echo "Cut a release (preferred — atomic tag + assets, runs in CI):"
	@echo "  Actions UI -> 'Release' workflow -> Run workflow -> enter $(VERSION)"
	@echo "  Or from the CLI: git tag $(VERSION) && git push origin $(VERSION)"
	@echo ""
	@echo "  NOTE: tag must be bare X.Y.Z, no 'v' prefix — the release"
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
	cp internal/envvars/registry.json cli/defenseclaw/_data/envvars/
	cp scripts/install-openshell-sandbox.sh cli/defenseclaw/_data/scripts/
	cp -r skills/codeguard cli/defenseclaw/_data/skills/
	@# Curated LLM model catalog consumed by `defenseclaw setup llm` and the
	@# Textual TUI model picker via importlib.resources. Tracked source lives
	@# at bundles/llm/; _data/llm/ is the gitignored build-staging copy.
	cp bundles/llm/model_catalog.json cli/defenseclaw/_data/llm/
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
	@# mirror there. That fallback loses inode stability, but the obs Docker stack
	@# — the only consumer of that property — never runs on those Windows build
	@# hosts, so the tradeoff is safe. Mirrors the rsync-or-cp guard in
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
	rm -f $(GATEWAY) $(GATEWAY)$(EXE) $(BINARY)-linux-* $(BINARY)-darwin-*
	rm -rf $(VENV) cli/*.egg-info
	rm -rf $(PLUGIN_DIR)/dist $(PLUGIN_DIR)/node_modules
	rm -f coverage.out coverage-py.xml
	rm -rf cli/defenseclaw/_data
	find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
