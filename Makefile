BINARY      := defenseclaw
GATEWAY     := defenseclaw-gateway
VERSION     := 0.2.0
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
VENV        := .venv
GOBIN       := $(shell go env GOPATH)/bin
INSTALL_DIR := $(HOME)/.local/bin
PLUGIN_DIR  := extensions/defenseclaw
DC_EXT_DIR  := $(HOME)/.defenseclaw/extensions/defenseclaw
OC_EXT_DIR  := $(HOME)/.openclaw/extensions/defenseclaw

DIST_DIR    := dist
BIN_DIR     := bin

.PHONY: all path doctor uninstall quickstart llm-setup \
        build install cli-install dev-install pycli dev-pycli gateway gateway-cross gateway-run start gateway-install \
        plugin plugin-install test cli-test cli-test-cov gateway-test tui-test go-test-cov \
        test-verbose test-file lint py-lint go-lint ts-test rego-test clean \
        check check-audit-actions check-error-codes check-schemas check-v7 check-provider-coverage \
        dist dist-cli dist-gateway dist-plugin dist-sandbox dist-test dist-checksums dist-clean \
        docs-gen docs-check docs-deadlinks docs-clean-generated

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
	@if [ "$${NO_QUICKSTART:-0}" = "1" ]; then \
		echo "NO_QUICKSTART=1 set — skipping quickstart"; \
	elif [ -x "$(INSTALL_DIR)/defenseclaw" ]; then \
		"$(INSTALL_DIR)/defenseclaw" quickstart --non-interactive --yes \
			|| echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
	elif [ -x "$(VENV)/bin/defenseclaw" ]; then \
		"$(VENV)/bin/defenseclaw" quickstart --non-interactive --yes \
			|| echo "  Quickstart reported errors — run 'defenseclaw doctor' to investigate"; \
	else \
		echo "  Could not locate the defenseclaw binary — run 'make install' first."; \
		exit 1; \
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

install: cli-install gateway-install plugin-install
	@echo ""
	@echo "All components installed:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw  (activate with: source $(VENV)/bin/activate)"
	@echo "  • Go gateway   → $(INSTALL_DIR)/$(GATEWAY)"
	@echo "  • OpenClaw plugin → ~/.defenseclaw/extensions/defenseclaw/"
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

# ---------------------------------------------------------------------------
# Individual build targets
# ---------------------------------------------------------------------------

dev-install:
	@./scripts/install-dev.sh

pycli:
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — install from https://docs.astral.sh/uv/"; exit 1; }
	@find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	uv venv $(VENV) --python 3.12 --clear
	uv pip install -e . --python $(VENV)/bin/python

dev-pycli: pycli
	uv pip install --group dev --python $(VENV)/bin/python
	@echo ""
	@echo "Done. Activate the environment and run:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw --help"

gateway:
	go build $(GOFLAGS) -o $(GATEWAY) ./cmd/defenseclaw
	@echo "Built $(GATEWAY)"
	@echo "  Run with: ./$(GATEWAY)"
	@echo "  Check status: ./$(GATEWAY) status"

gateway-cross:
	@test -n "$(GOOS)" -a -n "$(GOARCH)" || { echo "Usage: make gateway-cross GOOS=linux GOARCH=amd64"; exit 1; }
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(BINARY)-$(GOOS)-$(GOARCH) ./cmd/defenseclaw
	@echo "Built $(BINARY)-$(GOOS)-$(GOARCH)"

gateway-run: gateway
	./$(GATEWAY)

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
	@ln -sf "$(CURDIR)/$(VENV)/bin/defenseclaw" "$(INSTALL_DIR)/defenseclaw"
	@ln -sf "$(CURDIR)/$(VENV)/bin/litellm" "$(INSTALL_DIR)/litellm" 2>/dev/null || true
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
		src="$(CURDIR)/$(VENV)/bin/$$tool"; \
		if [ -x "$$src" ]; then \
			ln -sf "$$src" "$(INSTALL_DIR)/$$tool"; \
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
	@gwt="$(INSTALL_DIR)/$(GATEWAY)"; \
	tmp="$$gwt.new.$$$$"; \
	trap 'rm -f "$$tmp"' EXIT INT TERM; \
	cp $(GATEWAY) "$$tmp"; \
	chmod +x "$$tmp"; \
	mv -f "$$tmp" "$$gwt"
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(GATEWAY) 2>/dev/null || true; \
	fi
	@echo "Installed $(GATEWAY) to $(INSTALL_DIR)"
	@# If a sidecar is already running it kept the old inode; tell the
	@# operator so they know a restart is needed to pick up the new build.
	@# Use pgrep -x against the *basename* only — `pgrep -f "$(GATEWAY)"`
	@# matches this very make invocation ("make gateway-install") and
	@# any editor/tail window with the binary path on its cmdline, so
	@# it would fire a false "sidecar is running" hint on every build.
	@if pgrep -x "$(GATEWAY)" >/dev/null 2>&1; then \
		echo "  Gateway sidecar is running an older build — restart with:"; \
		echo "    $(INSTALL_DIR)/$(GATEWAY) restart"; \
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

cli-test:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v

cli-test-cov:
	$(VENV)/bin/python -m pytest cli/tests/ -v --tb=short --cov=defenseclaw --cov-report=xml:coverage-py.xml

gateway-test:
	go test -race ./internal/gateway/ ./internal/tui/ ./test/... -v

tui-test:
	go test -race -count=1 ./internal/tui/ -v

go-test-cov:
	go test -race -count=1 -coverprofile=coverage.out ./...

ts-test:
	cd $(PLUGIN_DIR) && npx vitest run

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

check: check-v7 check-provider-coverage

check-v7: check-audit-actions check-error-codes check-schemas
	@echo "check-v7: all parity gates passed."

check-audit-actions:
	@$(VENV)/bin/python scripts/check_audit_actions.py

check-error-codes:
	@$(VENV)/bin/python scripts/check_error_codes.py

check-schemas:
	@$(VENV)/bin/python scripts/check_schemas.py

# check-provider-coverage runs the shared test/testdata/llm-endpoints.json
# corpus through both the Go shape detector (provider_coverage_test.go)
# and the TS interceptor (provider-coverage.test.ts). A drift between
# the two sides — e.g. a new provider added to providers.json but
# never exercised — would be the exact "silent bypass" failure mode
# Layer 4 of the robust-guardrail plan is designed to surface.
check-provider-coverage:
	@echo "==> provider coverage (Go)"
	@go test ./internal/gateway -run TestProviderCoverageCorpus -count=1
	@echo "==> provider coverage (TS)"
	@cd extensions/defenseclaw && npx --prefer-offline --no-install vitest run src/__tests__/provider-coverage.test.ts
	@echo "check-provider-coverage: corpus is in sync across Go + TS."

# ---------------------------------------------------------------------------
# docs-site generator pipeline
# ---------------------------------------------------------------------------
#
# See docs-site/_meta/AUTOGEN.md for the sentinel contract and
# scripts/docgen/ for the implementation.
#
#   make docs-gen           — regenerate every AUTOGEN block + scaffold
#                             any missing MDX stubs. Idempotent.
#   make docs-check         — CI gate: run docs-gen and fail if git
#                             diff is non-empty (drift).
#   make docs-deadlinks     — walk all MDX links and verify targets.
#   make docs-clean-generated — delete the docs-site/ tree (recovery).

DOCGEN_PY := $(VENV)/bin/python -m scripts.docgen

$(BIN_DIR)/docgen-go: cmd/docgen-go/main.go $(wildcard internal/cli/*.go)
	@mkdir -p $(BIN_DIR)
	go build -o $@ ./cmd/docgen-go

docs-gen: $(BIN_DIR)/docgen-go
	$(DOCGEN_PY)

docs-verify: $(BIN_DIR)/docgen-go
	$(VENV)/bin/python scripts/docs_verify.py

docs-check: docs-gen docs-verify docs-deadlinks
	@if ! git diff --quiet -- docs-site/; then \
		echo "docs-site/ has uncommitted drift from make docs-gen:"; \
		git --no-pager diff --stat -- docs-site/; \
		exit 1; \
	fi
	@echo "docs-site/ is up to date."

docs-deadlinks:
	$(VENV)/bin/python scripts/docs_deadlinks.py docs-site/

docs-clean-generated:
	@echo "Removing docs-site/ (will be regenerated from sources)."
	rm -rf docs-site/

# ---------------------------------------------------------------------------
# Lint targets
# ---------------------------------------------------------------------------

lint: py-lint go-lint
	$(VENV)/bin/python -m py_compile cli/defenseclaw/main.py

py-lint:
	$(VENV)/bin/ruff check cli/defenseclaw/

go-lint:
	@# gofmt drift is the #1 review comment on every PR, so fail fast
	@# on it before running the heavier analyzers.
	@unformatted=$$(gofmt -l . 2>/dev/null); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$unformatted" | sed 's/^/  /'; \
		echo "Run 'gofmt -w .' to fix."; \
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

dist: dist-cli dist-gateway dist-plugin dist-sandbox dist-checksums
	@echo ""
	@echo "Release artifacts:"
	@ls -lh $(DIST_DIR)/
	@echo ""
	@echo "Test locally:"
	@echo "  ./scripts/install.sh --local $(DIST_DIR)"
	@echo ""
	@echo "Upload to GitHub release:"
	@echo "  gh release create v$(VERSION) $(DIST_DIR)/*"

dist-cli: _bundle-data
	@mkdir -p $(DIST_DIR)
	@rm -rf build cli/*.egg-info
	uv build --wheel --out-dir $(DIST_DIR)

_bundle-data:
	@mkdir -p cli/defenseclaw/_data/policies/rego
	@mkdir -p cli/defenseclaw/_data/policies/openshell
	@mkdir -p cli/defenseclaw/_data/policies/guardrail
	@mkdir -p cli/defenseclaw/_data/scripts
	@mkdir -p cli/defenseclaw/_data/skills
	@rm -rf cli/defenseclaw/_data/splunk_local_bridge
	@rm -rf cli/defenseclaw/_data/local_observability_stack
	cp policies/rego/*.rego cli/defenseclaw/_data/policies/rego/
	rm -f cli/defenseclaw/_data/policies/rego/*_test.rego
	cp policies/rego/data.json cli/defenseclaw/_data/policies/rego/
	cp policies/*.yaml cli/defenseclaw/_data/policies/
	cp policies/openshell/*.rego cli/defenseclaw/_data/policies/openshell/
	cp policies/openshell/*.yaml cli/defenseclaw/_data/policies/openshell/
	cp -r policies/guardrail/default cli/defenseclaw/_data/policies/guardrail/default
	cp -r policies/guardrail/strict cli/defenseclaw/_data/policies/guardrail/strict
	cp -r policies/guardrail/permissive cli/defenseclaw/_data/policies/guardrail/permissive
	cp scripts/install-openshell-sandbox.sh cli/defenseclaw/_data/scripts/
	cp -r skills/codeguard cli/defenseclaw/_data/skills/
	cp -r bundles/splunk_local_bridge cli/defenseclaw/_data/
	cp -r bundles/local_observability_stack cli/defenseclaw/_data/
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

dist-checksums:
	@test -d $(DIST_DIR) || { echo "Run 'make dist' first"; exit 1; }
	cd $(DIST_DIR) && find . -type f ! -name checksums.txt | sort | xargs shasum -a 256 > checksums.txt
	@echo "Checksums written to $(DIST_DIR)/checksums.txt"

dist-clean:
	rm -rf $(DIST_DIR)
	rm -rf cli/defenseclaw/_data
	rm -rf sandbox-test-*

clean:
	rm -f $(GATEWAY) $(BINARY)-linux-* $(BINARY)-darwin-*
	rm -rf $(VENV) cli/*.egg-info
	rm -rf $(PLUGIN_DIR)/dist $(PLUGIN_DIR)/node_modules
	rm -f coverage.out coverage-py.xml
	rm -rf cli/defenseclaw/_data
	find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
