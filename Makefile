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

.PHONY: build install dev-install pycli dev-pycli gateway gateway-cross gateway-run start gateway-install \
        plugin plugin-install test cli-test cli-test-cov gateway-test go-test-cov \
        test-verbose test-file lint py-lint go-lint ts-test rego-test clean \
        dist dist-cli dist-gateway dist-plugin dist-sandbox dist-test dist-checksums dist-clean

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

install: pycli gateway-install plugin-install
	@echo ""
	@echo "All components installed:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw  (activate with: source $(VENV)/bin/activate)"
	@echo "  • Go gateway   → $(INSTALL_DIR)/$(GATEWAY)"
	@echo "  • OpenClaw plugin → ~/.defenseclaw/extensions/defenseclaw/"
	@echo ""
	@echo "Next steps:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw init"
	@echo "  defenseclaw setup guardrail   # configure LLM guardrail"
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
	uv venv $(VENV) --python 3.12
	uv pip install -e . --python $(VENV)/bin/python
	@mkdir -p $(INSTALL_DIR)
	@ln -sf $(CURDIR)/$(VENV)/bin/litellm $(INSTALL_DIR)/litellm 2>/dev/null || true

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
	cd $(PLUGIN_DIR) && NODE_ENV=development npm ci --include=dev && npm run build
	@echo ""
	@echo "Built OpenClaw plugin → $(PLUGIN_DIR)/dist/"
	@echo "  Install with: make plugin-install"

# ---------------------------------------------------------------------------
# Individual install targets
# ---------------------------------------------------------------------------

gateway-install: gateway
	@mkdir -p $(INSTALL_DIR)
	@cp $(GATEWAY) $(INSTALL_DIR)/$(GATEWAY)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(GATEWAY) 2>/dev/null || true; \
	fi
	@echo "Installed $(GATEWAY) to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

plugin-install: plugin
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
	go test -race ./internal/gateway/ ./test/... -v

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
# Lint targets
# ---------------------------------------------------------------------------

lint: py-lint go-lint
	$(VENV)/bin/python -m py_compile cli/defenseclaw/main.py

py-lint:
	$(VENV)/bin/ruff check cli/defenseclaw/

go-lint:
	PATH="$(GOBIN):$(PATH)" golangci-lint run

# ---------------------------------------------------------------------------
# Distribution targets — build release artifacts into dist/
# ---------------------------------------------------------------------------

dist: dist-cli dist-gateway dist-plugin dist-sandbox dist-test dist-checksums
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
	@mkdir -p cli/defenseclaw/_data/scripts
	@mkdir -p cli/defenseclaw/_data/skills
	@rm -rf cli/defenseclaw/_data/splunk_local_bridge
	cp policies/rego/*.rego cli/defenseclaw/_data/policies/rego/
	rm -f cli/defenseclaw/_data/policies/rego/*_test.rego
	cp policies/rego/data.json cli/defenseclaw/_data/policies/rego/
	cp policies/*.yaml cli/defenseclaw/_data/policies/
	cp policies/openshell/*.rego cli/defenseclaw/_data/policies/openshell/
	cp policies/openshell/*.yaml cli/defenseclaw/_data/policies/openshell/
	cp scripts/install-openshell-sandbox.sh cli/defenseclaw/_data/scripts/
	cp -r skills/codeguard cli/defenseclaw/_data/skills/
	cp -r bundles/splunk_local_bridge cli/defenseclaw/_data/

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
	cp scripts/test-litellm-proxy.py $(DIST_DIR)/test/
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
