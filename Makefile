BINARY      := defenseclaw
GATEWAY     := defenseclaw-gateway
VERSION     := 0.2.0
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
VENV        := .venv
INSTALL_DIR := $(HOME)/.local/bin

.PHONY: dev-install pycli gateway gateway-install test cli-test gateway-test test-verbose test-file lint clean

dev-install:
	@./scripts/install-dev.sh

pycli:
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — install from https://docs.astral.sh/uv/"; exit 1; }
	uv venv $(VENV)
	uv pip install -e cli --python $(VENV)/bin/python
	@echo ""
	@echo "Done. Activate the environment and run:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw --help"

gateway:
	go build $(GOFLAGS) -o $(GATEWAY) ./cmd/defenseclaw
	@echo "Built $(GATEWAY)"
	@echo "  Run with: ./$(GATEWAY)"
	@echo "  Check status: ./$(GATEWAY) status"

gateway-run: gateway
	./$(GATEWAY)

gateway-install: gateway
	@mkdir -p $(INSTALL_DIR)
	@cp $(GATEWAY) $(INSTALL_DIR)/$(GATEWAY)
	@# Re-sign on macOS (copying invalidates adhoc signature)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(GATEWAY) 2>/dev/null || true; \
	fi
	@echo "Installed $(GATEWAY) to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

test: cli-test gateway-test

cli-test:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v

gateway-test:
	go test -race ./internal/gateway/ ./test/... -v

test-verbose:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v --failfast

test-file:
	@test -n "$(FILE)" || { echo "Usage: make test-file FILE=test_config"; exit 1; }
	$(VENV)/bin/python -m unittest cli.tests.$(FILE) -v

lint:
	$(VENV)/bin/python -m py_compile cli/defenseclaw/main.py

clean:
	rm -f $(GATEWAY) $(GATEWAY)-*
	rm -rf $(VENV) cli/*.egg-info cli/defenseclaw/__pycache__ cli/defenseclaw/**/__pycache__
