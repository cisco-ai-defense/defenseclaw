BINARY      := defenseclaw
VERSION     := 0.2.0
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
INSTALL_DIR := $(HOME)/.local/bin

.PHONY: build build-all build-linux-arm64 build-linux-amd64 build-darwin-arm64 build-darwin-amd64 test lint clean vet install

build:
	go build $(GOFLAGS) -o $(BINARY) ./cmd/defenseclaw

build-all: build-linux-arm64 build-linux-amd64 build-darwin-arm64 build-darwin-amd64

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BINARY)-linux-arm64 ./cmd/defenseclaw

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-linux-amd64 ./cmd/defenseclaw

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(BINARY)-darwin-arm64 ./cmd/defenseclaw

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY)-darwin-amd64 ./cmd/defenseclaw

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY) $(BINARY)-*

install: build
	@mkdir -p $(INSTALL_DIR)
	@cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Installed $(BINARY) to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi
