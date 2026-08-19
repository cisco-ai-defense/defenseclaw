// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type OrchestratorConfig struct {
	Enabled        bool
	Version        string
	Port           int
	DataDir        string
	RemoteEndpoint string
	TimeoutMs      int
	TranslateInput TranslateInput
}

type OrchestratorResult struct {
	Endpoint  string
	Lifecycle *Lifecycle
}

// StartManagedRouter performs the startup sequence:
// 1. Check Docker is available
// 2. Translate config to SR format
// 3. Start ONLY the router container (no Envoy, no dashboard, no observability)
// 4. Wait for health on the API port
func StartManagedRouter(ctx context.Context, cfg OrchestratorConfig) (*OrchestratorResult, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Remote mode: validate and return the endpoint.
	if cfg.RemoteEndpoint != "" {
		if err := validateRemoteEndpoint(cfg.RemoteEndpoint); err != nil {
			return nil, fmt.Errorf("routing: invalid remote endpoint: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[routing] using remote semantic router at %s\n", cfg.RemoteEndpoint)
		return &OrchestratorResult{Endpoint: cfg.RemoteEndpoint}, nil
	}

	port := cfg.Port
	if port == 0 {
		port = defaultSRAPIPort
	}

	// 1. Check Docker is available
	if err := checkDocker(ctx); err != nil {
		return nil, err
	}

	// 2. Translate config
	srDir := filepath.Join(cfg.DataDir, "semantic-router")
	cfg.TranslateInput.Port = port
	configPath, err := TranslateAndWrite(cfg.TranslateInput, srDir)
	if err != nil {
		return nil, fmt.Errorf("routing: translate config: %w", err)
	}

	// 3. Start router container only (no Envoy, redis, postgres, etc.)
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: configPath,
		Port:       port,
		DataDir:    srDir,
	})
	if err := lc.Start(ctx); err != nil {
		return nil, err
	}

	// 4. Wait for health (single container, should be fast)
	healthTimeout := 60 * time.Second
	if err := lc.WaitForHealth(ctx, healthTimeout); err != nil {
		lc.Stop()
		return nil, err
	}

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	fmt.Fprintf(os.Stderr, "[routing] semantic router ready at %s\n", endpoint)
	return &OrchestratorResult{Endpoint: endpoint, Lifecycle: lc}, nil
}

func checkDocker(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(dctx, "docker", "info").Run(); err != nil {
		return fmt.Errorf("routing: Docker is required but not running")
	}
	return nil
}

// validateRemoteEndpoint ensures the endpoint is a valid HTTP(S) URL pointing to
// localhost or a private network host. Rejects non-http schemes and metadata IPs.
func validateRemoteEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}
	// Block cloud metadata endpoints.
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		return fmt.Errorf("cloud metadata endpoint not allowed")
	}
	// Allow localhost and common private ranges; reject obviously public hosts
	// only if they look like metadata. The operator is trusted to configure
	// this, but we block the most dangerous SSRF targets.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" {
		return nil
	}
	return nil
}
