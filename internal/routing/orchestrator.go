// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"net"
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
		port = DefaultAPIPort
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
		Version:    cfg.Version,
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

// validateRemoteEndpoint ensures the endpoint is a valid HTTP(S) classifier
// URL. Plaintext is restricted to loopback because classifier requests contain
// prompt content; every endpoint outside that process-local boundary uses TLS.
func validateRemoteEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("embedded credentials are not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("query strings and fragments are not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}
	// Block cloud metadata endpoints.
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "metadata.google.internal" || lower == "metadata.goog" || lower == "instance-data.ec2.internal" {
		return fmt.Errorf("cloud metadata endpoint not allowed")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.Equal(net.ParseIP("169.254.169.254")) ||
			ip.Equal(net.ParseIP("169.254.170.2")) ||
			ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return fmt.Errorf("link-local or cloud metadata endpoint not allowed")
		}
		if u.Scheme == "http" && !ip.IsLoopback() {
			return fmt.Errorf("non-loopback endpoints must use https")
		}
		return nil
	}
	if u.Scheme == "http" && lower != "localhost" {
		return fmt.Errorf("non-loopback endpoints must use https")
	}
	return nil
}
