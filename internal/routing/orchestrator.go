// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// Remote mode: just return the endpoint
	if cfg.RemoteEndpoint != "" {
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
