// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"os"
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

// StartManagedRouter performs the full startup sequence:
// 1. Ensure vllm-sr is installed (pip)
// 2. Check Docker is available
// 3. Translate config to SR format
// 4. Start vllm-sr serve
// 5. Wait for health
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
		port = defaultSRPort
	}

	// 1. Ensure vllm-sr is installed
	mgr := NewManager(cfg.DataDir)
	if err := mgr.EnsureInstalled(ctx, cfg.Version); err != nil {
		return nil, err
	}

	// 2. Check Docker
	if !mgr.DockerAvailable() {
		return nil, fmt.Errorf("routing: Docker is required for vllm-sr serve but is not running")
	}

	// 3. Translate config
	srDir := filepath.Join(cfg.DataDir, "semantic-router")
	cfg.TranslateInput.Port = port
	configPath, err := TranslateAndWrite(cfg.TranslateInput, srDir)
	if err != nil {
		return nil, fmt.Errorf("routing: translate config: %w", err)
	}

	// 4. Start vllm-sr serve
	lc := NewLifecycle(LifecycleConfig{
		ConfigPath: configPath,
		Port:       port,
	})
	if err := lc.Start(ctx); err != nil {
		return nil, err
	}

	// 5. Wait for health (Docker containers take time to start)
	healthTimeout := 30 * time.Second
	if err := lc.WaitForHealth(ctx, healthTimeout); err != nil {
		lc.Stop()
		return nil, err
	}

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	fmt.Fprintf(os.Stderr, "[routing] semantic router ready at %s\n", endpoint)
	return &OrchestratorResult{Endpoint: endpoint, Lifecycle: lc}, nil
}
