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

// OrchestratorConfig holds everything needed to start the managed SR.
type OrchestratorConfig struct {
	Enabled       bool
	Version       string
	Port          int
	DataDir       string // ~/.defenseclaw
	RemoteEndpoint string // if set, skip managed lifecycle
	TimeoutMs     int

	// Config translation inputs
	TranslateInput TranslateInput
}

// OrchestratorResult is returned after successful startup.
type OrchestratorResult struct {
	Endpoint  string     // http://127.0.0.1:{port}
	Lifecycle *Lifecycle // nil if remote mode
}

// StartManagedRouter performs the full startup sequence:
// 1. Ensure binary is downloaded
// 2. Translate config to SR native format
// 3. Start SR subprocess
// 4. Wait for health
// Returns the endpoint URL to connect to.
func StartManagedRouter(ctx context.Context, cfg OrchestratorConfig) (*OrchestratorResult, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Remote mode: just return the endpoint
	if cfg.RemoteEndpoint != "" {
		fmt.Fprintf(os.Stderr, "[routing] using remote semantic router at %s\n", cfg.RemoteEndpoint)
		return &OrchestratorResult{Endpoint: cfg.RemoteEndpoint}, nil
	}

	// Managed mode
	port := cfg.Port
	if port == 0 {
		port = 8080
	}

	srDir := filepath.Join(cfg.DataDir, "semantic-router")

	// 1. Ensure binary
	mgr := NewBinaryManager(cfg.DataDir)
	binPath, err := mgr.EnsureBinary(ctx, cfg.Version)
	if err != nil {
		return nil, fmt.Errorf("routing: ensure binary: %w", err)
	}

	// 2. Translate config
	cfg.TranslateInput.Port = port
	configPath, err := TranslateAndWrite(cfg.TranslateInput, srDir)
	if err != nil {
		return nil, fmt.Errorf("routing: translate config: %w", err)
	}

	// 3. Start subprocess
	lc := NewLifecycle(LifecycleConfig{
		BinaryPath: binPath,
		ConfigPath: configPath,
		Port:       port,
		DataDir:    srDir,
	})
	if err := lc.Start(ctx); err != nil {
		return nil, fmt.Errorf("routing: start sr: %w", err)
	}

	// 4. Wait for health
	healthTimeout := 10 * time.Second
	if err := lc.WaitForHealth(ctx, healthTimeout); err != nil {
		lc.Stop()
		return nil, fmt.Errorf("routing: sr health check failed: %w", err)
	}

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	return &OrchestratorResult{Endpoint: endpoint, Lifecycle: lc}, nil
}
