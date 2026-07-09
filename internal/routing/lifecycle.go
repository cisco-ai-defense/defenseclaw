// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	defaultSRPort    = 8888 // Envoy listener port (unused in our integration)
	defaultSRAPIPort = 8080 // Router API server port (classify/intent, health)
	srRouterImage    = "ghcr.io/vllm-project/semantic-router/vllm-sr:latest"
	srContainerName  = "defenseclaw-semantic-router"
)

// Lifecycle manages the semantic router container.
// We start ONLY the router container (not Envoy/dashboard/observability)
// since DefenseClaw only needs the /api/v1/classify/intent endpoint.
type Lifecycle struct {
	configPath string
	port       int
	dataDir    string
}

type LifecycleConfig struct {
	ConfigPath string
	Port       int
	DataDir    string
}

func NewLifecycle(cfg LifecycleConfig) *Lifecycle {
	port := cfg.Port
	if port == 0 {
		port = defaultSRAPIPort
	}
	return &Lifecycle{
		configPath: cfg.ConfigPath,
		port:       port,
		dataDir:    cfg.DataDir,
	}
}

// Start launches only the router container via Docker.
// This gives us the /api/v1/classify/intent API without Envoy or extras.
func (l *Lifecycle) Start(ctx context.Context) error {
	// Stop any existing container
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", srContainerName).Run()

	configDir := filepath.Dir(l.configPath)
	configFile := filepath.Base(l.configPath)

	args := []string{
		"run", "-d",
		"--name", srContainerName,
		"--network", "host",
		"-v", fmt.Sprintf("%s:/app/config", configDir),
		"-e", fmt.Sprintf("CONFIG_FILE=/app/config/%s", configFile),
		"-p", fmt.Sprintf("%d:8080", l.port),
		"-p", "9190:9190",
		srRouterImage,
		"/app/start-router.sh", fmt.Sprintf("/app/config/%s", configFile),
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("routing: docker run router failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[routing] router container started (port=%d, container=%s)\n", l.port, srContainerName)
	return nil
}

// WaitForHealth polls the SR API endpoint until it responds or timeout.
func (l *Lifecycle) WaitForHealth(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", l.port)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(os.Stderr, "[routing] router healthy (port=%d)\n", l.port)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("routing: router health check timed out after %v", timeout)
}

// Stop removes the router container.
func (l *Lifecycle) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", srContainerName).Run()
	fmt.Fprintf(os.Stderr, "[routing] router container stopped\n")
	return nil
}

// IsRunning checks if the router container is healthy.
func (l *Lifecycle) IsRunning() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", l.port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Port returns the configured API port.
func (l *Lifecycle) Port() int {
	return l.port
}
