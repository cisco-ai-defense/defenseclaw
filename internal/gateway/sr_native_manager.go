// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

const (
	srDefaultPort      = 8080
	srHealthPath       = "/health"
	srStartupTimeout   = 15 * time.Second
)

// SRNativeManager starts and manages the vLLM Semantic Router as a native
// process (no Docker). The binary is expected at the path set by
// DEFENSECLAW_SR_BINARY or the default location.
type SRNativeManager struct {
	port       int
	binaryPath string
	configPath string
	libPath    string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool
	cancel  context.CancelFunc
}

// NewSRNativeManager creates a manager for the native SR binary.
func NewSRNativeManager(configPath string) *SRNativeManager {
	binary := os.Getenv("DEFENSECLAW_SR_BINARY")
	if binary == "" {
		binary = "router"
	}
	libPath := os.Getenv("DEFENSECLAW_SR_LIB_PATH")

	return &SRNativeManager{
		port:       srDefaultPort,
		binaryPath: binary,
		configPath: configPath,
		libPath:    libPath,
	}
}

// Endpoint returns the HTTP endpoint for the running SR.
func (m *SRNativeManager) Endpoint() string {
	return fmt.Sprintf("http://127.0.0.1:%d", m.port)
}

// Start launches the SR binary and waits for it to become healthy.
func (m *SRNativeManager) Start(ctx context.Context) error {
	if _, err := exec.LookPath(m.binaryPath); err != nil {
		return fmt.Errorf("sr: binary %q not found on PATH: %w", m.binaryPath, err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	m.cmd = exec.CommandContext(childCtx, m.binaryPath,
		fmt.Sprintf("-config=%s", m.configPath),
	)
	m.cmd.Stdout = os.Stderr
	m.cmd.Stderr = os.Stderr

	env := os.Environ()
	if m.libPath != "" {
		env = append(env, fmt.Sprintf("LD_LIBRARY_PATH=%s", m.libPath))
		env = append(env, fmt.Sprintf("DYLD_LIBRARY_PATH=%s", m.libPath))
	}
	m.cmd.Env = env

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("sr: start process: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[sr] started native process (pid %d, port %d)\n", m.cmd.Process.Pid, m.port)

	go m.watchProcess()

	if err := m.waitHealthy(ctx); err != nil {
		m.cmd.Process.Kill()
		return fmt.Errorf("sr: %w", err)
	}

	return nil
}

// Healthy returns true if the SR process is responding.
func (m *SRNativeManager) Healthy() bool {
	resp, err := http.Get(m.Endpoint() + srHealthPath)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// Stop gracefully terminates the SR process.
func (m *SRNativeManager) Stop() {
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { m.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			m.cmd.Process.Kill()
		}
	}
	fmt.Fprintf(os.Stderr, "[sr] stopped\n")
}

func (m *SRNativeManager) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(srStartupTimeout)
	url := m.Endpoint() + srHealthPath
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Fprintf(os.Stderr, "[sr] healthy\n")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("did not become healthy within %s", srStartupTimeout)
}

func (m *SRNativeManager) watchProcess() {
	err := m.cmd.Wait()
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	if stopped {
		return
	}
	fmt.Fprintf(os.Stderr, "[sr] process exited unexpectedly: %v\n", err)
}
