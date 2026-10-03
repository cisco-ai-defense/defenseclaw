// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	litellmDefaultPort     = 4001
	litellmHealthPath      = "/health/liveliness"
	litellmModelNewPath    = "/model/new"
	litellmModelUpdatePath = "/model/update"
	litellmStartupTimeout  = 30 * time.Second
)

// LiteLLMManager starts, configures, and monitors a LiteLLM proxy as a
// managed child process. The gateway owns its lifecycle: start, health,
// model push via REST API, and graceful shutdown.
type LiteLLMManager struct {
	port       int
	dataDir    string
	masterKey  string
	pythonPath string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool
	cancel  context.CancelFunc
}

// NewLiteLLMManager creates a manager from the gateway config.
func NewLiteLLMManager(cfg *config.Config) *LiteLLMManager {
	masterKey := os.Getenv("DEFENSECLAW_GATEWAY_TOKEN")
	dataDir := cfg.DataDir

	return &LiteLLMManager{
		port:       litellmDefaultPort,
		dataDir:    dataDir,
		masterKey:  masterKey,
		pythonPath: filepath.Join(dataDir, "litellm"),
	}
}

// BaseURL returns the HTTP endpoint for the running LiteLLM sidecar.
func (m *LiteLLMManager) BaseURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", m.port)
}

// Start launches the LiteLLM process with a minimal bootstrap config and
// blocks until it is healthy or the context is cancelled.
func (m *LiteLLMManager) Start(ctx context.Context) error {
	bootstrapPath, err := m.writeBootstrapConfig()
	if err != nil {
		return fmt.Errorf("litellm: write bootstrap config: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	m.cmd = exec.CommandContext(childCtx, "litellm",
		"--config", bootstrapPath,
		"--port", fmt.Sprintf("%d", m.port),
		"--host", "127.0.0.1",
	)
	m.cmd.Stdout = os.Stderr
	m.cmd.Stderr = os.Stderr
	m.cmd.Env = append(os.Environ(),
		fmt.Sprintf("PYTHONPATH=%s:%s", m.pythonPath, os.Getenv("PYTHONPATH")),
		fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%s", m.masterKey),
	)

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("litellm: start process: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[litellm] started on port %d (pid %d)\n", m.port, m.cmd.Process.Pid)

	go m.watchProcess()

	if err := m.waitHealthy(ctx); err != nil {
		m.cmd.Process.Kill()
		return fmt.Errorf("litellm: %w", err)
	}

	return nil
}

// PushModels registers all models from the gateway config via POST /model/new.
func (m *LiteLLMManager) PushModels(cfg *config.Config) error {
	models := TranslateLiteLLMModels(cfg)
	for _, model := range models {
		if err := m.pushModel(model); err != nil {
			fmt.Fprintf(os.Stderr, "[litellm] warning: failed to push model %q: %v\n", model.ModelName, err)
		} else {
			fmt.Fprintf(os.Stderr, "[litellm] registered model %q -> %s\n", model.ModelName, model.LiteLLMParams.Model)
		}
	}
	return nil
}

// UpdateModelKey updates the API key for a registered model without restart.
func (m *LiteLLMManager) UpdateModelKey(modelName, newKey string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"model_name": modelName,
		"litellm_params": map[string]string{
			"api_key": newKey,
		},
	})
	url := m.BaseURL() + litellmModelUpdatePath
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.masterKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update model key: status %d: %s", resp.StatusCode, truncateBody(respBody, 200))
	}
	return nil
}

// Healthy returns true if the LiteLLM process is responding to health checks.
func (m *LiteLLMManager) Healthy() bool {
	resp, err := http.Get(m.BaseURL() + litellmHealthPath)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// Stop gracefully terminates the LiteLLM child process.
func (m *LiteLLMManager) Stop() {
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
	fmt.Fprintf(os.Stderr, "[litellm] stopped\n")
}

func (m *LiteLLMManager) writeBootstrapConfig() (string, error) {
	dir := filepath.Join(m.dataDir, "litellm")
	os.MkdirAll(dir, 0700)

	bootstrap := fmt.Sprintf(`general_settings:
  master_key: "os.environ/DEFENSECLAW_GATEWAY_TOKEN"
  store_model_in_db: true
  database_url: "sqlite:///%s/litellm.db"

litellm_settings:
  drop_params: true
  modify_params: true
  callbacks: ["filter_empty.proxy_handler_instance"]
`, dir)

	path := filepath.Join(dir, "bootstrap.yaml")
	if err := safefile.Write(path, []byte(bootstrap)); err != nil {
		return "", err
	}
	return path, nil
}

func (m *LiteLLMManager) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(litellmStartupTimeout)
	url := m.BaseURL() + litellmHealthPath
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Fprintf(os.Stderr, "[litellm] healthy\n")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("did not become healthy within %s", litellmStartupTimeout)
}

func (m *LiteLLMManager) watchProcess() {
	err := m.cmd.Wait()
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	if stopped {
		return
	}
	fmt.Fprintf(os.Stderr, "[litellm] process exited unexpectedly: %v\n", err)
}

func (m *LiteLLMManager) pushModel(model LiteLLMModelParams) error {
	body, err := json.Marshal(model)
	if err != nil {
		return err
	}
	url := m.BaseURL() + litellmModelNewPath
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.masterKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, truncateBody(respBody, 200))
	}
	return nil
}

func truncateBody(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
