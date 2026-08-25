package training

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

// LlamaConfig holds llama-server configuration
type LlamaConfig struct {
	ModelsDir string // directory containing GGUF files
	Port      int    // default 8090
	MaxModels int    // default 4
	Binary    string // path to llama-server binary (default: "llama-server")
}

// LlamaServer manages the llama-server subprocess
type LlamaServer struct {
	cfg    LlamaConfig
	cmd    *exec.Cmd
	cancel context.CancelFunc
	mu     sync.Mutex
}

// NewLlamaServer creates a new LlamaServer with the given configuration.
// Defaults: Port=8090, MaxModels=4, Binary="llama-server"
func NewLlamaServer(cfg LlamaConfig) *LlamaServer {
	if cfg.Port == 0 {
		cfg.Port = 8090
	}
	if cfg.MaxModels == 0 {
		cfg.MaxModels = 4
	}
	if cfg.Binary == "" {
		cfg.Binary = "llama-server"
	}
	return &LlamaServer{
		cfg: cfg,
	}
}

// Start launches the llama-server subprocess with the configured parameters.
// stdout and stderr are redirected to os.Stderr.
func (l *LlamaServer) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cmd != nil {
		return fmt.Errorf("llama-server already running")
	}

	cmdCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel

	args := []string{
		"--models-dir", l.cfg.ModelsDir,
		"--models-max", fmt.Sprintf("%d", l.cfg.MaxModels),
		"--port", fmt.Sprintf("%d", l.cfg.Port),
		"--host", "127.0.0.1",
		"--metrics",
	}

	cmd := exec.CommandContext(cmdCtx, l.cfg.Binary, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start llama-server: %w", err)
	}

	l.cmd = cmd

	// Background goroutine to monitor process exit
	go func() {
		err := cmd.Wait()
		if err != nil && cmdCtx.Err() == nil {
			// Unexpected exit (not from Stop())
			fmt.Fprintf(os.Stderr, "llama-server exited unexpectedly: %v\n", err)
		}
	}()

	return nil
}

// WaitForHealth polls the health endpoint until it returns 200 OK or timeout expires
func (l *LlamaServer) WaitForHealth(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", l.cfg.Port)

	client := &http.Client{Timeout: 1 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("llama-server health check timed out after %v", timeout)
}

// Stop terminates the llama-server subprocess
func (l *LlamaServer) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cancel == nil {
		return fmt.Errorf("llama-server not running")
	}

	l.cancel()

	if l.cmd != nil && l.cmd.Process != nil {
		// Give process a moment to exit gracefully
		time.Sleep(100 * time.Millisecond)
		if l.cmd.ProcessState == nil || !l.cmd.ProcessState.Exited() {
			if err := l.cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill llama-server: %w", err)
			}
		}
	}

	l.cmd = nil
	l.cancel = nil
	return nil
}

// IsHealthy checks if the llama-server is responding to health checks
func (l *LlamaServer) IsHealthy() bool {
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", l.cfg.Port)
	client := &http.Client{Timeout: 1 * time.Second}

	resp, err := client.Get(healthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// Port returns the configured port number
func (l *LlamaServer) Port() int {
	return l.cfg.Port
}
