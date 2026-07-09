package routing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const (
	defaultSRPort      = 8888
	defaultSRDashboard = 8700
)

// Lifecycle manages the vllm-sr serve process.
type Lifecycle struct {
	configPath string
	port       int
	cmd        *exec.Cmd
	cancel     context.CancelFunc
}

type LifecycleConfig struct {
	ConfigPath string
	Port       int
}

func NewLifecycle(cfg LifecycleConfig) *Lifecycle {
	port := cfg.Port
	if port == 0 {
		port = defaultSRPort
	}
	return &Lifecycle{
		configPath: cfg.ConfigPath,
		port:       port,
	}
}

// Start launches `vllm-sr serve` with the generated config.
func (l *Lifecycle) Start(ctx context.Context) error {
	procCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel

	args := []string{"serve", "--config", l.configPath}

	l.cmd = exec.CommandContext(procCtx, srCLIName, args...)
	l.cmd.Stdout = os.Stderr
	l.cmd.Stderr = os.Stderr

	if err := l.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("routing: vllm-sr serve start failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[routing] vllm-sr serve started (pid=%d, port=%d)\n", l.cmd.Process.Pid, l.port)

	// Background goroutine to wait for exit
	go func() {
		_ = l.cmd.Wait()
		if procCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[routing] vllm-sr serve exited unexpectedly\n")
		}
	}()

	return nil
}

// WaitForHealth polls the SR endpoint until it responds or timeout.
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
				fmt.Fprintf(os.Stderr, "[routing] vllm-sr healthy (port=%d)\n", l.port)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("routing: vllm-sr health check timed out after %v", timeout)
}

// Stop gracefully stops vllm-sr serve.
func (l *Lifecycle) Stop() error {
	if l.cancel != nil {
		l.cancel()
	}

	// Also call vllm-sr stop for clean Docker container teardown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, srCLIName, "stop").Run()

	fmt.Fprintf(os.Stderr, "[routing] vllm-sr stopped\n")
	return nil
}

// IsRunning checks if vllm-sr is serving.
func (l *Lifecycle) IsRunning() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", l.port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Port returns the configured port.
func (l *Lifecycle) Port() int {
	return l.port
}
