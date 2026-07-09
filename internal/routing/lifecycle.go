package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Lifecycle manages the semantic router subprocess.
type Lifecycle struct {
	binPath    string
	configPath string
	port       int
	dataDir    string // ~/.defenseclaw/semantic-router/
	cmd        *exec.Cmd
	cancel     context.CancelFunc
}

// LifecycleConfig holds startup parameters.
type LifecycleConfig struct {
	BinaryPath string
	ConfigPath string
	Port       int
	DataDir    string // parent dir for logs/PID (e.g. ~/.defenseclaw/semantic-router)
}

// NewLifecycle creates a lifecycle manager.
func NewLifecycle(cfg LifecycleConfig) *Lifecycle {
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	return &Lifecycle{
		binPath:    cfg.BinaryPath,
		configPath: cfg.ConfigPath,
		port:       cfg.Port,
		dataDir:    cfg.DataDir,
	}
}

// Start launches the SR subprocess. Returns once the process is running
// (does NOT wait for health — caller should use WaitForHealth).
func (l *Lifecycle) Start(ctx context.Context) error {
	if err := os.MkdirAll(l.dataDir, 0700); err != nil {
		return fmt.Errorf("routing lifecycle: mkdir: %w", err)
	}

	logPath := filepath.Join(l.dataDir, "router.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("routing lifecycle: open log: %w", err)
	}

	procCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel

	l.cmd = exec.CommandContext(procCtx, l.binPath,
		"--config", l.configPath,
		"--port", strconv.Itoa(l.port),
		"--host", "127.0.0.1",
	)
	l.cmd.Stdout = logFile
	l.cmd.Stderr = logFile
	l.cmd.Dir = l.dataDir

	if err := l.cmd.Start(); err != nil {
		logFile.Close()
		cancel()
		return fmt.Errorf("routing lifecycle: start: %w", err)
	}

	// Write PID file
	pidPath := filepath.Join(l.dataDir, "router.pid")
	pidData, _ := json.Marshal(map[string]interface{}{
		"pid":        l.cmd.Process.Pid,
		"port":       l.port,
		"start_time": time.Now().Unix(),
	})
	_ = os.WriteFile(pidPath, pidData, 0600)

	fmt.Fprintf(os.Stderr, "[routing] sr started (pid=%d, port=%d)\n", l.cmd.Process.Pid, l.port)

	// Background goroutine to wait for process exit and cleanup
	go func() {
		_ = l.cmd.Wait()
		logFile.Close()
		os.Remove(pidPath)
		if procCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[routing] sr exited unexpectedly (pid=%d)\n", l.cmd.Process.Pid)
		}
	}()

	return nil
}

// WaitForHealth polls the SR health endpoint until it responds 200 or timeout.
func (l *Lifecycle) WaitForHealth(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}
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
				fmt.Fprintf(os.Stderr, "[routing] sr healthy (port=%d)\n", l.port)
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("routing: sr health check timed out after %v", timeout)
}

// Stop gracefully shuts down the SR subprocess.
func (l *Lifecycle) Stop() error {
	if l.cmd == nil || l.cmd.Process == nil {
		return nil
	}

	// Cancel the context (signals the process via CommandContext)
	if l.cancel != nil {
		l.cancel()
	}

	// Send SIGTERM for graceful shutdown
	if err := l.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// Process may have already exited
		return nil
	}

	// Wait up to 5s for graceful exit
	done := make(chan struct{})
	go func() {
		l.cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Fprintf(os.Stderr, "[routing] sr stopped gracefully\n")
	case <-time.After(5 * time.Second):
		// Force kill
		_ = l.cmd.Process.Kill()
		fmt.Fprintf(os.Stderr, "[routing] sr killed (SIGKILL after 5s timeout)\n")
	}

	// Cleanup PID file
	pidPath := filepath.Join(l.dataDir, "router.pid")
	os.Remove(pidPath)

	return nil
}

// IsRunning checks if the SR process is still alive.
func (l *Lifecycle) IsRunning() bool {
	if l.cmd == nil || l.cmd.Process == nil {
		return false
	}
	// Check if process exists
	err := l.cmd.Process.Signal(syscall.Signal(0))
	return err == nil
}

// Port returns the configured port.
func (l *Lifecycle) Port() int {
	return l.port
}

// PID returns the process ID (0 if not running).
func (l *Lifecycle) PID() int {
	if l.cmd == nil || l.cmd.Process == nil {
		return 0
	}
	return l.cmd.Process.Pid
}
