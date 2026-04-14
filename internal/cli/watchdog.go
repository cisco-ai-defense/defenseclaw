// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

const (
	watchdogPIDFile = "watchdog.pid"
	watchdogLogFile = "watchdog.log"
)

type watchdogState int

const (
	stateHealthy watchdogState = iota
	stateDegraded
	stateDown
)

func (s watchdogState) String() string {
	switch s {
	case stateHealthy:
		return "healthy"
	case stateDegraded:
		return "degraded"
	case stateDown:
		return "down"
	default:
		return "unknown"
	}
}

var watchdogCmd = &cobra.Command{
	Use:   "watchdog",
	Short: "Health watchdog that notifies when the gateway is down",
	Long: `The watchdog polls the gateway /health endpoint and sends desktop
notifications when the sidecar is unreachable or degraded.

Run in the foreground:  defenseclaw-gateway watchdog
Run as background:      defenseclaw-gateway watchdog start
Stop:                   defenseclaw-gateway watchdog stop`,
	RunE:              runWatchdogForeground,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
}

var watchdogStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the watchdog as a background daemon",
	RunE:  runWatchdogStart,
}

var watchdogStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running watchdog daemon",
	RunE:  runWatchdogStop,
}

func init() {
	watchdogCmd.AddCommand(watchdogStartCmd)
	watchdogCmd.AddCommand(watchdogStopCmd)
	rootCmd.AddCommand(watchdogCmd)
}

func runWatchdogForeground(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	interval := time.Duration(cfg.Gateway.Watchdog.Interval) * time.Second
	if interval < time.Second {
		interval = 30 * time.Second
	}
	debounce := cfg.Gateway.Watchdog.Debounce
	if debounce < 1 {
		debounce = 2
	}

	healthURL := watchdogHealthURL(cfg)

	var webhooks *gateway.WebhookDispatcher
	if len(cfg.Webhooks) > 0 {
		webhooks = gateway.NewWebhookDispatcher(cfg.Webhooks)
	}

	fmt.Fprintf(os.Stderr, "[watchdog] starting: poll=%s debounce=%d url=%s\n",
		interval, debounce, healthURL)

	// Write PID file
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644)
	defer os.Remove(pidPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runWatchdogLoop(ctx, healthURL, interval, debounce, webhooks)
	if webhooks != nil {
		webhooks.Close()
	}
	fmt.Fprintf(os.Stderr, "[watchdog] stopped\n")
	return nil
}

func watchdogHealthURL(cfg *config.Config) string {
	apiPort := 18970
	if cfg != nil && cfg.Gateway.APIPort != 0 {
		apiPort = cfg.Gateway.APIPort
	}

	apiBind := "127.0.0.1"
	if cfg != nil {
		if cfg.Gateway.APIBind != "" {
			apiBind = cfg.Gateway.APIBind
		} else if cfg.OpenShell.IsStandalone() && cfg.Guardrail.Host != "" && cfg.Guardrail.Host != "localhost" {
			apiBind = cfg.Guardrail.Host
		}
	}

	return fmt.Sprintf("http://%s:%d/health", apiBind, apiPort)
}

func runWatchdogLoop(ctx context.Context, healthURL string, interval time.Duration, debounce int, webhooks *gateway.WebhookDispatcher) {
	current := stateHealthy
	failCount := 0
	client := &http.Client{Timeout: 5 * time.Second}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probed := probeHealth(client, healthURL)

			switch probed {
			case stateHealthy:
				failCount = 0
				if current != stateHealthy {
					fmt.Fprintf(os.Stderr, "[watchdog] gateway recovered: %s → healthy\n", current)
					_ = notify.Send("DefenseClaw", "Gateway is back online. Protection restored.")
					dispatchHealthEvent(webhooks, "gateway-recovered", "INFO", "Gateway recovered from "+current.String())
				}
				current = stateHealthy

			case stateDegraded:
				failCount++
				if failCount >= debounce && current == stateHealthy {
					fmt.Fprintf(os.Stderr, "[watchdog] gateway degraded\n")
					_ = notify.Send("DefenseClaw", "Gateway guardrail is disconnected. Prompt protection is disabled.")
					dispatchHealthEvent(webhooks, "guardrail-degraded", "HIGH", "Guardrail proxy is disconnected; prompt protection is disabled")
					current = stateDegraded
				}

			default: // stateDown
				failCount++
				if failCount >= debounce && current != stateDown {
					fmt.Fprintf(os.Stderr, "[watchdog] gateway down (after %d failures)\n", failCount)
					_ = notify.Send("DefenseClaw", "Gateway is not running. Your AI agent traffic is unprotected.")
					dispatchHealthEvent(webhooks, "gateway-down", "CRITICAL", fmt.Sprintf("Gateway unreachable after %d consecutive failures", failCount))
					current = stateDown
				}
			}
		}
	}
}

func dispatchHealthEvent(webhooks *gateway.WebhookDispatcher, action, severity, details string) {
	if webhooks == nil {
		return
	}
	webhooks.Dispatch(audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "defenseclaw-gateway",
		Actor:     "defenseclaw-watchdog",
		Details:   details,
		Severity:  severity,
	})
}

func probeHealth(client *http.Client, url string) watchdogState {
	resp, err := client.Get(url)
	if err != nil {
		return stateDown
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != http.StatusOK {
		return stateDown
	}

	var snap struct {
		Gateway struct {
			State string `json:"state"`
		} `json:"gateway"`
		Guardrail struct {
			State string `json:"state"`
		} `json:"guardrail"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		return stateDown
	}

	if snap.Gateway.State != "running" {
		return stateDown
	}
	if snap.Guardrail.State != "" && snap.Guardrail.State != "running" {
		return stateDegraded
	}
	return stateHealthy
}

func runWatchdogStart(_ *cobra.Command, _ []string) error {
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)

	// Check if already running.
	if data, err := os.ReadFile(pidPath); err == nil {
		if pid, err := strconv.Atoi(string(data)); err == nil {
			if proc, err := os.FindProcess(pid); err == nil {
				if err := proc.Signal(syscall.Signal(0)); err == nil {
					fmt.Printf("Watchdog is already running (PID %d)\n", pid)
					return nil
				}
			}
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("watchdog: resolve executable: %w", err)
	}

	logPath := filepath.Join(dataDir, watchdogLogFile)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("watchdog: open log: %w", err)
	}

	cmd := &execCommand{path: exe, args: []string{"watchdog"}, logFile: logFile}
	if err := cmd.start(); err != nil {
		logFile.Close()
		return fmt.Errorf("watchdog: start background: %w", err)
	}

	fmt.Printf("Watchdog started (PID %d)\n", cmd.pid)
	fmt.Printf("  Log file: %s\n", logPath)
	return nil
}

type execCommand struct {
	path    string
	args    []string
	logFile *os.File
	pid     int
}

func (c *execCommand) start() error {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	proc, err := os.StartProcess(c.path, append([]string{c.path}, c.args...), &os.ProcAttr{
		Dir:   "/",
		Files: []*os.File{devNull, c.logFile, c.logFile},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	_ = devNull.Close()
	if err != nil {
		return err
	}
	c.pid = proc.Pid
	_ = proc.Release()
	return nil
}

func runWatchdogStop(_ *cobra.Command, _ []string) error {
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)

	data, err := os.ReadFile(pidPath)
	if err != nil {
		fmt.Println("Watchdog is not running")
		return nil
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Println("Watchdog is not running (invalid PID file)")
		_ = os.Remove(pidPath)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("Watchdog is not running")
		_ = os.Remove(pidPath)
		return nil
	}

	fmt.Printf("Stopping watchdog (PID %d)... ", pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Println("already stopped")
		_ = os.Remove(pidPath)
		return nil
	}

	// Wait briefly for graceful exit.
	done := make(chan struct{})
	go func() {
		_, _ = proc.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = proc.Signal(syscall.SIGKILL)
	}

	_ = os.Remove(pidPath)
	fmt.Println("OK")
	return nil
}
