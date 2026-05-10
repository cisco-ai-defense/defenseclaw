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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/notify"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	watchdogPIDFile   = "watchdog.pid"
	watchdogLogFile   = "watchdog.log"
	watchdogStateFile = "watchdog.state"
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

var watchdogStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the watchdog daemon status",
	RunE:  runWatchdogStatus,
}

func init() {
	watchdogCmd.AddCommand(watchdogStartCmd)
	watchdogCmd.AddCommand(watchdogStopCmd)
	watchdogCmd.AddCommand(watchdogStatusCmd)
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

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an
	// unrelated process"): the PID file is now opened with an
	// exclusive flock that the watchdog process holds for its entire
	// lifetime. A second `defenseclaw-gateway watchdog` invocation
	// will fail to acquire the lock and refuse to start. The PID file
	// payload is a JSON fingerprint (pid + executable path + start
	// time) so stop / status can verify the process before signalling
	// — a stale-PID-reuse scenario where another user's process now
	// owns the recorded PID will be detected by the executable check
	// and the stale PID file removed instead of signalling.
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	exe, exeErr := os.Executable()
	if exeErr != nil {
		exe = ""
	}
	pidFile, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{
		PID:        os.Getpid(),
		Executable: exe,
		StartTime:  time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("watchdog: another instance is already running (cannot acquire %s): %w", pidPath, err)
	}
	defer func() {
		_ = pidFile.Close()
		_ = os.Remove(pidPath)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The watchdog subcommand overrides rootCmd.PersistentPreRunE (see the
	// empty stub on watchdogCmd) so the shared otelProvider is never
	// initialized on this code path. Bring up a local provider here so the
	// defenseclaw.watcher.restarts counter fires on recovery. NewProvider
	// returns a disabled no-op when cfg.OTel.Enabled is false, keeping this
	// safe for users who haven't opted into telemetry.
	tel, telErr := telemetry.NewProvider(ctx, cfg, appVersion)
	if telErr != nil {
		fmt.Fprintf(os.Stderr, "[watchdog] warn: otel init failed: %v\n", telErr)
		tel = nil
	}
	defer func() {
		if tel != nil {
			// Filter the "collector unreachable" flavours so a
			// half-configured OTel block (the most common case) does
			// not produce a stderr banner every time the watchdog
			// exits. See isTransientOTelShutdownError for the rationale.
			if err := tel.Shutdown(context.Background()); err != nil && !isTransientOTelShutdownError(err) {
				fmt.Fprintf(os.Stderr, "[watchdog] warn: otel shutdown: %v\n", err)
			}
		}
	}()

	runWatchdogLoop(ctx, healthURL, interval, debounce, webhooks, tel)
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

func runWatchdogLoop(ctx context.Context, healthURL string, interval time.Duration, debounce int, webhooks *gateway.WebhookDispatcher, tel *telemetry.Provider) {
	dataDir := config.DefaultDataPath()
	current := loadWatchdogState(dataDir)
	failCount := 0
	if current != stateHealthy {
		failCount = debounce // carry over so first healthy probe triggers recovery
	}
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
					dispatchHealthEvent(webhooks, string(audit.ActionGatewayRecovered), "INFO", "Gateway recovered from "+current.String())
					// The watchdog is the only surface that observes the
					// full "down → healthy" transition from outside the
					// sidecar process, so this is where the reconnection
					// counter must fire. It complements the in-process
					// bump on sidecar WS reconnects and gives operators a
					// metric even when the sidecar itself was restarted.
					if tel != nil {
						tel.RecordWatcherRestart(ctx)
					}
				}
				current = stateHealthy
				saveWatchdogState(dataDir, current)

			case stateDegraded:
				failCount++
				if failCount >= debounce && current == stateHealthy {
					fmt.Fprintf(os.Stderr, "[watchdog] gateway degraded\n")
					_ = notify.Send("DefenseClaw", "Gateway guardrail is disconnected. Prompt protection is disabled.")
					dispatchHealthEvent(webhooks, string(audit.ActionGuardrailDegraded), "HIGH", "Guardrail proxy is disconnected; prompt protection is disabled")
					current = stateDegraded
					saveWatchdogState(dataDir, current)
				}

			default: // stateDown
				failCount++
				if failCount >= debounce && current != stateDown {
					fmt.Fprintf(os.Stderr, "[watchdog] gateway down (after %d failures)\n", failCount)
					_ = notify.Send("DefenseClaw", "Gateway is not running. Your AI agent traffic is unprotected.")
					dispatchHealthEvent(webhooks, string(audit.ActionGatewayDown), "CRITICAL", fmt.Sprintf("Gateway unreachable after %d consecutive failures", failCount))
					current = stateDown
					saveWatchdogState(dataDir, current)
				}
			}
		}
	}
}

func saveWatchdogState(dataDir string, state watchdogState) {
	_ = os.WriteFile(filepath.Join(dataDir, watchdogStateFile), []byte(state.String()), 0o644)
}

func loadWatchdogState(dataDir string) watchdogState {
	data, err := os.ReadFile(filepath.Join(dataDir, watchdogStateFile))
	if err != nil {
		return stateHealthy
	}
	switch strings.TrimSpace(string(data)) {
	case "down":
		return stateDown
	case "degraded":
		return stateDegraded
	default:
		return stateHealthy
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

	// hardening: probe for a running watchdog by attempting
	// to take the PID-file flock. If the lock is held, the watchdog
	// is alive. If the lock is free, ANY old plaintext PID file
	// content is by definition stale (a live watchdog would still
	// hold the flock) and we drop it before spawning the new child.
	if locked, info := watchdogIsLocked(pidPath); locked {
		Warn(fmt.Sprintf("Watchdog is already running (PID %d)", info.PID))
		return nil
	}
	// Stale or absent: clear the file so the child gets a clean
	// canvas and any name-only attacker cannot leave a fake PID
	// behind for stop to signal.
	_ = os.Remove(pidPath)

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

	fmt.Printf("Watchdog %s (PID %d)\n", Style("started", "fg=green", "bold"), cmd.pid)
	fmt.Printf("  %s %s\n", Style("Log file:", "fg=bright_black", "bold"), logPath)
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

	info, err := readWatchdogPIDInfo(pidPath)
	if err != nil {
		fmt.Println(Dim("Watchdog is not running"))
		return nil
	}

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an
	// unrelated process"): verify the recorded fingerprint BEFORE
	// signalling. A PID-reuse race (the watchdog crashed and the
	// kernel handed its PID to an unrelated user-owned process) used
	// to result in SIGTERM / SIGKILL to that unrelated process. Now
	// the executable path / signal-0 verification rejects the stale
	// PID and we just remove the file.
	if !verifyWatchdogProcess(info) {
		fmt.Println(Dim("Watchdog is not running (stale PID file removed)"))
		_ = os.Remove(pidPath)
		return nil
	}

	proc, err := os.FindProcess(info.PID)
	if err != nil {
		fmt.Println(Dim("Watchdog is not running"))
		_ = os.Remove(pidPath)
		return nil
	}

	fmt.Printf("Stopping watchdog (PID %d)... ", info.PID)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Println(Dim("already stopped"))
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
		// Re-verify the fingerprint immediately before SIGKILL so a
		// fast-restart-and-PID-reuse window cannot be exploited to
		// kill the new occupant. If verification now fails we just
		// abandon the kill and clean up the stale file.
		if verifyWatchdogProcess(info) {
			_ = proc.Signal(syscall.SIGKILL)
		}
	}

	_ = os.Remove(pidPath)
	fmt.Println(Style("OK", "fg=green", "bold"))
	return nil
}

func runWatchdogStatus(_ *cobra.Command, _ []string) error {
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)

	cfg, cfgErr := config.Load()
	enabled := cfgErr == nil && cfg.Gateway.Watchdog.Enabled

	info, err := readWatchdogPIDInfo(pidPath)
	if err != nil {
		if enabled {
			Warn("Watchdog: enabled but not running")
			Subhead("Start with: defenseclaw-gateway watchdog start")
		} else {
			fmt.Println(Dim("Watchdog: disabled"))
			Subhead("Enable in config: gateway.watchdog.enabled = true")
		}
		return nil
	}

	// hardening: same fingerprint check as stop. If the
	// recorded executable does not match /proc/<pid>/exe (Linux) the
	// PID was reused by an unrelated process; report not-running and
	// clear the stale file.
	if !verifyWatchdogProcess(info) {
		Warn(fmt.Sprintf("Watchdog: not running (PID %d does not match recorded fingerprint)", info.PID))
		_ = os.Remove(pidPath)
		return nil
	}

	fmt.Printf("Watchdog: %s (PID %d)\n", Style("running", "fg=green", "bold"), info.PID)

	state := loadWatchdogState(dataDir)
	fmt.Printf("  %s %s\n", Style("Last known state:", "fg=bright_black", "bold"), state.String())

	return nil
}

// watchdogPIDInfo is the JSON payload of watchdog.pid. The fingerprint
// (Executable + StartTime) lets stop/status verify that the recorded PID
// is still the same process that wrote the file rather than a recycled
// PID owned by an unrelated user-space process. See S3.HIGH_BUG
// "Stale watchdog PID file can stop an unrelated process".
type watchdogPIDInfo struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable,omitempty"`
	StartTime  int64  `json:"start_time,omitempty"`
}

// acquireWatchdogPIDFile opens (creating if missing) the PID file with
// 0600 perms, takes an exclusive non-blocking flock, truncates it, and
// writes a JSON fingerprint. Returns the locked file -- the caller MUST
// keep it open for the lifetime of the watchdog so a second instance
// cannot acquire the lock. Closing the file releases the kernel-level
// lock automatically.
func acquireWatchdogPIDFile(path string, info watchdogPIDInfo) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(info); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// readWatchdogPIDInfo parses the JSON PID file. For backward compat with
// older watchdog versions that wrote a bare integer PID, the parser also
// accepts a plain decimal number; in that case the returned info has no
// Executable / StartTime and verifyWatchdogProcess only does the
// signal-0 liveness check.
func readWatchdogPIDInfo(path string) (watchdogPIDInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return watchdogPIDInfo{}, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return watchdogPIDInfo{}, fmt.Errorf("watchdog: empty pid file")
	}
	var info watchdogPIDInfo
	if err := json.Unmarshal([]byte(trimmed), &info); err == nil {
		if info.PID > 0 {
			return info, nil
		}
		return watchdogPIDInfo{}, fmt.Errorf("watchdog: invalid pid in pid file")
	}
	// Legacy plain-text fallback. Only the liveness check is possible.
	pid, err := strconv.Atoi(trimmed)
	if err != nil || pid <= 0 {
		return watchdogPIDInfo{}, fmt.Errorf("watchdog: malformed pid file")
	}
	return watchdogPIDInfo{PID: pid}, nil
}

// verifyWatchdogProcess returns true only if the PID still resolves to
// a running process AND, when an executable fingerprint is available,
// /proc/<pid>/exe matches. Without this the previous implementation
// treated ANY live process at the recorded PID as "the watchdog" and
// would happily SIGTERM an unrelated user shell that happened to grab
// the recycled PID after a crash.
func verifyWatchdogProcess(info watchdogPIDInfo) bool {
	if info.PID <= 0 {
		return false
	}
	proc, err := os.FindProcess(info.PID)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	if info.Executable == "" {
		// Legacy pid file: signal-0 is all we can verify. The
		// foreground watchdog now writes the fingerprint, so any
		// pidfile written by 0.5+ has it; legacy compat preserves
		// the previous behaviour for unmigrated installs.
		return true
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
	if err != nil || exePath == "" {
		// /proc not available (e.g. macOS): conservatively trust the
		// signal-0 result. The daemon side has the same limitation
		// (see verifyProcessDarwin in internal/daemon).
		return true
	}
	return exePath == info.Executable
}

// watchdogIsLocked reports whether the PID-file flock is currently
// held. Used by `watchdog start` to detect a live watchdog without
// signalling anything. Always closes the test file before returning so
// the lock is released for the child to take.
func watchdogIsLocked(path string) (bool, watchdogPIDInfo) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		// File does not exist -- nothing locked.
		return false, watchdogPIDInfo{}
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Lock held by another process: it's the live watchdog.
		info, _ := readWatchdogPIDInfo(path)
		return true, info
	}
	// We took the lock; release it now so the child can re-acquire.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, watchdogPIDInfo{}
}
