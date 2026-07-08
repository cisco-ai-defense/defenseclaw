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

const maxWatchdogHealthBytes = 64 << 10

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

// watchdogHealthRequirements is an immutable snapshot of the protection
// surfaces required by the configuration loaded when the watchdog starts.
// Optional observability subsystems are deliberately absent: disabling local
// telemetry or sinks does not remove protection from an agent traffic path.
type watchdogHealthRequirements struct {
	requireFleet     bool
	requireGuardrail bool
	requireWatcher   bool
	connectors       []string
}

func watchdogHealthRequirementsFromConfig(cfg *config.Config) watchdogHealthRequirements {
	if cfg == nil {
		return watchdogHealthRequirements{}
	}
	configured := cfg.ActiveConnectors()
	connectors := make([]string, 0, len(configured))
	for _, name := range configured {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			connectors = append(connectors, name)
		}
	}
	return watchdogHealthRequirements{
		requireFleet:     gateway.RequiresFleetGateway(cfg),
		requireGuardrail: cfg.Guardrail.Enabled,
		requireWatcher:   cfg.Gateway.Watcher.Enabled,
		connectors:       connectors,
	}
}

type watchdogAssessment struct {
	state        watchdogState
	notification string
	action       string
	severity     string
	details      string
}

func healthyWatchdogAssessment() watchdogAssessment {
	return watchdogAssessment{state: stateHealthy}
}

func degradedWatchdogAssessment(details string) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDegraded,
		notification: "A required DefenseClaw protection subsystem is unavailable. Check gateway status.",
		action:       string(audit.ActionGuardrailDegraded),
		severity:     "HIGH",
		details:      details,
	}
}

func downWatchdogAssessment(details string) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDown,
		notification: "DefenseClaw sidecar health is unavailable. Protection status cannot be verified.",
		action:       string(audit.ActionGatewayDown),
		severity:     "CRITICAL",
		details:      details,
	}
}

func fleetDownWatchdogAssessment(state gateway.SubsystemState) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDown,
		notification: "The required OpenClaw fleet gateway is unavailable. Agent traffic protection is interrupted.",
		action:       string(audit.ActionGatewayDown),
		severity:     "CRITICAL",
		details:      fmt.Sprintf("Required OpenClaw fleet gateway is %s", displayHealthState(state)),
	}
}

func displayHealthState(state gateway.SubsystemState) string {
	if state == "" {
		return "missing from the health response"
	}
	return string(state)
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
	requirements := watchdogHealthRequirementsFromConfig(cfg)

	var webhooks *gateway.WebhookDispatcher
	// Include per-connector webhook overrides (D5b) so a global-empty install
	// that routes a connector to its own webhook still gets a dispatcher.
	if len(cfg.Webhooks) > 0 || len(cfg.Observability.Connectors) > 0 {
		webhooks = gateway.NewWebhookDispatcher(cfg.Webhooks, cfg.Observability)
	}

	fmt.Fprintf(os.Stderr, "[watchdog] starting: poll=%s debounce=%d url=%s\n",
		interval, debounce, healthURL)

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an
	// unrelated process"): hold an exclusive lock on the PID file for the
	// watchdog's entire lifetime so a second instance refuses to start,
	// and record a JSON fingerprint (pid + executable + start time) so
	// stop/status can verify the recorded PID still belongs to this
	// process before signalling. acquireWatchdogPIDFile is
	// platform-specific (flock on unix, LockFileEx on Windows).
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	exe, exeErr := os.Executable()
	if exeErr != nil {
		exe = ""
	}
	pidFile, err := acquireWatchdogPIDFile(pidPath, watchdogPIDInfo{
		PID:           os.Getpid(),
		Executable:    exe,
		StartTime:     time.Now().Unix(),
		StartIdentity: watchdogProcessStartIdentity(os.Getpid()),
	})
	if err != nil {
		return fmt.Errorf("watchdog: another instance is already running (cannot acquire %s): %w", pidPath, err)
	}
	defer func() {
		_ = pidFile.Close()
		_ = os.Remove(pidPath)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), watchdogShutdownSignals()...)
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

	runWatchdogLoop(ctx, healthURL, interval, debounce, requirements, webhooks, tel)
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

func runWatchdogLoop(ctx context.Context, healthURL string, interval time.Duration, debounce int, requirements watchdogHealthRequirements, webhooks *gateway.WebhookDispatcher, tel *telemetry.Provider) {
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
			assessment := probeHealth(client, healthURL, requirements)

			switch assessment.state {
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
					fmt.Fprintf(os.Stderr, "[watchdog] protection degraded: %s\n", assessment.details)
					_ = notify.Send("DefenseClaw", assessment.notification)
					dispatchHealthEvent(webhooks, assessment.action, assessment.severity, assessment.details)
					current = stateDegraded
					saveWatchdogState(dataDir, current)
				}

			default: // stateDown
				failCount++
				if failCount >= debounce && current != stateDown {
					fmt.Fprintf(os.Stderr, "[watchdog] protection down (after %d failures): %s\n", failCount, assessment.details)
					_ = notify.Send("DefenseClaw", assessment.notification)
					dispatchHealthEvent(webhooks, assessment.action, assessment.severity, assessment.details)
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

func probeHealth(client *http.Client, url string, requirements watchdogHealthRequirements) watchdogAssessment {
	resp, err := client.Get(url)
	if err != nil {
		return downWatchdogAssessment("Sidecar health API is unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWatchdogHealthBytes+1))
	if err != nil {
		return downWatchdogAssessment("Sidecar health response could not be read")
	}
	if len(body) > maxWatchdogHealthBytes {
		return downWatchdogAssessment("Sidecar health response exceeds the size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return downWatchdogAssessment(fmt.Sprintf("Sidecar health API returned HTTP %d", resp.StatusCode))
	}

	var snap struct {
		Gateway    *gateway.SubsystemHealth   `json:"gateway"`
		Watcher    *gateway.SubsystemHealth   `json:"watcher"`
		Guardrail  *gateway.SubsystemHealth   `json:"guardrail"`
		Connector  *gateway.ConnectorHealth   `json:"connector"`
		Connectors *[]gateway.ConnectorHealth `json:"connectors"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		return downWatchdogAssessment("Sidecar health response is malformed")
	}

	if requirements.requireFleet {
		if snap.Gateway == nil || snap.Gateway.State != gateway.StateRunning {
			var state gateway.SubsystemState
			if snap.Gateway != nil {
				state = snap.Gateway.State
			}
			return fleetDownWatchdogAssessment(state)
		}
	}
	if requirements.requireGuardrail && (snap.Guardrail == nil || snap.Guardrail.State != gateway.StateRunning) {
		var state gateway.SubsystemState
		if snap.Guardrail != nil {
			state = snap.Guardrail.State
		}
		return degradedWatchdogAssessment("Required guardrail is " + displayHealthState(state))
	}
	if requirements.requireWatcher && (snap.Watcher == nil || snap.Watcher.State != gateway.StateRunning) {
		var state gateway.SubsystemState
		if snap.Watcher != nil {
			state = snap.Watcher.State
		}
		return degradedWatchdogAssessment("Required watcher is " + displayHealthState(state))
	}
	if assessment := assessRequiredConnectors(snap.Connector, snap.Connectors, requirements.connectors); assessment.state != stateHealthy {
		return assessment
	}
	return healthyWatchdogAssessment()
}

func assessRequiredConnectors(primary *gateway.ConnectorHealth, connectors *[]gateway.ConnectorHealth, required []string) watchdogAssessment {
	if len(required) == 0 {
		return healthyWatchdogAssessment()
	}
	byName := make(map[string]gateway.SubsystemState)
	if connectors != nil {
		for _, health := range *connectors {
			name := strings.ToLower(strings.TrimSpace(health.Name))
			if name != "" {
				byName[name] = health.State
			}
		}
	}
	// Older sidecars exposed only the singular connector field. Accept that
	// representation when it identifies one of the configured connectors.
	if primary != nil {
		name := strings.ToLower(strings.TrimSpace(primary.Name))
		if name != "" {
			byName[name] = primary.State
		}
	}
	for _, name := range required {
		state, ok := byName[name]
		if !ok {
			return degradedWatchdogAssessment(fmt.Sprintf("Required connector %s is missing from the health response", name))
		}
		if state != gateway.StateRunning {
			return degradedWatchdogAssessment(fmt.Sprintf("Required connector %s is %s", name, displayHealthState(state)))
		}
	}
	return healthyWatchdogAssessment()
}

func runWatchdogStart(_ *cobra.Command, _ []string) error {
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)

	// Probe for a running watchdog by attempting to take the PID-file
	// lock. If the lock is held, the watchdog is alive. If the lock is
	// free, any old PID file content is by definition stale (a live
	// watchdog holds the lock for its whole lifetime) so we drop it
	// before spawning the new child.
	if locked, info := watchdogIsLocked(pidPath); locked {
		Warn(fmt.Sprintf("Watchdog is already running (PID %d)", info.PID))
		return nil
	}
	// Stale or absent: clear the file so the child gets a clean canvas
	// and a name-only attacker cannot leave a fake PID for stop to signal.
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
		Dir:   watchdogStartDir(),
		Files: []*os.File{devNull, c.logFile, c.logFile},
		Sys:   watchdogSysProcAttr(),
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

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an unrelated
	// process"): verify the recorded fingerprint BEFORE signalling. A
	// PID-reuse race (the watchdog crashed and the kernel handed its PID
	// to an unrelated user-owned process) used to send SIGTERM/SIGKILL to
	// that unrelated process. The executable fingerprint / liveness check
	// now rejects the stale PID and we just remove the file.
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
	if err := watchdogTerminate(proc); err != nil {
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
		// Re-verify the fingerprint immediately before force-kill so a
		// fast-restart-and-PID-reuse window cannot be exploited to kill
		// the new occupant of the recycled PID.
		if verifyWatchdogProcess(info) {
			_ = watchdogKill(proc)
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

	// Same fingerprint check as stop. If the recorded executable no
	// longer matches the live process the PID was reused by an unrelated
	// process; report not-running and clear the stale file.
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
// PID owned by an unrelated process. See S3.HIGH_BUG "Stale watchdog PID
// file can stop an unrelated process".
type watchdogPIDInfo struct {
	PID           int    `json:"pid"`
	Executable    string `json:"executable,omitempty"`
	StartTime     int64  `json:"start_time,omitempty"`
	StartIdentity string `json:"start_identity,omitempty"`
}

// writeWatchdogPIDInfo truncates f and writes info as JSON, flushing to
// disk. The caller is responsible for holding the platform lock on f.
func writeWatchdogPIDInfo(f *os.File, info watchdogPIDInfo) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(info); err != nil {
		return err
	}
	return f.Sync()
}

// readWatchdogPIDInfo parses the JSON PID file. For backward compat with
// older watchdog versions that wrote a bare integer PID, the parser also
// accepts a plain decimal number; in that case the returned info has no
// Executable / StartTime / StartIdentity and verifyWatchdogProcess only does
// the liveness check.
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

// verifyWatchdogProcess returns true only if the PID still resolves to a
// running process and every available identity fingerprint matches. Windows
// uses the kernel process-creation identity; Linux additionally compares
// /proc/<pid>/exe. Without this the previous implementation treated ANY live
// process at the recorded PID as "the watchdog" and could terminate an
// unrelated process that grabbed the recycled PID after a crash.
func verifyWatchdogProcess(info watchdogPIDInfo) bool {
	if info.PID <= 0 {
		return false
	}
	proc, err := os.FindProcess(info.PID)
	if err != nil {
		return false
	}
	if !watchdogProcessAlive(info.PID, proc) {
		return false
	}
	if info.StartIdentity != "" {
		currentIdentity := watchdogProcessStartIdentity(info.PID)
		if currentIdentity == "" || currentIdentity != info.StartIdentity {
			return false
		}
	}
	if info.Executable == "" {
		// No executable fingerprint remains; any start identity was already
		// verified above. Legacy bare-int files therefore use liveness only.
		return true
	}
	// Linux exposes the running binary at /proc/<pid>/exe. On platforms
	// without it, retain the verified start identity when available and
	// otherwise preserve the legacy liveness fallback.
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
	if err != nil || exePath == "" {
		return true
	}
	return exePath == info.Executable
}
