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
	"errors"
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
)

const (
	watchdogPIDFile         = "watchdog.pid"
	watchdogOwnershipFile   = ".watchdog.lock"
	watchdogLogFile         = "watchdog.log"
	watchdogStateFile       = "watchdog.state"
	maxWatchdogHealthBytes  = 64 << 10
	maxWatchdogPIDFileBytes = 16 << 10
	watchdogStartTimeout    = 15 * time.Second
	watchdogStartInterval   = 25 * time.Millisecond
)

type watchdogState int

type watchdogRecoveryRecorder interface {
	RecordWatchdogRecovery(context.Context) error
}

type watchdogAPIRecoveryRecorder struct {
	client *http.Client
	url    string
	token  string
}

// watchdogPIDOwnershipInspection keeps lifetime-lock trust separate from the
// canonical PID publication. Explicit lifecycle repair may act on the latter
// only after the former was positively inspected without error.
type watchdogPIDOwnershipInspection struct {
	locked         bool
	info           watchdogPIDInfo
	ownershipErr   error
	publicationErr error
}

func (inspection watchdogPIDOwnershipInspection) combinedErr() error {
	return errors.Join(inspection.ownershipErr, inspection.publicationErr)
}

func watchdogIsLocked(path string) (bool, watchdogPIDInfo, error) {
	inspection := inspectWatchdogPIDOwnership(path)
	return inspection.locked, inspection.info, inspection.combinedErr()
}

var (
	watchdogExecutablePath              = os.Executable
	watchdogCurrentProcessStartIdentity = watchdogProcessStartIdentity
	watchdogLoopRunner                  = runWatchdogLoop
	watchdogStartPublicationProbe       = watchdogStartPublicationReady
)

func (recorder *watchdogAPIRecoveryRecorder) RecordWatchdogRecovery(ctx context.Context) error {
	if recorder == nil || recorder.client == nil || ctx == nil ||
		strings.TrimSpace(recorder.url) == "" || strings.TrimSpace(recorder.token) == "" {
		return fmt.Errorf("watchdog: recovery recorder unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recorder.url, strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("watchdog: build recovery request")
	}
	req.Header.Set("Authorization", "Bearer "+recorder.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "watchdog")
	response, err := recorder.client.Do(req)
	if err != nil {
		return fmt.Errorf("watchdog: recovery request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("watchdog: recovery request rejected")
	}
	return nil
}

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

// watchdogHealthRequirements is the protection surface snapshot captured
// from the configuration loaded when the watchdog starts. Optional telemetry
// destinations do not affect these requirements.
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

func healthyWatchdogAssessment() watchdogAssessment { return watchdogAssessment{state: stateHealthy} }

func degradedWatchdogAssessment(details string) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDegraded,
		notification: "A required DefenseClaw protection subsystem is unavailable. Check gateway status.",
		action:       string(audit.ActionGuardrailDegraded), severity: "HIGH", details: details,
	}
}

func downWatchdogAssessment(details string) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDown,
		notification: "DefenseClaw sidecar health is unavailable. Protection status cannot be verified.",
		action:       string(audit.ActionGatewayDown), severity: "CRITICAL", details: details,
	}
}

func fleetDownWatchdogAssessment(state gateway.SubsystemState) watchdogAssessment {
	return watchdogAssessment{
		state:        stateDown,
		notification: "The required OpenClaw fleet gateway is unavailable. Agent traffic protection is interrupted.",
		action:       string(audit.ActionGatewayDown), severity: "CRITICAL",
		details: fmt.Sprintf("Required OpenClaw fleet gateway is %s", displayHealthState(state)),
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
	cfg, err := config.LoadRuntimeV8File(config.ConfigPath())
	if err != nil {
		return fmt.Errorf("watchdog: load schema-v8 config: %w", err)
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
	currentPID := os.Getpid()
	exe, exeErr := watchdogExecutablePath()
	if exeErr != nil {
		if watchdogRequiresStrongProcessIdentity() {
			return fmt.Errorf("watchdog: resolve executable identity: %w", exeErr)
		}
		exe = ""
	}
	pidInfo := watchdogPIDInfo{
		PID:           currentPID,
		Executable:    exe,
		StartTime:     time.Now().Unix(),
		StartIdentity: watchdogCurrentProcessStartIdentity(currentPID),
	}
	if watchdogRequiresStrongProcessIdentity() && !watchdogHasStrongProcessIdentity(pidInfo) {
		return errors.New("watchdog: complete executable and process start identity are required on Windows")
	}

	var webhooks *gateway.WebhookDispatcher
	// Include per-connector webhook overrides (D5b) so a global-empty install
	// that routes a connector to its own webhook still gets a dispatcher.
	if len(cfg.Webhooks) > 0 || len(cfg.Observability.Connectors) > 0 {
		webhooks = gateway.NewWebhookDispatcher(cfg.Webhooks, cfg.Observability)
	}

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an
	// unrelated process"): hold an exclusive lock on the PID file for the
	// watchdog's entire lifetime so a second instance refuses to start,
	// and record a JSON fingerprint (pid + executable + start time) so
	// stop/status can verify the recorded PID still belongs to this
	// process before signalling. acquireWatchdogPIDFile is
	// platform-specific (flock on unix, LockFileEx on Windows).
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)
	controlName, controlTriggered, closeControl, controlErr := watchdogCreateControl()
	if controlErr != nil {
		return fmt.Errorf("watchdog: create shutdown control: %w", controlErr)
	}
	defer closeControl()
	pidInfo.ControlName = controlName
	pidFile, err := acquireWatchdogPIDFile(pidPath, pidInfo)
	if err != nil {
		return fmt.Errorf("watchdog: another instance is already running (cannot acquire %s): %w", pidPath, err)
	}
	defer func() {
		_ = pidFile.Close()
		removeWatchdogPIDIfOwned(pidPath, pidInfo)
	}()
	fmt.Fprintf(os.Stderr, "[watchdog] starting: poll=%s debounce=%d url=%s\n",
		interval, debounce, healthURL)

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), watchdogShutdownSignals()...)
	defer stopSignals()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	if controlTriggered != nil {
		go func() {
			select {
			case <-controlTriggered:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	var recoveryRecorder watchdogRecoveryRecorder
	if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
		recoveryRecorder = &watchdogAPIRecoveryRecorder{
			client: &http.Client{Timeout: 5 * time.Second},
			url:    strings.TrimSuffix(healthURL, "/health") + "/api/v1/watchdog/recovery",
			token:  token,
		}
	} else {
		fmt.Fprintln(os.Stderr, "[watchdog] warn: gateway token unavailable; recovery telemetry will not be recorded")
	}

	watchdogLoopRunner(ctx, healthURL, interval, debounce, requirements, webhooks, recoveryRecorder)
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

func runWatchdogLoop(ctx context.Context, healthURL string, interval time.Duration, debounce int, requirements watchdogHealthRequirements, webhooks *gateway.WebhookDispatcher, recovery watchdogRecoveryRecorder) {
	dataDir := config.DefaultDataPath()
	current := loadWatchdogState(dataDir)
	failCount := 0
	pendingRecovery := false
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
					pendingRecovery = true
				}
				current = stateHealthy
				saveWatchdogState(dataDir, current)
				// The recovered sidecar owns the canonical v8 runtime. Keep
				// retrying this narrow authenticated notification on healthy
				// probes until its generated restart metric is acknowledged.
				if pendingRecovery && recovery != nil {
					if err := recovery.RecordWatchdogRecovery(ctx); err == nil {
						pendingRecovery = false
					}
				}

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
	state, err := readWatchdogState(dataDir)
	if err != nil {
		return stateHealthy
	}
	return state
}

func readWatchdogState(dataDir string) (watchdogState, error) {
	f, err := os.Open(filepath.Join(dataDir, watchdogStateFile))
	if err != nil {
		return stateHealthy, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil {
		return stateHealthy, err
	}
	if len(data) > 64 {
		return stateHealthy, errors.New("watchdog: last-known state exceeds 64 bytes")
	}
	switch strings.TrimSpace(string(data)) {
	case "down":
		return stateDown, nil
	case "degraded":
		return stateDegraded, nil
	case "healthy":
		return stateHealthy, nil
	}
	return stateHealthy, errors.New("watchdog: last-known state is invalid")
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

	// Probe the platform ownership lock and the canonical PID identity before
	// spawning. Explicit start may safely repair an unlocked invalid/stale
	// private record; read-only status never does.
	inspection := inspectWatchdogPIDOwnership(pidPath)
	if inspection.ownershipErr != nil {
		return fmt.Errorf("watchdog: inspect stable PID ownership: %w", inspection.ownershipErr)
	}
	locked, info, lockErr := inspection.locked, inspection.info, inspection.publicationErr
	if locked {
		if lockErr != nil || !verifyWatchdogProcess(info) {
			info, lockErr = watchdogOwnedRecordWait(pidPath, watchdogStartTimeout, watchdogStartInterval)
			if lockErr != nil {
				return fmt.Errorf("watchdog: ownership is held but its PID publication is not ready: %w", lockErr)
			}
		}
		Warn(fmt.Sprintf("Watchdog is already running (PID %d)", info.PID))
		return nil
	}
	if lockErr == nil && watchdogUnlockedLiveProcessInfo(info) {
		return fmt.Errorf("watchdog: PID %d is alive but does not hold the ownership lock; refusing to start a duplicate", info.PID)
	}
	// Explicit start is the repair boundary for an unlocked invalid or stale
	// record. The platform helper binds validation and deletion to the exact
	// private, non-reparse file object; status never performs this cleanup.
	removed, cleanupErr := removeStaleWatchdogPIDFile(pidPath)
	if cleanupErr != nil {
		return fmt.Errorf("watchdog: repair stale PID ownership: %w", cleanupErr)
	}
	if lockErr != nil && !removed {
		return fmt.Errorf("watchdog: inspect PID ownership: %w", lockErr)
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
	if err := watchdogStartBackground(cmd); err != nil {
		logFile.Close()
		return fmt.Errorf("watchdog: start background: %w", err)
	}
	_ = logFile.Close()
	if err := waitForWatchdogStart(pidPath, cmd.pid, watchdogStartTimeout, watchdogStartInterval); err != nil {
		return fmt.Errorf("watchdog: start readiness: %w", err)
	}

	fmt.Printf("Watchdog %s (PID %d)\n", Style("started", "fg=green", "bold"), cmd.pid)
	fmt.Printf("  %s %s\n", Style("Log file:", "fg=bright_black", "bold"), logPath)
	return nil
}

func waitForWatchdogOwnedRecord(pidPath string, timeout, interval time.Duration) (watchdogPIDInfo, error) {
	if timeout <= 0 {
		timeout = watchdogStartTimeout
	}
	if interval <= 0 {
		interval = watchdogStartInterval
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		locked, info, err := watchdogIsLocked(pidPath)
		if err == nil && locked && verifyWatchdogProcess(info) {
			return info, nil
		}
		if !locked {
			if err != nil {
				return watchdogPIDInfo{}, err
			}
			return watchdogPIDInfo{}, errors.New("ownership lock was released before PID publication")
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("published PID identity does not match its owner")
		}
		if !time.Now().Before(deadline) {
			return watchdogPIDInfo{}, lastErr
		}
		time.Sleep(interval)
	}
}

var watchdogOwnedRecordWait = waitForWatchdogOwnedRecord

func waitForWatchdogStart(pidPath string, expectedPID int, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		publicationReady, err := watchdogStartPublicationProbe(pidPath, expectedPID)
		if publicationReady {
			locked, info, inspectionErr := watchdogIsLocked(pidPath)
			err = inspectionErr
			if err == nil && locked {
				if info.PID != expectedPID {
					// Atomic publication intentionally acquires ownership before it
					// replaces the canonical PID record. During that short window a
					// reader may still see the prior record; keep polling until the
					// bounded readiness deadline instead of rejecting the child early.
					err = fmt.Errorf("ownership lock belongs to PID %d, expected %d", info.PID, expectedPID)
				} else if !verifyWatchdogProcess(info) {
					err = fmt.Errorf("ownership lock PID %d lacks a verified process identity", expectedPID)
				} else {
					return nil
				}
			}
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("PID ownership remained unreadable: %w", err)
			}
			return fmt.Errorf("PID %d did not acquire its ownership lock within %s", expectedPID, timeout)
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
}

type execCommand struct {
	path    string
	args    []string
	logFile *os.File
	pid     int
}

var watchdogStartBackground = func(command *execCommand) error {
	return command.start()
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

	inspection := inspectWatchdogPIDOwnership(pidPath)
	if inspection.ownershipErr != nil {
		return fmt.Errorf("watchdog: inspect stable PID ownership: %w", inspection.ownershipErr)
	}
	locked, info, lockErr := inspection.locked, inspection.info, inspection.publicationErr
	if locked && (lockErr != nil || !verifyWatchdogProcess(info)) {
		info, lockErr = watchdogOwnedRecordWait(pidPath, watchdogStartTimeout, watchdogStartInterval)
		if lockErr != nil {
			return fmt.Errorf("watchdog: ownership is held but its PID publication is not ready: %w", lockErr)
		}
	}
	if !locked {
		if lockErr == nil && watchdogUnlockedLiveProcessInfo(info) {
			return fmt.Errorf("watchdog: PID %d is alive but does not hold the ownership lock; refusing to report a successful stop", info.PID)
		}
		removed, cleanupErr := removeStaleWatchdogPIDFile(pidPath)
		if cleanupErr != nil {
			return fmt.Errorf("watchdog: repair stale PID ownership: %w", cleanupErr)
		}
		if removed {
			fmt.Println(Dim("Watchdog is not running (stale or invalid PID file repaired)"))
		} else {
			fmt.Println(Dim("Watchdog is not running"))
		}
		return nil
	}

	// S3.HIGH_BUG ("Stale watchdog PID file can stop an unrelated
	// process"): verify the recorded fingerprint BEFORE signalling. A
	// PID-reuse race (the watchdog crashed and the kernel handed its PID
	// to an unrelated user-owned process) used to send SIGTERM/SIGKILL to
	// that unrelated process. A held ownership lock with a mismatched
	// fingerprint is not deletion or signalling authority.
	if !verifyWatchdogProcess(info) {
		return errors.New("watchdog: ownership lock is held by a process that does not match the recorded identity; refusing cleanup")
	}

	proc, err := os.FindProcess(info.PID)
	if err != nil {
		fmt.Println(Dim("Watchdog is not running"))
		removeWatchdogPIDIfOwned(pidPath, info)
		return nil
	}
	defer proc.Release() //nolint:errcheck -- closes the retained Windows handle.

	fmt.Printf("Stopping watchdog (PID %d)... ", info.PID)
	if err := watchdogRequestTerminate(info, proc); err != nil {
		if !verifyWatchdogProcess(info) {
			removeWatchdogPIDIfOwned(pidPath, info)
			fmt.Println(Dim("already stopped"))
			return nil
		}
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("watchdog: request stop: %w", err)
	}

	if !watchdogWaitForExit(proc, info, 5*time.Second) {
		// Re-verify the fingerprint immediately before force-kill so a
		// fast-restart-and-PID-reuse window cannot be exploited to kill
		// the new occupant of the recycled PID.
		if !verifyWatchdogProcess(info) {
			fmt.Println(Style("FAILED", "fg=red", "bold"))
			return errors.New("watchdog: process identity changed before force stop")
		}
		if err := watchdogKill(proc); err != nil && verifyWatchdogProcess(info) {
			fmt.Println(Style("FAILED", "fg=red", "bold"))
			return fmt.Errorf("watchdog: force stop: %w", err)
		}
		if !watchdogWaitForExit(proc, info, 2*time.Second) {
			fmt.Println(Style("FAILED", "fg=red", "bold"))
			return errors.New("watchdog: process did not exit after force stop")
		}
	}

	removeWatchdogPIDIfOwned(pidPath, info)
	fmt.Println(Style("OK", "fg=green", "bold"))
	return nil
}

var watchdogRequestTerminate = watchdogTerminate

func runWatchdogStatus(_ *cobra.Command, _ []string) error {
	dataDir := config.DefaultDataPath()
	pidPath := filepath.Join(dataDir, watchdogPIDFile)

	cfg, cfgErr := config.LoadRuntimeV8File(config.ConfigPath())
	enabled := cfgErr == nil && cfg.Gateway.Watchdog.Enabled

	inspection := inspectWatchdogPIDOwnership(pidPath)
	if inspection.ownershipErr != nil {
		return fmt.Errorf("watchdog: inspect stable PID ownership: %w", inspection.ownershipErr)
	}
	locked, info, lockErr := inspection.locked, inspection.info, inspection.publicationErr
	if !locked {
		if lockErr != nil {
			Warn(fmt.Sprintf("Watchdog: not running (invalid or unsafe PID file retained: %v)", lockErr))
		} else if watchdogUnlockedLiveProcessInfo(info) {
			return fmt.Errorf("watchdog: PID %d is alive but does not hold the ownership lock; status is indeterminate", info.PID)
		} else if info.PID > 0 {
			Warn(fmt.Sprintf("Watchdog: not running (stale PID %d record retained)", info.PID))
		} else if enabled {
			Warn("Watchdog: enabled but not running")
		} else {
			fmt.Println(Dim("Watchdog: disabled"))
		}
		if enabled {
			Subhead("Start with: defenseclaw-gateway watchdog start")
		} else if info.PID == 0 && lockErr == nil {
			Subhead("Enable in config: gateway.watchdog.enabled = true")
		}
		return nil
	}
	if lockErr != nil {
		return fmt.Errorf("watchdog: ownership is held but its PID record is unreadable: %w", lockErr)
	}

	// Same fingerprint check as stop. Status is read-only: a mismatched live
	// owner is reported but never removed or signalled.
	if !verifyWatchdogProcess(info) {
		Warn(fmt.Sprintf("Watchdog: ownership held but PID %d does not match the recorded fingerprint; PID file retained", info.PID))
		return nil
	}

	fmt.Printf("Watchdog: %s (PID %d)\n", Style("running", "fg=green", "bold"), info.PID)

	state, stateErr := readWatchdogState(dataDir)
	if stateErr != nil {
		Warn(fmt.Sprintf("Watchdog last known state: unavailable (%v)", stateErr))
		return nil
	}
	switch state {
	case stateDegraded:
		Warn("Watchdog last known state: degraded (a required downstream connector or protection subsystem did not converge; restarting the watchdog is not a repair)")
	case stateDown:
		Warn("Watchdog last known state: down (gateway health is unavailable and protection status cannot be verified)")
	default:
		fmt.Printf("  %s %s\n", Style("Last known state:", "fg=bright_black", "bold"), state.String())
	}

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
	ControlName   string `json:"control_name,omitempty"`
}

func removeWatchdogPIDIfOwned(path string, stopped watchdogPIDInfo) {
	_, _ = removeWatchdogPIDFileIf(path, func(data []byte) bool {
		current, err := parseWatchdogPIDInfo(data)
		if err != nil {
			return false
		}
		if current.PID != stopped.PID {
			return false
		}
		if stopped.StartIdentity != "" && current.StartIdentity != stopped.StartIdentity {
			return false
		}
		return stopped.ControlName == "" || current.ControlName == stopped.ControlName
	})
}

func watchdogUnlockedLiveProcess(path string) (bool, watchdogPIDInfo) {
	locked, info, err := watchdogIsLocked(path)
	if err != nil || locked {
		return false, watchdogPIDInfo{}
	}
	return watchdogUnlockedLiveProcessInfo(info), info
}

func watchdogUnlockedLiveProcessInfo(info watchdogPIDInfo) bool {
	// An unlocked legacy PID record proves only that some process currently
	// owns the numeric PID. Treating that as the watchdog would let an
	// unrelated recycled PID block lifecycle operations indefinitely. Only
	// preserve an unlocked record when the platform can strongly bind its
	// fingerprint to the original process.
	if !watchdogHasStrongProcessIdentity(info) {
		return false
	}
	return verifyWatchdogProcess(info)
}

// removeStaleWatchdogPIDFile is used only by explicit lifecycle commands. It
// removes the exact unlocked private PID object when it is invalid or when its
// complete process identity no longer names a live watchdog. It never treats a
// numeric PID alone as deletion authority and never signals a process.
func removeStaleWatchdogPIDFile(path string) (bool, error) {
	return removeWatchdogPIDFileIf(path, func(data []byte) bool {
		info, err := parseWatchdogPIDInfo(data)
		if err != nil {
			return true
		}
		return !watchdogUnlockedLiveProcessInfo(info)
	})
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
// Executable / StartTime and verifyWatchdogProcess only does the liveness
// check.
func readWatchdogPIDInfo(path string) (watchdogPIDInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return watchdogPIDInfo{}, err
	}
	defer f.Close()
	return readWatchdogPIDInfoFile(f)
}

func readWatchdogPIDInfoFile(f *os.File) (watchdogPIDInfo, error) {
	if _, err := f.Seek(0, 0); err != nil {
		return watchdogPIDInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWatchdogPIDFileBytes+1))
	if err != nil {
		return watchdogPIDInfo{}, err
	}
	if len(data) > maxWatchdogPIDFileBytes {
		return watchdogPIDInfo{}, fmt.Errorf(
			"watchdog: pid file exceeds %d bytes",
			maxWatchdogPIDFileBytes,
		)
	}
	return parseWatchdogPIDInfo(data)
}

func parseWatchdogPIDInfo(data []byte) (watchdogPIDInfo, error) {
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
// running process AND, when an executable fingerprint is available and the
// platform exposes /proc, /proc/<pid>/exe matches. Without this the
// previous implementation treated ANY live process at the recorded PID as
// "the watchdog" and would happily terminate an unrelated process that
// grabbed the recycled PID after a crash. See DeepSec S3.HIGH_BUG.
func verifyWatchdogProcess(info watchdogPIDInfo) bool {
	if info.PID <= 0 {
		return false
	}
	if watchdogRequiresStrongProcessIdentity() && !watchdogHasStrongProcessIdentity(info) {
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
	return watchdogProcessExecutableMatches(info)
}
