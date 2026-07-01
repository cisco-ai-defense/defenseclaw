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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	defaultStopTimeout           = 10 * time.Second
	defaultStartReadinessTimeout = 10 * time.Second
	defaultReadinessPollInterval = 100 * time.Millisecond
	defaultReadinessHTTPTimeout  = time.Second
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gateway sidecar as a background daemon",
	Long: `Start the DefenseClaw gateway sidecar as a background daemon.

The daemon process runs independently and survives terminal close.
Use 'status' to check health and 'stop' to shut it down.

Logs are written to ~/.defenseclaw/gateway.log (rotated by size; old files compressed in the same directory).
PID is stored in ~/.defenseclaw/gateway.pid`,
	RunE:              runStart,
	PersistentPreRunE: nil, // Skip config loading for daemon commands
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running gateway sidecar daemon",
	Long: `Stop the DefenseClaw gateway sidecar daemon.

Sends SIGTERM for graceful shutdown, then SIGKILL if needed.`,
	RunE:              runStop,
	PersistentPreRunE: nil,
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the gateway sidecar daemon",
	Long: `Restart the DefenseClaw gateway sidecar daemon.

Equivalent to 'stop' followed by 'start'.`,
	RunE:              runRestart,
	PersistentPreRunE: nil,
}

func init() {
	// Override PersistentPreRunE to skip config/audit loading for daemon management commands
	startCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }
	stopCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }
	restartCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(restartCmd)
}

func runStart(cmd *cobra.Command, _ []string) error {
	d := daemon.New(config.DefaultDataPath())

	if running, pid := d.IsRunning(); running {
		Warn(fmt.Sprintf("Gateway sidecar is already running (PID %d)", pid))
		fmt.Println("Use 'defenseclaw-gateway status' to check health")
		return nil
	}

	fmt.Print("Starting gateway sidecar daemon... ")

	// Pass through relevant flags to the daemon process
	args := collectDaemonArgs(cmd)

	startAttemptedAt := time.Now()
	pid, err := d.Start(args)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("start daemon: %w", err)
	}

	cfg, cfgErr := config.Load()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	snap, ready, err := waitForGatewayReadiness(
		&http.Client{Timeout: defaultReadinessHTTPTimeout},
		sidecarHealthURL(cfg),
		defaultStartReadinessTimeout,
		defaultReadinessPollInterval,
		daemonReadinessRequirementsFromConfig(cfg, startAttemptedAt),
		func() bool {
			running, currentPID := d.IsRunning()
			return running && currentPID == pid
		},
	)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("start daemon readiness: %w (check %s for errors)", err, d.LogFile())
	}

	printDaemonStartResult(pid, snap, ready)
	fmt.Println()
	fmt.Printf("  Log file: %s\n", d.LogFile())
	fmt.Printf("  PID file: %s\n", d.PIDFile())
	fmt.Println()
	fmt.Println("Use 'defenseclaw-gateway status' to check health")
	fmt.Println("Use 'defenseclaw-gateway stop' to stop the daemon")
	printSplunkLocalHint()

	// Auto-start watchdog if enabled in config.
	if cfgErr == nil && cfg.Gateway.Watchdog.Enabled {
		if err := runWatchdogStart(nil, nil); err != nil {
			fmt.Printf("  Watchdog: auto-start failed: %v\n", err)
		} else {
			fmt.Println("  Watchdog: started")
		}
	} else {
		fmt.Println("  Watchdog: disabled (enable with gateway.watchdog.enabled)")
	}

	return nil
}

func runStop(_ *cobra.Command, _ []string) error {
	// Stop watchdog first since it monitors the gateway.
	_ = runWatchdogStop(nil, nil)

	d := daemon.New(config.DefaultDataPath())

	running, pid := d.IsRunning()
	if !running {
		fmt.Println(Dim("Gateway sidecar is not running"))
		return nil
	}

	fmt.Printf("Stopping gateway sidecar (PID %d)... ", pid)

	if err := d.Stop(defaultStopTimeout); err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("stop daemon: %w", err)
	}

	fmt.Println(Style("OK", "fg=green", "bold"))
	printHint("Start again:  defenseclaw-gateway start")
	return nil
}

func runRestart(cmd *cobra.Command, _ []string) error {
	d := daemon.New(config.DefaultDataPath())

	// Stop the watchdog first so it doesn't fire false alarms during restart.
	_ = runWatchdogStop(nil, nil)

	if running, pid := d.IsRunning(); running {
		fmt.Printf("Stopping gateway sidecar (PID %d)... ", pid)
		if err := d.Stop(defaultStopTimeout); err != nil {
			fmt.Println(Style("FAILED", "fg=red", "bold"))
			return fmt.Errorf("stop for restart: %w", err)
		}
		fmt.Println(Style("OK", "fg=green", "bold"))
	}

	fmt.Print("Starting gateway sidecar daemon... ")

	args := collectDaemonArgs(cmd)
	startAttemptedAt := time.Now()
	pid, err := d.Start(args)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("start daemon: %w", err)
	}

	cfg, cfgErr := config.Load()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	snap, ready, err := waitForGatewayReadiness(
		&http.Client{Timeout: defaultReadinessHTTPTimeout},
		sidecarHealthURL(cfg),
		defaultStartReadinessTimeout,
		defaultReadinessPollInterval,
		daemonReadinessRequirementsFromConfig(cfg, startAttemptedAt),
		func() bool {
			running, currentPID := d.IsRunning()
			return running && currentPID == pid
		},
	)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("restart daemon readiness: %w (check %s for errors)", err, d.LogFile())
	}

	printDaemonStartResult(pid, snap, ready)
	fmt.Println()
	fmt.Printf("  Log file: %s\n", d.LogFile())
	fmt.Println()
	printSplunkLocalHint()

	// Re-start watchdog if enabled in config.
	if cfgErr == nil && cfg.Gateway.Watchdog.Enabled {
		if err := runWatchdogStart(nil, nil); err != nil {
			fmt.Printf("  Warning: watchdog auto-start failed: %v\n", err)
		}
	}

	return nil
}

// printSplunkLocalHint prints Splunk Web credentials when the local bridge
// is configured, so the user knows how to access the dashboards.
func printSplunkLocalHint() {
	dataDir := config.DefaultDataPath()

	// Check bridge env first (written by Python setup splunk --logs)
	bridgeEnvPath := filepath.Join(dataDir, "splunk-bridge", "env", ".env")
	bridgeEnv := readDotEnv(bridgeEnvPath)
	if pw := bridgeEnv["SPLUNK_PASSWORD"]; pw != "" {
		Section("Splunk Local Mode")
		fmt.Printf("  %s http://127.0.0.1:8000\n", Style("Web UI:", "fg=bright_black", "bold"))
		fmt.Printf("  %s admin\n", Style("Username:", "fg=bright_black", "bold"))
		fmt.Printf("  %s (stored in %s)\n", Style("Password:", "fg=bright_black", "bold"), bridgeEnvPath)
		return
	}

	// Fallback: legacy DEFENSECLAW_LOCAL_* keys
	dotenvPath := filepath.Join(dataDir, ".env")
	env := readDotEnv(dotenvPath)
	user := env["DEFENSECLAW_LOCAL_USERNAME"]
	pass := env["DEFENSECLAW_LOCAL_PASSWORD"]
	if user == "" || pass == "" {
		return
	}
	Section("Splunk Local Mode")
	fmt.Printf("  %s http://127.0.0.1:8000\n", Style("Web UI:", "fg=bright_black", "bold"))
	fmt.Printf("  %s %s\n", Style("Username:", "fg=bright_black", "bold"), user)
	fmt.Printf("  %s (stored in %s)\n", Style("Password:", "fg=bright_black", "bold"), dotenvPath)
}

// readDotEnv reads KEY=VALUE pairs from a .env file.
func readDotEnv(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	env := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		env[k] = v
	}
	return env
}

type daemonReadinessRequirements struct {
	guardrailEnabled bool
	watcherEnabled   bool
	telemetryEnabled bool
	sinksEnabled     bool
	startedNotBefore time.Time
}

func daemonReadinessRequirementsFromConfig(cfg *config.Config, startedNotBefore time.Time) daemonReadinessRequirements {
	if cfg == nil {
		return daemonReadinessRequirements{startedNotBefore: startedNotBefore}
	}
	requirements := daemonReadinessRequirements{
		guardrailEnabled: cfg.Guardrail.Enabled,
		watcherEnabled:   cfg.Gateway.Watcher.Enabled,
		telemetryEnabled: cfg.OTel.Enabled,
		startedNotBefore: startedNotBefore,
	}
	for _, sink := range cfg.AuditSinks {
		requirements.sinksEnabled = requirements.sinksEnabled || sink.Enabled
	}
	for _, connectorConfig := range cfg.Observability.Connectors {
		if connectorConfig.AuditSinks == nil {
			continue
		}
		for _, sink := range *connectorConfig.AuditSinks {
			requirements.sinksEnabled = requirements.sinksEnabled || sink.Enabled
		}
	}
	return requirements
}

// waitForGatewayReadiness waits for every required startup subsystem to reach
// its final state. The health endpoint and API can become reachable before
// connector Setup finishes, so API=running alone is not readiness. In
// particular, an enabled guardrail's initial disabled state must transition to
// running before start/restart prints OK.
func waitForGatewayReadiness(
	client *http.Client,
	healthURL string,
	timeout time.Duration,
	pollInterval time.Duration,
	requirements daemonReadinessRequirements,
	processRunning func() bool,
) (gateway.HealthSnapshot, bool, error) {
	if pollInterval <= 0 {
		pollInterval = defaultReadinessPollInterval
	}
	deadline := time.Now().Add(timeout)
	var lastSnap gateway.HealthSnapshot
	var lastProbeErr error

	for {
		if processRunning != nil && !processRunning() {
			if lastProbeErr != nil {
				return lastSnap, false, fmt.Errorf(
					"gateway process exited before readiness (last health probe: %v)",
					lastProbeErr,
				)
			}
			return lastSnap, false, fmt.Errorf("gateway process exited before readiness")
		}

		snap, err := fetchSidecarHealth(client, healthURL)
		if err == nil {
			lastSnap = snap
			lastProbeErr = nil
			ready, readinessErr := gatewaySnapshotReady(snap, requirements)
			if readinessErr != nil {
				return snap, false, readinessErr
			}
			if ready {
				return snap, true, nil
			}
		} else {
			lastProbeErr = err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			detail := summarizeHealthSnapshot(lastSnap)
			if lastProbeErr != nil {
				return lastSnap, false, fmt.Errorf(
					"gateway readiness timed out after %s (last health probe: %v)",
					timeout,
					lastProbeErr,
				)
			}
			return lastSnap, false, fmt.Errorf(
				"gateway readiness timed out after %s (last health: %s)",
				timeout,
				detail,
			)
		}
		delay := pollInterval
		if remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		<-timer.C
	}
}

func gatewaySnapshotReady(
	snap gateway.HealthSnapshot,
	requirements daemonReadinessRequirements,
) (bool, error) {
	// A process can briefly answer on the same port while restart is handing
	// off between generations. Never declare the new PID ready from an older
	// process's final health snapshot.
	if !requirements.startedNotBefore.IsZero() && snap.StartedAt.Before(requirements.startedNotBefore) {
		return false, nil
	}

	subsystems := []struct {
		name   string
		health gateway.SubsystemHealth
	}{
		{name: "api", health: snap.API},
		{name: "gateway", health: snap.Gateway},
		{name: "watcher", health: snap.Watcher},
		{name: "guardrail", health: snap.Guardrail},
		{name: "telemetry", health: snap.Telemetry},
		{name: "sinks", health: snap.Sinks},
	}
	for _, subsystem := range subsystems {
		switch subsystem.health.State {
		case gateway.StateStopped:
			detail := strings.TrimSpace(subsystem.health.LastError)
			if detail == "" {
				detail = string(subsystem.health.State)
			}
			return false, fmt.Errorf(
				"gateway %s failed during startup: %s",
				subsystem.name,
				detail,
			)
		}
	}
	// The gateway uplink retries after StateError, so an error there is
	// transitional until the readiness deadline. The other required startup
	// components do not recover in-place from Error and can fail immediately.
	for _, subsystem := range []struct {
		name   string
		health gateway.SubsystemHealth
	}{
		{name: "api", health: snap.API},
		{name: "watcher", health: snap.Watcher},
		{name: "guardrail", health: snap.Guardrail},
		{name: "telemetry", health: snap.Telemetry},
		{name: "sinks", health: snap.Sinks},
	} {
		if subsystem.health.State != gateway.StateError {
			continue
		}
		detail := strings.TrimSpace(subsystem.health.LastError)
		if detail == "" {
			detail = string(subsystem.health.State)
		}
		return false, fmt.Errorf(
			"gateway %s failed during startup: %s",
			subsystem.name,
			detail,
		)
	}

	if snap.API.State != gateway.StateRunning {
		return false, nil
	}
	// The OpenClaw fleet uplink is intentionally disabled for native hook-only
	// standalone installs, including Windows. That is a final ready state, not
	// a failure. A reconnecting/starting uplink is still pending.
	if snap.Gateway.State != gateway.StateRunning && snap.Gateway.State != gateway.StateDisabled {
		return false, nil
	}
	if !subsystemMatchesConfiguredState(snap.Watcher.State, requirements.watcherEnabled) {
		return false, nil
	}
	if !subsystemMatchesConfiguredState(snap.Guardrail.State, requirements.guardrailEnabled) {
		return false, nil
	}
	// Guardrail starts life as disabled in NewSidecarHealth. When disabled is
	// the configured final state, require the guardrail goroutine to publish a
	// newer health record so the initial placeholder cannot win the race.
	if !requirements.guardrailEnabled && !snap.StartedAt.IsZero() && !snap.Guardrail.Since.After(snap.StartedAt) {
		return false, nil
	}
	if !subsystemMatchesConfiguredState(snap.Telemetry.State, requirements.telemetryEnabled) {
		return false, nil
	}
	if !subsystemMatchesConfiguredState(snap.Sinks.State, requirements.sinksEnabled) {
		return false, nil
	}
	return true, nil
}

func subsystemMatchesConfiguredState(state gateway.SubsystemState, enabled bool) bool {
	if enabled {
		return state == gateway.StateRunning
	}
	return state == gateway.StateDisabled
}

func printDaemonStartResult(pid int, snap gateway.HealthSnapshot, ready bool) {
	if ready {
		fmt.Printf("%s (PID %d)\n", Style("OK", "fg=green", "bold"), pid)
		fmt.Printf("  Health: %s\n", summarizeHealthSnapshot(snap))
		return
	}

	fmt.Printf("%s (PID %d)\n", Style("STARTING", "fg=yellow", "bold"), pid)
	fmt.Printf(
		"  Health: still starting after %s (use 'defenseclaw-gateway status')\n",
		defaultStartReadinessTimeout,
	)
}

func summarizeHealthSnapshot(snap gateway.HealthSnapshot) string {
	subsystems := []struct {
		name   string
		health gateway.SubsystemHealth
	}{
		{name: "gateway", health: snap.Gateway},
		{name: "watcher", health: snap.Watcher},
		{name: "guardrail", health: snap.Guardrail},
		{name: "api", health: snap.API},
		{name: "telemetry", health: snap.Telemetry},
		{name: "sinks", health: snap.Sinks},
	}
	if snap.Sandbox != nil {
		subsystems = append(subsystems, struct {
			name   string
			health gateway.SubsystemHealth
		}{name: "sandbox", health: *snap.Sandbox})
	}

	var parts []string
	for _, sub := range subsystems {
		state := string(sub.health.State)
		switch strings.ToLower(state) {
		case "running", "healthy":
			parts = append(parts, sub.name+":ok")
		case "disabled", "stopped":
			parts = append(parts, sub.name+":off")
		case "":
			continue
		default:
			parts = append(parts, sub.name+":"+state)
		}
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, ", ")
}

func collectDaemonArgs(cmd *cobra.Command) []string {
	// When starting as daemon, we run the root command (sidecar mode)
	// Pass through any flags that were set EXCEPT --token, which is
	// a secret. Passing the token on argv would leave it visible in
	// the long-lived daemon process via ps(1) and /proc/<pid>/cmdline
	// for any local user that can see same-user processes -- closing
	// finding "daemon start propagates gateway token on the
	// child process command line".
	//
	// Instead, when --token was supplied we promote it into the
	// process environment as DEFENSECLAW_GATEWAY_TOKEN so the child
	// inherits it via the env block daemon.Start passes to
	// exec.Command. The child's PreRunE / config loader (and
	// GatewayConfig.ResolvedToken) already prefers the env var, so
	// behaviour is preserved without ever putting the secret on argv.
	var args []string

	if sidecarToken != "" {
		// Belt-and-suspenders: also set the canonical Go env name
		// so the child inherits it. We intentionally do NOT append
		// `--token <secret>` to args here.
		_ = os.Setenv("DEFENSECLAW_GATEWAY_TOKEN", sidecarToken)
		fmt.Fprintln(os.Stderr,
			"[daemon] --token is deprecated; promoting to DEFENSECLAW_GATEWAY_TOKEN "+
				"env so it is NOT exposed on argv. Set DEFENSECLAW_GATEWAY_TOKEN "+
				"or gateway.token in config and stop passing --token.")
	}
	if sidecarHost != "" {
		args = append(args, "--host", sidecarHost)
	}
	if sidecarPort > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", sidecarPort))
	}

	return args
}
