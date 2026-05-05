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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

const defaultStopTimeout = 10 * time.Second

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

	pid, err := d.Start(args)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("start daemon: %w", err)
	}

	fmt.Printf("%s (PID %d)\n", Style("OK", "fg=green", "bold"), pid)
	fmt.Println()
	fmt.Printf("  Log file: %s\n", d.LogFile())
	fmt.Printf("  PID file: %s\n", d.PIDFile())
	fmt.Println()
	fmt.Println("Use 'defenseclaw-gateway status' to check health")
	fmt.Println("Use 'defenseclaw-gateway stop' to stop the daemon")
	printSplunkLocalHint()

	// Auto-start watchdog if enabled in config.
	cfg, cfgErr := config.Load()
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
	pid, err := d.Start(args)
	if err != nil {
		fmt.Println(Style("FAILED", "fg=red", "bold"))
		return fmt.Errorf("start daemon: %w", err)
	}

	fmt.Printf("%s (PID %d)\n", Style("OK", "fg=green", "bold"), pid)
	fmt.Println()
	fmt.Printf("  Log file: %s\n", d.LogFile())
	fmt.Println()
	printCompactHealthSummary(cfg)
	printSplunkLocalHint()

	// Re-start watchdog if enabled in config.
	cfg, cfgErr := config.Load()
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

// printCompactHealthSummary polls /health and prints a one-line status.
func printCompactHealthSummary(cfg *config.Config) {
	if cfg == nil {
		return
	}
	apiPort := cfg.Gateway.APIPort
	if apiPort == 0 {
		apiPort = 18790
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", apiPort)

	client := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			fmt.Printf("  Health: %s\n", summarizeHealth(body))
			return
		}
	}
	fmt.Println("  Health: not responding yet (use 'defenseclaw-gateway status')")
}

func summarizeHealth(body []byte) string {
	var health map[string]json.RawMessage
	if err := json.Unmarshal(body, &health); err != nil {
		return "ok"
	}
	subsystems := []string{"gateway", "watcher", "guardrail", "api", "telemetry", "splunk", "sandbox"}
	var parts []string
	for _, sub := range subsystems {
		raw, ok := health[sub]
		if !ok {
			continue
		}
		var info struct {
			State  string `json:"state"`
			Status string `json:"status"`
		}
		if json.Unmarshal(raw, &info) != nil {
			continue
		}
		state := info.State
		if state == "" {
			state = info.Status
		}
		switch strings.ToLower(state) {
		case "running", "healthy":
			parts = append(parts, sub+":ok")
		case "disabled", "stopped":
			parts = append(parts, sub+":off")
		default:
			parts = append(parts, sub+":"+state)
		}
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, ", ")
}

func collectDaemonArgs(cmd *cobra.Command) []string {
	// When starting as daemon, we run the root command (sidecar mode)
	// Pass through any flags that were set
	var args []string

	if sidecarToken != "" {
		args = append(args, "--token", sidecarToken)
	}
	if sidecarHost != "" {
		args = append(args, "--host", sidecarHost)
	}
	if sidecarPort > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", sidecarPort))
	}

	return args
}
