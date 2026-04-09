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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var (
	sidecarToken string
	sidecarHost  string
	sidecarPort  int
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show health of the running sidecar's subsystems",
	Long: `Query the sidecar's REST API to display the health of all three subsystems:
gateway connection, skill watcher, and API server.

The sidecar must be running for this command to work.`,
	RunE: runSidecarStatus,
}

func init() {
	rootCmd.Flags().StringVar(&sidecarToken, "token", "", "Gateway auth token (overrides config)")
	rootCmd.Flags().StringVar(&sidecarHost, "host", "", "Gateway host (default: from config)")
	rootCmd.Flags().IntVar(&sidecarPort, "port", 0, "Gateway port (default: from config)")
	rootCmd.AddCommand(statusCmd)
}

func runSidecar(_ *cobra.Command, _ []string) error {
	if sidecarToken != "" {
		cfg.Gateway.Token = sidecarToken
	}
	if sidecarHost != "" {
		cfg.Gateway.Host = sidecarHost
	}
	if sidecarPort > 0 {
		cfg.Gateway.Port = sidecarPort
	}

	// Resolve token from env var if not set directly (via flag or config).
	if cfg.Gateway.Token == "" {
		cfg.Gateway.Token = cfg.Gateway.ResolvedToken()
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║       DefenseClaw Gateway Sidecar            ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Gateway:      %s:%d\n", cfg.Gateway.Host, cfg.Gateway.Port)
	fmt.Printf("  Auto-approve: %v\n", cfg.Gateway.AutoApprove)
	fmt.Printf("  Auth:         %s\n", tokenStatus(cfg.Gateway.Token))
	fmt.Printf("  API port:     %d\n", cfg.Gateway.APIPort)
	fmt.Printf("  Watcher:      %v\n", cfg.Gateway.Watcher.Enabled)
	if cfg.Gateway.Watcher.Enabled {
		fmt.Printf("    Skill:      enabled=%v take_action=%v\n",
			cfg.Gateway.Watcher.Skill.Enabled, cfg.Gateway.Watcher.Skill.TakeAction)
		if len(cfg.Gateway.Watcher.Skill.Dirs) > 0 {
			fmt.Printf("    Skill dirs: %v\n", cfg.Gateway.Watcher.Skill.Dirs)
		} else {
			fmt.Printf("    Skill dirs: autodiscover (from claw mode)\n")
		}
	}
	if cfg.Guardrail.Enabled {
		fmt.Printf("  Guardrail:    port=%d mode=%s\n", cfg.Guardrail.Port, cfg.Guardrail.Mode)
		fmt.Printf("    Model:      %s → %s\n", cfg.Guardrail.Model, cfg.Guardrail.ModelName)
		fmt.Printf("    API key:    %s\n", cfg.Guardrail.APIKeyEnv)
	} else {
		fmt.Printf("  Guardrail:    disabled\n")
	}
	fmt.Println()

	sc, err := gateway.NewSidecar(cfg, auditStore, auditLog, shell, otelProvider)
	if err != nil {
		return fmt.Errorf("sidecar: init: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[sidecar] shutting down...")
		cancel()
	}()

	return sc.Run(ctx)
}

func runSidecarStatus(_ *cobra.Command, _ []string) error {
	bind := "127.0.0.1"
	if cfg.Gateway.APIBind != "" {
		bind = cfg.Gateway.APIBind
	} else if cfg.OpenShell.IsStandalone() && cfg.Guardrail.Host != "" && cfg.Guardrail.Host != "localhost" {
		bind = cfg.Guardrail.Host
	}
	addr := fmt.Sprintf("http://%s:%d/health", bind, cfg.Gateway.APIPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		fmt.Println("Sidecar Status: NOT RUNNING")
		fmt.Printf("  Could not reach %s\n", addr)
		fmt.Println("  Start the sidecar with: defenseclaw sidecar")
		return nil
	}
	defer resp.Body.Close()

	var snap gateway.HealthSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return fmt.Errorf("sidecar status: parse response: %w", err)
	}

	uptime := time.Duration(snap.UptimeMs) * time.Millisecond

	fmt.Println("DefenseClaw Sidecar Health")
	fmt.Println("══════════════════════════")
	fmt.Printf("  Started:  %s\n", snap.StartedAt.Format(time.RFC3339))
	fmt.Printf("  Uptime:   %s\n", formatDuration(uptime))
	fmt.Println()

	printSubsystem("Gateway", snap.Gateway)
	printSubsystem("Watcher", snap.Watcher)
	printSubsystem("API", snap.API)
	printSubsystem("Guardrail", snap.Guardrail)
	printSubsystem("Telemetry", snap.Telemetry)
	printSubsystem("Splunk", snap.Splunk)
	if snap.Sandbox != nil {
		printSubsystem("Sandbox", *snap.Sandbox)
	}

	return nil
}

func printSubsystem(name string, h gateway.SubsystemHealth) {
	stateStr := strings.ToUpper(string(h.State))
	fmt.Printf("  %-10s %s", name+":", stateStr)
	if !h.Since.IsZero() {
		fmt.Printf(" (since %s)", h.Since.Format(time.RFC3339))
	}
	fmt.Println()

	if h.LastError != "" {
		fmt.Printf("             last error: %s\n", h.LastError)
	}
	if len(h.Details) > 0 {
		for k, v := range h.Details {
			if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") {
				continue
			}
			fmt.Printf("             %s: %v\n", k, v)
		}
	}
	fmt.Println()
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func tokenStatus(token string) string {
	if token == "" {
		return "none (will use device identity only)"
	}
	if len(token) > 8 {
		return token[:4] + "..." + token[len(token)-4:]
	}
	return "***"
}
