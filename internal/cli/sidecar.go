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
	"sort"
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
	rootCmd.Flags().StringVar(&sidecarToken, "token", "",
		"DEPRECATED: gateway auth token. Passing secrets on the command line exposes them to ps/procfs. "+
			"Use OPENCLAW_GATEWAY_TOKEN env or gateway.token in config instead.")
	// Hide from default help so we don't advertise the insecure path, but
	// keep it working so existing scripts don't break. We emit a one-line
	// deprecation warning at runtime when it's actually used.
	if f := rootCmd.Flags().Lookup("token"); f != nil {
		f.Hidden = true
	}
	rootCmd.Flags().StringVar(&sidecarHost, "host", "", "Gateway host (default: from config)")
	rootCmd.Flags().IntVar(&sidecarPort, "port", 0, "Gateway port (default: from config)")
	rootCmd.AddCommand(statusCmd)
}

func runSidecar(_ *cobra.Command, _ []string) error {
	if sidecarToken != "" {
		fmt.Fprintln(os.Stderr,
			"[sidecar] WARNING: --token is deprecated and will be removed in a future release. "+
				"Secrets on argv are visible to any local user via ps(1) / /proc/<pid>/cmdline. "+
				"Set OPENCLAW_GATEWAY_TOKEN (or gateway.token in config) instead.")
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

	// Always capture the common shutdown signals so we can cancel ctx
	// cleanly. Previously this function also installed wide signal
	// capture, a 5s heartbeat ticker, and verbose defer/return diagnostics
	// to chase a CI-only ARM64 flake (see PR #111). That telemetry is
	// now gated behind DEFENSECLAW_SIDECAR_DIAG=1 so it doesn't ship as
	// default operator-visible log noise.
	//
	// SIGPIPE is also always registered here: without it, Go's default
	// handler terminates the process when a client disconnects on a
	// non-TTY fd. We want to swallow that regardless of trace flag.
	sigCh := make(chan os.Signal, 8)
	diag := sidecarDiagEnabled()
	if diag {
		signal.Notify(sigCh,
			syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGHUP, syscall.SIGQUIT,
			syscall.SIGPIPE, syscall.SIGUSR1, syscall.SIGUSR2)
	} else {
		signal.Notify(sigCh,
			syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGHUP, syscall.SIGQUIT,
			syscall.SIGPIPE)
	}
	go func() {
		for sig := range sigCh {
			// SIGPIPE is a normal condition when a client disconnects on
			// a non-TTY fd; don't treat it as a shutdown trigger.
			sysSig, ok := sig.(syscall.Signal)
			if ok && sysSig == syscall.SIGPIPE {
				if diag {
					fmt.Fprintf(os.Stderr,
						"[sidecar][diag] ignoring SIGPIPE at %s pid=%d\n",
						time.Now().UTC().Format(time.RFC3339Nano),
						os.Getpid())
				}
				continue
			}
			if diag {
				sigNum := -1
				if ok {
					sigNum = int(sysSig)
				}
				fmt.Fprintf(os.Stderr,
					"[sidecar][diag] received signal %v (%d) at %s; pid=%d cancelling ctx\n",
					sig, sigNum,
					time.Now().UTC().Format(time.RFC3339Nano),
					os.Getpid())
			}
			cancel()
			return
		}
	}()

	if diag {
		// Heartbeat ticker + return diagnostics are only emitted when
		// DEFENSECLAW_SIDECAR_DIAG=1. Keep this cheap path off by
		// default — the 5s tick writes to stderr which can flood CI
		// runners and disk on long-lived sidecars.
		go func() {
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			start := time.Now()
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-tick.C:
					fmt.Fprintf(os.Stderr,
						"[sidecar][diag][heartbeat] alive at %s pid=%d uptime=%s\n",
						t.UTC().Format("15:04:05.000"),
						os.Getpid(),
						t.Sub(start).Truncate(time.Second))
				}
			}
		}()

		defer func() {
			fmt.Fprintf(os.Stderr,
				"[sidecar][diag] runSidecar defer: ctxErr=%v at %s pid=%d\n",
				ctx.Err(),
				time.Now().UTC().Format(time.RFC3339Nano),
				os.Getpid())
		}()
	}

	runErr := sc.Run(ctx)
	if diag {
		fmt.Fprintf(os.Stderr,
			"[sidecar][diag] sc.Run returned: err=%v ctxErr=%v at %s pid=%d\n",
			runErr, ctx.Err(),
			time.Now().UTC().Format(time.RFC3339Nano),
			os.Getpid())
	}
	return runErr
}

// sidecarDiagEnabled reports whether DEFENSECLAW_SIDECAR_DIAG is set to a
// truthy value. When enabled, the sidecar emits a 5s heartbeat, wide
// signal capture, and defer/return diagnostics to stderr. These are
// intended for CI troubleshooting only — never enable in production.
func sidecarDiagEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_SIDECAR_DIAG"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
		fmt.Println("  Start the sidecar with: defenseclaw-gateway start")
		return fmt.Errorf("sidecar unreachable")
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
	printSubsystem("Sinks", snap.Sinks)
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
		keys := make([]string, 0, len(h.Details))
		for k := range h.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") {
				continue
			}
			fmt.Printf("             %s: %v\n", k, h.Details[k])
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
