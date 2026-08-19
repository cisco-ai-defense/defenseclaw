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
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// configurationPollInterval is how often the sidecar re-reads the
// guardian's out-of-band state file. Spec 003 tolerates a lag up to
// one interval between a guardian-side transition and the health
// surface reflecting it; 5s is short enough for a Secure Client UI to
// update in near-real-time without burning IO on non-managed
// deployments (the poller is only started under managed_enterprise).
const configurationPollInterval = 5 * time.Second

var (
	sidecarToken string
	sidecarHost  string
	sidecarPort  int
)

func init() {
	rootCmd.Flags().StringVar(&sidecarToken, "token", "",
		"DEPRECATED: gateway auth token. Passing secrets on the command line exposes them to ps/procfs. "+
			"Use DEFENSECLAW_GATEWAY_TOKEN env or gateway.token in config instead.")
	// Hide from default help so we don't advertise the insecure path, but
	// keep it working so existing scripts don't break. We emit a one-line
	// deprecation warning at runtime when it's actually used.
	if f := rootCmd.Flags().Lookup("token"); f != nil {
		f.Hidden = true
	}
	rootCmd.Flags().StringVar(&sidecarHost, "host", "", "Gateway host (default: from config)")
	rootCmd.Flags().IntVar(&sidecarPort, "port", 0, "Gateway port (default: from config)")
}

func runSidecar(cmd *cobra.Command, _ []string) error {
	if sidecarToken != "" {
		fmt.Fprintln(os.Stderr,
			"[sidecar] WARNING: --token is deprecated and will be removed in a future release. "+
				"Secrets on argv are visible to any local user via ps(1) / /proc/<pid>/cmdline. "+
				"Set DEFENSECLAW_GATEWAY_TOKEN (or gateway.token in config) instead.")
	}
	materializeSidecarGatewayToken(&cfg.Gateway, sidecarToken)
	if sidecarHost != "" {
		cfg.Gateway.Host = sidecarHost
	}
	if sidecarPort > 0 {
		cfg.Gateway.Port = sidecarPort
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

	sc, err := gateway.NewSidecar(cfg, auditStore, auditLog, shell)
	if err != nil {
		return fmt.Errorf("sidecar: init: %w", err)
	}

	// Spec 003 (docs/specs/003-windows-deferred-config/) health-surface
	// wiring. Only under managed_enterprise: mark the daemon-side of
	// the collapsing rule loaded (we reached this point AFTER
	// loadGatewayConfigV8 succeeded — either directly or via the wait
	// loop in rootPersistentPreRunE), wire the sidecar's guardian
	// state reader against the well-known .state file path, and start
	// a periodic RefreshConfiguration ticker so a guardian-side
	// transition surfaces without a daemon-side event.
	//
	// Non-managed-enterprise deployments (OSS / SaaS / DP / CP) never
	// call SetDaemonConfigLoaded, so their health snapshot omits the
	// top-level "configuration" block entirely — byte-for-byte
	// backward compatible with today.
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		sc.Health().SetDaemonConfigLoaded(true)
		statePath := guardianstate.PathForDataDir(cfg.DataDir)
		sc.Health().SetGuardianStateReader(func() string {
			return guardianstate.ReadState(statePath)
		})
	}

	// Local UDS gRPC server for external consumers. Only constructed
	// when the deployment mode / operator opt-in asks for it — see
	// internal/ipc for the wire contract. Construction failures
	// (malformed socket_mode, unresolvable path, etc.) are logged
	// and skipped rather than aborting the whole sidecar, mirroring
	// the fault-isolation posture of the other opt-in subsystems
	// (guardrail, watcher, AI discovery): a broken IPC surface must
	// never take the gateway offline.
	if cfg.ManagedIPCEnabled() {
		ipcSrv, err := ipc.NewServer(ipc.ServerOptions{
			Config:     cfg,
			Health:     sc.Health(),
			Store:      sc.AuditStore(),
			Dispatcher: sc.OSNotifier(),
			Version:    version.Current().BinaryVersion,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"[sidecar] ipc init failed, continuing without IPC surface: %v\n", err)
		} else {
			sc.SetIPCRunner(ipcSrv)
		}
	}

	// Use Cobra's caller-owned context so a native Windows SCM stop can
	// request the same graceful shutdown path as SIGTERM. Interactive and
	// ordinary daemon invocations still receive a background parent context.
	parentCtx := cmd.Context()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	if err := bootstrapConfiguredObservabilityRuntime(ctx, cfg, activeObservabilityV8Startup, sc); err != nil {
		return err
	}
	if err := sc.EmitPostBootstrapPlatformHealth(); err != nil {
		return fmt.Errorf("sidecar: post-bootstrap platform health: %w", err)
	}

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
	signal.Notify(sigCh, sidecarSignals(diag)...)
	go func() {
		for sig := range sigCh {
			// SIGPIPE is a normal condition when a client disconnects on
			// a non-TTY fd; don't treat it as a shutdown trigger.
			if isSigPipe(sig) {
				if diag {
					fmt.Fprintf(os.Stderr,
						"[sidecar][diag] ignoring SIGPIPE at %s pid=%d\n",
						time.Now().UTC().Format(time.RFC3339Nano),
						os.Getpid())
				}
				continue
			}
			if diag {
				fmt.Fprintf(os.Stderr,
					"[sidecar][diag] received signal %v at %s; pid=%d cancelling ctx\n",
					sig,
					time.Now().UTC().Format(time.RFC3339Nano),
					os.Getpid())
			}
			cancel()
			return
		}
	}()

	// Spec 003 periodic guardian-state poller. Only under
	// managed_enterprise (SetDaemonConfigLoaded was called only in
	// that branch above; RefreshConfiguration is a cheap no-op when
	// SidecarHealth's configuration pointer is still nil, so this
	// goroutine is safe to always start but we gate it anyway to
	// keep the goroutine off entirely under non-managed deployments).
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		go func() {
			tick := time.NewTicker(configurationPollInterval)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					sc.Health().RefreshConfiguration()
				}
			}
		}()
	}

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

func materializeSidecarGatewayToken(gatewayConfig *config.GatewayConfig, explicit string) {
	if explicit != "" {
		gatewayConfig.Token = explicit
		return
	}
	// Materialize the documented custom env -> canonical env -> legacy env ->
	// inline-config ladder before the API server captures its authentication
	// token. Daemon readiness uses the same ResolvedToken contract; resolving
	// only when Token was empty let a stale inline token disagree with a newer
	// environment token and made a healthy sidecar answer its parent with 401.
	gatewayConfig.Token = gatewayConfig.ResolvedToken()
}

type observabilityRuntimeBootstrapper interface {
	BootstrapObservabilityRuntime(context.Context, string, []byte) (bool, error)
}

// bootstrapConfiguredObservabilityRuntime is the single CLI activation gate
// between Sidecar construction and serving. A Config without the validated v8
// source snapshot is rejected, as is a bootstrap that reports a no-op: the target
// runtime must never fall through to legacy exporters or serve partially bound.
func bootstrapConfiguredObservabilityRuntime(
	ctx context.Context,
	c *config.Config,
	startup *observabilityV8Startup,
	bootstrapper observabilityRuntimeBootstrapper,
) error {
	if c == nil {
		return fmt.Errorf("sidecar: observability bootstrap: config is unavailable")
	}
	if c.ConfigVersion != 8 {
		return fmt.Errorf("sidecar: observability bootstrap requires schema v8; run 'defenseclaw upgrade' first")
	}
	if ctx == nil || startup == nil || strings.TrimSpace(startup.sourceName) == "" || len(startup.raw) == 0 || bootstrapper == nil {
		return fmt.Errorf("sidecar: observability v8 bootstrap state is incomplete")
	}
	bound, err := bootstrapper.BootstrapObservabilityRuntime(ctx, startup.sourceName, startup.raw)
	if err != nil {
		return fmt.Errorf("sidecar: observability v8 bootstrap: %w", err)
	}
	if !bound {
		return fmt.Errorf("sidecar: observability v8 bootstrap did not bind a runtime")
	}
	return nil
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

func tokenStatus(token string) string {
	if token == "" {
		return "none (will use device identity only)"
	}
	if len(token) > 8 {
		return token[:4] + "..." + token[len(token)-4:]
	}
	return "***"
}
