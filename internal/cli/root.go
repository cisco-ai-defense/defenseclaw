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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

var (
	cfg          *config.Config
	auditStore   *audit.Store
	auditLog     *audit.Logger
	otelProvider *telemetry.Provider
	appVersion   string
)

func SetVersion(v string) {
	appVersion = v
	rootCmd.Version = v
}

func SetBuildInfo(commit, date string) {
	rootCmd.SetVersionTemplate(
		fmt.Sprintf("{{.Name}} version {{.Version}} (commit=%s, built=%s)\n", commit, date),
	)
}

var rootCmd = &cobra.Command{
	Use:   "defenseclaw-gateway",
	Short: "DefenseClaw gateway sidecar daemon",
	Long: `DefenseClaw gateway sidecar — connects to the OpenClaw gateway WebSocket,
monitors tool_call and tool_result events, enforces policy in real time,
and exposes a local REST API for the Python CLI.

Run without arguments to start the sidecar daemon.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Load the data-dir .env BEFORE config.Load() so that
		// token_env-style references in audit_sinks (e.g.
		// SplunkHECSinkConfig.TokenEnv → os.Getenv) can resolve against
		// secrets persisted by `defenseclaw setup` / `defenseclaw init`.
		// config.Load() validates each sink at startup, and the sidecar
		// daemon runs without the user's interactive shell environment,
		// so reading .env first is what makes token_env usable at all.
		loadDotEnvIntoOS(filepath.Join(config.DefaultDataPath(), ".env"))

		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config — run 'defenseclaw init' first: %w", err)
		}
		version.SetBinaryVersion(appVersion)

		auditStore, err = audit.NewStore(cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}
		if err := auditStore.Init(); err != nil {
			return fmt.Errorf("failed to init audit store: %w", err)
		}

		auditLog = audit.NewLogger(auditStore)
		// Re-run with the resolved data dir in case DEFENSECLAW_HOME
		// redirected it; second call is a no-op when paths match.
		if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
			loadDotEnvIntoOS(resolved)
		}
		initAuditSinks()
		initOTelProvider()
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {
		if otelProvider != nil {
			if err := otelProvider.Shutdown(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "warning: otel shutdown: %v\n", err)
			}
		}
		if auditLog != nil {
			auditLog.Close()
		}
		if auditStore != nil {
			auditStore.Close()
		}
	},
	RunE:         runSidecar,
	SilenceUsage: true,
}

// Execute runs the root command and returns the exit code. The actual
// os.Exit call belongs in main() so deferred cleanup (PersistentPostRun)
// always executes.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		return 1
	}
	return 0
}

func initOTelProvider() {
	if cfg == nil || !cfg.OTel.Enabled {
		return
	}

	p, err := telemetry.NewProvider(context.Background(), cfg, appVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: otel init: %v\n", err)
		return
	}

	otelProvider = p
	auditLog.SetOTelProvider(p)
}

// loadDotEnvIntoOS reads KEY=VALUE pairs from path and sets them as
// environment variables unless already present. This ensures secrets
// persisted by `defenseclaw setup` (Splunk HEC tokens, OTLP bearer
// tokens, generic webhook auth) are visible to the audit-sink Manager
// and OTel provider when the sidecar runs as a daemon without the
// user's interactive shell environment.
func loadDotEnvIntoOS(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
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
		if k != "" && os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

// initAuditSinks builds every enabled `audit_sinks:` entry from config
// and installs them on the audit logger. Build errors are logged but
// non-fatal — a misconfigured sink should not take down the sidecar.
//
// Per-sink construction lives in internal/cli/audit_sinks.go to keep
// root.go focused on lifecycle.
func initAuditSinks() {
	if cfg == nil || len(cfg.AuditSinks) == 0 {
		return
	}
	mgr, err := buildAuditSinks(cfg.AuditSinks, appVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit sinks init: %v\n", err)
	}
	if mgr != nil && mgr.Len() > 0 {
		auditLog.SetSinks(mgr)
	}
}
