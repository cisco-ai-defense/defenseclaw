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
		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config — run 'defenseclaw init' first: %w", err)
		}

		auditStore, err = audit.NewStore(cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}
		if err := auditStore.Init(); err != nil {
			return fmt.Errorf("failed to init audit store: %w", err)
		}

		auditLog = audit.NewLogger(auditStore)
		loadDotEnvIntoOS(filepath.Join(cfg.DataDir, ".env"))
		initSplunkForwarder()
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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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
// persisted by "defenseclaw setup splunk" (e.g. SPLUNK_ACCESS_TOKEN)
// are available to the OTel provider and Splunk HEC forwarder when
// the sidecar runs as a daemon without the user's shell environment.
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

func initSplunkForwarder() {
	if cfg == nil || !cfg.Splunk.Enabled {
		return
	}

	token := cfg.Splunk.ResolvedHECToken()
	if token == "" {
		fmt.Fprintln(os.Stderr, "warning: splunk.enabled=true but no HEC token configured")
		return
	}

	splunkCfg := audit.SplunkConfig{
		HECEndpoint:   cfg.Splunk.HECEndpoint,
		HECToken:      token,
		Index:         cfg.Splunk.Index,
		Source:        cfg.Splunk.Source,
		SourceType:    cfg.Splunk.SourceType,
		VerifyTLS:     cfg.Splunk.VerifyTLS,
		Enabled:       true,
		BatchSize:     cfg.Splunk.BatchSize,
		FlushInterval: cfg.Splunk.FlushInterval,
	}

	fwd, err := audit.NewSplunkForwarder(splunkCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: splunk init: %v\n", err)
		return
	}

	auditLog.SetSplunkForwarder(fwd)
}
