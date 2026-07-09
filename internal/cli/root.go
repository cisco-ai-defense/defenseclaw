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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

var (
	cfg                          *config.Config
	auditStore                   *audit.Store
	auditLog                     *audit.Logger
	otelProvider                 *telemetry.Provider // deprecated schema-v7 lifecycle seam
	appVersion                   string
	activeObservabilityV8Startup *observabilityV8Startup
)

// observabilityV8Startup is the immutable source snapshot that was validated
// before any v8-owned stores or exporters were constructed. The sidecar passes
// this exact byte sequence to the authoritative runtime bootstrap immediately
// before Run, preventing a file change between validation and activation from
// producing a mixed generation.
type observabilityV8Startup struct {
	sourceName string
	raw        []byte
}

func SetVersion(v string) {
	appVersion = v
	rootCmd.Version = v
}

func SetBuildInfo(commit, date string) {
	rootCmd.SetVersionTemplate(
		fmt.Sprintf("{{.Name}} version {{.Version}} (commit=%s, built=%s)\n", commit, date),
	)
}

// rootPersistentPreRunE is also used by enterprise hook commands that need
// the same authenticated v8 runtime context without executing the root command.
func rootPersistentPreRunE(_ *cobra.Command, _ []string) error {
	if err := daemon.RegisterCurrentProcess(); err != nil {
		return err
	}
	activeObservabilityV8Startup = nil
	loadDotEnvIntoOS(filepath.Join(config.DefaultDataPath(), ".env"))
	var err error
	cfg, activeObservabilityV8Startup, err = loadGatewayConfigV8(config.ConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load v8 config — run 'defenseclaw upgrade' first: %w", err)
	}
	version.SetBinaryVersion(appVersion)
	if auditDir := filepath.Dir(cfg.AuditDB); auditDir != "." {
		if err := safefile.ProtectDirectory(auditDir); err != nil {
			return fmt.Errorf("failed to prepare audit store directory: %w", err)
		}
	}
	auditStore, err = audit.NewStore(cfg.AuditDB)
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	if err := auditStore.Init(); err != nil {
		return fmt.Errorf("failed to init audit store: %w", err)
	}
	auditLog = audit.NewLogger(auditStore)
	installCorrelator(auditStore, os.Stderr)
	if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
		loadDotEnvIntoOS(resolved)
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "defenseclaw-gateway",
	Short: "DefenseClaw gateway sidecar daemon",
	Long: `DefenseClaw gateway sidecar — connects to the OpenClaw gateway WebSocket,
monitors tool_call and tool_result events, enforces policy in real time,
and exposes a local REST API for the Python CLI.

Run without arguments to start the sidecar daemon.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Windows daemon children can explicitly break away from the launcher's
		// Job Object. Register their strong process identity before any fallible
		// initialization so cancellation cannot strand an unmanaged sidecar.
		if err := daemon.RegisterCurrentProcess(); err != nil {
			return err
		}
		// Cobra normally executes this process once, but tests and embedders can
		// execute the command tree repeatedly. Never retain a previous source.
		activeObservabilityV8Startup = nil

		// Load the default installation .env before strict v8 compilation so
		// destination token_env/bearer_env references work for a daemon without
		// an interactive shell. loadConfigV8File repeats this for the source's
		// resolved data_dir before validating destination secrets.
		loadDotEnvIntoOS(filepath.Join(config.DefaultDataPath(), ".env"))

		var err error
		cfg, activeObservabilityV8Startup, err = loadGatewayConfigV8(config.ConfigPath())
		if err != nil {
			return fmt.Errorf("failed to load v8 config — run 'defenseclaw upgrade' first: %w", err)
		}
		version.SetBinaryVersion(appVersion)

		if auditDir := filepath.Dir(cfg.AuditDB); auditDir != "." {
			if err := safefile.ProtectDirectory(auditDir); err != nil {
				return fmt.Errorf("failed to prepare audit store directory: %w", err)
			}
		}
		auditStore, err = audit.NewStore(cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}
		if err := auditStore.Init(); err != nil {
			return fmt.Errorf("failed to init audit store: %w", err)
		}

		auditLog = audit.NewLogger(auditStore)

		// Register the sliding-window correlator so EmitScanResult
		// runs it against every persisted scan's session window.
		// A failure to load the embedded pattern set logs to stderr
		// and leaves correlation disabled — the rest of the guardrail
		// stack is unaffected.
		installCorrelator(auditStore, os.Stderr)

		// Re-run with the resolved data dir in case DEFENSECLAW_HOME
		// redirected it; second call is a no-op when paths match.
		if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
			loadDotEnvIntoOS(resolved)
		}
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {
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

// loadGatewayConfigV8 strict-parses and compiles the exact source snapshot
// before the general Config decoder sees it. The target gateway therefore
// never invokes v7 compatibility decoding or runtime migration; those belong
// exclusively to `defenseclaw upgrade`.
func loadGatewayConfigV8(path string) (*config.Config, *observabilityV8Startup, error) {
	loaded, err := loadConfigV8File(path, config.DefaultDataPath())
	if err != nil {
		return nil, nil, err
	}
	candidate, err := config.LoadRuntimeV8FromBytes(loaded.source, loaded.raw)
	if err != nil {
		return nil, nil, err
	}
	if candidate.ConfigVersion != config.ObservabilityV8ConfigVersion {
		return nil, nil, fmt.Errorf("schema v8 is required; run 'defenseclaw upgrade' first")
	}
	startup, err := prepareCompiledObservabilityV8Startup(candidate, loaded)
	if err != nil {
		return nil, nil, err
	}
	return candidate, startup, nil
}

// prepareObservabilityV8Startup remains a testable exact-source seam for
// callers that already hold a proven v8 Config. Production startup uses
// loadGatewayConfigV8 so strict parsing always precedes Config decoding.
func prepareObservabilityV8Startup(c *config.Config) (*observabilityV8Startup, error) {
	if c == nil || c.ConfigVersion != config.ObservabilityV8ConfigVersion {
		return nil, fmt.Errorf("schema version 8 is required")
	}
	sourceName := strings.TrimSpace(c.ConfigFilePath)
	if sourceName == "" {
		sourceName = config.ConfigPath()
	}
	loaded, err := loadConfigV8File(sourceName, c.DataDir)
	if err != nil {
		return nil, err
	}
	return prepareCompiledObservabilityV8Startup(c, loaded)
}

func prepareCompiledObservabilityV8Startup(c *config.Config, loaded *loadedConfigV8File) (*observabilityV8Startup, error) {
	if c == nil || loaded == nil || loaded.compiled == nil || loaded.compiled.Plan == nil {
		return nil, fmt.Errorf("canonical compiler returned no effective plan")
	}
	snapshot := loaded.compiled.Plan.Snapshot()
	if strings.TrimSpace(snapshot.Local.Path) == "" || strings.TrimSpace(snapshot.Local.JudgeBodiesPath) == "" {
		return nil, fmt.Errorf("effective local store paths are incomplete")
	}
	if err := config.ApplyRuntimeV8DataDirDefaultsFromBytes(
		c, loaded.source, loaded.raw, loaded.compiled.DataDir,
	); err != nil {
		return nil, err
	}

	c.DataDir = loaded.compiled.DataDir
	c.AuditDB = snapshot.Local.Path
	c.JudgeBodiesDB = snapshot.Local.JudgeBodiesPath
	return &observabilityV8Startup{
		sourceName: loaded.source,
		raw:        append([]byte(nil), loaded.raw...),
	}, nil
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

// loadDotEnvIntoOS reads KEY=VALUE pairs from path and sets them as
// environment variables unless already present. This makes v8 destination
// token_env/bearer_env references and non-observability application secrets
// available when the sidecar runs without an interactive shell.
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
