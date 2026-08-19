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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

var (
	cfg                          *config.Config
	auditStore                   *audit.Store
	auditLog                     *audit.Logger
	appVersion                   string
	appCommit                    string
	appBuildDate                 string
	versionJSON                  bool
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
	appCommit = commit
	appBuildDate = date
	rootCmd.SetVersionTemplate(
		fmt.Sprintf("{{.Name}} version {{.Version}} (commit=%s, built=%s)\n", commit, date),
	)
}

type machineVersionReport struct {
	SchemaVersion int    `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit,omitempty"`
	Built         string `json:"built,omitempty"`
}

func writeMachineVersion(w io.Writer) error {
	return json.NewEncoder(w).Encode(machineVersionReport{
		SchemaVersion: 1,
		Name:          "defenseclaw-gateway",
		Version:       appVersion,
		Commit:        appCommit,
		Built:         appBuildDate,
	})
}

func rootPersistentPreRunE(cmd *cobra.Command, _ []string) error {
	if versionJSON {
		return nil
	}
	// Enterprise hook commands also use this initializer so they receive the
	// same authenticated v8 runtime context as the root sidecar command.
	// A Windows daemon may explicitly break away from the TUI's Job Object.
	// Claim its strong PID identity before any fallible/slow initialization so
	// an abruptly cancelled launcher cannot leave an unmanaged live sidecar.
	if err := daemon.RegisterCurrentProcess(); err != nil {
		return err
	}
	activeObservabilityV8Startup = nil
	loadDotEnvIntoOS(filepath.Join(config.DefaultDataPath(), ".env"))
	var err error
	cfgPath := config.ConfigPath()
	cfg, activeObservabilityV8Startup, err = loadGatewayConfigV8(cfgPath)
	if err != nil {
		// Spec 003 B2: in managed_enterprise, tolerate a missing
		// config.yaml at startup by fsnotify-waiting for UCB to drop
		// it. Non-managed-enterprise deployments (OSS / SaaS / DP /
		// CP) retain the existing fail-fast; the pin-based gate
		// makes sure a wait loop never starts outside its intended
		// scope. See docs/specs/003-windows-deferred-config/.
		retry, waitErr := enterConfigWaitLoopIfManaged(cmd.Context(), cfgPath, err, cmd.ErrOrStderr())
		if waitErr != nil {
			return waitErr
		}
		if !retry {
			return fmt.Errorf("failed to load config: %w", err)
		}
		cfg, activeObservabilityV8Startup, err = loadGatewayConfigV8(cfgPath)
		if err != nil {
			// The wait declared config.yaml present; a second
			// failure now is a real parse/permission problem, not
			// another missing-file case worth waiting through.
			return fmt.Errorf("failed to load config after wait: %w", err)
		}
	}
	version.SetBinaryVersion(appVersion)
	if auditDir := filepath.Dir(cfg.AuditDB); auditDir != "." {
		if err := managed.PrepareServiceRuntimeDir(cfg.DeploymentMode, auditDir, "audit store directory"); err != nil {
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
	PersistentPreRunE: rootPersistentPreRunE,
	PersistentPostRun: func(_ *cobra.Command, _ []string) {
		if auditLog != nil {
			auditLog.Close()
		}
		if auditStore != nil {
			auditStore.Close()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionJSON {
			return writeMachineVersion(cmd.OutOrStdout())
		}
		return runSidecar(cmd, args)
	},
	SilenceUsage: true,
}

// rootPersistentPreRunNoAuditE mirrors rootPersistentPreRunE minus the
// audit.db open. Used by co-resident subcommands that never read or write the
// audit store — most importantly the hook-guardian's `enterprise hooks watch`,
// which runs as a long-lived LaunchDaemon beside the main gateway. SQLite
// cannot accept two RW owners on the same file, so opening audit.db from a
// co-resident daemon consistently fails with SQLITE_BUSY (5); and the same
// unlink-on-close hazard flagged in loadGatewayCommandConfigOnly's comment
// applies to long-lived hooks daemons too. The enterprise hooks pathway does
// not read auditStore / auditLog anywhere, so skipping the open is dead-work
// removal, not a feature drop.
func rootPersistentPreRunNoAuditE(cmd *cobra.Command, _ []string) error {
	if versionJSON {
		return nil
	}
	if err := daemon.RegisterCurrentProcess(); err != nil {
		return err
	}
	if err := loadGatewayCommandConfigOnly(); err != nil {
		return err
	}
	return nil
}

// loadGatewayCommandConfigOnly performs the strict v8 configuration phase
// shared by the daemon and read-only control commands. It deliberately does
// not open audit.db: a short-lived `status` process must never become a second
// SQLite owner beside the running daemon, because closing that connection can
// unlink the daemon's live WAL/SHM files on supported SQLite implementations.
func loadGatewayCommandConfigOnly() error {
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
		return fmt.Errorf("failed to load config: %w", err)
	}
	version.SetBinaryVersion(appVersion)

	// Re-run with the resolved data dir in case DEFENSECLAW_HOME redirected
	// it; the second call is a no-op when paths match.
	if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
		loadDotEnvIntoOS(resolved)
	}
	return nil
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

// SetCommandName selects one of the two release-owned names for the shared Go
// executable. The enterprise package installs the same command surface as
// defenseclaw.exe for administrator lifecycle operations and as
// defenseclaw-gateway.exe for SCM hosting. Arbitrary argv[0] values are never
// reflected into help or diagnostics.
func SetCommandName(name string) {
	switch name {
	case "defenseclaw", "defenseclaw-gateway":
		rootCmd.Use = name
	}
}

func init() {
	rootCmd.Flags().BoolVar(&versionJSON, "version-json", false, "emit the exact build version as JSON and exit")
}

// Execute runs the root command and returns the exit code. The actual
// os.Exit call belongs in main() so deferred cleanup (PersistentPostRun)
// always executes.
func Execute() int {
	return ExecuteContext(context.Background())
}

// ExecuteContext runs the root command with a caller-owned lifetime.
//
// Interactive invocations use Execute, which preserves the historical
// background context. A native Windows Service Control Manager host uses this
// entry point so SERVICE_CONTROL_STOP and SERVICE_CONTROL_SHUTDOWN can cancel
// the long-running gateway or hook-guardian command without terminating the
// process abruptly.
func ExecuteContext(ctx context.Context) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		// Cancellation is the expected completion path for an SCM stop. Do not
		// report it as a service failure or trigger failure-recovery restarts.
		if errors.Is(err, context.Canceled) {
			return 0
		}
		return commandExitCode(err)
	}
	return 0
}

// loadDotEnvIntoOS reads KEY=VALUE pairs from path and sets them as
// environment variables unless already present. This makes v8 destination
// token_env/bearer_env references and non-observability application secrets
// available when the sidecar runs without an interactive shell.
func loadDotEnvIntoOS(path string) {
	data, err := safefile.ReadRegularFileBounded(path, safefile.MaxDotEnvBytes)
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
		if !dotEnvKeyIsValid(k) || strings.IndexByte(v, 0) >= 0 || dotEnvKeyIsProcessControl(k) {
			continue
		}
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" && os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

func dotEnvKeyIsProcessControl(key string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(key))
	switch normalized {
	case "ALL_PROXY", "BASH_ENV", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COMSPEC",
		"CURL_CA_BUNDLE",
		"DEFENSECLAW_CODEX_LOOPBACK_TRUST",
		"DEFENSECLAW_CONFIG", "DEFENSECLAW_DATA_DIR", "DEFENSECLAW_GATEWAY_BIN",
		"DEFENSECLAW_HOME", "DEFENSECLAW_DEV", "DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM",
		"DEFENSE" + "CLAW_DISABLE_REDACTION", "DEFENSECLAW_DUMP_RAW_SECRETS",
		"DEFENSECLAW_FAIL_MODE", "DEFENSECLAW_FORCE_AWS_HTTP1_SHIM",
		"DEFENSECLAW_JSONL_DISABLE", "DEFENSECLAW_OPENSHELL_ALLOW_UNPINNED",
		"DEFENSECLAW_OTEL_TLS_INSECURE", "DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA",
		"DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY", "DEFENSECLAW_REVEAL_PII",
		"DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP", "DEFENSECLAW_STRICT_AVAILABILITY",
		"DEFENSECLAW_TEST", "DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN",
		"DEFENSECLAW_TRUSTED_PROXY_CIDRS", "DEFENSECLAW_UNGUARDED_CHATGPT_CODEX_RESPONSES",
		"DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED", "DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST",
		daemon.EnvDaemon,
		"ENV", "GIT_SSL_NO_VERIFY", "HOME", "HTTP_PROXY", "HTTPS_PROXY",
		"LOCPATH", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NO_PROXY", "PATH", "PATHEXT",
		"PYTHONHOME", "PYTHONPATH",
		"PYTHONSTARTUP", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "USERPROFILE",
		"REQUESTS_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE", "WINDIR",
		"XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
		"XDG_RUNTIME_DIR", "XDG_STATE_HOME":
		return true
	default:
		return strings.HasPrefix(normalized, "LD_") ||
			strings.HasPrefix(normalized, "DYLD_") ||
			strings.HasPrefix(normalized, "DEFENSE"+"CLAW_ALLOW_")
	}
}

func dotEnvKeyIsValid(key string) bool {
	if key == "" {
		return false
	}
	for index := 0; index < len(key); index++ {
		character := key[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character == '_' ||
			index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
